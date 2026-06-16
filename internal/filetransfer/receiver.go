package filetransfer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/weishengsuptp/innerlink-core/internal/protocol"
)

// ReceivedFile is what Receiver produces on disk.
type ReceivedFile struct {
	FileID   string
	Name     string
	Path     string // final location
	Size     int64
	SHA256   string
	fromPeer string // hex peerID, for logs
}

// OnOffer is a callback the upper layer can use to decide
// whether to accept an incoming transfer. Return nil to accept;
// return a non-nil error to reject (Receiver will then send
// Abort and drop the offer). The default behaviour when this
// is nil is to accept every offer.
type OnOffer func(offer FileOffer, fromPeer string) error

// Receiver handles incoming file offers on a Channel. Run Loop
// in its own goroutine; it returns when ctx is cancelled or
// the channel is closed.
type Receiver struct {
	ch       *protocol.Channel
	saveDir  string
	onOffer  OnOffer
	fromPeer string

	// in-memory state for resume support. In v0.1 we keep this
	// for the lifetime of a single Receiver instance, so a
	// partial transfer can be resumed if the channel comes
	// back up before Receiver is stopped. Persisting this
	// across restarts is a v0.3 feature.
	partFiles map[string]*partFile // key = fileID
}

type partFile struct {
	offer       FileOffer
	path        string // temp file path
	have        []bool // have[index] == true
	hashWhole   hashAccumulator
	bytesOnDisk int64
}

// NewReceiver constructs a Receiver. saveDir is the directory
// where completed files land; onOffer (if non-nil) gates each
// incoming offer. fromPeer is the human-readable peer label
// passed to onOffer.
func NewReceiver(ch *protocol.Channel, saveDir string, onOffer OnOffer, fromPeer string) (*Receiver, error) {
	if err := os.MkdirAll(saveDir, 0o755); err != nil {
		return nil, fmt.Errorf("filetransfer: mkdir save dir: %w", err)
	}
	// Incoming staging dir for temp files; clean any stale
	// parts from a prior crash.
	if err := os.MkdirAll(filepath.Join(saveDir, ".incoming"), 0o755); err != nil {
		return nil, fmt.Errorf("filetransfer: mkdir incoming: %w", err)
	}
	return &Receiver{
		ch:        ch,
		saveDir:   saveDir,
		onOffer:   onOffer,
		fromPeer:  fromPeer,
		partFiles: make(map[string]*partFile),
	}, nil
}

// Loop reads envelopes from the channel until ctx is cancelled
// or the channel is closed. Any chat/text/ping traffic is
// silently dropped — the chat pump is a separate goroutine.
//
// IMPORTANT: a single Channel must have exactly ONE goroutine
// calling Channel.Recv at a time. If you also need a chat
// pump on the same channel, use Handle() and dispatch from
// your own pump loop instead of calling Loop().
//
// The actual file-data path is: receive offer → maybe accept
// → stream chunks to disk → verify → send Done.
func (r *Receiver) Loop(ctx context.Context) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		env, err := r.ch.Recv(ctx)
		if err != nil {
			return err
		}
		r.Handle(ctx, env)
	}
}

// Handle dispatches one envelope to the receiver. Use this
// from a single-pump dispatch loop (see cmd/innerlink) when
// chat and file traffic share the same Channel. The receiver
// owns the Envelopes of file types (Offer / Chunk / Abort);
// all other types are silently dropped.
func (r *Receiver) Handle(ctx context.Context, env protocol.Envelope) {
	switch env.Type {
	case protocol.TypeFileOffer:
		r.handleOffer(ctx, env)
	case protocol.TypeFileChunk:
		r.handleChunk(ctx, env)
	case protocol.TypeFileAbort:
		// From a sender that gives up. Clean up our temp
		// file if any.
		var a FileAbort
		if err := json.Unmarshal(env.Payload, &a); err == nil {
			r.abort(a.FileID, a.Reason)
		}
	default:
		// Not for us. Drop.
	}
}

// handleOffer reacts to a new incoming file. It writes back the
// Accept (with the empty "have" list — v0.1 has no resume
// across restarts), creates the temp file, and registers the
// part in r.partFiles.
func (r *Receiver) handleOffer(ctx context.Context, env protocol.Envelope) {
	var offer FileOffer
	if err := json.Unmarshal(env.Payload, &offer); err != nil {
		return
	}
	if r.onOffer != nil {
		if err := r.onOffer(offer, r.fromPeer); err != nil {
			_ = sendJSON(ctx, r.ch, protocol.TypeFileAbort,
				FileAbort{FileID: offer.FileID, Reason: err.Error()})
			return
		}
	}
	// We always start from scratch. If a previous attempt left
	// a temp file, overwrite it (the new offer has a new
	// fileID, so collisions are vanishingly unlikely).
	pf := &partFile{
		offer:     offer,
		have:      make([]bool, offer.TotalChunks),
		hashWhole: *newHashAccumulator(),
	}
	pf.path = filepath.Join(r.saveDir, ".incoming", offer.FileID+".part")
	f, err := os.Create(pf.path)
	if err != nil {
		_ = sendJSON(ctx, r.ch, protocol.TypeFileAbort,
			FileAbort{FileID: offer.FileID, Reason: err.Error()})
		return
	}
	_ = f.Close()
	r.partFiles[offer.FileID] = pf

	// Accept with empty list: no resume in v0.1.
	accept := FileAccept{FileID: offer.FileID, AcceptedChunks: nil}
	_ = sendJSON(ctx, r.ch, protocol.TypeFileAccept, accept)
}

// handleChunk writes one chunk to the temp file at the right
// offset, verifies the per-chunk SHA-256, and checks if this
// is the last chunk — if so, verify the full file hash and
// send Done.
func (r *Receiver) handleChunk(ctx context.Context, env protocol.Envelope) {
	var fc FileChunk
	if err := json.Unmarshal(env.Payload, &fc); err != nil {
		return
	}
	pf, ok := r.partFiles[fc.FileID]
	if !ok {
		// Unknown fileID — probably an old chunk arriving
		// after we've aborted. Drop.
		return
	}
	if fc.Index >= pf.offer.TotalChunks {
		_ = r.sendDone(ctx, pf, false, "index out of range")
		r.abort(fc.FileID, "out of range")
		return
	}
	// Per-chunk hash.
	got := sha256.Sum256(fc.Data)
	if hex.EncodeToString(got[:]) != fc.SHA256 {
		_ = r.sendDone(ctx, pf, false, "chunk sha256 mismatch")
		r.abort(fc.FileID, "chunk sha256 mismatch")
		return
	}
	// Write at offset.
	f, err := os.OpenFile(pf.path, os.O_WRONLY, 0o644)
	if err != nil {
		_ = r.sendDone(ctx, pf, false, err.Error())
		return
	}
	offset := int64(fc.Index) * int64(ChunkSize)
	if _, err := f.WriteAt(fc.Data, offset); err != nil {
		_ = f.Close()
		_ = r.sendDone(ctx, pf, false, err.Error())
		return
	}
	_ = f.Close()
	pf.have[fc.Index] = true
	pf.hashWhole.Write(fc.Data)
	pf.bytesOnDisk += int64(len(fc.Data))

	// Last chunk?
	if uint32(fc.Index) == pf.offer.TotalChunks-1 {
		if err := r.finalize(ctx, pf); err != nil {
			_ = r.sendDone(ctx, pf, false, err.Error())
			r.abort(fc.FileID, err.Error())
		}
	}
}

// finalize verifies the full-file SHA-256, renames the temp
// file into the save directory, and sends Done.
func (r *Receiver) finalize(ctx context.Context, pf *partFile) error {
	// All chunks present?
	for i, h := range pf.have {
		if !h {
			return fmt.Errorf("missing chunk %d", i)
		}
	}
	if pf.hashWhole.SumHex() != pf.offer.SHA256 {
		return errors.New("full-file sha256 mismatch")
	}
	finalPath := filepath.Join(r.saveDir, pf.offer.Name)
	if err := os.Rename(pf.path, finalPath); err != nil {
		// Cross-device rename: fall back to copy + unlink.
		if err := copyFile(pf.path, finalPath); err != nil {
			return err
		}
		_ = os.Remove(pf.path)
	}
	return r.sendDone(ctx, pf, true, "")
}

func (r *Receiver) sendDone(ctx context.Context, pf *partFile, ok bool, errMsg string) error {
	return sendJSON(ctx, r.ch, protocol.TypeFileDone, FileDone{
		FileID: pf.offer.FileID,
		OK:     ok,
		Err:    errMsg,
	})
}

func (r *Receiver) abort(fileID, reason string) {
	pf, ok := r.partFiles[fileID]
	if !ok {
		return
	}
	_ = os.Remove(pf.path)
	delete(r.partFiles, fileID)
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Close()
}
