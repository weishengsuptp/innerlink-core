package filetransfer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

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
	// replyWaiters is a registry of goroutines blocked inside
	// Sender.Send waiting for the matching Accept / Done /
	// Abort envelope. The dispatcher pump on the cmd/innerlink
	// CLI is the one goroutine that actually reads envelopes
	// from the channel, so file Send and file Receive both
	// share a single Recv path. The Receiver owns this
	// registry because it is the one already inside Handle()
	// when an Accept/Done envelope arrives; it forwards the
	// envelope to whichever Send() is waiting on it.
	//
	// Keys are "<wantType>:<fileID>" so a sender waiting for
	// Accept and a different sender waiting for Done on the
	// same fileID don't collide.
	replyWaiters map[string]chan<- protocol.Envelope
	// pendingReplies caches reply envelopes that arrived
	// before their corresponding WaitForReply registration
	// — e.g. the receiver emits Accept as soon as it
	// receives Offer, which can happen before the sender
	// has called WaitForReply(ctx, TypeFileAccept, fileID).
	// Without this cache, the Accept would be dropped and
	// the sender would block on wait accept until ctx
	// timeout.
	//
	// Only one envelope is cached per (wantType, fileID)
	// key — the most recent reply wins. (In v0.1 each
	// fileID has at most one Accept and one Done, so there
	// is no real "most recent" ambiguity.)
	pendingReplies map[string]protocol.Envelope
	replyMu        sync.Mutex
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
		ch:             ch,
		saveDir:        saveDir,
		onOffer:        onOffer,
		fromPeer:       fromPeer,
		partFiles:      make(map[string]*partFile),
		replyWaiters:   make(map[string]chan<- protocol.Envelope),
		pendingReplies: make(map[string]protocol.Envelope),
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
	// Accept / Done / Abort envelopes are replies to a
	// Sender blocked in Send(). Forward them to the
	// registered waiter so the sender's wait loop can
	// continue. This is the only correct way to do file
	// transfer on a channel that is also being read by a
	// dispatcher pump — the dispatcher reads every envelope,
	// so the sender cannot also call ch.Recv directly (it
	// would race the dispatcher for Accept and the dispatcher
	// would silently drop Accept as "non-file traffic").
	if env.Type == protocol.TypeFileAccept ||
		env.Type == protocol.TypeFileDone ||
		env.Type == protocol.TypeFileAbort {
		// Extract the fileID from the payload so we can
		// route to the correct waiter. For TypeFileAbort
		// we also want to clean up the part file.
		var fileID string
		switch env.Type {
		case protocol.TypeFileAccept:
			var a FileAccept
			_ = json.Unmarshal(env.Payload, &a)
			fileID = a.FileID
		case protocol.TypeFileDone:
			var d FileDone
			_ = json.Unmarshal(env.Payload, &d)
			fileID = d.FileID
		case protocol.TypeFileAbort:
			var a FileAbort
			_ = json.Unmarshal(env.Payload, &a)
			fileID = a.FileID
			// Also clean up our temp file if any.
			r.abort(a.FileID, a.Reason)
		}
		if fileID != "" {
			r.deliverReply(env.Type, fileID, env)
		}
		// For Done/Abort the receiver-side Handle path
		// still wants to react (cleanup, etc.). For Accept
		// there is no per-receiver action in v0.1; the
		// sender has already moved on to sending chunks.
		if env.Type == protocol.TypeFileDone {
			var d FileDone
			_ = json.Unmarshal(env.Payload, &d)
			if d.OK {
				_ = d.FileID // success log only — keep noise down
			}
		}
		return
	}
	switch env.Type {
	case protocol.TypeFileOffer:
		r.handleOffer(ctx, env)
	case protocol.TypeFileChunk:
		r.handleChunk(ctx, env)
	default:
		// Not for us. Drop.
	}
}

// WaitForReply blocks until an envelope of want type for
// fileID arrives at Handle, or ctx fires. The dispatcher
// (the one goroutine reading from ch.Recv) must call Handle
// for this to work — otherwise the envelope never reaches
// us and we deadlock.
//
// One waiter per (wantType, fileID) pair. The caller (Send)
// registers, reads the envelope, then unregisters. If ctx
// fires before the envelope arrives, the unregister still
// happens (via defer) so we don't leak a registered channel.
func (r *Receiver) WaitForReply(ctx context.Context, wantType protocol.MsgType, fileID string) (protocol.Envelope, error) {
	key := replyKey(wantType, fileID)
	// First check the pending-reply cache: an Accept
	// envelope may have arrived at Handle() before we
	// got here (Receiver's handleOffer replies
	// synchronously, so the Accept can be in the pipe
	// before Send calls WaitForReply). If we find a
	// cached envelope, return it without ever blocking.
	r.replyMu.Lock()
	if cached, ok := r.pendingReplies[key]; ok {
		delete(r.pendingReplies, key)
		r.replyMu.Unlock()
		return cached, nil
	}
	ch := make(chan protocol.Envelope, 1)
	r.replyWaiters[key] = ch
	r.replyMu.Unlock()
	defer func() {
		r.replyMu.Lock()
		if w, ok := r.replyWaiters[key]; ok && w == ch {
			delete(r.replyWaiters, key)
		}
		// Drain the cache on the way out so a later
		// WaitForReply on the same key starts clean.
		delete(r.pendingReplies, key)
		r.replyMu.Unlock()
		close(ch)
	}()
	select {
	case env, ok := <-ch:
		if !ok {
			return protocol.Envelope{}, ctx.Err()
		}
		return env, nil
	case <-ctx.Done():
		return protocol.Envelope{}, ctx.Err()
	}
}

func replyKey(wantType protocol.MsgType, fileID string) string {
	return string(wantType) + ":" + fileID
}

func (r *Receiver) deliverReply(wantType protocol.MsgType, fileID string, env protocol.Envelope) {
	key := replyKey(wantType, fileID)
	r.replyMu.Lock()
	ch := r.replyWaiters[key]
	if ch == nil {
		// No live waiter. The reply arrived before
		// WaitForReply was called (e.g. the receiver
		// emits Accept synchronously from
		// handleOffer, so the Accept is on the wire
		// before the sender has even called
		// WaitForReply). Cache it; the next
		// WaitForReply on this key will pick it up.
		r.pendingReplies[key] = env
		r.replyMu.Unlock()
		return
	}
	r.replyMu.Unlock()
	// Non-blocking send: if the waiter already gave up
	// (ctx done) it has closed the channel; we must not
	// panic. The defer in WaitForReply has already removed
	// the waiter from the map, so this branch should be
	// rare. Use a recover for safety.
	defer func() { _ = recover() }()
	select {
	case ch <- env:
	default:
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
	writeStart := time.Now()
	if _, err := f.WriteAt(fc.Data, offset); err != nil {
		_ = f.Close()
		_ = r.sendDone(ctx, pf, false, err.Error())
		return
	}
	writeDur := time.Since(writeStart)
	_ = f.Close()
	pf.have[fc.Index] = true
	pf.hashWhole.Write(fc.Data)
	pf.bytesOnDisk += int64(len(fc.Data))
	log.Printf("[FILE] recv chunk idx=%d/%d size=%d writeAt=%s peer=%s",
		fc.Index, pf.offer.TotalChunks, len(fc.Data), writeDur, r.fromPeer)

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
