package filetransfer

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/weishengsuptp/innerlink-core/internal/protocol"
)

// FileOffer is the JSON payload of protocol.TypeFileOffer. The
// receiver uses it to decide whether it can store the file
// (size, name) and to verify integrity on completion (sha256).
type FileOffer struct {
	FileID      string `json:"fileID"`
	Name        string `json:"name"`
	Size        int64  `json:"size"`
	SHA256      string `json:"sha256"`      // full-file hex
	TotalChunks uint32 `json:"totalChunks"` // ceil(Size / ChunkSize)
	ChunkSize   int32  `json:"chunkSize"`   // always ChunkSize in v0.1
}

// FileAccept is the JSON payload of protocol.TypeFileAccept. The
// sender skips any chunk index in AcceptedChunks — that's how
// resume works.
type FileAccept struct {
	FileID         string   `json:"fileID"`
	AcceptedChunks []uint32 `json:"acceptedChunks"`
}

// FileChunk is the JSON payload of protocol.TypeFileChunk.
// Data is the base64 encoding of the raw ChunkSize-byte slice
// (or the smaller tail slice for the last chunk).
type FileChunk struct {
	FileID string `json:"fileID"`
	Index  uint32 `json:"index"`
	SHA256 string `json:"sha256"` // per-chunk hex
	Data   []byte `json:"data"`   // base64 auto-marshalled
}

// FileDone is the JSON payload of protocol.TypeFileDone.
type FileDone struct {
	FileID string `json:"fileID"`
	OK     bool   `json:"ok"`
	Err    string `json:"err,omitempty"`
}

// FileAbort is the JSON payload of protocol.TypeFileAbort.
type FileAbort struct {
	FileID string `json:"fileID"`
	Reason string `json:"reason"`
}

// ProgressFn is called periodically by Send so the UI can draw
// a progress bar. The sender does not block on this callback.
type ProgressFn func(sent, total int64)

// Send streams the file at path to the peer reachable through
// the given protocol.Channel. It blocks until the receiver
// acknowledges Done, the transfer is aborted, or ctx fires.
//
// On success, the file's SHA-256 has been verified by the
// receiver. Send returns nil only after that ack.
func Send(ctx context.Context, ch *protocol.Channel, path string, progress ProgressFn) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("filetransfer: open: %w", err)
	}
	defer f.Close()

	stat, err := f.Stat()
	if err != nil {
		return fmt.Errorf("filetransfer: stat: %w", err)
	}
	if !stat.Mode().IsRegular() {
		return fmt.Errorf("filetransfer: not a regular file: %s", path)
	}

	// Hash the whole file up front so the Offer carries the
	// full-file checksum. For multi-GB files this means the
	// sender reads the file once for hashing, then a second
	// time for sending. v0.1 keeps it simple: a v0.2 streaming
	// variant could cache the chunk hashes from this pass.
	fullHash, err := HashFileSHA256(path)
	if err != nil {
		return fmt.Errorf("filetransfer: hash: %w", err)
	}

	totalChunks := uint32((stat.Size() + int64(ChunkSize) - 1) / int64(ChunkSize))
	offer := FileOffer{
		FileID:      NewFileID(),
		Name:        stat.Name(),
		Size:        stat.Size(),
		SHA256:      fullHash,
		TotalChunks: totalChunks,
		ChunkSize:   int32(ChunkSize),
	}

	// 1) Send Offer.
	if err := sendJSON(ctx, ch, protocol.TypeFileOffer, offer); err != nil {
		return fmt.Errorf("filetransfer: send offer: %w", err)
	}

	// 2) Wait for Accept. The receiver may take a moment to
	//    decide (UI prompt, disk check, etc.).
	acceptRaw, err := recvFileFrame(ctx, ch, offer.FileID, protocol.TypeFileAccept)
	if err != nil {
		return fmt.Errorf("filetransfer: wait accept: %w", err)
	}
	var accept FileAccept
	if err := json.Unmarshal(acceptRaw.Payload, &accept); err != nil {
		return fmt.Errorf("filetransfer: decode accept: %w", err)
	}
	if accept.FileID != offer.FileID {
		return fmt.Errorf("filetransfer: accept fileID mismatch")
	}
	skip := chunkSet(accept.AcceptedChunks)

	// 3) Stream chunks. The progress callback is throttled to
	//    ~10 Hz to avoid log spam.
	buf := make([]byte, ChunkSize)
	var sent int64
	lastReport := time.Now()
	for idx := uint32(0); idx < totalChunks; idx++ {
		if err := ctx.Err(); err != nil {
			sendAbort(ctx, ch, offer.FileID, ctx.Err().Error())
			return err
		}
		if skip[idx] {
			// Resuming: this chunk is already on the other side.
			n, _ := f.Seek(int64(idx)*int64(ChunkSize), io.SeekStart)
			sent = n
			if progress != nil && time.Since(lastReport) > 100*time.Millisecond {
				progress(sent, stat.Size())
				lastReport = time.Now()
			}
			continue
		}

		n, rerr := io.ReadFull(f, buf)
		if rerr != nil && rerr != io.ErrUnexpectedEOF && rerr != io.EOF {
			return fmt.Errorf("filetransfer: read chunk %d: %w", idx, rerr)
		}
		chunk := buf[:n]
		chunkHash := HashChunkSHA256(chunk)
		fc := FileChunk{
			FileID: offer.FileID,
			Index:  idx,
			SHA256: chunkHash,
			Data:   chunk, // base64 by json marshal
		}
		if err := sendJSON(ctx, ch, protocol.TypeFileChunk, fc); err != nil {
			return fmt.Errorf("filetransfer: send chunk %d: %w", idx, err)
		}
		sent += int64(n)
		if progress != nil && time.Since(lastReport) > 100*time.Millisecond {
			progress(sent, stat.Size())
			lastReport = time.Now()
		}
	}
	if progress != nil {
		progress(stat.Size(), stat.Size())
	}

	// 4) Wait for Done.
	doneRaw, err := recvFileFrame(ctx, ch, offer.FileID, protocol.TypeFileDone)
	if err != nil {
		return fmt.Errorf("filetransfer: wait done: %w", err)
	}
	var done FileDone
	if err := json.Unmarshal(doneRaw.Payload, &done); err != nil {
		return fmt.Errorf("filetransfer: decode done: %w", err)
	}
	if !done.OK {
		return fmt.Errorf("filetransfer: receiver reported failure: %s", done.Err)
	}
	return nil
}

// sendAbort is best-effort. We use a fresh context with a short
// timeout so a cancelled parent ctx still allows us to flush
// the abort before giving up.
func sendAbort(ctx context.Context, ch *protocol.Channel, fileID, reason string) {
	abortCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = sendJSON(abortCtx, ch, protocol.TypeFileAbort, FileAbort{FileID: fileID, Reason: reason})
	_ = ctx
}

func sendJSON(ctx context.Context, ch *protocol.Channel, t protocol.MsgType, payload any) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return ch.Send(ctx, protocol.Envelope{
		Version: protocol.ProtocolVersion,
		Type:    t,
		MsgID:   newMsgID(),
		Payload: raw,
	})
}

// recvFileFrame blocks on ch.Recv until an Envelope of the
// expected type and fileID arrives, or ctx fires. Any envelope
// of a different type or fileID is silently dropped (other
// transfers / chat can be multiplexed on the same channel).
//
// If a TypeFileAbort for our fileID arrives while we wait, we
// return immediately with a typed error.
func recvFileFrame(ctx context.Context, ch *protocol.Channel, fileID string, want protocol.MsgType) (protocol.Envelope, error) {
	for {
		if err := ctx.Err(); err != nil {
			return protocol.Envelope{}, err
		}
		env, err := ch.Recv(ctx)
		if err != nil {
			return protocol.Envelope{}, err
		}
		// Aborts interrupt the wait regardless of what we
		// were waiting for. Match by fileID so a different
		// transfer's abort doesn't poison us.
		if env.Type == protocol.TypeFileAbort {
			if envelopeMatchesFileID(env, fileID) {
				var a FileAbort
				_ = json.Unmarshal(env.Payload, &a)
				return protocol.Envelope{}, fmt.Errorf("filetransfer: aborted by peer: %s", a.Reason)
			}
			continue
		}
		if env.Type != want {
			// Could be chat from the other side, or a chunk
			// from a different transfer. Drop it; the caller
			// of Send does not care about non-file traffic
			// and the Receiver goroutine is the one that
			// would normally handle those.
			continue
		}
		// Best-effort: every payload we care about carries a
		// "fileID" string; if it's missing or mismatched, the
		// envelope is for someone else.
		if !envelopeMatchesFileID(env, fileID) {
			continue
		}
		return env, nil
	}
}

func envelopeMatchesFileID(env protocol.Envelope, fileID string) bool {
	// Cheap parse: every payload we care about starts with
	// {"fileID":"<hex>", ...}. Avoid a full Unmarshal per
	// envelope; use json.RawMessage probing.
	var probe struct {
		FileID string `json:"fileID"`
	}
	if err := json.Unmarshal(env.Payload, &probe); err != nil {
		return false
	}
	return probe.FileID == fileID
}

func chunkSet(in []uint32) map[uint32]bool {
	m := make(map[uint32]bool, len(in))
	for _, v := range in {
		m[v] = true
	}
	return m
}

// newMsgID returns 8 random bytes. protocol.Envelope.MsgID is
// []byte; the protocol layer's existing helper generates 8
// bytes for the chat code, so we match that width.
func newMsgID() []byte {
	b := make([]byte, 8)
	_, _ = randRead(b)
	return b
}
