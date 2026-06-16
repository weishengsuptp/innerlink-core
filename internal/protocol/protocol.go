// Package protocol implements the encrypted application-layer
// message format that innerlink peers exchange after a successful
// handshake.
//
// What it does, in one sentence:
// each application message is wrapped in an Envelope, serialized
// to JSON, encrypted with SM4-GCM (using the SM4 session key from
// internal/handshake), and sent over a transport.Conn as a single
// frame.
//
// What it does NOT do:
//   - Transport: see internal/transport.
//   - Identity / key agreement: see internal/handshake.
//   - File transfer: that uses its own chunking on top of this
//     layer (see internal/filetransfer, v0.1 follow-up).
//
// On-wire format:
//
//	+--------+--------+---------------------+
//	| nonce  |  ct+tag|       ...           |
//	| 12 B   |  ...   |       ...           |
//	+--------+--------+---------------------+
//	\_________________  _________________/
//	                  \/
//	    SM4-GCM(SessionKey, nonce, AAD=msgID, plaintext=JSON(envelope))
//
// The Envelope is JSON, not Protobuf, for v0.1. The serialized
// JSON form is the input to SM4-GCM (the envelope never appears
// on the wire in cleartext). v0.2 migrates to Protobuf.
package protocol

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	ic "github.com/weishengsuptp/innerlink-core/internal/crypto"
	"github.com/weishengsuptp/innerlink-core/internal/handshake"
	"github.com/weishengsuptp/innerlink-core/internal/transport"
)

// ProtocolVersion is the envelope version baked into every message.
// Bumped if the wire format changes incompatibly.
const ProtocolVersion = 1

// MaxEnvelopeSize caps the post-decryption envelope size.
//
// 4 MiB fits one full filetransfer chunk (1 MiB raw bytes
// base64-encoded to ~1.4 MiB, plus JSON/Envelope overhead) with
// ~2.6 MiB of headroom. A peer sending 4 MiB of envelope is
// almost certainly broken (or malicious), but a single
// legitimate file chunk must fit.
//
// See internal/filetransfer.ChunkSize for the matching chunk
// size on the wire.
const MaxEnvelopeSize = 4 << 20 // 4 MiB

// MsgType enumerates the message kinds we know about today.
type MsgType string

const (
	// TypeText is a 1:1 chat message. Payload is a UTF-8 string.
	TypeText MsgType = "text"
	// TypePing is a liveness probe; payload is empty. Reply with TypePong.
	TypePing MsgType = "ping"
	// TypePong is the response to TypePing.
	TypePong MsgType = "pong"
	// TypeAck acknowledges receipt of a message by msgID. Useful
	// for at-least-once delivery semantics in v0.2; v0.1 sends it
	// but doesn't yet use it for anything.
	TypeAck MsgType = "ack"

	// -- File transfer (v0.2) --

	// TypeFileOffer is sent by the file sender to advertise a new
	// transfer. Payload is JSON-encoded FileOffer:
	//   {fileID, name, size, sha256, totalChunks, chunkSize}
	TypeFileOffer MsgType = "file-offer"
	// TypeFileAccept is the receiver's response. Payload is JSON:
	//   {fileID, acceptedChunks:[uint32...]}   // indexes already
	//   on disk, sender skips them (resume support).
	TypeFileAccept MsgType = "file-accept"
	// TypeFileChunk is one slice of the file. Payload is JSON:
	//   {fileID, index, sha256, data(base64-of-1MiB)}
	TypeFileChunk MsgType = "file-chunk"
	// TypeFileDone is the receiver's final ack: all chunks
	// received, full-file SHA-256 verified.
	//   {fileID, ok, err?}
	TypeFileDone MsgType = "file-done"
	// TypeFileAbort is sent by either side to cancel the transfer.
	//   {fileID, reason}
	TypeFileAbort MsgType = "file-abort"
)

// Envelope is the application-level message structure that gets
// encrypted before transmission. See package doc for the on-wire
// encoding.
type Envelope struct {
	Version uint8     `json:"v"`   // ProtocolVersion
	Type    MsgType   `json:"t"`   // one of TypeText/Ping/Pong/Ack
	From    []byte    `json:"f"`   // 16 bytes (sender's PeerID)
	TS      int64     `json:"ts"`  // unix milliseconds
	MsgID   []byte    `json:"mid"` // 8 bytes, random per message
	Payload []byte    `json:"p"`   // type-specific (for text: utf-8 string bytes)
}

// Channel is a single encrypted message stream between two peers.
// It is created after a successful handshake; from then on Send
// and Recv transparently encrypt/decrypt.
type Channel struct {
	conn       *transport.Conn
	session    *handshake.Session
	remotePeer []byte // 16 bytes, copy of session.RemotePeerID

	// recvMu serializes Channel.Recv because the underlying
	// transport.Conn is single-reader. Multiple goroutines on
	// the same Channel may still call Send concurrently (writes
	// are serialized inside transport.Conn.writeMu), but only
	// one goroutine at a time may call Recv.
	recvMu sync.Mutex
}

// NewChannel wraps a transport.Conn that has just completed the
// handshake. The Channel takes ownership of the Conn; callers
// should not use conn directly after this.
func NewChannel(conn *transport.Conn, session *handshake.Session) (*Channel, error) {
	if conn == nil {
		return nil, errors.New("protocol: nil conn")
	}
	if session == nil {
		return nil, errors.New("protocol: nil session")
	}
	if len(session.SessionKey) != handshake.SessionKeySize {
		return nil, fmt.Errorf("protocol: bad session key length %d, want %d",
			len(session.SessionKey), handshake.SessionKeySize)
	}
	remote := make([]byte, len(session.RemotePeerID))
	copy(remote, session.RemotePeerID)
	return &Channel{
		conn:       conn,
		session:    session,
		remotePeer: remote,
	}, nil
}

// RemotePeerID returns a defensive copy of the 16-byte peer ID
// of the other end of this channel.
func (c *Channel) RemotePeerID() []byte {
	out := make([]byte, len(c.remotePeer))
	copy(out, c.remotePeer)
	return out
}

// Close shuts down the underlying conn.
func (c *Channel) Close() error {
	return c.conn.Close()
}

// SendText is the convenience method for sending a chat message.
func (c *Channel) SendText(ctx context.Context, text string) error {
	return c.send(ctx, Envelope{
		Type:    TypeText,
		Payload: []byte(text),
	})
}

// SendPing sends a liveness probe.
func (c *Channel) SendPing(ctx context.Context) error {
	return c.send(ctx, Envelope{Type: TypePing})
}

// Send transmits a fully-formed Envelope. The Channel fills in
// Version, From, TS, and MsgID if the caller leaves them zero.
// Type and Payload must be set.
//
// Use this for non-chat message types (file transfer, custom
// application protocols). For chat, prefer SendText.
func (c *Channel) Send(ctx context.Context, env Envelope) error {
	return c.send(ctx, env)
}

// send is the internal workhorse. Builds an Envelope (filling in
// From, TS, MsgID, Version), JSON-encodes it, SM4-GCM-encrypts
// the result, and writes a single transport frame to conn.
func (c *Channel) send(ctx context.Context, env Envelope) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	env.Version = ProtocolVersion
	if env.From == nil {
		env.From = c.localPeerID() // we don't currently know our own
		// PeerID at the Channel layer; leave blank if unknown. The
		// recipient verifies identity at the handshake layer; the
		// envelope's From field is informational.
	}
	if env.TS == 0 {
		env.TS = time.Now().UnixMilli()
	}
	if env.MsgID == nil {
		id, err := ic.NewNonce(8)
		if err != nil {
			return fmt.Errorf("protocol: gen msgID: %w", err)
		}
		env.MsgID = id
	}
	plain, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("protocol: marshal envelope: %w", err)
	}
	// 12-byte nonce per message (SM4-GCM standard).
	nonce, err := ic.NewNonce(ic.SM4GCMNonceSize)
	if err != nil {
		return fmt.Errorf("protocol: gen nonce: %w", err)
	}
	// v0.1: no AAD. The MsgID is inside the encrypted envelope,
	// so GCM still authenticates it as part of the plaintext.
	// A future revision can pass env.MsgID as AAD after sending
	// the MsgID in cleartext first.
	ct, err := ic.SM4EncryptGCM(c.session.SessionKey, nonce, plain, nil)
	if err != nil {
		return fmt.Errorf("protocol: encrypt: %w", err)
	}
	// On-wire: nonce || ct (ct already includes the tag).
	frame := make([]byte, 0, len(nonce)+len(ct))
	frame = append(frame, nonce...)
	frame = append(frame, ct...)
	return c.conn.Send(frame)
}

// Recv blocks until one frame arrives, decrypts it, and returns
// the inner Envelope. Honors ctx for cancellation.
//
// Multiple goroutines may safely call Recv on the same Channel
// — they will be serialized internally. (The underlying
// transport.Conn is single-reader; the Channel manages a
// recvMu to enforce this.)
func (c *Channel) Recv(ctx context.Context) (Envelope, error) {
	if err := ctx.Err(); err != nil {
		return Envelope{}, err
	}
	c.recvMu.Lock()
	defer c.recvMu.Unlock()
	// Re-check ctx after acquiring the lock — a cancellation
	// may have happened while we were queued.
	if err := ctx.Err(); err != nil {
		return Envelope{}, err
	}
	fr, err := c.conn.Recv(ctx)
	if err != nil {
		return Envelope{}, fmt.Errorf("protocol: recv frame: %w", err)
	}
	if len(fr.Body) < ic.SM4GCMNonceSize+ic.SM4GCMTagSize {
		return Envelope{}, errors.New("protocol: frame too short")
	}
	if len(fr.Body) > MaxEnvelopeSize {
		return Envelope{}, errors.New("protocol: frame too large")
	}
	nonce := fr.Body[:ic.SM4GCMNonceSize]
	ct := fr.Body[ic.SM4GCMNonceSize:]
	// v0.1: no AAD (matches Send). GCM still authenticates the
	// entire envelope (including MsgID) since they're inside
	// the ciphertext. See package doc for future AAD plans.
	plain, err := ic.SM4DecryptGCM(c.session.SessionKey, nonce, ct, nil)
	if err != nil {
		return Envelope{}, fmt.Errorf("protocol: decrypt: %w", err)
	}
	var env Envelope
	if err := json.Unmarshal(plain, &env); err != nil {
		return Envelope{}, fmt.Errorf("protocol: unmarshal envelope: %w", err)
	}
	// Verify the version is one we understand. We accept the
	// current version only — future versions would need explicit
	// compat code.
	if env.Version != ProtocolVersion {
		return Envelope{}, fmt.Errorf("protocol: unsupported version %d", env.Version)
	}
	return env, nil
}

// localPeerID is a hook for the CLI to inject the local PeerID
// into envelopes. Returns nil if not set; the recipient's
// verification doesn't depend on From anyway (handshake handles
// identity).
func (c *Channel) localPeerID() []byte {
	return nil
}
