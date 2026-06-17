// Package storage is the local encrypted chat-log persistence
// layer for innerlink-core.
//
// It writes every chat message to chat.enc under the configured
// save directory (default ~/Downloads/innerlink/), in a
// self-describing append-only frame format:
//
//	[4 B big-endian ciphertext length]
//	[12 B IV]
//	[N B SM4-CBC ciphertext (PKCS#7 padded plaintext)]
//
// The plaintext of each record is a JSON-encoded
// Record{Version, Timestamp, From, To, Direction, Body, MsgID},
// where Direction is "in" / "out" and Body is the original
// chat text the user typed or received.
//
// The SM4 key is derived from the device's SM2 private scalar
// D via the crypto.KDF construction:
//
//	storageKey = KDF(D, "innerlink-storage-v1", 16)
//
// so a single device key unlocks all of its chat history, and
// losing the device key (or moving chat.enc to a machine
// without the matching device.key) makes the file permanently
// undecryptable. This is intentional: we never store the
// derived key on disk.
//
// M3 v0.1 scope: write only, plus cmd/innerlink REPL "history"
// command for read. No ping/pong, no file attachments, no UI,
// no automatic rotation, no remote sync. See docs/PRD.md.
package storage

import (
	"errors"
)

const (
	// FileName is the on-disk name of the encrypted chat log.
	// Lived at saveDir/chat.enc when SaveDir was the default
	// ~/Downloads/innerlink/ in v0.1.
	FileName = "chat.enc"

	// FileMode is the file permission used when creating a
	// fresh chat.enc. 0600 because the file is decryptable
	// by anyone who reads it AND has the device key — we
	// don't want random local users to be able to read the
	// ciphertext either, since it leaks metadata (timestamps,
	// peer IDs) even before decryption.
	FileMode = 0o600

	// DirMode is the permission for the save directory. 0700
	// keeps other local users out of the directory entirely.
	DirMode = 0o700

	// FrameHeaderSize is the size of the per-record length
	// prefix (4 bytes big-endian).
	FrameHeaderSize = 4

	// FrameIVSize is the size of the per-record IV.
	// SM4-CBC requires exactly 16 bytes (gmsm
	// hard-asserts this — see internal/crypto/sm4.go
	// SM4EncryptCBC). We use the standard 16-byte CBC
	// IV; each record gets a fresh IV generated from
	// crypto/rand via ic.NewNonce, so per-record IV
	// uniqueness is guaranteed.
	FrameIVSize = 16

	// KeySize is the SM4-128 key length we use.
	KeySize = 16

	// recordsPerSync is the writer's fsync cadence. We
	// accumulate this many in-memory records before calling
	// file.Sync, so a power-cut loses at most
	// recordsPerSync-1 records but normal exit() doesn't
	// stall on every keystroke. The trade-off is documented
	// in Store.Append.
	recordsPerSync = 10

	// keyDerivationInfo is the KDF domain-separation tag.
	// It MUST be stable across innerlink versions — if we
	// ever change it, every existing chat.enc becomes
	// undecryptable (which is what we want for a version
	// bump, but we should be very deliberate about it).
	keyDerivationInfo = "innerlink-storage-v1"
)

// ErrClosed is returned by Store.Append when the Store has
// been Close()d. Append after Close is a programmer error;
// callers should treat it as fatal in the same way they
// would treat "writing to a closed file" in any other I/O
// API.
var ErrClosed = errors.New("storage: store is closed")

// ErrCorrupt is returned by ReadAll when chat.enc contains
// a frame that can't be decrypted with the current key, or
// whose length prefix is invalid. The reader stops at the
// first corrupt frame and returns everything it had
// successfully decoded plus this error. Callers should log
// the error and consider the file unrecoverable.
var ErrCorrupt = errors.New("storage: chat.enc is corrupt at current offset")
