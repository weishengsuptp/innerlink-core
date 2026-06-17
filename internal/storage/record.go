package storage

import (
	"encoding/json"
	"time"
)

// Record is one chat message as it lives on disk (after
// JSON encoding, SM4-CBC encryption, and a length prefix).
//
// It is intentionally minimal. We do NOT store the channel
// session ID, the SM4-GCM nonce, the signature, or the
// transport metadata — those are all properties of the
// in-flight envelope, not of the message the user typed
// and read.
//
// Field-level notes:
//
//   - Version is the on-disk record format version.
//     Currently always 1. Bumping it is a one-line change
//     here; old readers are expected to refuse records
//     with a Version they don't understand.
//
//   - Timestamp is the wall-clock time the message was
//     saved to local storage. For Direction=="out" this
//     is the moment cmd/innerlink received the user
//     keystroke (more precisely, the moment the SendText
//     call returned nil). For Direction=="in" this is
//     the moment the dispatcher handed the envelope to
//     Store.Append.
//
//   - From and To are 32-char lowercase hex PeerIDs
//     (16 raw bytes). For Direction=="out" the From is
//     this device's PeerID; for Direction=="in" the
//     From is the peer's PeerID. To is the converse.
//
//   - Direction is "in" or "out". v0.1 only ever writes
//     these two values. M3+ may add "system" for local
//     events like "peer joined" or "key rotated".
//
//   - Body is the actual chat text. In v0.1 it is always
//     valid UTF-8; M4+ may add binary attachments which
//     would change Body to a base64 string + ContentType.
//
//   - MsgID is the Envelope.MsgID from the original
//     on-the-wire message (8 bytes hex). We store it so
//     a future v0.3 reader can dedupe re-delivered
//     envelopes. v0.1's reader does not check it.
type Record struct {
	Version   int       `json:"v"`
	Timestamp time.Time `json:"ts"`
	From      string    `json:"from"`     // 32-char hex PeerID
	To        string    `json:"to"`       // 32-char hex PeerID
	Direction string    `json:"dir"`      // "in" or "out"
	Body      string    `json:"body"`     // chat text
	MsgID     string    `json:"msgID"`    // 16-char hex, envelope MsgID
}

// CurrentVersion is the on-disk record version produced by
// this build. Bumped only when the JSON shape of Record
// changes incompatibly (e.g. we add a new required field).
const CurrentVersion = 1

// encode serializes r to the bytes that go into SM4-CBC
// encryption. We use json.Marshal (not json.Encoder) so the
// caller can reuse the returned slice; the result is owned
// by the caller.
func (r *Record) encode() ([]byte, error) {
	return json.Marshal(r)
}

// decodeRecord is the inverse of (*Record).encode. It is
// the only function that knows the JSON shape of Record.
func decodeRecord(b []byte) (*Record, error) {
	var r Record
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, err
	}
	if r.Version != CurrentVersion {
		return nil, errUnknownVersion{r: r.Version}
	}
	return &r, nil
}

// errUnknownVersion is returned when a record's Version
// field is not CurrentVersion. The reader treats this as
// "stop here, the file has been touched by a newer (or
// older) innerlink that I don't know how to read".
type errUnknownVersion struct{ r int }

func (e errUnknownVersion) Error() string {
	return "storage: unknown record version"
}
