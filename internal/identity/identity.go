// Package identity wraps the SM2 key pair that represents an innerlink
// "device" — i.e. this installation on this machine.
//
// In innerlink there is no account system. The closest thing to a user
// identity is an SM2 key pair:
//
//   - The PRIVATE key (D, a 256-bit integer) is generated once on first
//     launch and stored under ~/.innerlink/device.key (file mode 0600).
//     It signs handshake challenges and decrypts incoming messages. It
//     must never leave the device.
//
//   - The PUBLIC key (X, Y on the SM2 curve) is broadcast to every peer
//     you meet. It is the input to:
//
//       1. SM2 ECDH — shared secret derivation during handshake
//       2. SM2 signature VERIFICATION — confirming a message is from
//          the peer you think it's from
//
//   - The PeerID = first 16 bytes of SM3(public key). This is the
//     short, UI-friendly identifier shown in chat lists and used as
//     the routing key in the protocol.
//
// We deliberately do NOT try to expose gmsm types through this package's
// public API. Callers operate on []byte and string forms, and never
// see *sm2.PrivateKey directly except via the Identity struct (which
// lives in this package and is the only handle to the underlying key).
package identity

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	ic "github.com/weishengsuptp/innerlink-core/internal/crypto"
	"github.com/tjfoc/gmsm/sm2"
)

// PeerIDSize is the canonical length of a PeerID in bytes.
// 16 bytes = 128 bits — collision-resistant for any realistic deployment
// size and short enough to render as a 32-char hex string in a UI.
const PeerIDSize = 16

// Identity is the innerlink device's SM2 key pair.
//
// It carries both the private and public halves because every consumer
// that holds an Identity needs both (e.g. signing + verification
// against a peer's public key require different halves but they're
// paired at construction time).
type Identity struct {
	priv   *sm2.PrivateKey
	pubKey []byte // 64-byte X||Y form (cached)
	peerID []byte // 16-byte PeerID (cached)
}

// Generate creates a fresh SM2 identity backed by crypto/rand.
//
// The returned Identity holds a freshly generated private key — losing
// it means losing this device's identity forever. Pair with
// Save(path) immediately on first launch.
func Generate() (*Identity, error) {
	priv, err := ic.GenerateSM2Key()
	if err != nil {
		return nil, fmt.Errorf("identity: generate SM2 key: %w", err)
	}
	return wrap(priv), nil
}

// wrap builds an Identity from a raw private key, computing the
// public-key bytes and PeerID once and caching them.
func wrap(priv *sm2.PrivateKey) *Identity {
	pubBytes := marshalPublic(priv)
	peerID := ic.SM3Sum(pubBytes)[:PeerIDSize]
	return &Identity{
		priv:   priv,
		pubKey: pubBytes,
		peerID: peerID,
	}
}

// PublicKey returns the 64-byte SM2 public key (X || Y, big-endian,
// 32 bytes each). This is what gets broadcast in discovery packets and
// what peers use to verify signatures or derive shared secrets.
//
// Callers should treat the returned slice as read-only; do not mutate.
func (id *Identity) PublicKey() []byte {
	return id.pubKey
}

// PeerID returns the 16-byte short identifier derived from the public key.
// Two identities with the same public key will always have the same PeerID;
// two identities with different public keys will (with overwhelming
// probability) have different PeerIDs.
//
// Returned slice is freshly allocated on each call so callers can hold
// onto it without aliasing concerns.
func (id *Identity) PeerID() []byte {
	out := make([]byte, PeerIDSize)
	copy(out, id.peerID)
	return out
}

// PeerIDHex returns PeerID() rendered as a 32-char lowercase hex string.
// This is the form you show in UIs, log lines, and the protocol's
// addressing fields.
func (id *Identity) PeerIDHex() string {
	return hex.EncodeToString(id.peerID)
}

// EqualPeerIDs is a convenience for "are these two identities the
// same peer?" — used by the chat list, dedup logic, etc.
func EqualPeerIDs(a, b []byte) bool {
	if len(a) != PeerIDSize || len(b) != PeerIDSize {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Sign signs msg with this identity's private key. The returned signature
// is ASN.1-encoded SEQUENCE { r, s } and is meant to be verified by the
// peer's VerifySignature (using this identity's PublicKey).
func (id *Identity) Sign(msg []byte) ([]byte, error) {
	if id == nil || id.priv == nil {
		return nil, errors.New("identity: nil identity")
	}
	return signWith(id.priv, msg)
}

// VerifySignature checks that sig is a valid SM2 signature of msg under
// the given peer's 64-byte public key. Returns true on success.
//
// This is a convenience that bundles crypto.SM2Verify + PublicKeyFromBytes
// so handshake code can do `id.VerifySignature(peerKey, msg, sig)` in
// one line instead of three.
//
// Note: `id` itself isn't used for verification — only its type acts
// as a namespace. We accept it as a method receiver so callers can
// chain: `id.VerifySignature(peerKey, msg, sig)` reads naturally.
// Any other Identity value (or even nil) would work for the
// verification step; the peer's public key is what matters.
func (id *Identity) VerifySignature(peerPublicKey, msg, sig []byte) bool {
	pub, err := PublicKeyFromBytes(peerPublicKey)
	if err != nil {
		return false
	}
	return ic.VerifySM2(pub, msg, sig)
}

// DefaultDeviceKeyPath is the conventional location for the device
// key on POSIX-style systems. On Windows the same path under
// %USERPROFILE%/.innerlink is used (see ResolveDeviceKeyPath).
const DefaultDeviceKeyPath = ".innerlink/device.key"

// ResolveDeviceKeyPath returns the absolute path to the device key file
// for the current user. On all platforms we use
// $HOME/.innerlink/device.key (Windows: %USERPROFILE%).
//
// We don't use os.UserConfigDir() because it points to AppData on
// Windows, which is hidden behind the user's Library — not the place
// a developer-friendly CLI tool should drop its first-run artifact.
func ResolveDeviceKeyPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("identity: cannot determine user home: %w", err)
	}
	return filepath.Join(home, DefaultDeviceKeyPath), nil
}

// Save writes the identity's private key to path with mode 0600.
// The file format is:
//
//   magic    [8]byte = "ILK1\0\0\0\0"        (Innerlink Key v1)
//   priv     [32]byte (big-endian D)
//
// We deliberately use a tiny binary format (not JSON, not PEM) because:
//   - It's 40 bytes total — small enough to fit in a single UDP
//     discovery packet if we ever want to (we don't, but the option
//     stays open).
//   - No parsing ambiguity.
//   - Fixed offset for D means tools can read it bytewise.
//
// SECURITY: file mode is forced to 0600 on POSIX. On Windows we set
// the readonly bit via os.WriteFile (Windows ACLs are out of scope
// for this layer — see storage/ for any additional hardening).
func (id *Identity) Save(path string) error {
	if id == nil || id.priv == nil {
		return errors.New("identity: nil identity")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("identity: create key dir: %w", err)
	}
	d := marshalPrivate(id.priv)
	if len(d) != 32 {
		return fmt.Errorf("identity: unexpected private-key length %d", len(d))
	}
	buf := make([]byte, 0, 40)
	buf = append(buf, []byte{'I', 'L', 'K', '1', 0x00, 0x00, 0x00, 0x00}...)
	buf = append(buf, d...)
	if err := os.WriteFile(path, buf, 0600); err != nil {
		return fmt.Errorf("identity: write key file: %w", err)
	}
	return nil
}

// Load reads a previously-saved identity from path. Returns an error if
// the file doesn't exist, has the wrong magic, or the wrong length.
//
// We do NOT auto-generate on missing file — callers that want
// "first-run creates a key" semantics should use LoadOrCreate.
func Load(path string) (*Identity, error) {
	buf, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("identity: read key file: %w", err)
	}
	if len(buf) != 40 {
		return nil, fmt.Errorf("identity: key file size %d, want 40", len(buf))
	}
	if string(buf[:8]) != "ILK1\x00\x00\x00\x00" {
		return nil, errors.New("identity: bad magic (not an innerlink key file)")
	}
	priv, err := unmarshalPrivate(buf[8:40])
	if err != nil {
		return nil, err
	}
	return wrap(priv), nil
}

// LoadOrCreate returns the identity at path; if no file exists it
// generates a fresh one, saves it, and returns that. This is the
// function first-run callers (cmd/innerlink) should use.
//
// The boolean return value is true if a new identity was created
// (vs. an existing one being loaded) — useful for first-run UX hints
// like "we generated a new identity, your PeerID is ..."
func LoadOrCreate(path string) (*Identity, bool, error) {
	id, err := Load(path)
	if err == nil {
		return id, false, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, false, err
	}
	id, err = Generate()
	if err != nil {
		return nil, false, err
	}
	if err := id.Save(path); err != nil {
		return nil, false, err
	}
	return id, true, nil
}

// PublicKeyFromBytes reconstructs a peer's 64-byte public key into a form
// suitable for ECDH / signature verification. Returns an error if
// the input is the wrong size or the point is not on the curve.
//
// Returns the concrete *sm2.PublicKey type — this is the one place in
// the package's public API where a gmsm type leaks out, because the
// handshake layer needs it to call SM2 ECDH functions directly.
// Most callers should not need this function.
func PublicKeyFromBytes(b []byte) (*sm2.PublicKey, error) {
	if len(b) != 64 {
		return nil, fmt.Errorf("identity: public key must be 64 bytes, got %d", len(b))
	}
	pub, err := ic.SM2UnmarshalPublic(b)
	if err != nil {
		return nil, err
	}
	return pub, nil
}

// PeerIDFromPublicKey derives a 16-byte PeerID from any 64-byte
// public key — typically a peer's. Lets us address-protocol messages
// by PeerID without ever materializing the full Identity.
func PeerIDFromPublicKey(pub []byte) ([]byte, error) {
	if len(pub) != 64 {
		return nil, fmt.Errorf("identity: public key must be 64 bytes, got %d", len(pub))
	}
	sum := ic.SM3Sum(pub)
	out := make([]byte, PeerIDSize)
	copy(out, sum[:PeerIDSize])
	return out, nil
}
