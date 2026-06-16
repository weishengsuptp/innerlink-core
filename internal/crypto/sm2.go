package crypto

import (
	"crypto/rand"
	"encoding/asn1"
	"errors"
	"io"
	"math/big"

	"github.com/tjfoc/gmsm/sm2"
)

// SM2PrivateKey is the innerlink-side alias for an SM2 private key.
// We keep the gmsm struct so callers can use it directly if they need
// protocol-level features (e.g. raw ECDH), but our wrapper API only
// returns the innerlink-friendly []byte forms.
type SM2PrivateKey = sm2.PrivateKey

// SM2PublicKey is the alias for an SM2 public key.
type SM2PublicKey = sm2.PublicKey

// GenerateSM2Key returns a fresh SM2 key pair using crypto/rand.
// The private key holds the public point as a sub-struct, so callers
// can derive the public side with priv.Public().
func GenerateSM2Key() (*SM2PrivateKey, error) {
	return sm2.GenerateKey(rand.Reader)
}

// SignSM2 signs msg with priv using the standard SM2-with-SM3 scheme
// (ZA || msg is hashed, then signed). The signature is ASN.1-encoded
// (SEQUENCE { r INTEGER, s INTEGER }) — the format that matches
// gmsm's PublicKey.Verify method.
//
// Use this for: identity signatures (device.key signs a handshake
// challenge), file integrity tags, anything that needs to be
// verifiable offline.
func SignSM2(priv *SM2PrivateKey, msg []byte) ([]byte, error) {
	if priv == nil {
		return nil, errors.New("crypto: nil private key")
	}
	return priv.Sign(rand.Reader, msg, nil)
}

// VerifySM2 checks that sign is a valid SM2 signature of msg under pub.
// Returns true on success. A false return is never panicking — callers
// should treat it as a normal protocol-level rejection.
func VerifySM2(pub *SM2PublicKey, msg, sign []byte) bool {
	if pub == nil {
		return false
	}
	var sig struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(sign, &sig); err != nil {
		return false
	}
	if sig.R == nil || sig.S == nil {
		return false
	}
	// gmsm's Sm2Verify takes (pub, msg, uid, r, s); default_uid is
	// the canonical "1234567812345678" the library uses elsewhere.
	return sm2.Sm2Verify(pub, msg, defaultUID, sig.R, sig.S)
}

// SM2MarshalPublic returns the canonical encoding of an SM2 public key:
// 32 bytes big-endian X || 32 bytes big-endian Y, total 64 bytes.
// This is what innerlink sends over the wire / stores on disk.
//
// We keep our own format (rather than reusing gmsm's sm2Cipher etc.)
// because:
//
//   - It's stable across gmsm versions (gmsm has no public Marshal for
//     raw PublicKey).
//   - It's easy to fingerprint: PeerID = SM3(MarshalPublic(pub))[:16].
//   - It's tiny: 64 bytes fits in a single UDP discovery packet.
func SM2MarshalPublic(pub *SM2PublicKey) []byte {
	if pub == nil || pub.X == nil || pub.Y == nil {
		return nil
	}
	x := pub.X.Bytes()
	y := pub.Y.Bytes()
	out := make([]byte, 64)
	// Right-pad X into bytes 0..32, Y into 32..64.
	copy(out[32-len(x):32], x)
	copy(out[64-len(y):64], y)
	return out
}

// SM2UnmarshalPublic parses the encoding produced by SM2MarshalPublic.
// Returns an error if the slice is the wrong size or the point is not
// on the SM2 curve.
func SM2UnmarshalPublic(b []byte) (*SM2PublicKey, error) {
	if len(b) != 64 {
		return nil, errors.New("crypto: SM2 public key must be 64 bytes")
	}
	pub := &sm2.PublicKey{
		Curve: sm2.P256Sm2(),
		X:     new(big.Int).SetBytes(b[:32]),
		Y:     new(big.Int).SetBytes(b[32:]),
	}
	if !pub.IsOnCurve(pub.X, pub.Y) {
		return nil, errors.New("crypto: SM2 public key not on curve")
	}
	return pub, nil
}

// SM2MarshalPrivate serializes a private key as 32 bytes big-endian D.
// Pair this with SM2MarshalPublic on the wire when you need both halves
// (e.g. on-device key backup).
//
// NOTE: This format is for in-memory transfer only. Persisted device
// keys MUST be encrypted at rest — see storage/.
func SM2MarshalPrivate(priv *SM2PrivateKey) []byte {
	if priv == nil || priv.D == nil {
		return nil
	}
	d := priv.D.Bytes()
	out := make([]byte, 32)
	copy(out[32-len(d):32], d)
	return out
}

// defaultUID is the canonical user identifier used by gmsm when no
// explicit UID is supplied. We hard-code it so the wire format is
// interoperable with other SM2 implementations (e.g. GmSSL).
var defaultUID = []byte("1234567812345678")

// Ensure rand.Reader is referenced so unused-import lint stays happy
// when callers only use Marshal/Unmarshal.
var _ = io.Reader(rand.Reader)
