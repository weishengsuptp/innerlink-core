package identity

import (
	"github.com/tjfoc/gmsm/sm2"
)

// Internal SM2 plumbing — kept in its own file so identity.go stays
// focused on the user-facing API. If we ever swap gmsm for a different
// SM2 implementation, only this file and helpers.go need to change.

// marshalPublic returns the 64-byte X||Y form of an SM2 private key's
// embedded public key (big-endian, 32 bytes per coordinate).
func marshalPublic(priv *sm2.PrivateKey) []byte {
	if priv == nil {
		return nil
	}
	pub := &priv.PublicKey
	if pub.X == nil || pub.Y == nil {
		return nil
	}
	x := pub.X.Bytes()
	y := pub.Y.Bytes()
	out := make([]byte, 64)
	copy(out[32-len(x):32], x)
	copy(out[64-len(y):64], y)
	return out
}

// marshalPrivate returns the 32-byte big-endian D of an SM2 private key.
func marshalPrivate(priv *sm2.PrivateKey) []byte {
	if priv == nil || priv.D == nil {
		return nil
	}
	d := priv.D.Bytes()
	out := make([]byte, 32)
	copy(out[32-len(d):32], d)
	return out
}

// unmarshalPrivate parses a 32-byte big-endian D back into an SM2 private
// key, recovering the public point via scalar multiplication with the
// curve base point.
func unmarshalPrivate(d []byte) (*sm2.PrivateKey, error) {
	if len(d) != 32 {
		return nil, errBadKeySize
	}
	curve := sm2.P256Sm2()
	priv := new(sm2.PrivateKey)
	priv.PublicKey.Curve = curve
	priv.D = newBigInt(d)
	priv.PublicKey.X, priv.PublicKey.Y = curve.ScalarBaseMult(priv.D.Bytes())
	return priv, nil
}

// signWith signs msg using the SM2-with-SM3 scheme. The signature is
// returned in ASN.1 form (SEQUENCE { r, s }) so peers can verify without
// depending on gmsm.
func signWith(priv *sm2.PrivateKey, msg []byte) ([]byte, error) {
	if priv == nil {
		return nil, errBadKeyType
	}
	return priv.Sign(randReader, msg, nil)
}

// marshalPublicKey returns the 64-byte X||Y form of an SM2 public key.
// Used both for the local identity's public half and (via
// SM2UnmarshalPublic in crypto/) for verifying peers' keys.
func marshalPublicKey(pub *sm2.PublicKey) []byte {
	if pub == nil || pub.X == nil || pub.Y == nil {
		return nil
	}
	x := pub.X.Bytes()
	y := pub.Y.Bytes()
	out := make([]byte, 64)
	copy(out[32-len(x):32], x)
	copy(out[64-len(y):64], y)
	return out
}
