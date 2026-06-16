package crypto

import (
	"encoding/binary"
	"errors"
)

// KDF derives `outLen` bytes of key material from `secret` and
// optional context `info`, using SM3 as the underlying PRF.
//
// Format follows the "concatenation KDF" pattern:
//
//	KDF(secret, info, L) = SM3(counter || secret || info) ||
//	                       SM3(counter+1 || secret || info) || ...
//
// where counter is a 4-byte big-endian integer starting at 1.
// This is the same shape innerlink's handshake uses to derive a
// 128-bit SM4 session key from an SM2 ECDH shared point.
//
// Parameters:
//   - secret: the input keying material (e.g. SM2 ECDH shared point).
//   - info:   domain-separation tag — concatenate whatever uniquely
//             identifies this use case (e.g. "innerlink-handshake-v1"
//             plus both nonces). Callers control this.
//   - outLen: how many bytes to derive. Must be > 0 and <= 255*32
//             (the SM3-based limit; in practice nobody needs more
//             than 64 bytes).
//
// Returns: outLen bytes of pseudorandom key material.
func KDF(secret, info []byte, outLen int) ([]byte, error) {
	if outLen <= 0 {
		return nil, errors.New("crypto: KDF outLen must be positive")
	}
	maxOut := 255 * SM3Size
	if outLen > maxOut {
		return nil, errors.New("crypto: KDF outLen exceeds SM3-KDF limit")
	}

	out := make([]byte, 0, outLen)
	var counter uint32 = 1
	for len(out) < outLen {
		// counter (4 bytes BE) || secret || info
		h := SM3()
		var ctrBuf [4]byte
		binary.BigEndian.PutUint32(ctrBuf[:], counter)
		h.Write(ctrBuf[:])
		h.Write(secret)
		h.Write(info)
		// Sum(nil) returns a fresh []byte of length 32 holding the digest.
		// Don't pass `out` as the buffer argument: gmsm's sm3.Sum(in)
		// implementation returns a slice of length SM3Size (32) regardless
		// of len(in), which would lose everything we've accumulated so
		// far. (This is a deviation from the stdlib hash.Hash contract,
		// tracked at github.com/tjfoc/gmsm#69 — the v1.4.1 behavior is
		// what we work around here.)
		out = append(out, h.Sum(nil)...)
		counter++
	}
	return out[:outLen], nil
}
