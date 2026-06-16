// Package crypto wraps the tjfoc/gmsm library to expose the four primitives
// innerlink needs at its core: SM3 hashing, SM2 signing + key agreement,
// SM4 symmetric encryption (GCM / CTR / CBC), and a KDF built on SM3.
//
// Implementation rules (see ARCHITECTURE.md red line #3):
//   - We never hand-roll SM2 / SM3 / SM4. Every byte of cryptographic
//     output comes from github.com/tjfoc/gmsm (or stdlib cipher, which gmsm
//     builds on for CTR).
//   - Functions in this package accept and return stdlib types wherever
//     reasonable ([]byte, *big.Int, error) so callers don't depend on the
//     gmsm type system.
package crypto

import (
	"hash"

	"github.com/tjfoc/gmsm/sm3"
)

// SM3 is a thin convenience wrapper around gmsm/sm3 that matches the
// stdlib `hash.Hash` interface.
//
// Use it like crypto/sha256:
//
//	h := crypto.SM3()
//	h.Write([]byte("hello"))
//	digest := h.Sum(nil) // 32 bytes
func SM3() hash.Hash { return sm3.New() }

// SM3Sum computes a one-shot SM3 digest of data.
//
// On a modern x86_64 CPU this runs at >500 MB/s; the only reason to use
// the streaming API is feeding data in chunks from a network/file reader.
func SM3Sum(data []byte) []byte { return sm3.Sm3Sum(data) }

// SM3Size is the digest length in bytes (always 32 for SM3).
const SM3Size = 32
