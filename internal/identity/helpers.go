package identity

import (
	"crypto/rand"
	"errors"
	"math/big"
)

// Package-internal helpers and error sentinels.
// Kept here (not in identity.go) because they're the messy plumbing
// layer; identity.go stays clean and readable.

// errBadKeySize is returned when a private-key blob isn't 32 bytes.
var errBadKeySize = errors.New("identity: private key must be 32 bytes")

// errBadKeyType is returned when an interface{} doesn't hold a *sm2.PrivateKey.
var errBadKeyType = errors.New("identity: key is not an SM2 private key")

// randReader is the package's default entropy source. It's just crypto/rand
// but exposing it as a package variable lets tests inject a deterministic
// source if we ever want property-based fuzzing.
var randReader = rand.Reader

// newBigInt is a tiny named helper so the call sites in sm2_io.go
// are easier to read.
func newBigInt(b []byte) *big.Int {
	return new(big.Int).SetBytes(b)
}
