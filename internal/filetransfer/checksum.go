package filetransfer

import (
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"io"
	"os"
)

// HashChunkSHA256 returns the hex SHA-256 of one chunk-sized
// slice. Use this when sending a chunk to populate the
// FileChunk.sha256 field — the receiver verifies it as soon as
// the chunk arrives so a single tampered slice is detected
// before the whole file is written.
func HashChunkSHA256(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// HashFileSHA256 streams the file at path through SHA-256 and
// returns the hex digest. It is used by the sender to populate
// the FileOffer.sha256 field (full-file checksum) without
// loading the whole file into memory.
func HashFileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// hashAccumulator is a small helper that wraps a hash.Hash and
// tracks the running total of bytes hashed, so callers can
// build a SHA-256 of a sub-range (e.g. an already-appended
// chunk of the assembled file) without re-reading from disk.
type hashAccumulator struct {
	h hash.Hash
	n int64
}

func newHashAccumulator() *hashAccumulator {
	return &hashAccumulator{h: sha256.New()}
}

func (a *hashAccumulator) Write(p []byte) (int, error) {
	n, err := a.h.Write(p)
	a.n += int64(n)
	return n, err
}

func (a *hashAccumulator) SumHex() string {
	return hex.EncodeToString(a.h.Sum(nil))
}

func (a *hashAccumulator) Bytes() int64 { return a.n }
