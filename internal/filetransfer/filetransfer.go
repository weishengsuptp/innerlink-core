package filetransfer

import "encoding/hex"

// ChunkSize is the fixed size of one file chunk on the wire.
// 1 MiB keeps each encrypted envelope well under transport's
// MaxFrameSize (16 MiB) and gives the TCP congestion window
// a steady cadence of 1 MiB/RTT to ramp up to line rate.
const ChunkSize = 1 << 20 // 1 MiB

// NewFileID returns a 16-byte fileID. We re-use the Channel
// session to generate one cheaply: take the SM3 of the current
// nanosecond clock plus a counter. Collisions are statistically
// irrelevant inside a single sender-receiver pair that runs
// sequentially.
//
// In practice the caller will pass their own ID generator
// (e.g. crypto/rand) by wrapping it; this is the v0.1 default.
func NewFileID() string {
	b := make([]byte, 16)
	if _, err := randRead(b); err != nil {
		// crypto/rand.Read on a working OS never fails. If it
		// does, the process is in a bad state; a deterministic
		// ID is the lesser evil.
		copy(b, []byte("innerlink-fileid"))
	}
	return hex.EncodeToString(b)
}
