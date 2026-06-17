package storage

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	ic "github.com/weishengsuptp/innerlink-core/internal/crypto"
)

// Store is the append-only encrypted chat log for a single
// device, persisted to a single file under SaveDir.
//
// Store is safe for concurrent use: a single Store may be
// Appended to from many goroutines (e.g. the chat dispatcher
// is Append'ing "in" records while the REPL goroutine is
// Append'ing "out" records). The mutex serializes the
// underlying file Write so the per-record framing stays
// intact even under interleaving. ReadAll holds the mutex
// too, so it sees a consistent snapshot at the moment it
// started.
//
// Lifecycle:
//
//	st, err := storage.Open(saveDir, id.PrivateKeyD())
//	if err != nil { ... }
//	// ... use st.Append() ...
//	if err := st.Close(); err != nil { ... }
//
// The SaveDir and the device key are fixed at Open time and
// never change for the lifetime of a Store. To "re-key"
// (e.g. after device.key rotation) the caller should Close
// the old Store and Open a new one — there is no Rotate()
// API in v0.1 because we never expect device keys to
// rotate in the field.
type Store struct {
	dir string     // absolute path of the save directory
	key []byte     // 16-byte SM4 key (derived in Open)
	f   *os.File   // underlying chat.enc, append-mode
	mu  sync.Mutex // guards f + unsynced count

	// unsynced is the number of records appended since the
	// last fsync. Reset to 0 in flushLocked. Used by
	// Append to decide when to call file.Sync so a
	// power-cut loses at most recordsPerSync-1 records
	// (which is a graceful trade-off — we get 10x lower
	// I/O latency on hot write paths at the cost of
	// potentially losing 9 in-flight records on crash).
	unsynced int
}

// Open prepares the save directory, derives the SM4 key
// from deviceD, and opens chat.enc in append mode. The
// returned Store is ready for Append and ReadAll.
//
// deviceD is the 32-byte big-endian SM2 private scalar
// (identity.Identity.PrivateKeyD()). It is consumed at
// this call and not stored; what stays in the Store is
// the 16-byte derived SM4 key. We hold the SM4 key in
// memory for the lifetime of the Store — this is safe as
// long as the process doesn't swap to disk or get its
// memory dumped. (v0.1 doesn't address either of those
// — M4+ would add mlock + GCM AEAD if it ever became a
// concern.)
//
// If chat.enc exists, Open does not validate it — the
// reader does that lazily on first ReadAll. This means a
// Store returned from a successful Open can be safely
// used for Append even if the file is corrupt; it just
// won't be readable until the user deletes it.
func Open(saveDir string, deviceD []byte) (*Store, error) {
	if len(deviceD) != 32 {
		return nil, fmt.Errorf("storage: device key must be 32 bytes, got %d", len(deviceD))
	}
	if err := os.MkdirAll(saveDir, DirMode); err != nil {
		return nil, fmt.Errorf("storage: mkdir save dir: %w", err)
	}
	key, err := ic.KDF(deviceD, []byte(keyDerivationInfo), KeySize)
	if err != nil {
		return nil, fmt.Errorf("storage: derive SM4 key: %w", err)
	}
	path := filepath.Join(saveDir, FileName)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, FileMode)
	if err != nil {
		return nil, fmt.Errorf("storage: open chat.enc: %w", err)
	}
	return &Store{
		dir: saveDir,
		key: key,
		f:   f,
	}, nil
}

// SaveDir returns the absolute path of the save directory
// the Store was opened against. Used by callers that need
// to show the user where the encrypted log lives.
func (s *Store) SaveDir() string {
	return s.dir
}

// Append encrypts r and writes it to chat.enc in the
// self-describing framing described in format.go's
// package comment.
//
// Append holds the Store's mutex for the duration of the
// I/O. The hold time is dominated by the syscall cost of
// writing a few hundred bytes to the OS — we are not
// CPU-bound. The fsync happens at most once every
// recordsPerSync Append calls (see recordsPerSync comment
// in format.go).
//
// Append is the only function that may produce a partial
// write to chat.enc if the OS / disk fails partway: in
// that case the file ends mid-frame, and the next
// ReadAll will surface ErrCorrupt at the boundary. The
// caller should treat this as "this message is lost";
// the records that came before are still readable because
// each frame's length is committed atomically by the
// (4-byte length prefix + ciphertext) pair.
func (s *Store) Append(r *Record) error {
	if r == nil {
		return errors.New("storage: nil record")
	}
	if r.Version == 0 {
		r.Version = CurrentVersion
	}
	plain, err := r.encode()
	if err != nil {
		return fmt.Errorf("storage: encode record: %w", err)
	}
	iv, err := ic.NewNonce(FrameIVSize)
	if err != nil {
		return fmt.Errorf("storage: generate IV: %w", err)
	}
	ct, err := ic.SM4EncryptCBC(s.key, iv, plain)
	if err != nil {
		return fmt.Errorf("storage: encrypt record: %w", err)
	}
	// Wire format:
	//
	//   [4B big-endian ct length]
	//   [12B IV]
	//   [len(ct) B ciphertext]
	//
	// The frame length is len(ct), NOT len(plain). At read
	// time we know exactly how many bytes to consume.
	frame := make([]byte, 0, FrameHeaderSize+FrameIVSize+len(ct))
	var lenBuf [FrameHeaderSize]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(ct)))
	frame = append(frame, lenBuf[:]...)
	frame = append(frame, iv...)
	frame = append(frame, ct...)

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.f == nil {
		return ErrClosed
	}
	if _, err := s.f.Write(frame); err != nil {
		return fmt.Errorf("storage: write frame: %w", err)
	}
	s.unsynced++
	if s.unsynced >= recordsPerSync {
		return s.flushLocked()
	}
	return nil
}

// Close flushes and closes the underlying file. After
// Close, Append returns ErrClosed and ReadAll returns
// whatever was already read (it does not re-open).
//
// Close is idempotent: calling it twice does not return
// an error the second time.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.f == nil {
		return nil
	}
	err := s.flushLocked()
	if cerr := s.f.Close(); cerr != nil && err == nil {
		err = cerr
	}
	s.f = nil
	return err
}

// flushLocked syncs the file to disk. Caller must hold
// s.mu. Used internally by Append and Close.
func (s *Store) flushLocked() error {
	if s.f == nil {
		return nil
	}
	if err := s.f.Sync(); err != nil {
		return fmt.Errorf("storage: sync: %w", err)
	}
	s.unsynced = 0
	return nil
}

// readAll is a package-private helper used by ReadAll.
// It is split out so the test file can drive it against
// a custom io.Reader without touching the on-disk file.
//
// Returns the slice of successfully decoded records, the
// number of bytes consumed (so the caller knows where the
// good data ended), and the first error encountered (if
// any). The records slice is non-nil even when err is
// non-nil; the caller should surface both to the user.
func readAll(r io.Reader, key []byte) (records []*Record, n int, err error) {
	br := newByteReader(r)
	for {
		var lenBuf [FrameHeaderSize]byte
		readN, rerr := io.ReadFull(br, lenBuf[:])
		if readN == 0 && rerr == io.EOF {
			// clean end-of-file
			return records, br.offset, nil
		}
		if rerr == io.EOF || rerr == io.ErrUnexpectedEOF {
			// file truncated mid-header; treat as clean
			// end-of-file only if we haven't seen any
			// records. Otherwise the file is corrupt.
			if len(records) == 0 {
				return records, br.offset, nil
			}
			return records, br.offset - readN, ErrCorrupt
		}
		if rerr != nil {
			return records, br.offset, fmt.Errorf("storage: read header: %w", rerr)
		}
		frameLen := binary.BigEndian.Uint32(lenBuf[:])
		// Sanity bound: a 1 MiB frame is already far more
		// than a single chat message could ever be. We
		// refuse to allocate more than this, which also
		// catches a corrupted length prefix where the
		// upper bits are garbage.
		const maxFrame = 1 << 20 // 1 MiB
		if frameLen == 0 || frameLen > maxFrame {
			return records, br.offset, ErrCorrupt
		}
		frame := make([]byte, FrameIVSize+int(frameLen))
		readN, rerr = io.ReadFull(br, frame)
		if rerr != nil {
			return records, br.offset, fmt.Errorf("storage: read frame body: %w", rerr)
		}
		iv := frame[:FrameIVSize]
		ct := frame[FrameIVSize:]
		plain, derr := ic.SM4DecryptCBC(key, iv, ct)
		if derr != nil {
			// Decryption failure is the most common
			// form of "this chat.enc is from a different
			// device.key, or has been tampered with".
			return records, br.offset, ErrCorrupt
		}
		rec, derr := decodeRecord(plain)
		if derr != nil {
			return records, br.offset, fmt.Errorf("storage: decode record: %w", derr)
		}
		records = append(records, rec)
	}
}

// byteReader is io.Reader + io.ReaderAt for the readAll
// path. We don't use os.File's ReadAt because the file
// may grow between ReadAll calls (a concurrent Append
// from the dispatcher would race the reader); for the
// read-once path we just need io.Reader + an offset
// counter for error reporting.
type byteReader struct {
	r      io.Reader
	offset int
}

func newByteReader(r io.Reader) *byteReader { return &byteReader{r: r} }

func (b *byteReader) Read(p []byte) (int, error) {
	n, err := b.r.Read(p)
	b.offset += n
	return n, err
}
