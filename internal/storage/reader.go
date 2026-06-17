package storage

import (
	"fmt"
	"os"
	"path/filepath"
)

// ReadAll loads every record from chat.enc under
// s.dir and returns them in append order (oldest first).
//
// The returned slice is freshly allocated; the caller
// owns it. Records whose on-disk version is greater than
// CurrentVersion stop the read and return an error — we
// refuse to silently drop records we don't understand.
//
// ReadAll is intended to be called once at startup
// (cmd/innerlink does this and keeps the slice in memory
// for the lifetime of the process, with the REPL "history"
// command reading from the in-memory slice). It is not
// intended for hot-path access during a transfer — the
// v0.1 store's append-only design means the file is
// only mutated by Store.Append, so an in-memory cache
// stays consistent with disk as long as nothing else
// rewrites chat.enc.
//
// If chat.enc does not exist (first launch, or after the
// user deleted it) ReadAll returns (nil, nil) — there is
// no history yet, not an error.
func (s *Store) ReadAll() ([]*Record, error) {
	s.mu.Lock()
	// ReadAll holds the mutex even though it only reads,
	// so it sees a consistent view of the file. We do the
	// disk read synchronously because v0.1 callers expect
	// the in-memory history to be ready by the time
	// ReadAll returns; that is what makes the "history"
	// REPL command work without any further disk I/O.
	defer s.mu.Unlock()
	path := filepath.Join(s.dir, FileName)
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("storage: open chat.enc: %w", err)
	}
	defer f.Close()
	records, _, err := readAll(f, s.key)
	return records, err
}
