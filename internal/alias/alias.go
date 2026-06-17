package alias

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// CurrentVersion is the on-disk file format version.
// Bump this if the JSON layout changes incompatibly.
const CurrentVersion = 1

// peerIDSize is the length of a PeerID in hex chars.
// Kept identical to identity.PeerIDSize (32) — we
// don't import identity to avoid a cycle (alias is
// a leaf package used by the cmd layer, identity is
// used by transport, etc., and a future split could
// place alias below identity).
const peerIDSize = 32

// ErrInvalidPeerID is returned by Set/Remove/Touch
// when the supplied peer id is not 32 lowercase hex
// chars. We validate eagerly so a typo doesn't
// silently create a separate alias entry under a
// different key.
var ErrInvalidPeerID = errors.New("alias: peer id must be 32 lowercase hex chars")

// ErrEmptyName is returned by Set when name is the
// empty string. Use Remove to delete an entry, not
// Set with "".
var ErrEmptyName = errors.New("alias: name must not be empty")

// ErrNameTooLong caps human-typed names at 64 chars.
// Anything longer is almost certainly a paste error.
var ErrNameTooLong = errors.New("alias: name must be <= 64 chars")

// Alias is one row of the alias table.
type Alias struct {
	Name      string    `json:"name"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// fileFormat is the on-disk JSON shape. We keep
// "v" so we can change the schema later without
// breaking older files.
type fileFormat struct {
	V       int             `json:"v"`
	Aliases map[string]Alias `json:"aliases"`
}

// Store is the in-memory + on-disk alias table. All
// exported methods are safe for concurrent use.
type Store struct {
	path string

	mu       sync.RWMutex // protects m
	m        map[string]Alias

	saveMu sync.Mutex // serializes Save()
	dirty  bool       // m has changes not yet on disk
}

// Open loads aliases from path. If the file does
// not exist, Open returns an empty Store ready to
// accept Set/Remove — the file is created on the
// first Save, not eagerly. This is consistent with
// how the device.key and storage layers behave: no
// side effects until the user actually does
// something.
//
// A corrupt or unparseable file is treated as a
// hard error. We don't want to silently start
// with an empty table when the user clearly had
// aliases saved — that would be the worst possible
// "we lost your data" failure mode. The right
// thing is to fail loud and let the user decide
// (delete the file, restore from backup, etc.).
func Open(path string) (*Store, error) {
	s := &Store{
		path: path,
		m:    make(map[string]Alias),
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return s, nil
		}
		return nil, fmt.Errorf("alias: read %s: %w", path, err)
	}
	var f fileFormat
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("alias: parse %s: %w", path, err)
	}
	if f.V != CurrentVersion {
		// Future-proof: when we bump CurrentVersion,
		// the migration path goes here. For now,
		// anything other than v1 is rejected.
		return nil, fmt.Errorf("alias: %s: unsupported version %d", path, f.V)
	}
	if f.Aliases != nil {
		s.m = f.Aliases
	}
	return s, nil
}

// DefaultPath is the conventional location of the
// alias file: <device-key-dir>/aliases.json. The
// device key dir is the same one identity uses
// (~/.innerlink on a normal install), so we share
// the directory rather than the file: the alias
// table belongs next to the device key it
// describes.
func DefaultPath(deviceKeyPath string) string {
	return filepath.Join(filepath.Dir(deviceKeyPath), "aliases.json")
}

// Get returns the alias for peerID and whether one
// was found. The bool is false for unknown peers.
func (s *Store) Get(peerID string) (Alias, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a, ok := s.m[peerID]
	return a, ok
}

// Set creates or updates the alias for peerID. If
// the peer already has an alias, the name is
// replaced and last_seen is bumped to now; the
// first_seen stays as it was so the user can see
// how long they've known this peer.
//
// Set validates the inputs and returns
// ErrInvalidPeerID or ErrEmptyName rather than
// silently coercing. The cmd layer's REPL handler
// turns these into a friendly error message.
func (s *Store) Set(peerID, name string) error {
	if !validPeerID(peerID) {
		return ErrInvalidPeerID
	}
	if name == "" {
		return ErrEmptyName
	}
	if len(name) > 64 {
		return ErrNameTooLong
	}
	now := time.Now().UTC()
	s.mu.Lock()
	if prev, ok := s.m[peerID]; ok {
		prev.Name = name
		prev.LastSeen = now
		s.m[peerID] = prev
	} else {
		s.m[peerID] = Alias{
			Name:      name,
			FirstSeen: now,
			LastSeen:  now,
		}
	}
	s.dirty = true
	s.mu.Unlock()
	return nil
}

// Remove deletes the alias for peerID. Removing a
// non-existent alias is a no-op, not an error.
func (s *Store) Remove(peerID string) error {
	if !validPeerID(peerID) {
		return ErrInvalidPeerID
	}
	s.mu.Lock()
	if _, ok := s.m[peerID]; ok {
		delete(s.m, peerID)
		s.dirty = true
	}
	s.mu.Unlock()
	return nil
}

// Touch updates last_seen to now for peerID, leaving
// the name alone. Called by the cmd layer whenever
// it sees activity from a peer (announce, incoming
// msg, handshake) so the `peers` REPL command can
// sort by recency.
//
// Touch on a peer that has no alias yet is allowed
// — the user might be looking at the unaliased
// peer table and want to know "when did I last
// hear from this thing?". Touch will NOT create an
// alias; if the user wants a name they call Set.
// This is a deliberate split: Touch is automatic
// (driven by the runtime), Set is manual (driven
// by the user typing `alias`).
func (s *Store) Touch(peerID string) {
	if !validPeerID(peerID) {
		return
	}
	now := time.Now().UTC()
	s.mu.Lock()
	if prev, ok := s.m[peerID]; ok {
		prev.LastSeen = now
		s.m[peerID] = prev
	} else {
		// Add a placeholder row. We use the
		// empty name; the `peers` REPL
		// command treats empty Name as
		// "unnamed" and shows the hex
		// prefix instead.
		s.m[peerID] = Alias{
			Name:      "",
			FirstSeen: now,
			LastSeen:  now,
		}
		s.dirty = true
	}
	s.mu.Unlock()
}

// List returns a snapshot of the alias table
// (name + first/last seen) keyed by peer id. The
// returned map is freshly allocated; mutating it
// is safe. The peer table is also tracked
// separately inside the discovery layer; alias
// merges those into a single UI view.
func (s *Store) List() map[string]Alias {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]Alias, len(s.m))
	for k, v := range s.m {
		out[k] = v
	}
	return out
}

// Save flushes the in-memory table to disk. It is
// safe to call concurrently; the actual file write
// is serialized. The on-disk file is rewritten
// atomically (write to <path>.tmp, then rename)
// so a crash mid-Save can't leave a half-written
// file.
//
// Save is a no-op if the in-memory state hasn't
// changed since the last successful save; this
// keeps the per-Set cost down without sacrificing
// durability (Set marks dirty).
func (s *Store) Save() error {
	s.saveMu.Lock()
	defer s.saveMu.Unlock()

	s.mu.RLock()
	dirty := s.dirty
	s.mu.RUnlock()
	if !dirty {
		return nil
	}

	s.mu.RLock()
	f := fileFormat{
		V:       CurrentVersion,
		Aliases: make(map[string]Alias, len(s.m)),
	}
	for k, v := range s.m {
		f.Aliases[k] = v
	}
	s.mu.RUnlock()

	data, err := json.MarshalIndent(&f, "", "  ")
	if err != nil {
		return fmt.Errorf("alias: marshal: %w", err)
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("alias: write tmp: %w", err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("alias: rename: %w", err)
	}
	s.mu.Lock()
	s.dirty = false
	s.mu.Unlock()
	return nil
}

// Close flushes pending changes and releases
// resources. Idempotent: subsequent Close calls
// are no-ops. After Close, the Store must not be
// used.
func (s *Store) Close() error {
	if err := s.Save(); err != nil {
		return err
	}
	return nil
}

// validPeerID is the gate for Set/Remove/Touch.
// It is intentionally strict: 32 lowercase hex
// characters, nothing else. We don't accept
// "alias names" in the peer id slot — that
// would be a layering violation; aliases are
// looked up via Resolve.
func validPeerID(s string) bool {
	if len(s) != peerIDSize {
		return false
	}
	for i := 0; i < peerIDSize; i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// IsValidPeerID is the exported form of
// validPeerID, so callers in other packages (the
// REPL handler) can validate input without
// having to write the same loop.
func IsValidPeerID(s string) bool { return validPeerID(s) }
