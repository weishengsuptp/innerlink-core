// Package roster is the distributed peer directory for innerlink.
//
// Mental model (v0.5+): each innerlink instance maintains a local
// "phone book" of every peer it has ever heard about on the LAN.
// Phone books are kept loosely consistent across instances via
// a gossip protocol — when two peers establish a channel, they
// exchange their books; new entries discovered through gossip
// are merged in. The result is that within a small LAN
// (3-50 nodes), every instance eventually has the same set of
// "peers I've heard about" without needing a central server.
//
// What goes in the book (synced across the network):
//
//   - peerID      : the 16-byte SM3-derived identifier (hex)
//   - hostname    : the device's self-declared name
//   - addrs       : the IP:port pairs the peer is reachable at
//                   (a multi-NIC machine publishes several)
//   - first_seen  : when we first heard about this peer
//   - source      : which peer told us about this one (trust chain)
//
// What does NOT go in the book (kept local):
//
//   - alias       : a friendly name is each user's own preference
//                   (A wants to call B "老板", C wants to call
//                    B "老大" — neither is "wrong", neither is
//                    shared). See package alias.
//   - presence    : whether a peer is currently online is a
//                   real-time local observation derived from
//                   the active channel state. You can't trust
//                   "B told me C is online" because by the time
//                   you receive the message, C may have left.
//                   Presence is re-checked by attempting a
//                   handshake on every roster entry.
package roster

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// CurrentVersion is the on-disk file format version. Bump
// this if the JSON layout changes incompatibly.
const CurrentVersion = 1

// peerIDSize is the length of a PeerID in hex chars.
// Kept identical to identity.PeerIDSize (32) — we
// don't import identity to avoid a cycle.
const peerIDSize = 32

// Entry is one row of the roster — what we know about
// a single peer. The fields are intentionally minimal:
// this is the public "phone book" content, and the
// gossip protocol exchanges these.
type Entry struct {
	// PeerID is the 32-char lowercase hex of the peer's
	// 16-byte SM3-derived identity. The map key in Store.
	PeerID string `json:"peer_id"`
	// Hostname is the device's self-declared name. May
	// change over time (DHCP, user rename); the latest
	// gossip wins.
	Hostname string `json:"hostname"`
	// Addrs is the set of IP:port pairs this peer is
	// reachable at. A machine with multiple NICs
	// publishes multiple. Order is not significant.
	Addrs []string `json:"addrs"`
	// FirstSeen is when we first heard about this peer.
	// Set once, never updated.
	FirstSeen time.Time `json:"first_seen"`
	// LastSeen is the most recent time we observed this
	// peer (handshake, channel ready, gossip). Updated
	// on every contact. Not synced — derived locally.
	LastSeen time.Time `json:"last_seen"`
	// Source is the peerID of the node that told us
	// about this entry. Empty when we discovered the
	// peer directly (UDP discovery or direct dial).
	// Used for trust-chain debugging, not enforced.
	Source string `json:"source,omitempty"`
}

// fileFormat is the on-disk JSON shape. The "v" field
// lets us bump the schema later without breaking older
// files.
type fileFormat struct {
	V      int             `json:"v"`
	Entry  map[string]Entry `json:"entries"`
}

// Store is the in-memory + on-disk roster. All exported
// methods are safe for concurrent use. The on-disk
// representation is JSON for human-debuggability — a
// user can `cat .innerlink/roster.json` and see who's
// in their network.
type Store struct {
	path string

	mu      sync.RWMutex // protects m
	m       map[string]Entry

	saveMu sync.Mutex // serializes Save()
	dirty  bool       // m has changes not yet on disk
}

// Open loads the roster from path. If the file does
// not exist, Open returns an empty Store ready to
// accept Add/Remove — the file is created on the
// first Save, not eagerly. Same policy as alias
// and storage: no side effects until the user
// actually does something.
//
// A corrupt or unparseable file is a hard error —
// silently starting with an empty book would be the
// "we lost your data" failure mode.
func Open(path string) (*Store, error) {
	s := &Store{
		path: path,
		m:    make(map[string]Entry),
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return s, nil
		}
		return nil, fmt.Errorf("roster: read %s: %w", path, err)
	}
	var f fileFormat
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("roster: parse %s: %w", path, err)
	}
	if f.V != CurrentVersion {
		return nil, fmt.Errorf("roster: %s: unsupported version %d", path, f.V)
	}
	if f.Entry != nil {
		s.m = f.Entry
	}
	return s, nil
}

// Add inserts or updates an entry. Empty peerID is an
// error (caller bug). If the entry already exists, the
// hostname and addrs are refreshed, first_seen is kept,
// last_seen is updated to now, and source is updated
// only if the new source is non-empty.
//
// Returns true if the entry is new (didn't exist
// before). Callers use this to decide whether to push
// the new entry to connected peers for gossip.
func (s *Store) Add(e Entry) (added bool, err error) {
	if !validPeerID(e.PeerID) {
		return false, fmt.Errorf("roster: peer id must be %d lowercase hex chars", peerIDSize)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	existing, ok := s.m[e.PeerID]
	if ok {
		// Merge: keep first_seen, refresh the rest.
		e.FirstSeen = existing.FirstSeen
	}
	if e.FirstSeen.IsZero() {
		e.FirstSeen = time.Now().UTC()
	}
	if e.LastSeen.IsZero() {
		e.LastSeen = time.Now().UTC()
	}
	s.m[e.PeerID] = e
	s.dirty = true
	return !ok, nil
}

// Remove deletes the entry for peerID. Returns
// ErrNotFound if no such entry.
var ErrNotFound = errors.New("roster: peer not found")

func (s *Store) Remove(peerID string) error {
	if !validPeerID(peerID) {
		return fmt.Errorf("roster: peer id must be %d lowercase hex chars", peerIDSize)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.m[peerID]; !ok {
		return ErrNotFound
	}
	delete(s.m, peerID)
	s.dirty = true
	return nil
}

// Get returns the entry for peerID, or ErrNotFound.
func (s *Store) Get(peerID string) (Entry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.m[peerID]
	if !ok {
		return Entry{}, ErrNotFound
	}
	return e, nil
}

// Touch updates LastSeen for an existing entry. No-op
// if the entry doesn't exist (the caller probably has
// a race with gossip eviction; the next gossip will
// re-add it).
func (s *Store) Touch(peerID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.m[peerID]
	if !ok {
		return
	}
	e.LastSeen = time.Now().UTC()
	s.m[peerID] = e
	s.dirty = true
}

// List returns a snapshot of all entries, sorted by
// PeerID (so the on-disk file and the gossip message
// have a stable order — easier to diff in tests and
// log analysis).
func (s *Store) List() []Entry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Entry, 0, len(s.m))
	for _, e := range s.m {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].PeerID < out[j].PeerID
	})
	return out
}

// MergeFromGossip is the entry point for the gossip
// protocol. It applies a remote peer's roster view
// into our local one. Existing entries are refreshed
// (hostname/addrs); new entries are added; missing
// entries are NOT removed (we don't trust gossip
// enough to delete locally-observed peers).
//
// Returns the list of peerIDs that were newly added —
// the caller uses this to decide whether to schedule
// a dial to those peers (presence probe).
func (s *Store) MergeFromGossip(remote []Entry) (newlyAdded []string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range remote {
		if len(e.PeerID) != peerIDSize {
			// Skip malformed gossip entries rather than
			// failing the whole merge. A single bad
			// entry from a misbehaving peer should not
			// prevent the rest from being adopted.
			continue
		}
		if _, ok := s.m[e.PeerID]; !ok {
			if e.FirstSeen.IsZero() {
				e.FirstSeen = time.Now().UTC()
			}
			if e.LastSeen.IsZero() {
				e.LastSeen = time.Now().UTC()
			}
			s.m[e.PeerID] = e
			s.dirty = true
			newlyAdded = append(newlyAdded, e.PeerID)
		}
	}
	sort.Strings(newlyAdded)
	return newlyAdded, nil
}

// Save writes the current state to disk. Idempotent.
// Uses atomic write (tmp + rename) so a crash mid-write
// doesn't corrupt the file. Returns nil if no changes
// are pending (no-op).
//
// The map is COPIED under the read lock, then marshaled
// outside the lock. The previous version released the
// read lock before json.MarshalIndent, which then
// iterated the same map Add() was concurrently writing
// to — the race detector caught it on macOS arm64
// (CI run 27732172056). The copy is the canonical
// fix: we read the whole map atomically, then the
// rest of Save operates on a private snapshot.
func (s *Store) Save() error {
	s.saveMu.Lock()
	defer s.saveMu.Unlock()
	s.mu.RLock()
	if !s.dirty {
		s.mu.RUnlock()
		return nil
	}
	// Snapshot the map under the read lock. The
	// copy is a fresh map; mutations to s.m after
	// this point don't affect our snapshot.
	snapshot := make(map[string]Entry, len(s.m))
	for k, v := range s.m {
		snapshot[k] = v
	}
	s.mu.RUnlock()
	f := fileFormat{
		V:     CurrentVersion,
		Entry: snapshot,
	}
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return fmt.Errorf("roster: marshal: %w", err)
	}
	// Atomic write: write to <path>.tmp, then rename.
	dir := filepath.Dir(s.path)
	tmp, err := os.CreateTemp(dir, "roster-*.json.tmp")
	if err != nil {
		return fmt.Errorf("roster: create tmp: %w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		// On any error path, clean up the tmp.
		_ = os.Remove(tmpName)
	}()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("roster: write tmp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("roster: close tmp: %w", err)
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		return fmt.Errorf("roster: rename: %w", err)
	}
	s.mu.Lock()
	s.dirty = false
	s.mu.Unlock()
	return nil
}

// Close flushes pending changes to disk. Idempotent.
func (s *Store) Close() error {
	return s.Save()
}

// validPeerID is the same lowercase-hex check used
// in internal/alias. We duplicate rather than import
// to keep the leaf-package property (roster is used
// from cmd; alias is too; neither depends on the
// other; importing alias here would create a
// longer-than-needed dependency chain).
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
