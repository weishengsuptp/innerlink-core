package alias

import (
	"sort"
	"strings"
	"time"
)

// ResolvePeerRef maps a user-supplied reference
// (either a 32-char peer-id-hex or a registered
// alias name) to a canonical peer-id-hex.
//
// Resolution order:
//  1. If ref is a valid peer-id-hex (32 lowercase
//     hex), return it as-is. This is the fast
//     path for power users who already know the
//     hex id.
//  2. Otherwise, scan the alias table for an
//     entry whose Name == ref. Return the
//     corresponding peer id.
//  3. Otherwise, return "" with found=false.
//
// Resolution is intentionally case-sensitive on
// the alias name. Aliases are user-typed in
// human languages (often Chinese) where case
// matters; matching 老王 != 老王. Same for
// peer-id-hex — we don't accept mixed case to
// avoid two peer ids that differ only in case.
func (s *Store) ResolvePeerRef(ref string) (peerID string, found bool) {
	if ref == "" {
		return "", false
	}
	if validPeerID(ref) {
		return ref, true
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for id, a := range s.m {
		if a.Name != "" && a.Name == ref {
			return id, true
		}
	}
	return "", false
}

// ListWithNames returns the alias table as a
// slice of (peerID, Alias) sorted by peer id
// lexicographically. The cmd's `peers` REPL
// command does its own sort by last_seen
// desc; this helper exists for the cases that
// need a stable order so tests can assert on
// output deterministically.
//
// Names with leading or trailing whitespace are
// trimmed; the alias table is allowed to store
// "老王" or "老王 " interchangeably, both
// resolve to the same peer.
func (s *Store) ListWithNames() []NamedAlias {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]NamedAlias, 0, len(s.m))
	for id, a := range s.m {
		out = append(out, NamedAlias{
			PeerID:    id,
			Name:      strings.TrimSpace(a.Name),
			FirstSeen: a.FirstSeen,
			LastSeen:  a.LastSeen,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PeerID < out[j].PeerID })
	return out
}

// NamedAlias is a single row returned by
// ListWithNames, factored out so the cmd layer
// can pass it to the `peers` formatter without
// having to know the on-disk Alias struct.
type NamedAlias struct {
	PeerID    string
	Name      string
	FirstSeen time.Time
	LastSeen  time.Time
}
