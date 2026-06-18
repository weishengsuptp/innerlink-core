package roster

import (
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// TestStore_OpenMissingFile verifies that opening a
// nonexistent file returns an empty Store ready for
// use, not an error. This matches the alias / storage
// policy: no side effects until the user does
// something.
func TestStore_OpenMissingFile(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "roster.json")
	s, err := Open(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if got := s.List(); len(got) != 0 {
		t.Errorf("fresh store has %d entries, want 0", len(got))
	}
}

// TestStore_AddAndGet is the happy path: add an entry,
// retrieve it, verify fields survive a round-trip
// through Save + Open.
func TestStore_AddAndGet(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "roster.json")
	s, err := Open(tmp)
	if err != nil {
		t.Fatal(err)
	}
	added, err := s.Add(Entry{
		PeerID:   "0123456789abcdef0123456789abcdef",
		Hostname: "alice",
		Addrs:    []string{"192.168.40.5:4748"},
		Source:   "",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !added {
		t.Error("Add on empty store: added=false, want true")
	}
	got, err := s.Get("0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	if got.Hostname != "alice" {
		t.Errorf("Hostname = %q, want alice", got.Hostname)
	}
	if len(got.Addrs) != 1 || got.Addrs[0] != "192.168.40.5:4748" {
		t.Errorf("Addrs = %v, want [192.168.40.5:4748]", got.Addrs)
	}
	if got.FirstSeen.IsZero() {
		t.Error("FirstSeen should be set by Add")
	}
	if got.LastSeen.IsZero() {
		t.Error("LastSeen should be set by Add")
	}
}

// TestStore_AddInvalidPeerID confirms the 32-char
// guard. We don't want a typo in the discovery layer
// to silently create a separate entry.
func TestStore_AddInvalidPeerID(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "roster.json")
	s, _ := Open(tmp)
	for _, bad := range []string{"", "abc", "0123456789abcdef0123456789abcde", "0123456789ABCDEF0123456789ABCDEF"} {
		_, err := s.Add(Entry{PeerID: bad, Hostname: "x"})
		if err == nil {
			t.Errorf("Add(%q) returned nil err, want validation failure", bad)
		}
	}
}

// TestStore_MergePreservesFirstSeen: when gossip brings
// us an entry we already have, the original first_seen
// must NOT be reset (otherwise the book "forgets" who
// was here first).
func TestStore_MergePreservesFirstSeen(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "roster.json")
	s, _ := Open(tmp)
	original := Entry{
		PeerID:   "0123456789abcdef0123456789abcdef",
		Hostname: "alice",
		Addrs:    []string{"192.168.40.5:4748"},
	}
	s.Add(original)
	first := s.List()[0].FirstSeen

	// Sleep a beat so a fresh FirstSeen would differ.
	// Then re-add via Add (not MergeFromGossip — same logic).
	s.Add(Entry{
		PeerID:   "0123456789abcdef0123456789abcdef",
		Hostname: "alice-laptop", // hostname changed
		Addrs:    []string{"192.168.40.5:4748", "10.0.0.5:4748"},
	})
	got := s.List()[0]
	if !got.FirstSeen.Equal(first) {
		t.Errorf("FirstSeen changed on re-Add: %v -> %v", first, got.FirstSeen)
	}
	if got.Hostname != "alice-laptop" {
		t.Errorf("Hostname = %q, want alice-laptop (refreshed)", got.Hostname)
	}
	if len(got.Addrs) != 2 {
		t.Errorf("Addrs len = %d, want 2 (refreshed)", len(got.Addrs))
	}
}

// TestStore_MergeFromGossip confirms the gossip path:
// new peers are added, existing peers are NOT
// refreshed (local direct observation is authoritative —
// gossip can be stale, and we have a direct channel
// that gives us fresher info), and malformed entries
// are silently skipped (defensive against a
// misbehaving peer).
func TestStore_MergeFromGossip(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "roster.json")
	s, _ := Open(tmp)
	// Pre-seed with peer X (we heard about it directly).
	s.Add(Entry{PeerID: "0123456789abcdef0123456789abcdef", Hostname: "x", Addrs: []string{"192.168.40.99:4748"}})

	// Gossip from B: introduces Y and Z, and tries to
	// "update" X with a different hostname. X should
	// be left alone (we have direct knowledge of X).
	remote := []Entry{
		{PeerID: "0123456789abcdef0123456789abcdef", Hostname: "x-refreshed", Addrs: []string{"192.168.40.1:4748"}},
		{PeerID: "fedcba9876543210fedcba9876543210", Hostname: "y", Addrs: []string{"192.168.40.2:4748"}},
		{PeerID: "11111111111111112222222222222222", Hostname: "z", Addrs: []string{"192.168.40.3:4748"}},
		{PeerID: "garbage", Hostname: "should-be-skipped"}, // malformed
	}
	newly, err := s.MergeFromGossip(remote)
	if err != nil {
		t.Fatal(err)
	}
	if len(newly) != 2 {
		t.Errorf("newly added = %v, want 2 entries (y, z)", newly)
	}
	// X should NOT be refreshed by gossip — local direct
	// observation wins. This is the v0.5 design choice
	// (see MergeFromGossip doc comment).
	x, _ := s.Get("0123456789abcdef0123456789abcdef")
	if x.Hostname != "x" {
		t.Errorf("X.Hostname = %q, want x (gossip must not refresh existing entries)", x.Hostname)
	}
	// Malformed should NOT be present.
	if _, err := s.Get("garbage"); err == nil {
		t.Error("garbage entry was not skipped")
	}
}

// TestStore_Remove verifies Remove + ErrNotFound.
func TestStore_Remove(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "roster.json")
	s, _ := Open(tmp)
	s.Add(Entry{PeerID: "0123456789abcdef0123456789abcdef", Hostname: "x"})
	if err := s.Remove("0123456789abcdef0123456789abcdef"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get("0123456789abcdef0123456789abcdef"); err != ErrNotFound {
		t.Errorf("after Remove, Get returned err = %v, want ErrNotFound", err)
	}
	// Removing again returns ErrNotFound.
	if err := s.Remove("0123456789abcdef0123456789abcdef"); err != ErrNotFound {
		t.Errorf("second Remove returned err = %v, want ErrNotFound", err)
	}
}

// TestStore_SaveAndReload is the round-trip test:
// Save, close, re-Open, verify state survives.
func TestStore_SaveAndReload(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "roster.json")
	s, _ := Open(tmp)
	s.Add(Entry{PeerID: "0123456789abcdef0123456789abcdef", Hostname: "alice", Addrs: []string{"1.2.3.4:4748"}})
	s.Add(Entry{PeerID: "fedcba9876543210fedcba9876543210", Hostname: "bob", Addrs: []string{"1.2.3.5:4748"}})
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}

	s2, err := Open(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if got := s2.List(); len(got) != 2 {
		t.Errorf("reloaded store has %d entries, want 2", len(got))
	}
}

// TestStore_ConcurrentAccess is the race detector
// smoke test. The Store claims to be safe for
// concurrent use; this test fails the race detector
// if that claim is false. Run with -race.
func TestStore_ConcurrentAccess(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "roster.json")
	s, _ := Open(tmp)
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(3)
		go func(i int) {
			defer wg.Done()
			pid := strings.Repeat("a", 30) + string(rune('a'+i)) + string(rune('0'))
			s.Add(Entry{PeerID: pid, Hostname: "x"})
		}(i)
		go func() {
			defer wg.Done()
			s.List()
		}()
		go func() {
			defer wg.Done()
			_ = s.Save()
		}()
	}
	wg.Wait()
}

// TestStore_ListSorted: List must return entries
// sorted by PeerID, for stable on-disk and gossip
// payloads. Easier to diff in tests and logs.
func TestStore_ListSorted(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "roster.json")
	s, _ := Open(tmp)
	// Add in random order.
	s.Add(Entry{PeerID: "ffffffffffffffffffffffffffffffff", Hostname: "f"})
	s.Add(Entry{PeerID: "00000000000000000000000000000000", Hostname: "0"})
	s.Add(Entry{PeerID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Hostname: "a"})

	got := s.List()
	if len(got) != 3 {
		t.Fatalf("List returned %d entries, want 3", len(got))
	}
	want := []string{
		"00000000000000000000000000000000",
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"ffffffffffffffffffffffffffffffff",
	}
	for i, w := range want {
		if got[i].PeerID != w {
			t.Errorf("List[%d].PeerID = %q, want %q", i, got[i].PeerID, w)
		}
	}
}
