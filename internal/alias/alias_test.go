package alias

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// fakePeerID returns a valid 32-char hex peer id
// from a 4-char seed. The seed is hex-padded so
// the result is always 32 lowercase hex chars.
func fakePeerID(seed string) string {
	h := strings.Repeat("0", 32-len(seed))
	return h + seed
}

func TestOpenMissingFile(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "aliases.json"))
	if err != nil {
		t.Fatalf("Open on missing file should not error, got %v", err)
	}
	if s == nil {
		t.Fatal("Open returned nil store")
	}
	if n := len(s.List()); n != 0 {
		t.Fatalf("new store should be empty, got %d entries", n)
	}
}

func TestSetAndGet(t *testing.T) {
	s, _ := Open(filepath.Join(t.TempDir(), "aliases.json"))
	id := fakePeerID("abcd")
	if err := s.Set(id, "老王工位机"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	a, ok := s.Get(id)
	if !ok {
		t.Fatal("Get: should have found the alias")
	}
	if a.Name != "老王工位机" {
		t.Fatalf("Get: name = %q, want 老王工位机", a.Name)
	}
	if a.FirstSeen.IsZero() {
		t.Fatal("Get: first_seen should be set")
	}
	if a.LastSeen.IsZero() {
		t.Fatal("Get: last_seen should be set")
	}
}

func TestSetRejectsInvalidPeerID(t *testing.T) {
	s, _ := Open(filepath.Join(t.TempDir(), "aliases.json"))
	cases := []string{
		"",                           // empty
		"abcd",                       // too short
		"abcdefghijklmnopqrstuvwxyz1234567", // 33 chars
		strings.ToUpper(fakePeerID("aa")), // uppercase
		fakePeerID("aa") + "g",       // non-hex
	}
	for _, c := range cases {
		if err := s.Set(c, "name"); err != ErrInvalidPeerID {
			t.Errorf("Set(%q): got %v, want ErrInvalidPeerID", c, err)
		}
	}
}

func TestSetRejectsEmptyAndLongNames(t *testing.T) {
	s, _ := Open(filepath.Join(t.TempDir(), "aliases.json"))
	id := fakePeerID("aa")
	if err := s.Set(id, ""); err != ErrEmptyName {
		t.Errorf("empty name: got %v, want ErrEmptyName", err)
	}
	long := strings.Repeat("x", 65)
	if err := s.Set(id, long); err != ErrNameTooLong {
		t.Errorf("65-char name: got %v, want ErrNameTooLong", err)
	}
}

func TestSetUpdatesExisting(t *testing.T) {
	s, _ := Open(filepath.Join(t.TempDir(), "aliases.json"))
	id := fakePeerID("1111")
	if err := s.Set(id, "first"); err != nil {
		t.Fatal(err)
	}
	a1, _ := s.Get(id)
	time.Sleep(2 * time.Millisecond)
	if err := s.Set(id, "second"); err != nil {
		t.Fatal(err)
	}
	a2, _ := s.Get(id)
	if a2.Name != "second" {
		t.Errorf("Name = %q, want second", a2.Name)
	}
	if !a2.FirstSeen.Equal(a1.FirstSeen) {
		t.Errorf("FirstSeen changed: %v -> %v", a1.FirstSeen, a2.FirstSeen)
	}
	if !a2.LastSeen.After(a1.LastSeen) {
		t.Errorf("LastSeen should advance: %v -> %v", a1.LastSeen, a2.LastSeen)
	}
}

func TestRemove(t *testing.T) {
	s, _ := Open(filepath.Join(t.TempDir(), "aliases.json"))
	id := fakePeerID("2222")
	_ = s.Set(id, "x")
	if err := s.Remove(id); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Get(id); ok {
		t.Fatal("Get: should not find removed alias")
	}
	// Removing a non-existent alias is a no-op, not
	// an error.
	if err := s.Remove(id); err != nil {
		t.Errorf("Remove non-existent: got %v, want nil", err)
	}
}

func TestRemoveRejectsInvalidPeerID(t *testing.T) {
	s, _ := Open(filepath.Join(t.TempDir(), "aliases.json"))
	if err := s.Remove("not-a-peer-id"); err != ErrInvalidPeerID {
		t.Errorf("got %v, want ErrInvalidPeerID", err)
	}
}

func TestTouchOnUnknownPeerCreatesPlaceholder(t *testing.T) {
	s, _ := Open(filepath.Join(t.TempDir(), "aliases.json"))
	id := fakePeerID("3333")
	s.Touch(id) // not via Set; just runtime saw activity
	a, ok := s.Get(id)
	if !ok {
		t.Fatal("Touch should have created a placeholder row")
	}
	if a.Name != "" {
		t.Errorf("placeholder Name = %q, want empty", a.Name)
	}
	if a.LastSeen.IsZero() {
		t.Error("placeholder LastSeen should be set")
	}
}

func TestTouchUpdatesLastSeen(t *testing.T) {
	s, _ := Open(filepath.Join(t.TempDir(), "aliases.json"))
	id := fakePeerID("4444")
	_ = s.Set(id, "named")
	a1, _ := s.Get(id)
	time.Sleep(2 * time.Millisecond)
	s.Touch(id)
	a2, _ := s.Get(id)
	if !a2.LastSeen.After(a1.LastSeen) {
		t.Errorf("LastSeen should advance: %v -> %v", a1.LastSeen, a2.LastSeen)
	}
	if a2.Name != "named" {
		t.Errorf("Touch must not change Name: %q", a2.Name)
	}
}

func TestSaveAndReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "aliases.json")
	s1, _ := Open(path)
	_ = s1.Set(fakePeerID("aaaa"), "alpha")
	_ = s1.Set(fakePeerID("bbbb"), "beta")
	if err := s1.Close(); err != nil {
		t.Fatal(err)
	}
	s2, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if a, ok := s2.Get(fakePeerID("aaaa")); !ok || a.Name != "alpha" {
		t.Errorf("reload: alpha = %v, ok=%v", a, ok)
	}
	if a, ok := s2.Get(fakePeerID("bbbb")); !ok || a.Name != "beta" {
		t.Errorf("reload: beta = %v, ok=%v", a, ok)
	}
}

func TestSaveIsAtomic(t *testing.T) {
	// After a successful Save, no .tmp file should
	// be left behind.
	path := filepath.Join(t.TempDir(), "aliases.json")
	s, _ := Open(path)
	_ = s.Set(fakePeerID("cccc"), "gamma")
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Errorf("tmp file should not exist after Save, stat err = %v", err)
	}
}

func TestSaveIsNoopWhenClean(t *testing.T) {
	// If we Open a non-empty file but never call
	// Set, the file's mtime should not change on
	// Save (we skip the rewrite).
	path := filepath.Join(t.TempDir(), "aliases.json")
	s, _ := Open(path)
	_ = s.Set(fakePeerID("dddd"), "delta")
	_ = s.Save()
	stat1, _ := os.Stat(path)
	time.Sleep(50 * time.Millisecond)
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	stat2, _ := os.Stat(path)
	if !stat1.ModTime().Equal(stat2.ModTime()) {
		t.Errorf("second Save should be a no-op; mtime changed %v -> %v",
			stat1.ModTime(), stat2.ModTime())
	}
}

func TestRejectsCorruptFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aliases.json")
	if err := os.WriteFile(path, []byte("not json{{{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path); err == nil {
		t.Fatal("Open on corrupt file should fail, got nil")
	}
}

func TestRejectsUnknownVersion(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aliases.json")
	f := fileFormat{V: 99}
	data, _ := json.Marshal(&f)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path); err == nil {
		t.Fatal("Open on v99 should fail")
	}
}

func TestResolvePeerRef(t *testing.T) {
	s, _ := Open(filepath.Join(t.TempDir(), "aliases.json"))
	id := fakePeerID("7777")
	_ = s.Set(id, "老王工位机")

	// 1. valid peer id resolves to itself
	got, ok := s.ResolvePeerRef(id)
	if !ok || got != id {
		t.Errorf("by-hex: got (%q, %v), want (%q, true)", got, ok, id)
	}
	// 2. alias resolves to the peer id
	got, ok = s.ResolvePeerRef("老王工位机")
	if !ok || got != id {
		t.Errorf("by-name: got (%q, %v), want (%q, true)", got, ok, id)
	}
	// 3. unknown reference resolves to nothing
	if got, ok := s.ResolvePeerRef("not a thing"); ok || got != "" {
		t.Errorf("unknown: got (%q, %v), want (\"\", false)", got, ok)
	}
	// 4. empty reference
	if got, ok := s.ResolvePeerRef(""); ok || got != "" {
		t.Errorf("empty: got (%q, %v), want (\"\", false)", got, ok)
	}
}

func TestListWithNamesDeterministic(t *testing.T) {
	// Insert in a deliberately non-sorted order so
	// the test catches "returns map iteration
	// order" bugs. ListWithNames must sort by
	// peer id lexicographically.
	s, _ := Open(filepath.Join(t.TempDir(), "aliases.json"))
	ids := []string{"cc", "aa", "dd", "bb"}
	for _, i := range ids {
		_ = s.Set(fakePeerID(i), "n-"+i)
	}
	got := s.ListWithNames()
	if len(got) != len(ids) {
		t.Fatalf("got %d entries, want %d", len(got), len(ids))
	}
	// Build the expected sorted-by-peerID slice.
	expected := make([]string, len(ids))
	for i, i2 := range ids {
		expected[i] = fakePeerID(i2)
	}
	sort.Strings(expected)
	for i, want := range expected {
		if got[i].PeerID != want {
			t.Errorf("entry %d: got %q, want %q", i, got[i].PeerID, want)
		}
	}
}

func TestDefaultPath(t *testing.T) {
	// Use platform-native path separators so the
	// test passes on Windows AND on macOS/Linux.
	// The hard-coded "C:\Users\liul\..." in earlier
	// versions broke the macOS CI build.
	deviceKey := filepath.Join("home", "alice", ".innerlink", "device.key")
	want := filepath.Join("home", "alice", ".innerlink", "aliases.json")
	got := DefaultPath(deviceKey)
	if got != want {
		t.Errorf("DefaultPath = %q, want %q", got, want)
	}
}

func TestIsValidPeerID(t *testing.T) {
	if !IsValidPeerID(fakePeerID("abcd")) {
		t.Error("hex should be valid")
	}
	if IsValidPeerID("not hex!") {
		t.Error("non-hex should be invalid")
	}
}

func TestCloseIdempotent(t *testing.T) {
	s, _ := Open(filepath.Join(t.TempDir(), "aliases.json"))
	_ = s.Set(fakePeerID("eeee"), "epsilon")
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	// Second Close should be a no-op and not error.
	if err := s.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}
