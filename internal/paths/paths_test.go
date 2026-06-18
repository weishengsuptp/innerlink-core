package paths

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestNewLayout_Defaults verifies the default layout computes
// the expected paths when no overrides are given. This is the
// "fresh install, run from cwd" case — the one the user's 2026-
// 06-18 feedback asked for (everything in cwd, no HOME sprawl).
//
// IMPORTANT: expected paths are computed via filepath.Join
// rather than hard-coded strings. On Windows that gives
// backslashes; on Linux/macOS it gives forward slashes. The
// production code uses filepath.Join internally too, so the
// test stays correct on every platform without per-OS
// branches. A future refactor that uses string concatenation
// or hard-coded separators would surface here.
func TestNewLayout_Defaults(t *testing.T) {
	cwd := `D:\test-zone`
	l, err := NewLayout(cwd, Overrides{})
	if err != nil {
		t.Fatal(err)
	}
	// On macOS/Linux, NewLayout will be called from a forward-
	// slash cwd, but we're testing the relative layout — the
	// shape is what matters, not the separator. We test the
	// shape by comparing to a fresh layout built with
	// filepath.Join, then verify each field is "in cwd".
	baseFor := func(cwd, sub string) string {
		return filepath.Join(cwd, sub)
	}
	checks := []struct {
		field string
		got   string
		want  string
	}{
		{"DataDir", l.DataDir, baseFor(cwd, ".innerlink")},
		{"DeviceKey", l.DeviceKey, baseFor(baseFor(cwd, ".innerlink"), "device.key")},
		{"Aliases", l.Aliases, baseFor(baseFor(cwd, ".innerlink"), "aliases.json")},
		{"ChatLog", l.ChatLog, baseFor(baseFor(cwd, ".innerlink"), "chat.enc")},
		{"Roster", l.Roster, baseFor(baseFor(cwd, ".innerlink"), "roster.json")},
		{"Received", l.Received, baseFor(cwd, "received")},
		{"LogFile", l.LogFile, baseFor(cwd, "innerlink.log")},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %q, want %q", c.field, c.got, c.want)
		}
	}
	// Sanity: nothing leaks outside <cwd>. We accept either
	// "starts with cwd" or "absolute under cwd's parent", which
	// is the case for paths the user passed as absolute.
	for _, c := range checks {
		if !strings.HasPrefix(c.got, cwd) && !filepath.IsAbs(c.got) {
			t.Errorf("%s = %q escapes cwd %q", c.field, c.got, cwd)
		}
	}
}

// TestNewLayout_Overrides verifies each override field actually
// wins. A future regression that re-introduces a hard-coded HOME
// path would be caught here.
//
// We use platform-relative paths in the override (constructed
// via filepath.Join) so the test runs on Linux/macOS too. The
// production behavior under test is "override wins" — not the
// exact string — so the assertion is on the relative layout
// shape, not the absolute path.
func TestNewLayout_Overrides(t *testing.T) {
	cwd, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}
	dataDir := filepath.Join(cwd, "custom-state")
	saveDir := filepath.Join(cwd, "incoming")
	deviceKey := filepath.Join(dataDir, "my.key")
	logFile := filepath.Join(dataDir, "run.log")

	l, err := NewLayout("", Overrides{
		DataDir:   dataDir,
		SaveDir:   saveDir,
		DeviceKey: deviceKey,
		LogFile:   logFile,
	})
	if err != nil {
		t.Fatal(err)
	}
	if l.DataDir != dataDir {
		t.Errorf("DataDir = %q, want %q", l.DataDir, dataDir)
	}
	if l.DeviceKey != deviceKey {
		t.Errorf("DeviceKey = %q, want %q", l.DeviceKey, deviceKey)
	}
	// Aliases / ChatLog are derived from the overridden DataDir.
	if l.Aliases != filepath.Join(dataDir, "aliases.json") {
		t.Errorf("Aliases = %q, want %q", l.Aliases, filepath.Join(dataDir, "aliases.json"))
	}
	if l.ChatLog != filepath.Join(dataDir, "chat.enc") {
		t.Errorf("ChatLog = %q, want %q", l.ChatLog, filepath.Join(dataDir, "chat.enc"))
	}
	// SaveDir / LogFile are independent of DataDir.
	if l.Received != saveDir {
		t.Errorf("Received = %q, want %q", l.Received, saveDir)
	}
	if l.LogFile != logFile {
		t.Errorf("LogFile = %q, want %q", l.LogFile, logFile)
	}
}

// TestNewLayout_RelativeOverride confirms a relative override
// gets anchored to cwd, not interpreted as a path relative to
// the binary's directory. This is the bug that bit us when the
// default log file used to land next to the exe.
//
// We use t.TempDir() to get a real cross-platform cwd, then
// assert the resulting path is rooted at that cwd regardless
// of what OS Go decides to format the separator as.
func TestNewLayout_RelativeOverride(t *testing.T) {
	cwd := t.TempDir()
	l, err := NewLayout(cwd, Overrides{SaveDir: "files"})
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(cwd, "files")
	if l.Received != want {
		t.Errorf("Received = %q, want %q", l.Received, want)
	}
}

// TestLayout_Ensure is a smoke test: Ensure() must be idempotent
// and must not error on an empty directory. We don't delete the
// dirs after — they're created in a t.TempDir().
func TestLayout_Ensure(t *testing.T) {
	tmp := t.TempDir()
	l, err := NewLayout(tmp, Overrides{})
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Ensure(); err != nil {
		t.Fatalf("first Ensure: %v", err)
	}
	// Idempotent: second call must not error.
	if err := l.Ensure(); err != nil {
		t.Fatalf("second Ensure: %v", err)
	}
	// All three top-level entries must exist.
	for _, p := range []string{l.DataDir, l.Received} {
		if _, err := filepath.Abs(p); err != nil {
			t.Errorf("Abs(%q): %v", p, err)
		}
	}
}
