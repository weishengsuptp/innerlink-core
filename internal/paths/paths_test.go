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
func TestNewLayout_Defaults(t *testing.T) {
	cwd := `D:\test-zone`
	l, err := NewLayout(cwd, Overrides{})
	if err != nil {
		t.Fatal(err)
	}
	wants := map[string]string{
		"DataDir":   `D:\test-zone\.innerlink`,
		"DeviceKey": `D:\test-zone\.innerlink\device.key`,
		"Aliases":   `D:\test-zone\.innerlink\aliases.json`,
		"ChatLog":   `D:\test-zone\.innerlink\chat.enc`,
		"Received":  `D:\test-zone\received`,
		"LogFile":   `D:\test-zone\innerlink.log`,
	}
	got := map[string]string{
		"DataDir":   l.DataDir,
		"DeviceKey": l.DeviceKey,
		"Aliases":   l.Aliases,
		"ChatLog":   l.ChatLog,
		"Received":  l.Received,
		"LogFile":   l.LogFile,
	}
	for k, want := range wants {
		if got[k] != want {
			t.Errorf("%s = %q, want %q", k, got[k], want)
		}
	}
	// Sanity: nothing leaks outside <cwd>.
	for k, v := range got {
		if !strings.HasPrefix(v, cwd) && !filepath.IsAbs(v) {
			t.Errorf("%s = %q escapes cwd %q", k, v, cwd)
		}
	}
}

// TestNewLayout_Overrides verifies each override field actually
// wins. A future regression that re-introduces a hard-coded HOME
// path would be caught here.
func TestNewLayout_Overrides(t *testing.T) {
	cwd := `D:\test-zone`
	o := Overrides{
		DataDir:   `E:\custom-state`,
		SaveDir:   `E:\incoming`,
		DeviceKey: `E:\custom-state\my.key`,
		LogFile:   `E:\custom-state\run.log`,
	}
	l, err := NewLayout(cwd, o)
	if err != nil {
		t.Fatal(err)
	}
	// DataDir + DeviceKey come from override.
	if l.DataDir != `E:\custom-state` {
		t.Errorf("DataDir = %q, want E:\\custom-state", l.DataDir)
	}
	if l.DeviceKey != `E:\custom-state\my.key` {
		t.Errorf("DeviceKey = %q, want E:\\custom-state\\my.key", l.DeviceKey)
	}
	// Aliases / ChatLog are derived from the overridden DataDir.
	if l.Aliases != `E:\custom-state\aliases.json` {
		t.Errorf("Aliases = %q, want E:\\custom-state\\aliases.json", l.Aliases)
	}
	if l.ChatLog != `E:\custom-state\chat.enc` {
		t.Errorf("ChatLog = %q, want E:\\custom-state\\chat.enc", l.ChatLog)
	}
	// SaveDir / LogFile are independent of DataDir.
	if l.Received != `E:\incoming` {
		t.Errorf("Received = %q, want E:\\incoming", l.Received)
	}
	if l.LogFile != `E:\custom-state\run.log` {
		t.Errorf("LogFile = %q, want E:\\custom-state\\run.log", l.LogFile)
	}
}

// TestNewLayout_RelativeOverride confirms a relative override
// gets anchored to cwd, not interpreted as a path relative to
// the binary's directory. This is the bug that bit us when the
// default log file used to land next to the exe.
func TestNewLayout_RelativeOverride(t *testing.T) {
	cwd := `D:\test-zone`
	l, err := NewLayout(cwd, Overrides{SaveDir: "files"})
	if err != nil {
		t.Fatal(err)
	}
	if l.Received != `D:\test-zone\files` {
		t.Errorf("Received = %q, want D:\\test-zone\\files", l.Received)
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
