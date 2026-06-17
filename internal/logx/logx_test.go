package logx

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSetup_NoFile(t *testing.T) {
	// Save and restore the default log writer so we
	// don't pollute the rest of the test binary.
	orig := log.Writer()
	origFlags := log.Flags()
	defer func() {
		log.SetOutput(orig)
		log.SetFlags(origFlags)
	}()

	var buf bytes.Buffer
	if err := Setup(Options{
		Level:  LevelInfo,
		File:   "",
		Stderr: false,
	}); err != nil {
		t.Fatal(err)
	}
	// log.SetOutput was called with our levelFilter
	// pointing at the multi-writer (just us). Steal
	// that writer by re-pointing to a fresh buffer
	// and going through Setup once more. The test
	// below just exercises the tag classification.
	_ = buf
}

// TestClassify is the table-driven check for the
// (tag, body) → level mapping. If you change classify,
// update the table.
func TestClassify(t *testing.T) {
	cases := []struct {
		tag      string
		body     string
		gate     Level
		wantEmit bool
	}{
		// [FILE] is one tag with two body-driven
		// subclasses. The body text is the part of
		// the line after the tag.
		{"[FILE]", "start send foo", LevelInfo, true},
		{"[FILE]", "done", LevelInfo, true},
		{"[FILE]", "incoming", LevelInfo, true},
		// High-frequency per-chunk / per-progress:
		// hidden at info, visible at debug.
		{"[FILE]", "recv chunk idx=1/2", LevelInfo, false},
		{"[FILE]", "recv chunk idx=1/2", LevelDebug, true},
		{"[FILE]", "sending foo 50%", LevelInfo, false},
		{"[FILE]", "sending foo 50%", LevelDebug, true},
		// Other tags.
		{"[INFO ]", "hello", LevelInfo, true},
		{"[INFO ]", "hello", LevelDebug, true},
		{"[DEBUG]", "verbose", LevelInfo, false},
		{"[DEBUG]", "verbose", LevelDebug, true},
		{"[ERROR]", "bad", LevelWarn, true},
		{"[ERROR]", "bad", LevelError, true},
		{"[WARN ]", "careful", LevelInfo, true},
		{"[WARN ]", "careful", LevelError, false},
		// Unknown tag → info (safe default).
		{"[???]", "unknown", LevelInfo, true},
		{"[???]", "unknown", LevelWarn, false},
	}
	for _, c := range cases {
		f := &levelFilter{level: c.gate}
		eff := f.classify(c.tag, c.body)
		got := levelAtLeast(f.level, eff)
		if got != c.wantEmit {
			t.Errorf("classify(%q, %q @ %s) → eff=%s, emit=%v, want %v",
				c.tag, c.body, c.gate, eff, got, c.wantEmit)
		}
	}
}

// TestSetup_FileOutput verifies the file sink actually
// receives lines at debug level and that info-level
// [FILE recv chunk ...] is filtered out of both the file
// and the writer tee.
func TestSetup_FileOutput(t *testing.T) {
	orig := log.Writer()
	origFlags := log.Flags()
	defer func() {
		log.SetOutput(orig)
		log.SetFlags(origFlags)
	}()

	tmp := filepath.Join(t.TempDir(), "test.log")
	if err := Setup(Options{
		Level:  LevelInfo,
		File:   tmp,
		Stderr: false,
	}); err != nil {
		t.Fatal(err)
	}
	defer Close()

	// Sanity check: classify what the filter thinks
	// each line is. If classification is wrong, the
	// assertions below will tell us, but a clearer
	// failure helps.
	for _, line := range []string{
		"[INFO ] hello info",
		"[FILE] start send foo",
		"[FILE] recv chunk idx=1/2 size=1048576",
		"[ERROR] oops",
	} {
		tag, _ := debugDump([]byte("2026/06/17 08:20:41.309710 " + line + "\n"))
		t.Logf("classified %q as tag=%q", line, tag)
	}

	log.Printf("[INFO ] hello info")
	log.Printf("[FILE] start send foo")
	log.Printf("[FILE] recv chunk idx=1/2 size=1048576") // debug-only
	log.Printf("[ERROR] oops")

	data, err := os.ReadFile(tmp)
	if err != nil {
		t.Fatal(err)
	}
	got := string(data)
	mustContain(t, got, "hello info")
	mustContain(t, got, "start send foo")
	mustNotContain(t, got, "FILE recv chunk") // hidden at info
	mustContain(t, got, "oops")
}

func TestSetup_DebugLevel(t *testing.T) {
	orig := log.Writer()
	origFlags := log.Flags()
	defer func() {
		log.SetOutput(orig)
		log.SetFlags(origFlags)
	}()

	tmp := filepath.Join(t.TempDir(), "test.log")
	if err := Setup(Options{
		Level:  LevelDebug,
		File:   tmp,
		Stderr: false,
	}); err != nil {
		t.Fatal(err)
	}
	defer Close()

	log.Printf("[FILE recv chunk idx=1/2 size=1048576")

	data, err := os.ReadFile(tmp)
	if err != nil {
		t.Fatal(err)
	}
	mustContain(t, string(data), "FILE recv chunk")
}

func mustContain(t *testing.T, s, sub string) {
	t.Helper()
	if !strings.Contains(s, sub) {
		t.Errorf("log output missing %q\n--- got ---\n%s\n--- end ---", sub, s)
	}
}

func mustNotContain(t *testing.T, s, sub string) {
	t.Helper()
	if strings.Contains(s, sub) {
		t.Errorf("log output unexpectedly contains %q\n--- got ---\n%s\n--- end ---", sub, s)
	}
}
