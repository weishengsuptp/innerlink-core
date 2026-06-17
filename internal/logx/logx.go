// Package logx is a thin wrapper around log/slog that
// routes output to a tee of (stderr, optional file) and
// gates the noisy per-chunk / per-frame logs behind a
// debug level so the default `info` mode stays readable
// when a 2 GiB file is in flight.
//
// Usage in cmd/innerlink:
//
//	func main() {
//	    logx.Setup(logx.Options{
//	        Level: logx.LevelInfo,    // or LevelDebug
//	        File:  "innerlink.log",   // or "" to skip file output
//	        Stderr: true,             // keep screen output
//	    })
//	    defer logx.Close()
//
// All other packages keep using the stdlib log package —
// Setup() just calls log.SetOutput() to a multi-writer and
// sets a slog Handler that decides per-call whether to
// forward to log. This is deliberate: rewriting 45+
// log.Printf call sites across cmd/innerlink to use slog
// directly is churn for no real benefit, and a future
// refactor can do it all at once.
package logx

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Level is the verbosity gate. The string values are the
// values the user passes to the -log-level CLI flag.
type Level string

const (
	LevelDebug Level = "debug"
	LevelInfo  Level = "info"
	LevelWarn  Level = "warn"
	LevelError Level = "error"
)

// Options controls logx.Setup.
type Options struct {
	// Level is the minimum level forwarded to the
	// destinations. The default (empty string) is
	// LevelInfo. Note that the per-call level comes
	// from the log line's leading tag ([FILE] / [INFO]
	// / [MSG] / [DEBUG] / etc.), not from slog's
	// built-in level — see Setup for the mapping.
	Level Level

	// File is the path of the log file. Empty means
	// "do not write a file". The file is opened
	// append-only; the parent directory is created
	// if needed. On close, the file is flushed and
	// closed.
	File string

	// Stderr keeps the screen output. Default true.
	// Set to false in tests where you only want the
	// file output.
	Stderr bool
}

var (
	mu       sync.Mutex
	fileOut  io.WriteCloser
	levelSet = LevelInfo
)

// Setup installs the global log writer. After Setup, every
// log.Printf / log.Println / log.Print call goes through
// the new sink. Idempotent: calling it twice closes the
// previous file and re-opens the new one.
func Setup(opts Options) error {
	mu.Lock()
	defer mu.Unlock()

	if opts.Level == "" {
		opts.Level = LevelInfo
	}
	levelSet = opts.Level

	// Open the log file (if any).
	if fileOut != nil {
		_ = fileOut.Close()
		fileOut = nil
	}
	var writers []io.Writer
	if opts.Stderr {
		writers = append(writers, os.Stderr)
	}
	if opts.File != "" {
		if err := os.MkdirAll(filepath.Dir(opts.File), 0o755); err != nil {
			return fmt.Errorf("logx: mkdir log dir: %w", err)
		}
		f, err := os.OpenFile(opts.File, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			return fmt.Errorf("logx: open log file: %w", err)
		}
		fileOut = f
		writers = append(writers, f)
	}

	var out io.Writer
	switch len(writers) {
	case 0:
		out = io.Discard
	case 1:
		out = writers[0]
	default:
		out = io.MultiWriter(writers...)
	}

	// Hand our writer to the stdlib log package, and
	// also wrap it in a slog handler that filters by
	// per-call level tag.
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	log.SetOutput(&levelFilter{
		w:     out,
		level: levelSet,
	})
	return nil
}

// Close flushes and closes the log file (if any). Safe to
// call multiple times.
func Close() error {
	mu.Lock()
	defer mu.Unlock()
	if fileOut == nil {
		return nil
	}
	err := fileOut.Close()
	fileOut = nil
	return err
}

// CurrentLevel returns the active level. Used by packages
// that want to gate their own per-line log calls (e.g.
// per-chunk progress).
func CurrentLevel() Level {
	mu.Lock()
	defer mu.Unlock()
	return levelSet
}

// levelFilter is the writer that log.SetOutput receives.
// It classifies each line by (tag, body) and drops lines
// below the configured level. This lets the existing 45+
// log.Printf call sites stay exactly as they are; only
// the leading tag and the body text after it matter.
//
// Tag-and-body → level mapping:
//
//	[DEBUG]                       → debug
//	[ERROR]                       → error
//	[WARN ] / [WARN]              → warn
//	[FILE] recv chunk ...         → debug  (per-chunk; hidden at info)
//	[FILE] sending ... %          → debug  (per-progress; hidden at info)
//	[FILE] (other)                → info
//	[INFO ] / [MSG  ] / [PEER ]   → info
//	[HANDS] / [USAGE] / [HELP ]   → info
//	(unknown tag)                 → info  (safe default)
type levelFilter struct {
	w     io.Writer
	level Level
}

func (f *levelFilter) Write(p []byte) (int, error) {
	tag, body := leadingTagAndBody(p)
	eff := f.classify(tag, body)
	if !levelAtLeast(f.level, eff) {
		// Pretend we wrote the bytes so the stdlib log
		// package doesn't think the write failed.
		return len(p), nil
	}
	return f.w.Write(p)
}

// classify maps (tag, body) → effective level. Split out
// from Write so the unit tests can hit it directly.
func (f *levelFilter) classify(tag, body string) Level {
	switch tag {
	case "[DEBUG]":
		return LevelDebug
	case "[ERROR]":
		return LevelError
	case "[WARN ]", "[WARN]":
		return LevelWarn
	case "[FILE]":
		// [FILE] lines are classified by their body.
		// The per-chunk "[FILE] recv chunk ..." and
		// per-progress "[FILE] sending ... %" lines
		// are the bulk of the volume during a large
		// transfer (2 GiB = 2048 + ~200 lines) and
		// are hidden at info.
		if strings.HasPrefix(body, "recv chunk") ||
			strings.HasPrefix(body, "sending") {
			return LevelDebug
		}
		return LevelInfo
	case "[INFO ]", "[INFO]", "[MSG  ]", "[MSG]",
		"[PEER ]", "[PEER]", "[HANDS]",
		"[USAGE]", "[HELP ]", "[HELP]":
		return LevelInfo
	default:
		// Anything we don't explicitly classify is
		// info so it shows up by default. This is
		// the safe choice — accidentally suppressing
		// a useful log is worse than one extra line.
		return LevelInfo
	}
}

// debugDump is a debug helper used by the unit tests
// to confirm tag classification. Not for production use.
func debugDump(p []byte) (string, string) {
	return leadingTagAndBody(p)
}

func levelAtLeast(gate, eff Level) bool {
	rank := map[Level]int{
		LevelDebug: 0,
		LevelInfo:  1,
		LevelWarn:  2,
		LevelError: 3,
	}
	return rank[eff] >= rank[gate]
}

// leadingTagAndBody returns the first bracket-tag in p
// (e.g. "[FILE]", "[INFO ]") and the text after the tag
// (with leading whitespace stripped). p is the buffer
// passed to Write by the stdlib log package; it always
// ends in '\n' and the timestamp has already been
// prepended (since we set LstdFlags). We scan the line
// for the first "[" and return up to the matching "]".
// If either bracket is missing, the tag is "" and the
// body is the trimmed line.
func leadingTagAndBody(p []byte) (string, string) {
	// Find first '[' in the line.
	nl := bytesIndexByte(p, '\n')
	if nl < 0 {
		nl = len(p)
	}
	line := p[:nl]
	lb := bytesIndexByte(line, '[')
	if lb < 0 {
		return "", strings.TrimSpace(string(line))
	}
	rb := bytesIndexByte(line[lb:], ']')
	if rb < 0 {
		// "[FILE start send foo" — no closing bracket.
		// The tag is empty and the body is the whole
		// bracket text so callers can still classify
		// by the body prefix.
		return "", strings.TrimSpace(string(line[lb:]))
	}
	tag := string(line[lb : lb+rb+1])
	body := strings.TrimSpace(string(line[lb+rb+1:]))
	return tag, body
}

func bytesIndexByte(b []byte, c byte) int {
	for i, x := range b {
		if x == c {
			return i
		}
	}
	return -1
}
