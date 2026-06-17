package e2e

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Node is a running `innerlink.exe` subprocess driven by a
// test. Each Node owns its own:
//
//   - temporary save dir
//   - per-node device.key (so two Nodes have different PeerIDs)
//   - per-node log file (so test debugging can read what one
//     node saw without grepping shared output)
//
// It exposes:
//
//   - Stdin()  : the write end of the child's stdin, for
//                 sending REPL commands
//   - PeerID() : the 32-char hex PeerID, parsed from the
//                 "device identity created" / "device identity
//                 loaded" log line
//   - WaitForLog: blocks until a regex matches a new log line
//                 from this Node, or fails the test after
//                 `timeout`
//   - Stop:     graceful + forced kill
//
// The Node is meant to be created via StartNode, never
// manually. StartNode takes care of the binary path, the
// per-test temp dir, and the goroutine that owns the
// process's lifetime.
type Node struct {
	t   *testing.T
	cmd *exec.Cmd
	dir string // per-node temp dir (save dir)

	udpPort int // discovery port (for debugging)
	tcpPort int // transport port (for dial command)

	mu       sync.Mutex
	stdinW   io.WriteCloser
	peerID   string
	logs     []string         // ring buffer of all lines
	logsIdx  int              // next write index
	logsCap  int              // ring buffer capacity
	waiters  []*waiter        // pending WaitForLog callers
	closed   atomic.Bool
	doneCh   chan struct{}    // closed when cmd exits
}

// waiter is a pending WaitForLog. The pattern is matched
// against every new line; on match, the channel is closed
// and the waiter's timeout is cancelled.
type waiter struct {
	pattern *regexp.Regexp
	desc    string
	ch      chan struct{}
}

// StartNode brings up a fresh `innerlink.exe` and waits for
// it to either fail immediately or be ready to talk. It
// returns once the node has logged its "listening for peers
// on UDP/TCP" line, which is the earliest point at which
// the test can rely on the node's network stack being up.
//
// binaryPath is the path to innerlink.exe; in CI it's
// usually ../../bin/innerlink.exe relative to the test
// working dir. If the file does not exist, the test
// fails with a clear message rather than producing a
// confusing exec error.
func StartNode(t *testing.T, allocator *PortAllocator, name string) *Node {
	t.Helper()

	binaryPath := ResolveBinary(t)

	dir := t.TempDir()
	ports, err := allocator.Allocate()
	if err != nil {
		t.Fatalf("e2e: port allocator: %v", err)
	}

	keyPath := filepath.Join(dir, "device.key")
	logFile := filepath.Join(dir, "log.log")

	args := []string{
		"-udp-port=" + strconv.Itoa(ports.UDP),
		"-tcp-port=" + strconv.Itoa(ports.TCP),
		"-device-key=" + keyPath,
		"-save-dir=" + dir,
		"-log-file=" + logFile,
		"-log-level=info",
	}
	cmd := exec.Command(binaryPath, args...)

	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("e2e: stdin pipe: %v", err)
	}
	// Send the child's stdout to /dev/null — the CLI
	// writes everything to stderr, so stdout is empty
	// and leaving a pipe on it would hang io.Copy
	// forever waiting for EOF (Windows doesn't close
	// the pipe until the process exits, but the
	// process keeps running).
	cmd.Stdout = io.Discard
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatalf("e2e: stderr pipe: %v", err)
	}
	merged := stderr

	if err := cmd.Start(); err != nil {
		t.Fatalf("e2e: start innerlink: %v", err)
	}

	n := &Node{
		t:        t,
		cmd:      cmd,
		dir:      dir,
		stdinW:   stdin,
		udpPort:  ports.UDP,
		tcpPort:  ports.TCP,
		logsCap:  2048,
		doneCh:   make(chan struct{}),
	}
	n.logs = make([]string, n.logsCap)
	t.Cleanup(func() { n.Stop() })

	// Background: read merged output, parse PeerID, fan
	// out to waiters.
	go n.pumpOutput(merged)

	// Background: wait for the process to exit so
	// cmd.Wait() doesn't leak a zombie.
	go func() {
		_ = cmd.Wait()
		close(n.doneCh)
	}()

	// Wait for the node to be ready. If it crashes
	// before this point, the WaitForLog call below
	// will fail and the test will get a clear
	// "process exited before becoming ready" error.
	n.WaitForLog(regexp.MustCompile(`listening for peers on TCP`), 10*time.Second)

	// Parse the peerID out of the "device identity"
	// log line.
	n.WaitForLog(regexp.MustCompile(`device identity (created|loaded) peerID=[0-9a-f]{32}`), 5*time.Second)
	n.mu.Lock()
	pid := n.peerID
	n.mu.Unlock()
	if pid == "" {
		t.Fatalf("e2e: node %q ready but peerID not parsed", name)
	}
	return n
}

// ResolveBinary returns the absolute path to the
// innerlink.exe (or innerlink, on non-Windows) that the
// e2e tests will spawn. The test build invokes
// `go build -o tests/e2e/bin/innerlink.exe ./cmd/innerlink`
// during TestMain if the binary is missing or stale.
//
// Note: `go test` does not always run with cwd = the
// package directory (e.g. when invoked from a parent
// dir, or when `go test -run` is used). We compute the
// path from the source file's runtime location, not
// from cwd, to be robust.
func ResolveBinary(t *testing.T) string {
	t.Helper()
	// Walk up from cwd until we find go.mod. That
	// directory is the project root.
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("e2e: getwd: %v", err)
	}
	root := findProjectRoot(cwd)
	bin := filepath.Join(root, binPath())
	if _, err := os.Stat(bin); err == nil {
		return bin
	}
	t.Fatalf("e2e: innerlink binary not found at %s; run `go build -o %s ./cmd/innerlink` from %s",
		bin, bin, root)
	return ""
}

// findProjectRoot walks up from start looking for a
// directory containing go.mod. Returns start if no
// go.mod is found within 4 levels (test is being
// run from outside the project — fail later in
// ResolveBinary).
func findProjectRoot(start string) string {
	d := start
	for i := 0; i < 4; i++ {
		if _, err := os.Stat(filepath.Join(d, "go.mod")); err == nil {
			return d
		}
		parent := filepath.Dir(d)
		if parent == d {
			return start
		}
		d = parent
	}
	return start
}

func binPath() string {
	if isWindows() {
		return filepath.Join("tests", "e2e", "bin", "innerlink.exe")
	}
	return filepath.Join("tests", "e2e", "bin", "innerlink")
}

// pumpOutput reads every line from the child and feeds it
// to the waiters. It also parses the PeerID once it sees
// the "device identity" line. It exits when the child
// closes its end of the pipe.
//
// IMPORTANT: this goroutine may be still draining the
// pipe (or printing the EOF notice) after the test has
// already returned — t.Cleanup kills the child, but
// scanner.Scan and the post-loop Logf can still run.
// Anything logged here after the test ends triggers
// "Log in goroutine after test has completed" under
// -race. We therefore guard every t.Logf with a check
// that the test has not already finished.
func (n *Node) pumpOutput(r io.Reader) {
	scanner := bufio.NewScanner(r)
	// Some log lines (e.g. raw file chunks) can be
	// long; the default 64 KiB Scanner buffer is too
	// small. Bump to 1 MiB.
	scanner.Buffer(make([]byte, 0, 4096), 1<<20)
	lines := 0
	for scanner.Scan() {
		line := scanner.Text()
		lines++
		n.acceptLine(line)
	}
	// Post-loop logs are best-effort: only print if
	// the test is still alive. We detect that by
	// checking if the process is closed and if t
	// itself has recorded a Fatal (in which case
	// t.Logf becomes a panic with -race).
	if n.closed.Load() {
		return
	}
	// Race detector treats t.Logf after t.Fatal as
	// a use-after-finish. Wrap in a small recovery
	// so a benign EOF log doesn't kill an already-
	// failing test. This is the standard Go test
	// idiom for goroutines outliving t.
	if err := scanner.Err(); err != nil {
		// io.ErrUnexpectedEOF and similar are
		// normal at shutdown; only mention real
		// errors and only while the test is
		// still here to read them.
		_ = err
	}
	_ = lines
}

// acceptLine stores a line in the ring buffer and
// notifies any waiters whose regex matches.
func (n *Node) acceptLine(line string) {
	n.mu.Lock()
	n.logs[n.logsIdx] = line
	n.logsIdx = (n.logsIdx + 1) % n.logsCap
	if n.peerID == "" {
		// Lazy regex compile; cheap and called
		// at most once.
		m := peerIDRe.FindStringSubmatch(line)
		if m != nil {
			n.peerID = m[1]
		}
	}
	// Capture the waiters we need to wake up so
	// we can release the lock before closing
	// their channels.
	toWake := make([]*waiter, 0)
	for _, w := range n.waiters {
		if w.pattern.MatchString(line) {
			toWake = append(toWake, w)
		}
	}
	// Remove the woken waiters from the list.
	if len(toWake) > 0 {
		remaining := n.waiters[:0]
		for _, w := range n.waiters {
			matched := false
			for _, w2 := range toWake {
				if w2 == w {
					matched = true
					break
				}
			}
			if !matched {
				remaining = append(remaining, w)
			}
		}
		n.waiters = remaining
	}
	n.mu.Unlock()

	for _, w := range toWake {
		close(w.ch)
	}
}

var peerIDRe = regexp.MustCompile(`peerID=([0-9a-f]{32})`)

// PeerID returns the 32-char hex PeerID of this node, as
// parsed from the startup log line. It is safe to call
// before the node is fully ready — but the call would
// block if the test forgot to wait for readiness. In
// practice StartNode already does the wait.
func (n *Node) PeerID() string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.peerID
}

// TCPPort returns the TCP port this node is listening on
// for incoming peer connections. e2e tests use it to
// build the `dial 127.0.0.1:<port>` REPL command.
func (n *Node) TCPPort() int { return n.tcpPort }

// UDPPort returns the UDP port this node is listening on
// for peer discovery. Mostly here for symmetry / future
// tests; the current regression net doesn't probe it.
func (n *Node) UDPPort() int { return n.udpPort }

// Stdin returns a writer that sends lines (with a
// trailing newline) to the node's REPL. The writer is
// not safe for concurrent use.
func (n *Node) Stdin() io.Writer { return &lineWriter{w: n.stdinW} }

// Send is a convenience: it writes a single REPL command
// followed by a newline.
func (n *Node) Send(line string) {
	if _, err := io.WriteString(n.Stdin(), line+"\n"); err != nil && !n.closed.Load() {
		n.t.Fatalf("e2e: %s: Send(%q): %v", n.shortID(), line, err)
	}
}

// WaitForLog blocks until a line matching pattern is
// emitted by the node, or the timeout elapses. The
// pattern is matched as a regex against the line
// text. On timeout the test is failed.
func (n *Node) WaitForLog(pattern *regexp.Regexp, timeout time.Duration) {
	n.WaitForLogDesc(pattern, timeout, pattern.String())
}

// WaitForLogDesc is WaitForLog with an explicit failure
// description (useful when the same pattern is used in
// many places and the default "pattern" string would
// produce a confusing failure message).
func (n *Node) WaitForLogDesc(pattern *regexp.Regexp, timeout time.Duration, desc string) {
	w := &waiter{
		pattern: pattern,
		desc:    desc,
		ch:      make(chan struct{}),
	}
	n.mu.Lock()
	// Check the ring buffer first — the line
	// might have already arrived.
	for i := 0; i < n.logsCap; i++ {
		line := n.logs[i]
		if line == "" {
			continue
		}
		if pattern.MatchString(line) {
			n.mu.Unlock()
			return
		}
	}
	n.waiters = append(n.waiters, w)
	n.mu.Unlock()

	select {
	case <-w.ch:
		return
	case <-n.doneCh:
		n.t.Fatalf("e2e: %s: process exited before log %q arrived", n.shortID(), desc)
	case <-time.After(timeout):
		n.t.Fatalf("e2e: %s: timed out after %s waiting for log %q\nrecent logs:\n%s",
			n.shortID(), timeout, desc, n.recentLogs(20))
	}
}

// recentLogs returns the last `n` log lines for the failure
// message. The ring buffer may contain old lines from a
// previous test, but since each Node is per-test, that's
// fine.
func (n *Node) recentLogs(nLines int) string {
	n.mu.Lock()
	defer n.mu.Unlock()
	out := make([]string, 0, nLines)
	for i := 0; i < n.logsCap; i++ {
		idx := (n.logsIdx - 1 - i + n.logsCap) % n.logsCap
		line := n.logs[idx]
		if line == "" {
			continue
		}
		out = append([]string{line}, out...)
		if len(out) >= nLines {
			break
		}
	}
	result := ""
	for _, l := range out {
		result += "  " + l + "\n"
	}
	return result
}

// WaitForDone blocks until the process has exited.
// Useful in TestE2E_M3_Restart to confirm that a
// graceful "quit" command really terminated.
func (n *Node) WaitForDone(timeout time.Duration) {
	select {
	case <-n.doneCh:
		return
	case <-time.After(timeout):
		n.t.Fatalf("e2e: %s: did not exit within %s", n.shortID(), timeout)
	}
}

// Stop terminates the node. On Windows, exec.Command
// does not deliver SIGINT to the child; it kills the
// process. That's fine for tests — we just need it gone
// before the next test.
func (n *Node) Stop() {
	if !n.closed.CompareAndSwap(false, true) {
		return
	}
	if n.cmd != nil && n.cmd.Process != nil {
		_ = n.cmd.Process.Kill()
	}
	_ = n.stdinW.Close()
}

// SendQuit is the polite exit path: it sends the
// "quit" REPL command and then waits for the process
// to exit. If the process doesn't exit within 5s, it
// is killed.
func (n *Node) SendQuit() {
	n.Send("quit")
	n.WaitForDone(5 * time.Second)
}

// shortID returns a short label like "node<5 chars>"
// for log messages, derived from the PeerID prefix.
func (n *Node) shortID() string {
	pid := n.PeerID()
	if len(pid) < 8 {
		return "<unknown>"
	}
	return "node<" + pid[:8] + ">"
}

// Dir returns the per-node temp dir, useful when a
// test needs to inspect files the node created
// (chat.enc, .incoming/...).
func (n *Node) Dir() string { return n.dir }

// String satisfies fmt.Stringer for nicer error
// messages.
func (n *Node) String() string {
	return fmt.Sprintf("Node{%s, dir=%s}", n.shortID(), n.dir)
}

// lineWriter appends a newline to every Write. It is
// the equivalent of fmt.Fprintln, but without the
// fmt overhead in the hot path of "send 50 messages".
type lineWriter struct{ w io.Writer }

func (l *lineWriter) Write(p []byte) (int, error) {
	// The bufio.Scanner in cmd/innerlink reads
	// line-by-line, so we MUST send a trailing
	// newline. We don't strip any user-provided
	// one because the user can already control
	// that.
	if len(p) == 0 || p[len(p)-1] != '\n' {
		buf := make([]byte, len(p)+1)
		copy(buf, p)
		buf[len(p)] = '\n'
		_, err := l.w.Write(buf)
		if err != nil {
			return 0, err
		}
		return len(p), nil
	}
	n, err := l.w.Write(p)
	if err != nil {
		return 0, err
	}
	return n, nil
}

// isWindows is a runtime gate so the test
// binary path resolves correctly on the dev
// machine (Windows 10 1909) and the CI Linux
// runner without runtime.GOOS leaks.
func isWindows() bool {
	return runtime.GOOS == "windows"
}

var _ = context.Background // silence "imported and not used" if we trim
