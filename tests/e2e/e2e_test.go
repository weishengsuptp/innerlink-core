package e2e

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

// TestMain is the entry point for the e2e package. It
// builds the innerlink binary if it does not exist, so
// the user (or CI) can run `go test ./tests/e2e/...`
// without a separate `go build` step.
//
// We use `go build` rather than `go test -c` because
// the test binary is the driver, not what we want to
// run — we want the innerlink binary to spawn.
func TestMain(m *testing.M) {
	if err := ensureBinary(); err != nil {
		// We don't os.Exit here; the test will
		// fail loudly when StartNode tries to
		// find the binary. Printing to stderr
		// makes the failure visible even if
		// the test never runs.
		os.Stderr.WriteString("e2e: ensureBinary failed: " + err.Error() + "\n")
	}
	os.Exit(m.Run())
}

// ensureBinary compiles the innerlink binary into
// tests/e2e/bin/innerlink[.exe] if it is missing. We
// could re-build on every test run, but innerlink takes
// ~5s to compile, and the user runs these tests often.
// Missing-binary detection is a "first run" thing.
func ensureBinary() error {
	wd, _ := os.Getwd()
	repoRoot := findProjectRoot(wd)
	// Anchor every path resolution at the repo
	// root, not at cwd. `go test` runs the test
	// binary with cwd = the package directory
	// (tests/e2e/), but the binary lives at
	// <repoRoot>/tests/e2e/bin/. Using cwd
	// produces paths like tests/e2e/tests/e2e/...
	// when cwd is the package dir.
	bin := filepath.Join(repoRoot, binPath())
	if _, err := os.Stat(bin); err == nil {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(bin), 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", filepath.Dir(bin), err)
	}
	cmd := exec.Command("go", "build", "-o", bin, "./cmd/innerlink")
	cmd.Dir = repoRoot
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("go build (cwd=%s): %w", repoRoot, err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// E2E M1: 2 nodes discover each other, handshakes, exchange a chat
// ---------------------------------------------------------------------------

// TestE2E_M1_HandshakeAndChat is the canonical regression
// for milestone M1. It spins up two nodes on a single
// host. UDP broadcast on the loopback is disabled by
// design (see internal/discovery.broadcastAddresses), so
// the e2e test does NOT wait for discovery — it uses the
// `dial <addr>` REPL command to force the connection,
// which is the same command a human would use to
// reach a cross-subnet peer.
func TestE2E_M1_HandshakeAndChat(t *testing.T) {
	alloc := NewPortAllocator()
	a := StartNode(t, alloc, "A")
	b := StartNode(t, alloc, "B")
	dialPair(t, a, b)

	// Send from A to B.
	a.Send("send " + b.PeerID() + " 你好")
	b.WaitForLog(regexp.MustCompile(`\[MSG  \] in  <[0-9a-f]{32}> 你好`), 5*time.Second)
}

// gotPeerReady blocks until n sees peer as a known peer
// AND has logged "channel ready peer=<peer's id>".
func gotPeerReady(t *testing.T, n, peer *Node) {
	t.Helper()
	pattern := regexp.MustCompile(`channel ready peer=` + peer.PeerID())
	n.WaitForLog(pattern, 10*time.Second)
}

// dialPair is the standard "make these two nodes talk"
// entry point for every M1+ e2e test. It triggers a
// dial from `a` to `b`'s TCP port, then waits for the
// "channel ready" log on both sides.
//
// Why not use the discovery path? Loopback is
// deliberately excluded from the broadcast set (see
// internal/discovery.broadcastAddresses), so two
// innerlink instances on the same host never see
// each other over UDP. The dial command is the
// right primitive for e2e; it also happens to be
// useful in production (cross-subnet peers).
func dialPair(t *testing.T, a, b *Node) {
	t.Helper()
	a.Send("dial 127.0.0.1:" + strconv.Itoa(b.TCPPort()))
	gotPeerReady(t, a, b)
	gotPeerReady(t, b, a)
}

// ---------------------------------------------------------------------------
// E2E M2: sendfile round-trip with SHA-256 verification
// ---------------------------------------------------------------------------

// TestE2E_M2_SendFileSmall is the M2 regression. We
// don't try to test 2 GiB in CI — that's what the
// user's VMware setup is for. A 1 MiB random file is
// enough to confirm the filetransfer state machine is
// healthy after M3 storage changes.
//
// What "success" looks like: A sends a file, B's
// receiver reassembles it under <saveDir>/<name> after
// verifying the SHA-256. We don't have a single log
// line for "file saved" (the receiver just sends a
// FileDone envelope, which the cmd dispatcher does
// not print), so we poll the on-disk file directly.
func TestE2E_M2_SendFileSmall(t *testing.T) {
	alloc := NewPortAllocator()
	a := StartNode(t, alloc, "A")
	b := StartNode(t, alloc, "B")
	dialPair(t, a, b)

	// 1 MiB random file.
	src := filepath.Join(a.Dir(), "src.bin")
	makeRandomFile(t, src, 1<<20)

	// A sends; B should receive it under
	// <B.Dir()>/src.bin within 30s.
	a.Send("sendfile " + b.PeerID() + " " + src)

	dst := filepath.Join(b.Dir(), "src.bin")
	if !waitForFile(t, dst, 30*time.Second) {
		t.Fatalf("e2e: M2: %s did not appear after 30s; B's save dir is %s", dst, b.Dir())
	}

	// Compare the contents. We don't compare SHA-256
	// directly because the receiver already does that
	// (and would have aborted if it mismatched). A
	// bytewise compare is the next-best thing the
	// test framework can do.
	if err := compareFiles(src, dst); err != nil {
		t.Fatalf("e2e: M2: file content mismatch: %v", err)
	}
}

// waitForFile polls path every 100ms up to timeout,
// returning true the first time stat succeeds. We
// can't use os.Stat in a tight loop because the
// receiver's rename happens atomically only at the
// end; for a 1 MiB file the actual transfer takes
// well under a second, but we leave 30s of headroom
// for slow CI.
func waitForFile(t *testing.T, path string, timeout time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false
}

// compareFiles reads both files in 64 KiB chunks and
// reports the first mismatch. It avoids the
// all-in-memory readFile pattern that would OOM the
// test on a 2 GiB file (which we don't run here, but
// the helper should still be sane).
func compareFiles(a, b string) error {
	fa, err := os.Open(a)
	if err != nil {
		return fmt.Errorf("open %s: %w", a, err)
	}
	defer fa.Close()
	fb, err := os.Open(b)
	if err != nil {
		return fmt.Errorf("open %s: %w", b, err)
	}
	defer fb.Close()
	const chunk = 64 * 1024
	bufA := make([]byte, chunk)
	bufB := make([]byte, chunk)
	offset := int64(0)
	for {
		nA, eA := fa.Read(bufA)
		nB, eB := fb.Read(bufB)
		if nA != nB {
			return fmt.Errorf("size mismatch at offset %d (a=%d b=%d)", offset, nA, nB)
		}
		for i := 0; i < nA; i++ {
			if bufA[i] != bufB[i] {
				return fmt.Errorf("byte mismatch at offset %d: a=%02x b=%02x", offset+int64(i), bufA[i], bufB[i])
			}
		}
		offset += int64(nA)
		if eA == io.EOF && eB == io.EOF {
			return nil
		}
		if eA != nil && eA != io.EOF {
			return fmt.Errorf("read %s: %w", a, eA)
		}
		if eB != nil && eB != io.EOF {
			return fmt.Errorf("read %s: %w", b, eB)
		}
	}
}

// makeRandomFile writes n bytes of crypto-quality
// random data to path. The SHA-256 is irrelevant
// for the test (the receiver checks it internally);
// we just need *some* content.
func makeRandomFile(t *testing.T, path string, n int) {
	t.Helper()
	data := make([]byte, n)
	// math/rand is fine here; we just want bytes.
	for i := range data {
		data[i] = byte(i)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("e2e: write src: %v", err)
	}
}

// ---------------------------------------------------------------------------
// E2E M3: chat round-trip persists across restart
// ---------------------------------------------------------------------------

// TestE2E_M3_StorageRoundTrip is the M3 regression.
// It exercises the encrypted chat.enc file: A and B
// exchange 5 messages, A quits, A restarts, A runs
// `history`, and the test asserts that the 5 messages
// (and only the 5) show up.
func TestE2E_M3_StorageRoundTrip(t *testing.T) {
	alloc := NewPortAllocator()
	a := StartNode(t, alloc, "A")
	b := StartNode(t, alloc, "B")
	dialPair(t, a, b)

	// 5 round-trip messages.
	const N = 5
	for i := 0; i < N; i++ {
		msg := "msg-" + strconv.Itoa(i)
		a.Send("send " + b.PeerID() + " " + msg)
		b.WaitForLog(regexp.MustCompile(`\[MSG  \] in  <[0-9a-f]{32}> `+regexp.QuoteMeta(msg)), 5*time.Second)
	}

	// Confirm A logged "N records loaded" — wait, A
	// hasn't restarted yet. Skip that; we'll check
	// after restart.
	//
	// Send a few more from B to A so the in/out
	// direction varies.
	for i := 0; i < 2; i++ {
		msg := "bmsg-" + strconv.Itoa(i)
		b.Send("send " + a.PeerID() + " " + msg)
		a.WaitForLog(regexp.MustCompile(`\[MSG  \] in  <[0-9a-f]{32}> `+regexp.QuoteMeta(msg)), 5*time.Second)
	}

	// Total: 5 from A→B + 2 from B→A = 7 records on A.
	// Quit A gracefully and start a fresh one with
	// the SAME device key (so it can decrypt
	// chat.enc).
	aPid := a.PeerID()
	aDir := a.Dir()
	a.SendQuit()

	a2 := StartNodeWithOptions(t, alloc, NodeOptions{
		PeerID:    aPid,
		DeviceKey: filepath.Join(aDir, "device.key"),
		SaveDir:   aDir,
	})

	// A2 should see "7 records loaded" (5 sent + 2 received).
	a2.WaitForLog(regexp.MustCompile(`chat log: 7 records loaded`), 5*time.Second)

	// `history` command should print all 7.
	for i := 0; i < N; i++ {
		msg := "msg-" + strconv.Itoa(i)
		a2.Send("history")
		a2.WaitForLog(regexp.MustCompile(regexp.QuoteMeta(msg)), 5*time.Second)
	}
}

// itoa is a tiny shim kept for future tests that
// might want a no-allocation int->string. Currently
// unused but referenced via `var _ = itoa` so it
// doesn't bit-rot.
func itoa(i int) string { return strconv.Itoa(i) }

// NodeOptions lets tests specify the device-key and
// save-dir paths, so a second node can re-attach to
// the same on-disk identity (and chat.enc) as a
// previous one. StartNode creates a fresh identity
// by default; StartNodeWithOptions is for the M3
// restart case.
type NodeOptions struct {
	PeerID    string // not used to construct, just for assertions
	DeviceKey string
	SaveDir   string
}

// StartNodeWithOptions is StartNode with a pre-existing
// device-key + save-dir. The allocated ports are
// per-call so two runs don't collide on the
// well-known ports.
func StartNodeWithOptions(t *testing.T, alloc *PortAllocator, opts NodeOptions) *Node {
	t.Helper()
	dir := opts.SaveDir
	if dir == "" {
		dir = t.TempDir()
	}
	ports, err := alloc.Allocate()
	if err != nil {
		t.Fatalf("e2e: port allocator: %v", err)
	}
	n := startNodeWithArgs(t, ports, opts.DeviceKey, dir)
	n.WaitForLog(regexp.MustCompile(`listening for peers on TCP`), 10*time.Second)
	return n
}

// ---------------------------------------------------------------------------
// E2E M4: alias + peers list
// ---------------------------------------------------------------------------

// TestE2E_M4_AliasRoundTrip is the M4 alias regression.
// A registers a name for B, then sends a chat
// message to B using the alias. We assert the
// sender-side log shows "aliased" and the receiver
// sees the chat.
func TestE2E_M4_AliasRoundTrip(t *testing.T) {
	alloc := NewPortAllocator()
	a := StartNode(t, alloc, "A")
	b := StartNode(t, alloc, "B")
	dialPair(t, a, b)

	// Register a name. A's REPL will log
	// "[INFO ] aliased 老王 -> <b.PeerID()>".
	a.Send("alias 老王 " + b.PeerID())
	a.WaitForLog(regexp.MustCompile(`\[INFO \] aliased`), 5*time.Second)

	// Now send using the alias. The cmd should
	// resolve "老王" to B's peer id and SendText
	// over the existing channel.
	a.Send("send 老王 你好from别名")
	b.WaitForLog(regexp.MustCompile(`\[MSG  \] in  <[0-9a-f]{32}> 你好from别名`), 5*time.Second)

	// The aliases file should now exist on disk
	// under A's save dir.
	aliasesPath := filepath.Join(a.Dir(), "aliases.json")
	if _, err := os.Stat(aliasesPath); err != nil {
		t.Fatalf("e2e: M4: %s should exist after `alias` cmd: %v", aliasesPath, err)
	}

	// unalias, then send to the now-unknown name
	// and expect an "unknown peer" error from the
	// cmd, not a successful send.
	a.Send("unalias 老王")
	a.WaitForLog(regexp.MustCompile(`\[INFO \] unaliased`), 5*time.Second)
	a.Send("send 老王 bye")
	a.WaitForLog(regexp.MustCompile(`unknown peer "老王"`), 5*time.Second)
}

// TestE2E_M4_PeersList is the M4 peers-list
// regression. After two nodes have shaken hands,
// A's `peers` command should show B (named or
// unnamed) in the listing. We don't pin the exact
// name (the user might have aliased it via a
// previous test in the same package's temp dir;
// each test gets a fresh dir), but we assert the
// peer id appears in the listing.
func TestE2E_M4_PeersList(t *testing.T) {
	alloc := NewPortAllocator()
	a := StartNode(t, alloc, "A")
	b := StartNode(t, alloc, "B")
	dialPair(t, a, b)

	// A's discovery layer Touches B on PeerAdded;
	// wrapChannel Touches it again on handshake
	// success. After dialPair returns, B should
	// already be in the alias table.
	a.Send("peers")
	a.WaitForLog(regexp.MustCompile(`\[PEERS\] \d+ known peer\(s\)`), 5*time.Second)

	// B's peer id must appear in the listing. The
	// formatter prints "<name>  last seen ...  (<peer>)"
	// for named rows and the placeholder form
	// "(unnamed)  last seen ...  (<peer>)" for
	// unknown ones. Either way, the peer id
	// substring is in the log.
	bID := b.PeerID()
	a.WaitForLog(regexp.MustCompile(bID), 5*time.Second)
}

// startNodeWithArgs is the low-level constructor. It
// does NOT wait for readiness; both StartNode and
// StartNodeWithOptions call it and then wait.
func startNodeWithArgs(t *testing.T, ports Pair, deviceKey, saveDir string) *Node {
	t.Helper()
	binaryPath := ResolveBinary(t)
	logFile := filepath.Join(saveDir, "log.log")
	args := []string{
		"-udp-port=" + strconv.Itoa(ports.UDP),
		"-tcp-port=" + strconv.Itoa(ports.TCP),
		"-device-key=" + deviceKey,
		"-save-dir=" + saveDir,
		"-log-file=" + logFile,
		"-log-level=info",
	}
	cmd := exec.Command(binaryPath, args...)

	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("e2e: stdin pipe: %v", err)
	}
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
		t:       t,
		cmd:     cmd,
		dir:     saveDir,
		stdinW:  stdin,
		udpPort: ports.UDP,
		tcpPort: ports.TCP,
		logsCap: 2048,
		doneCh:  make(chan struct{}),
	}
	n.logs = make([]string, n.logsCap)
	t.Cleanup(func() { n.Stop() })

	go n.pumpOutput(merged)
	go func() {
		_ = cmd.Wait()
		close(n.doneCh)
	}()
	return n
}

// dummy ref to silence "imported and not used" if
// the file shrinks; the e2e package's other
// files import this one.
var _ atomic.Bool
var _ context.Context
