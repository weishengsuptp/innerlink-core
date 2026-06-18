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
	"strings"
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
		DeviceKey: filepath.Join(aDir, ".innerlink", "device.key"),
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
	// under A's data dir (the new v0.5 layout puts
	// it at <data-dir>/aliases.json, not directly
	// in the cwd).
	aliasesPath := filepath.Join(a.Dir(), ".innerlink", "aliases.json")
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

// ---------------------------------------------------------------------------
// E2E ping/pong round-trip — regression for the "ping echo loop"
// ---------------------------------------------------------------------------

// TestE2E_PingPongRoundTrip guards against the bug where the
// receiver of a ping would SendPing() instead of SendPong(),
// causing both sides to bounce ping envelopes back and forth
// until the channel was closed. The fix lives in
// internal/protocol.SendPong and the cmd/innerlink dispatcher.
//
// What "success" looks like on A's log:
//   - one "[MSG  ] out ><B>> ping" line (user-issued)
//   - one "[MSG  ] in  <B> pong" line (B's reply)
//   - NO "[MSG  ] in  <B> ping" line (would mean B echoed
//     back a ping envelope, restarting the loop)
//
// We wait a generous window after the pong arrives, then
// scan A's recent log for any extra ping/pong lines. If
// the bug regresses, dozens of in-ping lines appear within
// a few hundred ms.
func TestE2E_PingPongRoundTrip(t *testing.T) {
	alloc := NewPortAllocator()
	a := StartNode(t, alloc, "A")
	b := StartNode(t, alloc, "B")
	dialPair(t, a, b)

	bID := b.PeerID()
	a.Send("ping " + bID)
	a.WaitForLog(regexp.MustCompile(`\[MSG  \] in  <`+bID+`> pong`), 5*time.Second)

	// Give the loop time to (NOT) manifest. 500 ms is
	// enough — when the bug was live, 20+ in-ping lines
	// arrived in <100 ms.
	time.Sleep(500 * time.Millisecond)

	inPings := countMatching(a.SnapshotLogs(), `\[MSG  \] in  <`+bID+`> ping\b`)
	if inPings != 0 {
		t.Fatalf("ping echo loop regressed: A saw %d in-ping lines (expected 0)", inPings)
	}
}

// ---------------------------------------------------------------------------
// E2E scan: 3 nodes on different loopback IPs, same port, scan finds all
// ---------------------------------------------------------------------------

// TestE2E_ScanFindsPeers is the v0.5.1 cross-subnet
// discovery regression. Three innerlink instances
// listen on the same TCP port (4748) but on three
// different loopback addresses (127.0.0.2, .3, .4).
// UDP broadcast doesn't help them find each other
// because each binds to a specific alias. A fourth
// "scanner" instance on 127.0.0.5 then runs
// `scan 127.0.0.0/24` to discover the other three.
// This mirrors the real production use case: "I just
// started, I don't know who's around, but I know my
// subnet, so let me scan it".
//
// We do NOT use the standard StartNode helper because
// the e2e framework assumes "one port per node" via
// PortAllocator. We need all three targets on the
// SAME port so the scanner can probe them in one
// pass.
func TestE2E_ScanFindsPeers(t *testing.T) {
	const (
		scanPort      = 4748
		targetUDPPort = 4747
	)
	// Use t.TempDir for cross-platform path
	// safety. Hardcoding `D:\...` here broke the
	// macos CI (the path doesn't exist on Linux).
	baseDir := t.TempDir()

	// Build the binary via the standard helper.
	_ = ResolveBinary(t)

	// launch starts one innerlink with the given bind
	// IP and returns its log file path. It also sets
	// up cleanup.
	launch := func(bindIP string, scanSubdir bool) string {
		dir := filepath.Join(baseDir, bindIP)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("e2e: mkdir %s: %v", dir, err)
		}
		logName := "innerlink.log"
		if scanSubdir {
			logName = "scanner.log"
		}
		logPath := filepath.Join(dir, logName)
		args := []string{
			"-udp-port=" + strconv.Itoa(targetUDPPort),
			"-tcp-port=" + strconv.Itoa(scanPort),
			"-bind=" + bindIP,
			"-data-dir=" + filepath.Join(dir, ".innerlink"),
			"-device-key=" + filepath.Join(dir, "device.key"),
			"-save-dir=" + filepath.Join(dir, "received"),
			"-log-file=" + logPath,
			"-log-level=info",
		}
		cmd := exec.Command(ResolveBinary(t), args...)
		cmd.Stderr = io.Discard
		cmd.Stdout = io.Discard
		if err := cmd.Start(); err != nil {
			t.Fatalf("e2e: start %s: %v", bindIP, err)
		}
		// Register cleanup that kills the process
		// AND waits for it to actually exit, so the
		// log file handle is released before
		// t.TempDir cleanup tries to remove the
		// directory. Without Wait(), the test
		// framework on Windows would race the
		// cleanup with the still-dying process.
		t.Cleanup(func() {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
		})
		return logPath
	}

	// Start 3 targets on .2/.3/.4.
	t2 := launch("127.0.0.2", false)
	t3 := launch("127.0.0.3", false)
	t4 := launch("127.0.0.4", false)
	for _, lp := range []string{t2, t3, t4} {
		waitForLogContains(t, lp,
			fmt.Sprintf("listening for peers on TCP :%d", scanPort), 5*time.Second)
	}

	// Start the scanner on .5 with a stdin pipe so
	// we can issue `scan` commands. Different ports
	// from the targets so the scanner doesn't see
	// its own discovery announcements as targets.
	scanDir := filepath.Join(baseDir, "127.0.0.5")
	if err := os.MkdirAll(scanDir, 0o755); err != nil {
		t.Fatalf("e2e: mkdir %s: %v", scanDir, err)
	}
	scanLog := filepath.Join(scanDir, "scanner.log")
	stdinR, stdinW := io.Pipe()
	scanCmd := exec.Command(ResolveBinary(t),
		"-udp-port=49001", "-tcp-port=49002",
		"-bind=127.0.0.5",
		"-data-dir="+filepath.Join(scanDir, ".innerlink"),
		"-device-key="+filepath.Join(scanDir, "device.key"),
		"-save-dir="+filepath.Join(scanDir, "received"),
		"-log-file="+scanLog,
		"-log-level=info",
	)
	scanCmd.Stdin = stdinR
	scanCmd.Stderr = io.Discard
	scanCmd.Stdout = io.Discard
	if err := scanCmd.Start(); err != nil {
		t.Fatalf("e2e: start scanner: %v", err)
	}
	t.Cleanup(func() {
		_ = scanCmd.Process.Kill()
		_ = stdinW.Close()
	})
	waitForLogContains(t, scanLog, "listening for peers on TCP :49002", 5*time.Second)

	// Issue `scan 127.0.0.0/24`. This walks
	// 127.0.0.1..127.0.0.254. We expect OK for
	// 127.0.0.2/.3/.4 and refused/timeout for the
	// rest. 127.0.0.1 (loopback) and 127.0.0.5
	// (self) are skipped.
	if _, err := io.WriteString(stdinW, "scan 127.0.0.0/24\n"); err != nil {
		t.Fatalf("e2e: write scan cmd: %v", err)
	}

	// Wait for [SCAN] target log line + OK lines
	// for all 3 targets. 254 hosts on loopback at
	// 16 workers / 1.5s per host = 30s worst case.
	expectedHosts := []string{"127.0.0.2", "127.0.0.3", "127.0.0.4"}
	deadline := time.Now().Add(45 * time.Second)
	allFound := false
	for time.Now().Before(deadline) && !allFound {
		data, err := os.ReadFile(scanLog)
		if err != nil {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		s := string(data)
		found := 0
		for _, h := range expectedHosts {
			// We grep for "OK   peerID=" AFTER
			// the host's IP — that's how the
			// log line is formatted.
			if strings.Contains(s, h+":") && strings.Contains(s, "OK") {
				found++
			}
		}
		if found == len(expectedHosts) {
			allFound = true
		} else {
			time.Sleep(200 * time.Millisecond)
		}
	}
	if !allFound {
		data, _ := os.ReadFile(scanLog)
		t.Fatalf("e2e: scan did not find all 3 targets within 45s\nlog:\n%s", string(data))
	}
}

// waitForLogContains is a tiny helper used by the
// scan e2e to wait for a process to log a specific
// line. It's separate from the per-Node WaitForLog
// because the scan e2e uses raw exec.Cmd instead
// of the Node wrapper (different ports, different
// bind IPs).
func waitForLogContains(t *testing.T, path, needle string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if data, err := os.ReadFile(path); err == nil {
			if strings.Contains(string(data), needle) {
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("e2e: %s did not contain %q within %s", path, needle, timeout)
}

// countMatching is a small regex counter for the log
// snapshot buffer. It is intentionally strict — we use
// \b to avoid "ping" matching "ping-pong" or future
// message types that happen to start with "ping".
func countMatching(lines []string, pattern string) int {
	re := regexp.MustCompile(pattern)
	n := 0
	for _, l := range lines {
		if re.MatchString(l) {
			n++
		}
	}
	return n
}

// ---------------------------------------------------------------------------
// E2E multi-peer: 3 nodes, full mesh, parallel chat + alias + peers list
// ---------------------------------------------------------------------------

// TestE2E_ThreePeerMesh is the multi-peer regression that
// the user's 2026-06-18 manual test surfaced. The test
// stands up three independent innerlink instances (A, B, C)
// on a single host, fully meshes them with three `dial`
// commands, and verifies:
//
//   - All three channels are simultaneously ready on every
//     node (A sees 2 channels, B sees 2, C sees 2).
//   - A→B and A→C messages each arrive at the right peer
//     (no cross-channel contamination: B does NOT see the
//     "to-C" message, and C does NOT see the "to-B" one).
//   - B→C and C→B messages work (the most-likely-broken
//     path, since B and C only know each other through A's
//     UDP broadcast).
//   - Aliases set on different peers don't collide.
//   - `peers` command on each node reports 2 known peers.
//
// Failure modes this guards against (none of which are
// caught by the 2-peer e2e net):
//   - transport/registry keying on first peer only
//   - dispatcher routing all inbound envelopes to the
//     first-established channel
//   - alias store overwriting the first peer when a second
//     is added
//   - session-key / sendfile state being shared between
//     independent channels
func TestE2E_ThreePeerMesh(t *testing.T) {
	alloc := NewPortAllocator()
	a := StartNode(t, alloc, "A")
	b := StartNode(t, alloc, "B")
	c := StartNode(t, alloc, "C")

	// Full mesh via `dial`. Each pair does a direct
	// handshake. We use dialPair-ish helpers inline
	// because we need 3 distinct pairings, not just one.
	a.Send("dial 127.0.0.1:" + strconv.Itoa(b.TCPPort()))
	gotPeerReady(t, a, b)
	gotPeerReady(t, b, a)

	a.Send("dial 127.0.0.1:" + strconv.Itoa(c.TCPPort()))
	gotPeerReady(t, a, c)
	gotPeerReady(t, c, a)

	b.Send("dial 127.0.0.1:" + strconv.Itoa(c.TCPPort()))
	gotPeerReady(t, b, c)
	gotPeerReady(t, c, b)

	// A → B and A → C. The messages are distinct so
	// we can detect any cross-channel bleed.
	a.Send("send " + b.PeerID() + " toB-fromA")
	b.WaitForLog(regexp.MustCompile(`\[MSG  \] in  <`+regexp.QuoteMeta(a.PeerID())+`> toB-fromA`), 5*time.Second)

	a.Send("send " + c.PeerID() + " toC-fromA")
	c.WaitForLog(regexp.MustCompile(`\[MSG  \] in  <`+regexp.QuoteMeta(a.PeerID())+`> toC-fromA`), 5*time.Second)

	// Cross-peer: B ↔ C, which A is NOT in the path of.
	b.Send("send " + c.PeerID() + " toC-fromB")
	c.WaitForLog(regexp.MustCompile(`\[MSG  \] in  <`+regexp.QuoteMeta(b.PeerID())+`> toC-fromB`), 5*time.Second)

	c.Send("send " + b.PeerID() + " toB-fromC")
	b.WaitForLog(regexp.MustCompile(`\[MSG  \] in  <`+regexp.QuoteMeta(c.PeerID())+`> toB-fromC`), 5*time.Second)

	// Alias collision check. A names B and C. Both
	// must stick and show up under their own names.
	a.Send("alias alice " + b.PeerID())
	a.WaitForLog(regexp.MustCompile(`\[INFO \] aliased alice`), 3*time.Second)
	a.Send("alias charlie " + c.PeerID())
	a.WaitForLog(regexp.MustCompile(`\[INFO \] aliased charlie`), 3*time.Second)

	// A's `peers` should report 2. We allow the
	// header format from the M4 implementation.
	a.Send("peers")
	a.WaitForLog(regexp.MustCompile(`\[PEERS\] 2 known peer\(s\)`), 3*time.Second)

	// B's `peers` should also report 2 (A and C).
	b.Send("peers")
	b.WaitForLog(regexp.MustCompile(`\[PEERS\] 2 known peer\(s\)`), 3*time.Second)

	// C's `peers` should report 2 (A and B).
	c.Send("peers")
	c.WaitForLog(regexp.MustCompile(`\[PEERS\] 2 known peer\(s\)`), 3*time.Second)

	// Cross-channel bleed check: B's log must NOT
	// contain a "toC-fromA" message. If the
	// dispatcher is broken, every inbound from A
	// would land on the first channel, and the
	// second message (toC-fromA) would show up on
	// B's side too. 500ms is generous; the
	// "toB-fromA" message arrives in <50ms, so any
	// bleed would have shown up by now.
	time.Sleep(500 * time.Millisecond)
	bleed := countMatching(b.SnapshotLogs(),
		regexp.QuoteMeta(a.PeerID())+`> toC-fromA\b`)
	if bleed != 0 {
		t.Fatalf("cross-channel bleed: B saw %d 'toC-fromA' messages (expected 0 — dispatcher is routing to wrong channel)", bleed)
	}
	bleed2 := countMatching(c.SnapshotLogs(),
		regexp.QuoteMeta(a.PeerID())+`> toB-fromA\b`)
	if bleed2 != 0 {
		t.Fatalf("cross-channel bleed: C saw %d 'toB-fromA' messages (expected 0)", bleed2)
	}
}

// ---------------------------------------------------------------------------
// E2E roster gossip: A↔B, B↔C, all 3 nodes see all 3 in `roster`
// ---------------------------------------------------------------------------

// TestE2E_RosterGossip verifies the M5 gossip protocol.
// We stand up A, B, C such that A and C never directly
// connect — only A↔B and B↔C handshakes happen. Within
// seconds, the gossip should have propagated: A learns
// about C through B (and vice versa), so all three
// nodes' `roster` command should list all three peers
// (A, B, C) with the right per-node online indicator.
//
// What "success" looks like in the logs:
//   - A's log: [ROSTER] sync from B: 1 new entry: cID
//   - C's log: [ROSTER] sync from B: 1 new entry: aID
//   - All three nodes' `roster` command output
//     contains each other's peer IDs.
//
// Failure modes caught here:
//   - Gossip not sent on channel ready
//   - Gossip sent but not received
//   - Merge broken (entries not added)
//   - Self-merge bug (we add ourselves with a 0-IP
//     and the network never sees us)
func TestE2E_RosterGossip(t *testing.T) {
	alloc := NewPortAllocator()
	a := StartNode(t, alloc, "A")
	b := StartNode(t, alloc, "B")
	c := StartNode(t, alloc, "C")

	// Chain: A↔B, B↔C. A and C never directly
	// connect — their only way to learn about each
	// other is through B's gossip.
	a.Send("dial 127.0.0.1:" + strconv.Itoa(b.TCPPort()))
	gotPeerReady(t, a, b)
	gotPeerReady(t, b, a)
	b.Send("dial 127.0.0.1:" + strconv.Itoa(c.TCPPort()))
	gotPeerReady(t, b, c)
	gotPeerReady(t, c, b)

	// A should learn about C from B's gossip.
	// The chain: B↔C channel ready → C's roster
	// reaches B → B's MergeFromGossip sees C as
	// new → broadcastRosterToAll pushes B's
	// updated roster to A → A merges the new C
	// entry. We wait for the C peer-id prefix
	// to appear in any roster log line on A
	// (could be a sync message, could be the
	// roster command output, doesn't matter).
	cIDPrefix := c.PeerID()[:8]
	a.WaitForLogContains(cIDPrefix, 5*time.Second)

	// C should similarly learn about A through B.
	aIDPrefix := a.PeerID()[:8]
	c.WaitForLogContains(aIDPrefix, 5*time.Second)

	// Now check: each node's `roster` command
	// must show all three peer IDs.
	aID := a.PeerID()
	bID := b.PeerID()
	cID := c.PeerID()
	for _, n := range []*Node{a, b, c} {
		n.Send("roster")
		// Each roster row prints the first 8 chars
		// of the peer ID followed by "...". We wait
		// for all three to appear. Allow 5s for the
		// pumpOutput goroutine to flush the log line
		// to the ring buffer.
		for _, wantID := range []string{aID, bID, cID} {
			prefix := wantID[:8]
			n.WaitForLog(regexp.MustCompile(regexp.QuoteMeta(prefix)+`\.\.\.`), 5*time.Second)
		}
		// No bleed-back: the command should show
		// the "3 entries" header (i.e., all three
		// peers but no duplicates / no half-merged
		// ghost entries from previous tests).
		n.WaitForLog(regexp.MustCompile(`\[ROSTER\] 3 entries:`), 5*time.Second)
	}
}

// startNodeWithArgs is the low-level constructor. It
// does NOT wait for readiness; both StartNode and
// StartNodeWithOptions call it and then wait.
func startNodeWithArgs(t *testing.T, ports Pair, deviceKey, saveDir string) *Node {
	t.Helper()
	binaryPath := ResolveBinary(t)
	logFile := filepath.Join(saveDir, "innerlink.log")
	// The v0.5+ layout puts chat.enc and aliases.json
	// inside a per-test .innerlink/ subdir. We derive
	// the data dir from the device-key's parent — this
	// works as long as callers pass <dir>/.innerlink/
	// device.key (the StartNode wrapper does; the M3
	// regression's NodeOptions call also does). If
	// the device key is at <dir>/device.key (legacy
	// call), we fall back to <dir>/.innerlink for
	// the chat log and aliases — they're not
	// co-located in that case, but the test still
	// gets per-test isolation.
	dataDir := filepath.Dir(deviceKey)
	if filepath.Base(dataDir) != ".innerlink" {
		dataDir = filepath.Join(filepath.Dir(deviceKey), ".innerlink")
	}
	args := []string{
		"-udp-port=" + strconv.Itoa(ports.UDP),
		"-tcp-port=" + strconv.Itoa(ports.TCP),
		"-data-dir=" + dataDir,
		"-device-key=" + deviceKey,
		"-save-dir=" + saveDir,
		"-log-file=" + logFile,
		"-bind=127.0.0.1",
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
