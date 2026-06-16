package filetransfer_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/weishengsuptp/innerlink-core/internal/handshake"
	"github.com/weishengsuptp/innerlink-core/internal/identity"
	"github.com/weishengsuptp/innerlink-core/internal/protocol"
	"github.com/weishengsuptp/innerlink-core/internal/transport"
	ft "github.com/weishengsuptp/innerlink-core/internal/filetransfer"
)

// channelPair stands up two real protocol.Channels on a loopback
// TCP. Mirrors the helper in protocol_test but exposes the
// channels and sessions.
func channelPair(t *testing.T) (*protocol.Channel, *protocol.Channel) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	type result struct {
		c   net.Conn
		err error
	}
	c1Ch := make(chan result, 1)
	go func() {
		c, err := ln.Accept()
		c1Ch <- result{c, err}
	}()
	c2, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	r := <-c1Ch
	if r.err != nil {
		t.Fatal(r.err)
	}
	cA := transport.NewConnForTest(c2)
	cB := transport.NewConnForTest(r.c)

	idA, _ := identity.Generate()
	idB, _ := identity.Generate()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	type hr struct {
		s *handshake.Session
		e error
	}
	aCh := make(chan hr, 1)
	bCh := make(chan hr, 1)
	go func() { s, e := handshake.RunAsInitiator(ctx, idA, cA); aCh <- hr{s, e} }()
	go func() { s, e := handshake.RunAsResponder(ctx, idB, cB); bCh <- hr{s, e} }()
	rA, rB := <-aCh, <-bCh
	if rA.e != nil {
		t.Fatalf("init: %v", rA.e)
	}
	if rB.e != nil {
		t.Fatalf("resp: %v", rB.e)
	}
	chA, err := protocol.NewChannel(cA, rA.s)
	if err != nil {
		t.Fatal(err)
	}
	chB, err := protocol.NewChannel(cB, rB.s)
	if err != nil {
		t.Fatal(err)
	}
	return chA, chB
}

// makeFile builds a temp file of size bytes filled with random
// data and returns the path and its expected SHA-256 hex.
func makeFile(t *testing.T, size int) (string, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "src.bin")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.New()
	// 1 MiB at a time to keep memory bounded.
	buf := make([]byte, 1<<20)
	var written int
	for written < size {
		n := len(buf)
		if size-written < n {
			n = size - written
		}
		if _, err := io.ReadFull(rand.Reader, buf[:n]); err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write(buf[:n]); err != nil {
			t.Fatal(err)
		}
		h.Write(buf[:n])
		written += n
	}
	f.Close()
	return path, hex.EncodeToString(h.Sum(nil))
}

func TestSendSmallFile(t *testing.T) {
	chA, chB := channelPair(t)
	defer chA.Close()
	defer chB.Close()

	// 64 KiB — well under one chunk.
	srcPath, srcHash := makeFile(t, 64*1024)

	// Receiver runs in background.
	recvDir := t.TempDir()
	rcv, err := ft.NewReceiver(chB, recvDir, nil, "peerA")
	if err != nil {
		t.Fatal(err)
	}
	rctx, rcancel := context.WithCancel(context.Background())
	defer rcancel()
	recvDone := make(chan struct{})
	go func() {
		_ = rcv.Loop(rctx)
		close(recvDone)
	}()

	// Send.
	var progressCalls int
	var lastSent int64
	if err := ft.Send(context.Background(), chA, srcPath, func(sent, total int64) {
		progressCalls++
		lastSent = sent
	}, nil); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if lastSent != 64*1024 {
		t.Fatalf("last progress sent=%d, want 65536", lastSent)
	}
	if progressCalls == 0 {
		t.Fatal("progress callback never fired")
	}

	// Find the received file.
	entries, err := os.ReadDir(recvDir)
	if err != nil {
		t.Fatal(err)
	}
	var got string
	for _, e := range entries {
		if e.Name() == "src.bin" {
			got = filepath.Join(recvDir, e.Name())
		}
	}
	if got == "" {
		t.Fatalf("received file not found; have: %+v", entries)
	}

	// Verify SHA-256.
	f, err := os.Open(got)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != srcHash {
		t.Fatalf("sha256 mismatch:\n  got:  %s\n  want: %s", got, srcHash)
	}
}

func TestSendMultiChunk(t *testing.T) {
	chA, chB := channelPair(t)
	defer chA.Close()
	defer chB.Close()

	// 3 MiB = exactly 3 chunks.
	srcPath, srcHash := makeFile(t, 3*ft.ChunkSize)

	recvDir := t.TempDir()
	rcv, err := ft.NewReceiver(chB, recvDir, nil, "peerA")
	if err != nil {
		t.Fatal(err)
	}
	rctx, rcancel := context.WithCancel(context.Background())
	defer rcancel()
	go func() {
		err := rcv.Loop(rctx)
		t.Logf("[recv] Loop returned: %v", err)
	}()

	if err := ft.Send(context.Background(), chA, srcPath, nil, nil); err != nil {
		t.Fatalf("Send: %v", err)
	}

	// Verify SHA-256.
	f, err := os.Open(filepath.Join(recvDir, "src.bin"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != srcHash {
		t.Fatalf("sha256 mismatch")
	}
}

func TestSendDetectsCorruptedChunk(t *testing.T) {
	// We can't easily corrupt a chunk in transit without a
	// MITM hook, so this test is a placeholder for v0.2 when
	// the channel exposes a packet-level hook. For now we
	// verify the hash-mismatch path via the per-chunk check:
	// build a file, send, but compare with a wrong hash to
	// ensure the receiver bails (the wrong-hash path is
	// triggered on the receiver side; the sender should
	// observe a failed Done).
	t.Skip("corruption path requires protocol-level hook (v0.2)")
}

// TestReceiverRejectsOffer makes sure the OnOffer callback can
// veto an incoming transfer.
func TestReceiverRejectsOffer(t *testing.T) {
	chA, chB := channelPair(t)
	defer chA.Close()
	defer chB.Close()

	// Pre-build a file so the Send is fast.
	srcPath, _ := makeFile(t, 1024)

	recvDir := t.TempDir()
	rcv, err := ft.NewReceiver(chB, recvDir, func(o ft.FileOffer, _ string) error {
		return errVeto
	}, "peerA")
	if err != nil {
		t.Fatal(err)
	}
	rctx, rcancel := context.WithCancel(context.Background())
	defer rcancel()
	go func() { _ = rcv.Loop(rctx) }()

	err = ft.Send(context.Background(), chA, srcPath, nil, nil)
	if err == nil {
		t.Fatal("Send should have failed when receiver rejected offer")
	}
	// The temp file should not be in saveDir.
	if _, err := os.Stat(filepath.Join(recvDir, "src.bin")); !os.IsNotExist(err) {
		t.Fatal("rejected file ended up in save dir")
	}
}

var errVeto = vetoError{}

type vetoError struct{}

func (vetoError) Error() string { return "vetoed by test" }

func TestSendUnalignedLastChunk(t *testing.T) {
	// 1 MiB + 17 bytes — the last chunk is partial.
	chA, chB := channelPair(t)
	defer chA.Close()
	defer chB.Close()

	size := ft.ChunkSize + 17
	srcPath, srcHash := makeFile(t, size)

	recvDir := t.TempDir()
	rcv, err := ft.NewReceiver(chB, recvDir, nil, "peerA")
	if err != nil {
		t.Fatal(err)
	}
	rctx, rcancel := context.WithCancel(context.Background())
	defer rcancel()
	go func() { _ = rcv.Loop(rctx) }()

	if err := ft.Send(context.Background(), chA, srcPath, nil, nil); err != nil {
		t.Fatalf("Send: %v", err)
	}

	gotBytes, err := os.ReadFile(filepath.Join(recvDir, "src.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if int64(len(gotBytes)) != int64(size) {
		t.Fatalf("size: got %d, want %d", len(gotBytes), size)
	}
	wantHash, _ := hex.DecodeString(srcHash)
	h := sha256.Sum256(gotBytes)
	if !bytes.Equal(h[:], wantHash) {
		t.Fatal("sha256 mismatch on unaligned file")
	}
}

// make sure imports are used (sync is not, but keep the import
// for future concurrent transfer tests).
var _ = sync.Mutex{}
