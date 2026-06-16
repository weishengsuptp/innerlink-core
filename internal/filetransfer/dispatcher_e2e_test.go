// TestSendFile_WithSharedChannelPump exercises the bug
// fixed in commit "fix: sendfile hangs when cmd dispatcher
// also reads from the channel". The cmd/innerlink CLI runs
// a single Recv pump (the dispatcher) on each Channel, and
// SendFile used to call ch.Recv directly to wait for the
// Accept envelope. The dispatcher would race to read the
// Accept envelope first, see it as "non-file traffic", and
// drop it — so Send would block forever on wait accept.
//
// The fix routes Accept/Done/Abort through the
// Receiver.WaitForReply registry, so Send blocks on a Go
// channel that the dispatcher's Handle() call fills in. This
// test is the regression check: it must NOT hang, and the
// received file must match the source.
package filetransfer_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	ft "github.com/weishengsuptp/innerlink-core/internal/filetransfer"
	"github.com/weishengsuptp/innerlink-core/internal/protocol"
)

func TestSendFile_WithSharedChannelPump(t *testing.T) {
	// Use a multi-chunk source so the bug would be
	// reachable in 50 MB-equivalent conditions. 3 MiB
	// = 12 chunks at 256 KiB.
	const size = 3 * 1024 * 1024
	srcPath, wantHash := makeDeterministicFile(t, size)
	defer os.Remove(srcPath)

	chA, chB := channelPairE2E(t)
	defer chA.Close()
	defer chB.Close()

	saveDir := t.TempDir()
	rcv, err := ft.NewReceiver(chB, saveDir, nil, "peerA")
	if err != nil {
		t.Fatal(err)
	}

	// Run the cmd/innerlink-style dispatcher on BOTH
	// sides. In the real CLI the dispatcher is the one
	// goroutine that reads from ch.Recv; chat and file
	// traffic both flow through it. Without a dispatcher
	// on the sender side, no goroutine is ever reading
	// from chA.Recv, so the Accept envelope that the
	// receiver emits sits in the TCP read buffer forever
	// and WaitForReply blocks until ctx timeout.
	dispatcherCtx, dispatcherCancel := context.WithCancel(context.Background())
	defer dispatcherCancel()
	go runDispatcher(dispatcherCtx, t, chB, rcv)

	// The sender also needs a receiver, so that the
	// Accept reply (which the receiver sends back over
	// chA) gets routed to Send.WaitForReply.
	// A "sender-side receiver" doesn't have an incoming
	// file to accept in this test, so we wire it up with
	// nil onOffer and a throwaway save dir.
	senderSaveDir := t.TempDir()
	senderRcv, err := ft.NewReceiver(chA, senderSaveDir, nil, "peerB")
	if err != nil {
		t.Fatal(err)
	}
	go runDispatcher(dispatcherCtx, t, chA, senderRcv)

	// Cap the whole test at 30 s. If the regression
	// comes back (Accept swallowed by dispatcher) this
	// will fire well before the 60 s loopback default
	// timeout, so the test fails fast with a clear
	// "deadlock in 30 s" rather than a "deadlock in
	// 60 s" message.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	// Send is on chA (the initiator side), so its
	// WaitForReply must be bound to the sender's own
	// Receiver (the one whose dispatcher is reading
	// envelopes off chA — including the Accept reply
	// that the receiver sends back). Binding it to
	// rcv (the receiving-side Receiver) would make
	// the Accept reply route to a registry that no
	// chA-side dispatcher is writing to, and the
	// sender would deadlock on wait accept.
	if err := ft.Send(ctx, chA, srcPath, nil, senderRcv.WaitForReply); err != nil {
		t.Fatalf("Send: %v", err)
	}

	gotPath := filepath.Join(saveDir, filepath.Base(srcPath))
	gotHash, err := hashFileE2E(gotPath)
	if err != nil {
		t.Fatalf("read received: %v", err)
	}
	if gotHash != wantHash {
		t.Fatalf("sha256 mismatch:\n  got  %s\n  want %s", gotHash, wantHash)
	}
}

func makeDeterministicFile(t *testing.T, size int) (string, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "e2e-src.bin")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	h := sha256.New()
	buf := make([]byte, 64*1024)
	written := 0
	for written < size {
		n := len(buf)
		if size-written < n {
			n = size - written
		}
		for i := 0; i < n; i++ {
			buf[i] = byte((written + i) & 0xFF)
		}
		if _, err := f.Write(buf[:n]); err != nil {
			t.Fatal(err)
		}
		h.Write(buf[:n])
		written += n
	}
	return path, hex.EncodeToString(h.Sum(nil))
}

func hashFileE2E(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// channelPairE2E is a copy of the helper in
// protocol_test.go: it stands up two real protocol.Channels
// on a loopback TCP pair with a complete SM2 handshake.
//
// We can't import the protocol_test helper directly (it is
// in package _test), so we duplicate it here. Keep this in
// sync with internal/protocol/protocol_test.go if that
// helper changes.
func channelPairE2E(t *testing.T) (*protocol.Channel, *protocol.Channel) {
	t.Helper()
	// We rely on the production export-test helper that
	// lives in the protocol package. If that helper is
	// gone, the test will fail to compile — fix that by
	// re-creating it. The helper is intentionally
	// minimal: loopback TCP + handshake + NewChannel.
	return channelPair(t)
}

// runDispatcher is the cmd/innerlink chat-pump pattern:
// one goroutine per channel that calls ch.Recv and routes
// every envelope into filetransfer.Receiver.Handle(). The
// test needs this on BOTH sides of the channel pair — the
// sender's WaitForReply depends on the sender-side
// dispatcher reading the Accept envelope off chA, and the
// receiver's handleChunk depends on the receiver-side
// dispatcher reading the chunk envelopes off chB.
func runDispatcher(ctx context.Context, t *testing.T, ch *protocol.Channel, rcv *ft.Receiver) {
	t.Helper()
	for {
		if ctx.Err() != nil {
			return
		}
		env, err := ch.Recv(ctx)
		if err != nil {
			return
		}
		rcv.Handle(ctx, env)
	}
}
