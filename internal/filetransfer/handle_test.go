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
)

// TestHandleDispatch verifies that a single pump loop can drive
// the Receiver via Handle() while still processing chat traffic
// — the cmd/innerlink CLI uses this pattern. Without it, two
// goroutines would call Channel.Recv concurrently and tear
// down the channel.
func TestHandleDispatch(t *testing.T) {
	chA, chB := channelPair(t)
	defer chA.Close()
	defer chB.Close()

	srcPath, srcHash := makeFile(t, 256*1024)

	recvDir := t.TempDir()
	rcv, err := ft.NewReceiver(chB, recvDir, nil, "peerA")
	if err != nil {
		t.Fatal(err)
	}
	rctx, rcancel := context.WithCancel(context.Background())
	defer rcancel()

	// Single-pump dispatcher: read chB.Recv, drop text, send
	// file envelopes to rcv.Handle().
	dispatchDone := make(chan struct{})
	go func() {
		defer close(dispatchDone)
		for {
			if rctx.Err() != nil {
				return
			}
			env, err := chB.Recv(rctx)
			if err != nil {
				return
			}
			if env.Type == "text" {
				// Simulate chat handler doing its thing.
				continue
			}
			rcv.Handle(rctx, env)
		}
	}()

	// Concurrently send a chat message from A → B, to prove
	// the dispatcher is the ONLY goroutine calling Recv.
	if err := chA.SendText(rctx, "ping from A"); err != nil {
		t.Fatal(err)
	}
	// Give the chat message a moment to land.
	time.Sleep(50 * time.Millisecond)

	if err := ft.Send(rctx, chA, srcPath, nil, nil); err != nil {
		t.Fatalf("Send: %v", err)
	}

	// Verify.
	f, err := os.Open(filepath.Join(recvDir, "src.bin"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(h.Sum(nil)) != srcHash {
		t.Fatal("sha256 mismatch")
	}
}
