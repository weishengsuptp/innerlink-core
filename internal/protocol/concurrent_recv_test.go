package protocol

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestChannelRecvConcurrentSafe verifies that calling Recv from
// multiple goroutines on the same Channel doesn't corrupt the
// frame stream. Before recvMu was added, two concurrent readers
// would split frames and produce "frame too short" errors.
func TestChannelRecvConcurrentSafe(t *testing.T) {
	cA, cB := loopbackPair(t)
	sA, sB := runHandshakePair(t, cA, cB)
	chA, err := NewChannel(cA, sA)
	if err != nil {
		t.Fatal(err)
	}
	chB, err := NewChannel(cB, sB)
	if err != nil {
		t.Fatal(err)
	}
	defer chA.Close()
	defer chB.Close()

	const N = 20
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// Two receivers race for envelopes. They keep going until
	// ctx is cancelled; we (the main goroutine) cancel once
	// all N envelopes are observed.
	var got int64
	var firstErr atomic.Pointer[errorWrapper]
	var wg sync.WaitGroup
	recordErr := func(e error) {
		firstErr.CompareAndSwap(nil, &errorWrapper{e})
	}
	for r := 0; r < 2; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				env, err := chB.Recv(ctx)
				if err != nil {
					// ctx cancellation is expected; ignore.
					if !errors.Is(err, context.Canceled) {
						recordErr(err)
					}
					return
				}
				if env.Type != TypeText {
					recordErr(errors.New("unexpected type: " + string(env.Type)))
					return
				}
				atomic.AddInt64(&got, 1)
			}
		}()
	}

	// Give receivers a moment to start their Recv loop.
	time.Sleep(20 * time.Millisecond)

	// Send N envelopes.
	for i := 0; i < N; i++ {
		if err := chA.SendText(ctx, "x"); err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
	}

	// Wait for all N to be received (with timeout), then cancel.
	deadline := time.Now().Add(3 * time.Second)
	for atomic.LoadInt64(&got) < int64(N) && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	wg.Wait()

	if w := firstErr.Load(); w != nil {
		t.Fatalf("receiver error: %v", w.e)
	}
	if got != int64(N) {
		t.Fatalf("expected %d, got %d", N, got)
	}
}

type errorWrapper struct{ e error }
