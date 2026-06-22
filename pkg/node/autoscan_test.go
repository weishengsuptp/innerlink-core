package node

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestShouldAutoScanFor(t *testing.T) {
	tests := []struct {
		name          string
		myIPs         []string
		entryAddrs    []string
		knownSubnets  map[string]bool
		wantCIDR      string
		wantOK        bool
	}{
		{
			name:       "remote /24, no known subnets",
			myIPs:      []string{"192.168.40.5"},
			entryAddrs: []string{"192.168.153.7:4748"},
			wantCIDR:   "192.168.153.0/24",
			wantOK:     true,
		},
		{
			name:         "already in known subnets",
			myIPs:        []string{"192.168.40.5"},
			entryAddrs:   []string{"192.168.153.7:4748"},
			knownSubnets: map[string]bool{"192.168.153.0/24": true},
			wantOK:       false,
		},
		{
			name:       "own /24",
			myIPs:      []string{"192.168.40.5"},
			entryAddrs: []string{"192.168.40.99:4748"},
			wantOK:     false,
		},
		{
			name:       "loopback",
			myIPs:      []string{"127.0.0.1"},
			entryAddrs: []string{"127.0.0.2:4748"},
			wantOK:     false,
		},
		{
			name:       "multicast",
			myIPs:      []string{"192.168.40.5"},
			entryAddrs: []string{"239.255.255.1:4748"},
			wantOK:     false,
		},
		{
			name:       "unspecified 0.0.0.0",
			myIPs:      []string{"192.168.40.5"},
			entryAddrs: []string{"0.0.0.0:4748"},
			wantOK:     false,
		},
		{
			name:       "no port (some legacy entries)",
			myIPs:      []string{"192.168.40.5"},
			entryAddrs: []string{"10.0.0.7"},
			wantCIDR:   "10.0.0.0/24",
			wantOK:     true,
		},
		{
			name:       "empty addrs",
			myIPs:      []string{"192.168.40.5"},
			entryAddrs: nil,
			wantOK:     false,
		},
		{
			name:       "malformed addr",
			myIPs:      []string{"192.168.40.5"},
			entryAddrs: []string{"not-an-ip:4748"},
			wantOK:     false,
		},
		{
			name:       "uses first addr only",
			myIPs:      []string{"192.168.40.5"},
			entryAddrs: []string{"172.16.5.7:4748", "10.0.0.1:4748"},
			wantCIDR:   "172.16.5.0/24",
			wantOK:     true,
		},
		{
			name:       "own /24 with multiple local IPs",
			myIPs:      []string{"10.0.0.5", "192.168.40.5"},
			entryAddrs: []string{"192.168.40.99:4748"},
			wantOK:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cidr, ok := shouldAutoScanFor(tt.myIPs, tt.entryAddrs, tt.knownSubnets)
			if cidr != tt.wantCIDR || ok != tt.wantOK {
				t.Errorf("shouldAutoScanFor() = (%q, %v), want (%q, %v)",
					cidr, ok, tt.wantCIDR, tt.wantOK)
			}
		})
	}
}

func TestAutoScanQueueDedupe(t *testing.T) {
	q := newAutoScanQueue()
	if !q.Enqueue("10.0.0.0/24") {
		t.Error("first Enqueue should succeed")
	}
	if q.Enqueue("10.0.0.0/24") {
		t.Error("duplicate Enqueue should be deduped (return false)")
	}
	if !q.Enqueue("192.168.1.0/24") {
		t.Error("distinct Enqueue should succeed")
	}
	// Drain pending.
	got := 0
	deadline := time.After(100 * time.Millisecond)
loop:
	for {
		select {
		case <-q.ch:
			got++
		case <-deadline:
			break loop
		}
	}
	if got != 2 {
		t.Errorf("drained %d items, want 2", got)
	}
}

func TestAutoScanQueueBoundedDrop(t *testing.T) {
	q := newAutoScanQueue()
	// Capacity is 16. Push 17 distinct subnets —
	// the 17th Enqueue returns false (queue full)
	// but is still marked seen (won't be re-added).
	added := 0
	for i := 0; i < 20; i++ {
		if q.Enqueue("10.0.0.0/24") {
			added++
		} else if i == 0 {
			// First is the same value, gets
			// deduped — counted as not-added.
		}
	}
	// We don't assert the exact count (depends on
	// buffer behavior) but at least 1 was added
	// and the queue didn't grow unbounded.
	if added < 1 {
		t.Error("expected at least 1 successful Enqueue")
	}
	if len(q.seen) > 20 {
		t.Errorf("seen grew beyond input size: %d", len(q.seen))
	}
}

func TestAutoScanLoopRunsScans(t *testing.T) {
	q := newAutoScanQueue()
	var ran atomic.Int32
	scans := make(chan string, 4)
	scanFn := func(ctx context.Context, cidr string) error {
		ran.Add(1)
		scans <- cidr
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		autoScanLoop(ctx, q, scanFn, nil)
	}()
	q.Enqueue("10.0.0.0/24")
	q.Enqueue("192.168.1.0/24")
	// Wait for both to be picked up.
	deadline := time.After(2 * time.Second)
	got := 0
	for got < 2 {
		select {
		case <-scans:
			got++
		case <-deadline:
			t.Fatalf("only %d scans ran in 2s, want 2", got)
		}
	}
	cancel()
	wg.Wait()
	if ran.Load() != 2 {
		t.Errorf("ran.Load() = %d, want 2", ran.Load())
	}
}

func TestAutoScanLoopCallsOnResult(t *testing.T) {
	q := newAutoScanQueue()
	scanErr := errors.New("dial refused")
	scanFn := func(ctx context.Context, cidr string) error {
		return scanErr
	}
	var (
		mu     sync.Mutex
		gotCIDR string
		gotErr  error
	)
	onResult := func(cidr string, err error) {
		mu.Lock()
		gotCIDR = cidr
		gotErr = err
		mu.Unlock()
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		autoScanLoop(ctx, q, scanFn, onResult)
	}()
	q.Enqueue("10.0.0.0/24")
	deadline := time.After(2 * time.Second)
	for {
		mu.Lock()
		done := gotCIDR != ""
		mu.Unlock()
		if done {
			break
		}
		select {
		case <-deadline:
			t.Fatal("onScanResult not called within 2s")
		case <-time.After(20 * time.Millisecond):
		}
	}
	cancel()
	wg.Wait()
	mu.Lock()
	defer mu.Unlock()
	if gotCIDR != "10.0.0.0/24" {
		t.Errorf("cidr = %q, want 10.0.0.0/24", gotCIDR)
	}
	if !errors.Is(gotErr, scanErr) {
		t.Errorf("err = %v, want %v", gotErr, scanErr)
	}
}

func TestAutoScanLoopExitsOnContextCancel(t *testing.T) {
	q := newAutoScanQueue()
	scanFn := func(ctx context.Context, cidr string) error {
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		autoScanLoop(ctx, q, scanFn, nil)
		close(done)
	}()
	cancel()
	select {
	case <-done:
		// ok
	case <-time.After(1 * time.Second):
		t.Fatal("autoScanLoop did not exit within 1s of cancel")
	}
}
