// Package main: v0.5.2 auto-scan. When the M5 roster
// picks up a peer from a /24 we don't already have
// any connection to, schedule a one-shot scan of that
// /24. The goal: "I'm on 192.168.40.x, a peer tells me
// about a 192.168.153.x host — I auto-probe
// 192.168.153.0/24 to find more peers in that subnet
// without the user having to type `scan 192.168.153.0/24`."
//
// Design choices:
//
//   - Opt-in: default OFF (`-auto-scan=false`). The
//     user is in control; auto-scan is an accelerator
//     for the "I just learned about a new subnet" case.
//     Without it, `scan <cidr>` is still manual.
//
//   - Single goroutine, serialized scans. A scan is
//     short (≤30s on /24 at 16 workers / 1.5s) so
//     serializing is fine and avoids two scans
//     contending on the dial budget.
//
//   - Dedup by /24. We won't re-scan a subnet we've
//     already scanned this session.
//
//   - Skips loopback and the user's own /24. UDP
//     discovery already covers same-subnet peers.
//
//   - Skips subnets we already have a live channel
//     to. The roster can have entries for peers we
//     haven't connected to yet, but if any of them
//     share a /24 with a connected peer, we already
//     know that subnet has innerlink and don't need
//     to scan.

package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
)

// autoScanQueue is a deduplicated, bounded channel
// of /24 CIDR strings. Producers (the roster merge
// path) call Enqueue; the single consumer
// (autoScanLoop) pulls and runs scans.
type autoScanQueue struct {
	ch   chan string
	mu   sync.Mutex
	seen map[string]bool
}

// newAutoScanQueue returns a queue with capacity 16.
// If more than 16 subnets arrive in a burst (unlikely;
// each entry comes from a gossiped roster), the
// extras are dropped silently — we'd rather drop
// than block the REPL.
func newAutoScanQueue() *autoScanQueue {
	return &autoScanQueue{
		ch:   make(chan string, 16),
		seen: make(map[string]bool),
	}
}

// Enqueue adds cidr to the queue if it hasn't been
// seen this session. Returns true if it was added.
func (q *autoScanQueue) Enqueue(cidr string) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.seen[cidr] {
		return false
	}
	q.seen[cidr] = true
	select {
	case q.ch <- cidr:
		return true
	default:
		// Queue full. The cidr is still in `seen`,
		// so we won't re-add — but it will be
		// dropped this round. Acceptable: a fresh
		// /24 is rare, and the next roster gossip
		// will re-trigger if it really matters.
		return false
	}
}

// Snapshot returns the current queue contents
// (pending + already-seen). Used by the `autoscan`
// REPL command to show status.
func (q *autoScanQueue) Snapshot() (pending []string, seen []string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	pending = make([]string, 0, len(q.ch))
	for {
		select {
		case c := <-q.ch:
			pending = append(pending, c)
		default:
			goto done
		}
	}
done:
	for c := range q.seen {
		seen = append(seen, c)
	}
	return pending, seen
}

// shouldAutoScanFor inspects one roster entry's first
// address and returns (cidr, true) if the entry
// represents a /24 that:
//   - is routable (not loopback, not link-local,
//     not all-zero)
//   - is not the local node's own /24
//   - is not already in knownSubnets (subnets we've
//     scanned or that have a live channel)
//
// Otherwise returns ("", false).
func shouldAutoScanFor(
	myIPs []string,
	entryAddrs []string,
	knownSubnets map[string]bool,
) (string, bool) {
	if len(entryAddrs) == 0 {
		return "", false
	}
	// Pull "ip:port" apart and grab just the IP.
	host, _, err := net.SplitHostPort(entryAddrs[0])
	if err != nil {
		// Some roster entries may carry just an IP
		// with no port; fall back to the raw string.
		host = entryAddrs[0]
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return "", false
	}
	v4 := ip.To4()
	if v4 == nil {
		// IPv6 or malformed. `scan` only does IPv4.
		return "", false
	}
	if v4[0] == 127 {
		// Loopback. UDP discovery would already
		// find 127.0.0.0/8 peers (well, 127.0.0.1
		// only on macOS — see TestE2E_ScanFindsPeers
		// skip note). Either way, scan a /24 of
		// loopback is pointless.
		return "", false
	}
	if v4[0] == 0 || v4[0] >= 224 {
		// 0.0.0.0/8 (unspecified), 224.0.0.0/4
		// (multicast), 240.0.0.0/4 (reserved).
		// Not routable. Skip.
		return "", false
	}
	cidr := fmt.Sprintf("%d.%d.%d.0/24", v4[0], v4[1], v4[2])
	if knownSubnets[cidr] {
		return "", false
	}
	// If the entry is in OUR /24, UDP discovery
	// will already have it (or will, the next
	// broadcast). Skipping avoids spamming scan
	// on every new peer in our own subnet.
	for _, mine := range myIPs {
		mi := net.ParseIP(mine)
		if mi == nil {
			continue
		}
		m4 := mi.To4()
		if m4 == nil {
			continue
		}
		if m4[0] == v4[0] && m4[1] == v4[1] && m4[2] == v4[2] {
			return "", false
		}
	}
	return cidr, true
}

// autoScanLoop is the single consumer of queue. It
// runs scans sequentially and is the only path that
// calls runScan from auto-scan; manual `scan <cidr>`
// from the REPL still goes through runScan directly
// (no queue) so user-initiated scans are not
// serialized behind a slow auto-scan.
//
// onScanResult is called after each scan (success or
// err) so the caller can update the list of
// "scanned" subnets and avoid re-queueing.
func autoScanLoop(
	ctx context.Context,
	queue *autoScanQueue,
	scanFn func(ctx context.Context, cidr string) error,
	onScanResult func(cidr string, err error),
) {
	for {
		select {
		case <-ctx.Done():
			return
		case cidr := <-queue.ch:
			log.Printf("[AUTOSCAN] %s (triggered by new roster entry)", cidr)
			err := scanFn(ctx, cidr)
			if onScanResult != nil {
				onScanResult(cidr, err)
			}
			if err != nil && ctx.Err() == nil {
				log.Printf("[ERROR] auto-scan %s: %v", cidr, err)
			}
		}
	}
}

// autoScanState bundles the queue + the inputs to
// shouldAutoScanFor. One state per process; the
// roster merge path and the REPL both call into it.
type autoScanState struct {
	queue        *autoScanQueue
	myIPs        []string
	mu           sync.Mutex
	knownSubnets map[string]bool
}

func newAutoScanState(myIPs []string) *autoScanState {
	return &autoScanState{
		queue:        newAutoScanQueue(),
		myIPs:        myIPs,
		knownSubnets: make(map[string]bool),
	}
}

// MarkScanned records that this /24 has been (or is
// being) scanned, so we don't re-enqueue.
func (s *autoScanState) MarkScanned(cidr string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.knownSubnets[cidr] = true
}

// MarkConnectedSubnet records a /24 we now have a
// live channel to. Same dedup effect as MarkScanned.
func (s *autoScanState) MarkConnectedSubnet(peerAddr string) {
	host, _, err := net.SplitHostPort(peerAddr)
	if err != nil {
		host = peerAddr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return
	}
	v4 := ip.To4()
	if v4 == nil || v4[0] == 127 {
		return
	}
	cidr := fmt.Sprintf("%d.%d.%d.0/24", v4[0], v4[1], v4[2])
	s.MarkScanned(cidr)
}

// EnqueueIfNew inspects one roster entry's addrs and
// enqueues its /24 if it's new to us.
func (s *autoScanState) EnqueueIfNew(addrs []string) {
	s.mu.Lock()
	known := make(map[string]bool, len(s.knownSubnets))
	for k, v := range s.knownSubnets {
		known[k] = v
	}
	s.mu.Unlock()
	cidr, ok := shouldAutoScanFor(s.myIPs, addrs, known)
	if !ok {
		return
	}
	if s.queue.Enqueue(cidr) {
		log.Printf("[AUTOSCAN] queued %s (new subnet from roster)", cidr)
	}
}

// Queue returns the underlying queue (used by the
// `autoscan` REPL command to show pending / seen).
func (s *autoScanState) Queue() *autoScanQueue {
	return s.queue
}
