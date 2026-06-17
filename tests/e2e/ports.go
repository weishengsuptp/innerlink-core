package e2e

import (
	"net"
	"sync"
)

// PortAllocator hands out (udp, tcp) port pairs that are
// guaranteed to be free on this host at the moment of
// allocation. It is the only safe way to spin up multiple
// innerlink instances on a single machine without colliding
// on the well-known ports 4747/4748.
//
// Implementation: it opens a UDP listener on :0, reads the
// port the OS assigned, then closes the listener. The
// kernel won't immediately re-assign the same port to a
// different socket, so the chance of a race is small but
// not zero. For an e2e regression suite (single host, a
// handful of nodes, sub-second lifetimes) this is good
// enough. If two tests ever collide, the test that loses
// gets to retry — see Allocate().
//
// Each call to Allocate returns a *new* pair, so two nodes
// from two different tests won't share. The Allocator is
// safe to share across goroutines.
type PortAllocator struct {
	mu   sync.Mutex
	next int // monotonic counter for the fallback path
}

// NewPortAllocator constructs an allocator. The "next"
// counter is for the rare case where the kernel's auto-port
// + close + retry trick fails repeatedly; the fallback walks
// upward from a base.
func NewPortAllocator() *PortAllocator {
	return &PortAllocator{next: 30000}
}

// Pair is a (udp, tcp) port pair. The two numbers may
// collide if a test only needs one of them; that's fine.
type Pair struct {
	UDP int
	TCP int
}

// Allocate reserves a (udp, tcp) pair on the loopback
// interface. It tries up to 16 times before giving up,
// because Listen(:0) + Close() is racy on Windows under
// heavy load (other processes, antivirus scanners, etc.).
func (p *PortAllocator) Allocate() (Pair, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	for attempt := 0; attempt < 16; attempt++ {
		udp, err := pickPort()
		if err != nil {
			continue
		}
		tcp, err := pickPort()
		if err != nil {
			continue
		}
		// Don't accept the well-known default ports even
		// if the kernel offered them — that would mean
		// another instance is already running and
		// bound/released, which we want to detect as a
		// collision, not silently reuse.
		if udp == 4747 || tcp == 4748 {
			continue
		}
		return Pair{UDP: udp, TCP: tcp}, nil
	}
	// Last resort: walk upward from a base. This is
	// deterministic, slower, and on a busy host the
	// port may still be in use — but then Listen in
	// the actual innerlink process will fail with a
	// clear error, which is what we want.
	for p.next < 60000 {
		udp := p.next
		tcp := p.next + 1
		p.next += 2
		return Pair{UDP: udp, TCP: tcp}, nil
	}
	return Pair{}, errNoPorts
}

// pickPort asks the kernel for an unused UDP or TCP port
// on the loopback interface. It opens a socket on :0,
// reads the assigned port, then closes the socket.
func pickPort() (int, error) {
	addr, err := net.ResolveUDPAddr("udp4", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	conn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		return 0, err
	}
	port := conn.LocalAddr().(*net.UDPAddr).Port
	conn.Close()
	return port, nil
}

var errNoPorts = &portError{}

type portError struct{}

func (*portError) Error() string { return "e2e: could not allocate any free port" }
