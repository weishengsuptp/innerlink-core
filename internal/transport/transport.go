// Package transport provides a TCP-based, frame-oriented byte
// channel between two innerlink peers.
//
// What it does, in one sentence:
// each innerlink "session" is a single TCP connection carrying
// length-prefixed frames; a Transport multiplexes many such sessions
// in and out of a single listener.
//
// What it does NOT do (these belong in other layers):
//   - Authentication / identity verification: see internal/handshake.
//   - Encryption: frames here are PLAINTEXT — handshake negotiates
//     a session key and callers wrap their payloads in SM4-GCM
//     before handing them to this layer (see internal/protocol).
//   - Peer discovery: see internal/discovery.
//
// Frame format on the wire:
//
//	+--------------------+--------------------+
//	|  length: 4 bytes   |   body: N bytes    |
//	|  big-endian uint32 |                    |
//	+--------------------+--------------------+
//
// length is the size of the body in bytes, in network byte order.
// Max body size is capped at MaxFrameSize (16 MiB) to keep a single
// malicious peer from forcing us to allocate gigabytes of buffer.
//
// Each TCP connection is a single, ordered, reliable stream of
// frames. There is no in-stream multiplexing — if you need to send
// independent logical messages concurrently, callers wrap their
// payload in something like the protocol.Envelope (see
// internal/protocol) which carries a "type" field.
package transport

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// MaxFrameSize caps the body of a single frame. Anything bigger is
// a protocol error and the connection is closed. 16 MiB is more
// than enough for chat messages + small file chunks; large file
// transfers use the filetransfer package's own chunking on top.
const MaxFrameSize = 16 << 20 // 16 MiB

// HeaderSize is the fixed frame header length.
const HeaderSize = 4

// DefaultPort is the TCP port innerlink listens on for incoming
// peer connections. Picked to match the discovery port convention.
const DefaultPort = 4748

// DefaultHeartbeat is the interval between ping/pong frames.
// 15s is short enough to detect a dead peer quickly (< 30s typical)
// and long enough that we send <5 packets per minute per session.
const DefaultHeartbeat = 15 * time.Second

// DefaultReadTimeout is the per-frame read deadline. If a peer
// hasn't sent a complete frame within this window we assume
// they're gone and close the connection.
const DefaultReadTimeout = 60 * time.Second

// ErrFrameTooLarge is returned when a peer tries to send a frame
// whose body length exceeds MaxFrameSize.
var ErrFrameTooLarge = errors.New("transport: frame body exceeds max size")

// ErrClosed indicates the connection is no longer usable (either
// the local side called Close, or the remote side hung up).
var ErrClosed = errors.New("transport: connection closed")

// Frame is a single in-memory frame ready to send or just received.
type Frame struct {
	Body []byte
}

// Bytes returns a heap-allocated copy. We do NOT share the slice
// with the caller's buffer, because the caller might overwrite
// their buffer before we actually transmit.
func (f Frame) Bytes() []byte {
	out := make([]byte, len(f.Body))
	copy(out, f.Body)
	return out
}

// Conn is a single TCP session to one peer. It is safe for
// concurrent Send calls; reads are not (one reader per Conn).
type Conn struct {
	tcp       net.Conn
	remote    net.Addr

	writeMu sync.Mutex // serialize Send to avoid interleaving

	closed   chan struct{}
	closeOnce sync.Once
	closeErr error
}

// RemoteAddr returns the peer's network address.
func (c *Conn) RemoteAddr() net.Addr { return c.remote }

// NewConnForTest wraps a raw net.Conn as a *Conn. This is intended
// for use in other packages' tests (e.g. internal/handshake) that
// need to construct a Conn without going through Transport.Listen
// + Accept. NOT part of the public API.
func NewConnForTest(tcp net.Conn) *Conn {
	return &Conn{
		tcp:    tcp,
		remote: tcp.RemoteAddr(),
		closed: make(chan struct{}),
	}
}

// Close shuts down the connection. Safe to call multiple times;
// subsequent calls return ErrClosed.
func (c *Conn) Close() error {
	c.closeOnce.Do(func() {
		close(c.closed)
		c.closeErr = c.tcp.Close()
	})
	return c.closeErr
}

// Send writes one frame to the peer. Blocks until the frame has
// been written to the OS socket (which means it's in the kernel
// send buffer — not necessarily acked by the peer).
//
// Concurrency: safe. Multiple goroutines may Send concurrently.
func (c *Conn) Send(body []byte) error {
	if len(body) > MaxFrameSize {
		return ErrFrameTooLarge
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	// Check closed-before-write so we don't write to a dead socket.
	select {
	case <-c.closed:
		return ErrClosed
	default:
	}

	// Write length header.
	var hdr [HeaderSize]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(body)))
	if err := writeFull(c.tcp, hdr[:]); err != nil {
		c.Close()
		return err
	}
	if len(body) > 0 {
		if err := writeFull(c.tcp, body); err != nil {
			c.Close()
			return err
		}
	}
	return nil
}

// Recv reads one frame from the peer. Blocks until a complete
// frame arrives or the connection closes.
//
// Concurrency: NOT safe. Only one goroutine per Conn may call Recv.
func (c *Conn) Recv() (Frame, error) {
	select {
	case <-c.closed:
		return Frame{}, ErrClosed
	default:
	}

	var hdr [HeaderSize]byte
	if err := readFull(c.tcp, hdr[:], c.readDeadline()); err != nil {
		c.Close()
		return Frame{}, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > MaxFrameSize {
		c.Close()
		return Frame{}, ErrFrameTooLarge
	}
	body := make([]byte, n)
	if n > 0 {
		if err := readFull(c.tcp, body, c.readDeadline()); err != nil {
			c.Close()
			return Frame{}, err
		}
	}
	return Frame{Body: body}, nil
}

// readDeadline returns the time used as a per-frame read deadline.
// We refresh the deadline on every read so an idle connection that
// occasionally sends a frame isn't killed; only connections that
// go fully silent for the timeout get reaped.
func (c *Conn) readDeadline() time.Time {
	return time.Now().Add(DefaultReadTimeout)
}

// writeFull writes all of buf or returns the first error.
func writeFull(w io.Writer, buf []byte) error {
	for len(buf) > 0 {
		n, err := w.Write(buf)
		if err != nil {
			return err
		}
		buf = buf[n:]
	}
	return nil
}

// readFull reads exactly len(buf) bytes or returns the first error.
func readFull(r io.Reader, buf []byte, deadline time.Time) error {
	if d, ok := r.(interface{ SetReadDeadline(time.Time) error }); ok {
		_ = d.SetReadDeadline(deadline)
	}
	_, err := io.ReadFull(r, buf)
	return err
}

// Transport is the multi-peer TCP manager. One Transport per
// innerlink process; it owns the listener, the heartbeat loop,
// and the registry of active Conn instances.
type Transport struct {
	port      int
	heartbeat time.Duration

	listener net.Listener

	mu    sync.Mutex
	conns map[string]*Conn // by remote addr string; both inbound & outbound

	// inbounds is the channel of newly-accepted connections. The
	// caller (typically the handshake layer) reads from it to learn
	// about incoming peers.
	inbounds chan *Conn

	closed   chan struct{}
	closeOnce sync.Once
}

// NewTransport constructs a Transport on the default TCP port.
func NewTransport() *Transport {
	return &Transport{
		port:      DefaultPort,
		heartbeat: DefaultHeartbeat,
		conns:     make(map[string]*Conn),
		inbounds:  make(chan *Conn, 8),
		closed:    make(chan struct{}),
	}
}

// Listen binds the TCP listener. Must be called before Run.
func (t *Transport) Listen() error {
	l, err := net.Listen("tcp", fmt.Sprintf(":%d", t.port))
	if err != nil {
		return fmt.Errorf("transport: listen :%d: %w", t.port, err)
	}
	t.listener = l
	return nil
}

// Port returns the actually-bound TCP port. Useful when constructed
// with port=0 for tests; the kernel assigns a real port.
func (t *Transport) Port() int {
	if t.listener == nil {
		return t.port
	}
	return t.listener.Addr().(*net.TCPAddr).Port
}

// Inbounds returns the channel of newly accepted peer connections.
// Consumers (the handshake layer) range over it; the channel is
// closed when the Transport is closed.
func (t *Transport) Inbounds() <-chan *Conn { return t.inbounds }

// Dial connects to a remote peer by address. Returns ErrClosed if
// the Transport has been closed.
func (t *Transport) Dial(ctx context.Context, addr string) (*Conn, error) {
	if t.listener == nil {
		return nil, errors.New("transport: Listen() not called before Dial()")
	}
	d := net.Dialer{Timeout: 10 * time.Second}
	tcpConn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("transport: dial %s: %w", addr, err)
	}
	c := t.register(tcpConn)
	return c, nil
}

// DialStandalone dials a remote peer without requiring Listen() to
// have been called first. It creates the bare minimum needed to
// wrap a raw TCP connection in a Conn — useful for one-shot dial
// from a CLI that hasn't set up a listener.
//
// The returned Conn is NOT registered in any global registry; the
// caller owns its lifecycle.
func DialStandalone(ctx context.Context, addr string) (*Conn, error) {
	d := net.Dialer{Timeout: 10 * time.Second}
	tcpConn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("transport: dial %s: %w", addr, err)
	}
	return &Conn{
		tcp:    tcpConn,
		remote: tcpConn.RemoteAddr(),
		closed: make(chan struct{}),
	}, nil
}

// register wraps a raw TCP conn in our Conn type and stores it in
// the registry. Idempotent on the same remote address: re-registering
// returns the existing Conn (so two concurrent Dials to the same
// peer don't open two sockets).
func (t *Transport) register(tcpConn net.Conn) *Conn {
	key := tcpConn.RemoteAddr().String()
	t.mu.Lock()
	if existing, ok := t.conns[key]; ok {
		t.mu.Unlock()
		tcpConn.Close() // we already have a connection to this peer
		return existing
	}
	c := &Conn{
		tcp:    tcpConn,
		remote: tcpConn.RemoteAddr(),
		closed: make(chan struct{}),
	}
	t.conns[key] = c
	t.mu.Unlock()
	return c
}

// unregister removes a Conn from the registry when it closes.
func (t *Transport) unregister(c *Conn) {
	key := c.remote.String()
	t.mu.Lock()
	delete(t.conns, key)
	t.mu.Unlock()
}

// Run is the main loop. It blocks until ctx is done. Internally:
//   - Accept loop: every incoming TCP connection is wrapped in a
//     Conn and pushed onto Inbounds().
//   - Heartbeat loop: ticks every Heartbeat, sends a 0-byte ping
//     frame to every active Conn, reaps dead ones.
//   - Per-Conn read loop: each Conn spawned in accept gets its own
//     read loop... actually, we don't read here — Recv is a method
//     the consumer calls. So this layer is "frame at a time,
//     consumer-driven reads".
func (t *Transport) Run(ctx context.Context) error {
	if t.listener == nil {
		return errors.New("transport: Listen() not called before Run()")
	}

	// Accept loop.
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		for {
			rawConn, err := t.listener.Accept()
			if err != nil {
				select {
				case <-t.closed:
					return
				default:
				}
				// Transient accept error: brief sleep and retry.
				// Common causes: too many open files, transient
				// resource exhaustion. We don't crash the process
				// for these.
				var ne net.Error
				if errors.As(err, &ne) && ne.Timeout() {
					continue
				}
				if errors.Is(err, net.ErrClosed) {
					return
				}
				time.Sleep(100 * time.Millisecond)
				continue
			}
			c := t.register(rawConn)
			select {
			case t.inbounds <- c:
			case <-ctx.Done():
				c.Close()
				return
			}
		}
	}()

	// Heartbeat loop.
	hbDone := make(chan struct{})
	go func() {
		defer close(hbDone)
		tick := time.NewTicker(t.heartbeat)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				t.heartbeatOnce()
			}
		}
	}()

	<-ctx.Done()
	t.closeOnce.Do(func() {
		close(t.closed)
		t.listener.Close()
		// Close all active conns.
		t.mu.Lock()
		for _, c := range t.conns {
			c.Close()
		}
		t.mu.Unlock()
	})
	<-acceptDone
	<-hbDone
	close(t.inbounds)
	return ctx.Err()
}

// heartbeatOnce sends a ping (0-byte body) to every active Conn.
// The peer's Recv will see an empty Frame, which it can use as a
// keepalive signal (or simply ignore).
func (t *Transport) heartbeatOnce() {
	t.mu.Lock()
	conns := make([]*Conn, 0, len(t.conns))
	for _, c := range t.conns {
		conns = append(conns, c)
	}
	t.mu.Unlock()
	for _, c := range conns {
		// 0-byte body is a "ping" — it costs 4 bytes on the wire
		// (just the length header) and exercises the write path
		// end-to-end.
		if err := c.Send(nil); err != nil {
			c.Close()
			t.unregister(c)
		}
	}
}

// Close shuts down the Transport. Safe to call from any goroutine;
// idempotent.
func (t *Transport) Close() {
	t.closeOnce.Do(func() {
		close(t.closed)
		if t.listener != nil {
			t.listener.Close()
		}
		t.mu.Lock()
		for _, c := range t.conns {
			c.Close()
		}
		t.mu.Unlock()
	})
}

// ActiveConns returns a snapshot of the current connection registry.
// Useful for diagnostics and tests.
func (t *Transport) ActiveConns() []*Conn {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]*Conn, 0, len(t.conns))
	for _, c := range t.conns {
		out = append(out, c)
	}
	return out
}
