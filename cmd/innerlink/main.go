// Command innerlink is the innerlink v0.1 CLI demo.
//
// It boots every layer we've built so far, in order:
//
//  1. Load or create the device's SM2 identity (file:
//     $HOME/.innerlink/device.key).
//  2. Start the UDP announcer (broadcasts "I'm <PeerID>" every 5s).
//  3. Start the TCP transport (listens for incoming peer connections).
//  4. When a new peer is discovered, dial it and run the handshake.
//  5. When the handshake completes, wrap the Conn in a Channel and
//     start piping outbound messages to it and inbound messages to
//     stdout.
//
// Usage:
//
//	$ go run ./cmd/innerlink
//	[INFO] device identity loaded peerID=...
//	[INFO] listening for peers on UDP :4747
//	[INFO] listening for peers on TCP :4748
//	[PEER ] joined   peer=7a8b9c0d... at 192.168.1.20
//	[PEER ] left     peer=7a8b9c0d...
//	[PEER ] joined   peer=7a8b9c0d... at 192.168.1.21
//	[HANDS] ok       peer=7a8b9c0d... (initiator)
//	[MSG  ] in  <7a8b9c0d...> hello from peer
//	> send hello there
//	[MSG  ] out >7a8b9c0d...> hello there
//
// The CLI has no flags in v0.1 — everything is hard-coded to the
// default ports. v0.2 adds flags for explicit peer addrs, custom
// ports, and so on.
package main

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"sync"
	"time"

	"github.com/weishengsuptp/innerlink-core/internal/discovery"
	"github.com/weishengsuptp/innerlink-core/internal/handshake"
	"github.com/weishengsuptp/innerlink-core/internal/identity"
	"github.com/weishengsuptp/innerlink-core/internal/protocol"
	"github.com/weishengsuptp/innerlink-core/internal/transport"
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("innerlink: %v", err)
	}
}

func run() error {
	// 1) Device identity.
	keyPath, err := identity.ResolveDeviceKeyPath()
	if err != nil {
		return fmt.Errorf("resolve device key path: %w", err)
	}
	id, created, err := identity.LoadOrCreate(keyPath)
	if err != nil {
		return fmt.Errorf("load identity: %w", err)
	}
	if created {
		log.Printf("[INFO ] device identity created peerID=%s", id.PeerIDHex())
	} else {
		log.Printf("[INFO ] device identity loaded  peerID=%s", id.PeerIDHex())
	}
	log.Printf("[INFO ] device key file: %s", keyPath)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	// 2) UDP announcer.
	ann := discovery.NewAnnouncer(id, hostname(), transport.DefaultPort)
	go func() {
		if err := ann.Run(ctx); err != nil && ctx.Err() == nil {
			log.Printf("[ERROR] announcer: %v", err)
		}
	}()

	// 3) TCP transport.
	tr := transport.NewTransport()
	if err := tr.Listen(); err != nil {
		return fmt.Errorf("transport listen: %w", err)
	}
	log.Printf("[INFO ] listening for peers on UDP :%d", discovery.DefaultPort)
	log.Printf("[INFO ] listening for peers on TCP :%d", transport.DefaultPort)
	go func() {
		if err := tr.Run(ctx); err != nil && ctx.Err() == nil {
			log.Printf("[ERROR] transport: %v", err)
		}
	}()

	// 4) + 5) Glue: discovery → dial → handshake → channel.
	channels := newChannelRegistry()
	defer channels.closeAll()

	// Dispatch incoming TCP connections to the handshake+channel setup.
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case inbound, ok := <-tr.Inbounds():
				if !ok {
					return
				}
				go handleInbound(ctx, id, inbound, channels)
			}
		}
	}()

	// When discovery reports a peer added, dial it.
	go func() {
		for ev := range ann.Events() {
			switch ev.Type {
			case discovery.PeerAdded:
				log.Printf("[PEER ] joined   peer=%s at %s", peerHex(ev.PeerID), ev.Peer.Addr)
				go dialAndHandshake(ctx, id, ev.Peer, channels)
			case discovery.PeerRemoved:
				log.Printf("[PEER ] left     peer=%s", peerHex(ev.PeerID))
			}
		}
	}()

	// Stdin command loop.
	go runStdinLoop(ctx, cancel, channels)

	// Wait for Ctrl+C.
	<-ctx.Done()
	log.Printf("[INFO ] shutting down...")
	// Give in-flight ops a moment to drain.
	time.Sleep(200 * time.Millisecond)
	return nil
}

// channelRegistry tracks the active encrypted Channels, keyed
// by remote PeerID. Used so the stdin loop and the receive
// goroutine can find the right Channel to talk to.
type channelRegistry struct {
	mu sync.Mutex
	m  map[string]*protocol.Channel
}

func newChannelRegistry() *channelRegistry {
	return &channelRegistry{m: make(map[string]*protocol.Channel)}
}

// set installs ch for peerID. If a Channel already exists for
// this peer, set() closes the new one and returns the existing
// one — the assumption is that the existing Channel was set up
// first and is in active use, and a concurrent re-handshake
// (caused by the announcer's periodic PeerAdded emissions) is
// the redundant one we want to drop.
//
// Returns true if ch was installed, false if the existing one
// was kept.
func (r *channelRegistry) set(peerID []byte, ch *protocol.Channel) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := string(peerID)
	if _, ok := r.m[key]; ok {
		return false
	}
	r.m[key] = ch
	return true
}

func (r *channelRegistry) get(peerID []byte) *protocol.Channel {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.m[string(peerID)]
}

func (r *channelRegistry) delete(peerID []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if ch, ok := r.m[string(peerID)]; ok {
		_ = ch.Close()
		delete(r.m, string(peerID))
	}
}

func (r *channelRegistry) closeAll() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, ch := range r.m {
		_ = ch.Close()
	}
	r.m = nil
}

// dialAndHandshake dials the peer's TCP endpoint (their transport
// port — same as ours, since both run the same code), runs the
// handshake, and registers the resulting Channel.
//
// If we already have a live Channel to this peer, this is a no-op
// (announcer fires every announce interval, so the same peer
// re-triggers PeerAdded on every cycle). The "have channel?"
// check is done here rather than at the call site so that races
// between two simultaneous dialAndHandshake goroutines for the
// same peer also collapse to a single connection.
func dialAndHandshake(ctx context.Context, id *identity.Identity, p *discovery.Peer, reg *channelRegistry) {
	if p.Addr == nil {
		return
	}
	// Skip if we already have a live channel to this peer. The
	// announcer fires every announce interval, so the same peer
	// re-triggers PeerAdded on every cycle; without this guard
	// we'd dial again, double-handshake, and the second
	// handshake would tear down the first channel.
	if reg.get(p.PeerID) != nil {
		return
	}
	tcpAddr := fmt.Sprintf("%s:%d", p.Addr.IP.String(), transport.DefaultPort)
	dctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	conn, err := reg_transportDial(dctx, tcpAddr)
	if err != nil {
		log.Printf("[ERROR] dial %s: %v", tcpAddr, err)
		return
	}
	sess, err := handshake.RunAsInitiator(dctx, id, conn)
	if err != nil {
		log.Printf("[ERROR] handshake (initiator) with %s: %v", peerHex(p.PeerID), err)
		return
	}
	log.Printf("[HANDS] ok       peer=%s (initiator)", peerHex(p.PeerID))
	wrapChannel(ctx, conn, sess, reg)
}

// handleInbound is the responder counterpart: another peer
// dialed us, ran the handshake; we accept and wrap.
func handleInbound(ctx context.Context, id *identity.Identity, conn *transport.Conn, reg *channelRegistry) {
	hctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	sess, err := handshake.RunAsResponder(hctx, id, conn)
	if err != nil {
		log.Printf("[ERROR] handshake (responder) from %s: %v", conn.RemoteAddr(), err)
		return
	}
	log.Printf("[HANDS] ok       peer=%s (responder)", peerHex(sess.RemotePeerID))
	wrapChannel(ctx, conn, sess, reg)
}

// wrapChannel takes a freshly-handed-shaked Conn+Session and
// constructs a Channel. Starts a goroutine that pumps inbound
// Envelopes to stdout and registers the channel in the registry.
func wrapChannel(ctx context.Context, conn *transport.Conn, sess *handshake.Session, reg *channelRegistry) {
	ch, err := protocol.NewChannel(conn, sess)
	if err != nil {
		log.Printf("[ERROR] new channel: %v", err)
		_ = conn.Close()
		return
	}
	if !reg.set(sess.RemotePeerID, ch) {
		// Race lost: another Channel for this peer was installed
		// first. Close this one and bail without starting the
		// Recv goroutine — the winner's goroutine already owns
		// receive for this peer.
		log.Printf("[INFO ] channel superseded peer=%s (keeping existing)", peerHex(sess.RemotePeerID))
		_ = ch.Close()
		return
	}
	log.Printf("[INFO ] channel ready peer=%s", peerHex(sess.RemotePeerID))

	go func() {
		defer reg.delete(sess.RemotePeerID)
		for {
			if ctx.Err() != nil {
				return
			}
			env, err := ch.Recv(ctx)
			if err != nil {
				log.Printf("[INFO ] channel closed peer=%s (%v)", peerHex(sess.RemotePeerID), err)
				return
			}
			switch env.Type {
			case protocol.TypeText:
				log.Printf("[MSG  ] in  <%s> %s", peerHex(sess.RemotePeerID), string(env.Payload))
			case protocol.TypePing:
				log.Printf("[MSG  ] in  <%s> ping", peerHex(sess.RemotePeerID))
				_ = ch.SendPing(ctx) // pong
			case protocol.TypePong:
				// ignore for v0.1
			}
		}
	}()
}

// runStdinLoop reads commands from stdin.
//
// Commands:
//   - send <peer-id-hex> <text>   send a chat message to a peer
//   - peers                        list known peers
//   - ping <peer-id-hex>           send a ping
//   - help                         list commands
//   - quit                         exit
func runStdinLoop(ctx context.Context, cancel context.CancelFunc, reg *channelRegistry) {
	scanner := bufio.NewScanner(os.Stdin)
	printPrompt()
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			printPrompt()
			continue
		}
		parts := strings.SplitN(line, " ", 3)
		cmd := parts[0]
		switch cmd {
		case "send":
			if len(parts) < 3 {
				log.Println("[USAGE] send <peer-id-hex> <text>")
			} else {
				sendTo(reg, parts[1], parts[2])
			}
		case "ping":
			if len(parts) < 2 {
				log.Println("[USAGE] ping <peer-id-hex>")
			} else {
				pingPeer(reg, parts[1])
			}
		case "peers":
			log.Printf("[INFO ] no peer listing in v0.1; check the [PEER] log lines above")
		case "help":
			log.Println("[HELP ] send <peer-id-hex> <text>  -- send a chat message")
			log.Println("[HELP ] ping <peer-id-hex>         -- send a liveness probe")
			log.Println("[HELP ] peers                       -- (see [PEER] log lines)")
			log.Println("[HELP ] help                        -- this list")
			log.Println("[HELP ] quit                        -- exit")
		case "quit", "exit":
			log.Println("[INFO ] bye")
			cancel()
			return
		default:
			log.Printf("[USAGE] unknown command %q (type 'help')", cmd)
		}
		printPrompt()
	}
	if err := scanner.Err(); err != nil {
		log.Printf("[ERROR] stdin: %v", err)
	}
}

func printPrompt() {
	fmt.Fprint(os.Stderr, "> ")
}

func sendTo(reg *channelRegistry, peerHex, text string) {
	pid, err := hexToBytes(peerHex)
	if err != nil {
		log.Printf("[ERROR] bad peer id hex: %v", err)
		return
	}
	ch := reg.get(pid)
	if ch == nil {
		log.Printf("[ERROR] no active channel for peer %s", peerHex)
		return
	}
	if err := ch.SendText(context.Background(), text); err != nil {
		log.Printf("[ERROR] send: %v", err)
		return
	}
	log.Printf("[MSG  ] out >%s> %s", peerHex, text)
}

func pingPeer(reg *channelRegistry, peerHex string) {
	pid, err := hexToBytes(peerHex)
	if err != nil {
		log.Printf("[ERROR] bad peer id hex: %v", err)
		return
	}
	ch := reg.get(pid)
	if ch == nil {
		log.Printf("[ERROR] no active channel for peer %s", peerHex)
		return
	}
	_ = ch.SendPing(context.Background())
	log.Printf("[MSG  ] out >%s> ping", peerHex)
}

// reg_transportDial is a tiny indirection so tests can swap it
// out. In the production build it uses transport.DialStandalone,
// which doesn't require a Transport to be set up first (useful
// for the CLI's "dial a peer I just discovered" hot path).
var reg_transportDial = func(ctx context.Context, addr string) (*transport.Conn, error) {
	return transport.DialStandalone(ctx, addr)
}

// peerHex returns a 32-char lowercase hex of a PeerID. If the
// input is the wrong length, we fall back to fmt.Sprintf so the
// log line at least doesn't panic.
func peerHex(pid []byte) string {
	if len(pid) == identity.PeerIDSize {
		return identityHex(pid)
	}
	return fmt.Sprintf("%x", pid)
}