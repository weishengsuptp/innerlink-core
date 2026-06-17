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
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/weishengsuptp/innerlink-core/internal/discovery"
	"github.com/weishengsuptp/innerlink-core/internal/filetransfer"
	"github.com/weishengsuptp/innerlink-core/internal/handshake"
	"github.com/weishengsuptp/innerlink-core/internal/identity"
	"github.com/weishengsuptp/innerlink-core/internal/logx"
	"github.com/weishengsuptp/innerlink-core/internal/protocol"
	"github.com/weishengsuptp/innerlink-core/internal/transport"
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("innerlink: %v", err)
	}
}

// defaultLogFile returns the default path of the innerlink
// log file. It is "innerlink.log" next to the executable so
// the user can find it on the desktop, and falls back to
// the current working directory when the executable path
// cannot be resolved (which happens for `go run`-built
// binaries where os.Executable returns a temp path).
func defaultLogFile() string {
	if exe, err := os.Executable(); err == nil {
		return filepath.Join(filepath.Dir(exe), "innerlink.log")
	}
	return "innerlink.log"
}

func run() error {
	// CLI flags. The defaults are tuned for normal use:
	// -log-level=info keeps the screen readable, and
	// -log-file=innerlink.log next to the binary gives
	// you a file you can attach to a bug report without
	// scrolling. For development / debugging sendfile
	// hangs, use -log-level=debug to also see the
	// per-chunk progress and writeAt timings.
	logLevel := flag.String("log-level", string(logx.LevelInfo),
		"log verbosity: debug | info | warn | error. "+
			"debug includes per-chunk [FILE recv chunk ...] and "+
			"per-100ms [FILE sending ... %] lines, which are "+
			"noisy during multi-GiB transfers.")
	logFile := flag.String("log-file", defaultLogFile(),
		"path of the log file (in addition to stderr). "+
			"Use \"\" to disable file output. The file is "+
			"appended, so successive runs share the same log.")
	flag.Parse()

	if err := logx.Setup(logx.Options{
		Level:  logx.Level(*logLevel),
		File:   *logFile,
		Stderr: true,
	}); err != nil {
		return fmt.Errorf("logx setup: %w", err)
	}
	defer logx.Close()

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

	// Default save dir for incoming files. Created on first
	// use by the Receiver.
	saveDir, err := defaultSaveDir()
	if err != nil {
		return fmt.Errorf("resolve save dir: %w", err)
	}
	log.Printf("[INFO ] incoming files save dir: %s", saveDir)

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
				go handleInbound(ctx, id, inbound, channels, saveDir)
			}
		}
	}()

	// When discovery reports a peer added, dial it.
	go func() {
		for ev := range ann.Events() {
			switch ev.Type {
			case discovery.PeerAdded:
				log.Printf("[PEER ] joined   peer=%s at %s", peerHex(ev.PeerID), ev.Peer.Addr)
				go dialAndHandshake(ctx, id, tr, ev.Peer, channels, saveDir)
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
//
// We also keep a per-channel Receiver so that sendFile can ask
// the Receiver to be its dispatcher-aware wait channel. This
// is the fix for the "sendfile silently hangs because the chat
// pump's Recv swallowed the Accept envelope" race: the Sender
// must not call ch.Recv directly when the dispatcher is also
// reading from the channel.
type channelState struct {
	ch  *protocol.Channel
	rcv *filetransfer.Receiver
}

type channelRegistry struct {
	mu sync.Mutex
	m  map[string]*channelState
}

func newChannelRegistry() *channelRegistry {
	return &channelRegistry{m: make(map[string]*channelState)}
}

// set installs state for peerID. If a Channel already exists for
// this peer, set() closes the new one and returns the existing
// one — the assumption is that the existing Channel was set up
// first and is in active use, and a concurrent re-handshake
// (caused by the announcer's periodic PeerAdded emissions) is
// the redundant one we want to drop.
//
// Returns true if state was installed, false if the existing one
// was kept.
func (r *channelRegistry) set(peerID []byte, st *channelState) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := string(peerID)
	if _, ok := r.m[key]; ok {
		return false
	}
	r.m[key] = st
	return true
}

func (r *channelRegistry) get(peerID []byte) *channelState {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.m[string(peerID)]
}

func (r *channelRegistry) delete(peerID []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if st, ok := r.m[string(peerID)]; ok {
		_ = st.ch.Close()
		delete(r.m, string(peerID))
	}
}

func (r *channelRegistry) closeAll() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, st := range r.m {
		_ = st.ch.Close()
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
func dialAndHandshake(ctx context.Context, id *identity.Identity, tr *transport.Transport, p *discovery.Peer, reg *channelRegistry, saveDir string) {
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
	// Use Transport.Dial, NOT transport.DialStandalone. The
	// former registers the Conn in the transport's registry, so
	// the heartbeat loop sends keepalives to it. DialStandalone
	// would skip registration and the conn would die from
	// read-deadline timeout after 60s of idle.
	conn, err := tr.Dial(dctx, tcpAddr)
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
	wrapChannel(ctx, conn, sess, reg, saveDir)
}

// handleInbound is the responder counterpart: another peer
// dialed us, ran the handshake; we accept and wrap.
func handleInbound(ctx context.Context, id *identity.Identity, conn *transport.Conn, reg *channelRegistry, saveDir string) {
	hctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	sess, err := handshake.RunAsResponder(hctx, id, conn)
	if err != nil {
		log.Printf("[ERROR] handshake (responder) from %s: %v", conn.RemoteAddr(), err)
		return
	}
	log.Printf("[HANDS] ok       peer=%s (responder)", peerHex(sess.RemotePeerID))
	wrapChannel(ctx, conn, sess, reg, saveDir)
}

// wrapChannel takes a freshly-handed-shaked Conn+Session and
// constructs a Channel. Starts:
//   - a Recv pump for chat traffic (text/ping/pong),
//   - a filetransfer.Receiver in the background to accept
//     incoming file offers.
//
// saveDir is where completed incoming files land. If empty,
// defaults to <home>/Downloads/innerlink.
func wrapChannel(ctx context.Context, conn *transport.Conn, sess *handshake.Session, reg *channelRegistry, saveDir string) {
	ch, err := protocol.NewChannel(conn, sess)
	if err != nil {
		log.Printf("[ERROR] new channel: %v", err)
		_ = conn.Close()
		return
	}
	// Single-pump dispatch loop. Channel.Recv is NOT safe to
	// call from multiple goroutines on the same Channel, so we
	// do exactly one Recv and route the envelope to the right
	// handler (chat or filetransfer) based on type.
	peerHexStr := peerHex(sess.RemotePeerID)
	rcv, err := filetransfer.NewReceiver(ch, saveDir, func(o filetransfer.FileOffer, _ string) error {
		log.Printf("[FILE] incoming peer=%s name=%q size=%d from=%s",
			peerHexStr, o.Name, o.Size, peerHexStr)
		return nil // accept everything by default
	}, peerHexStr)
	if err != nil {
		log.Printf("[ERROR] filetransfer receiver for %s: %v", peerHexStr, err)
		_ = ch.Close()
		return
	}
	if !reg.set(sess.RemotePeerID, &channelState{ch: ch, rcv: rcv}) {
		// Race lost: another Channel for this peer was installed
		// first. Close this one and bail without starting the
		// Recv goroutine — the winner's goroutine already owns
		// receive for this peer.
		log.Printf("[INFO ] channel superseded peer=%s (keeping existing)", peerHexStr)
		_ = ch.Close()
		return
	}
	log.Printf("[INFO ] channel ready peer=%s", peerHexStr)
	go func() {
		defer reg.delete(sess.RemotePeerID)
		for {
			if ctx.Err() != nil {
				return
			}
			env, err := ch.Recv(ctx)
			if err != nil {
				log.Printf("[INFO ] channel closed peer=%s (%v)", peerHexStr, err)
				return
			}
			switch env.Type {
			case protocol.TypeText:
				log.Printf("[MSG  ] in  <%s> %s", peerHexStr, string(env.Payload))
			case protocol.TypePing:
				log.Printf("[MSG  ] in  <%s> ping", peerHexStr)
				_ = ch.SendPing(ctx) // pong
			case protocol.TypePong:
				// ignore for v0.1
			default:
				// File traffic and anything else: let the
				// file receiver own it. Handle() is also
				// the dispatch point for the Sender's
				// wait channel — Accept / Done / Abort
				// envelopes get routed to whichever
				// Sender.Send() is blocked on WaitForReply.
				rcv.Handle(ctx, env)
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
		case "sendfile":
			if len(parts) < 3 {
				log.Println("[USAGE] sendfile <peer-id-hex> <local-path>")
			} else {
				sendFile(reg, parts[1], parts[2])
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
			log.Println("[HELP ] send <peer-id-hex> <text>   -- send a chat message")
			log.Println("[HELP ] sendfile <peer-id-hex> <path> -- send a file")
			log.Println("[HELP ] ping <peer-id-hex>           -- send a liveness probe")
			log.Println("[HELP ] peers                         -- (see [PEER] log lines)")
			log.Println("[HELP ] help                          -- this list")
			log.Println("[HELP ] quit                          -- exit")
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
	st := reg.get(pid)
	if st == nil {
		log.Printf("[ERROR] no active channel for peer %s", peerHex)
		return
	}
	if err := st.ch.SendText(context.Background(), text); err != nil {
		log.Printf("[ERROR] send: %v", err)
		return
	}
	log.Printf("[MSG  ] out >%s> %s", peerHex, text)
}

// sendFile streams a local file to the named peer. Blocking;
// the REPL doesn't accept new stdin until the transfer
// completes (or fails). Progress is logged every ~100ms.
func sendFile(reg *channelRegistry, peerHex, path string) {
	pid, err := hexToBytes(peerHex)
	if err != nil {
		log.Printf("[ERROR] bad peer id hex: %v", err)
		return
	}
	st := reg.get(pid)
	if st == nil {
		log.Printf("[ERROR] no active channel for peer %s", peerHex)
		return
	}
	progress := func(sent, total int64) {
		pct := int64(0)
		if total > 0 {
			pct = sent * 100 / total
		}
		log.Printf("[FILE] sending %s to %s  %d/%d bytes (%d%%)",
			path, peerHex, sent, total, pct)
	}
	log.Printf("[FILE] start send peer=%s path=%s", peerHex, path)
	if err := filetransfer.Send(context.Background(), st.ch, path, progress, st.rcv.WaitForReply); err != nil {
		log.Printf("[ERROR] sendfile: %v", err)
		return
	}
	log.Printf("[FILE] done peer=%s path=%s", peerHex, path)
}

func pingPeer(reg *channelRegistry, peerHex string) {
	pid, err := hexToBytes(peerHex)
	if err != nil {
		log.Printf("[ERROR] bad peer id hex: %v", err)
		return
	}
	st := reg.get(pid)
	if st == nil {
		log.Printf("[ERROR] no active channel for peer %s", peerHex)
		return
	}
	_ = st.ch.SendPing(context.Background())
	log.Printf("[MSG  ] out >%s> ping", peerHex)
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