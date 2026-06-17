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
	"github.com/weishengsuptp/innerlink-core/internal/storage"
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
	udpPort := flag.Uint("udp-port", uint(discovery.DefaultPort),
		"UDP port for peer discovery. Default matches the "+
			"default discovery port. The e2e tests pick a free "+
			"port per node so multiple instances can run on "+
			"one machine.")
	tcpPort := flag.Uint("tcp-port", uint(transport.DefaultPort),
		"TCP port for incoming peer connections. Default "+
			"matches the default transport port. The e2e "+
			"tests pick a free port per node.")
	deviceKey := flag.String("device-key", "",
		"path to the SM2 device key file. Empty (the "+
			"default) means ~/.innerlink/device.key. The e2e "+
			"tests use a per-node temp file so two instances "+
			"have different PeerIDs and can talk to each "+
			"other without sharing a long-term identity.")
	saveDir := flag.String("save-dir", "",
		"directory for incoming files and the encrypted "+
			"chat log (chat.enc). Empty (the default) means "+
			"~/Downloads/innerlink. The e2e tests use a per-"+
			"node temp dir so two instances don't share "+
			"a single chat.enc.")
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
	keyPath, err := resolveDeviceKey(*deviceKey)
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
	ann := discovery.NewAnnouncerOnPort(id, hostname(), uint16(*tcpPort), uint16(*udpPort))
	go func() {
		if err := ann.Run(ctx); err != nil && ctx.Err() == nil {
			log.Printf("[ERROR] announcer: %v", err)
		}
	}()

	// 3) TCP transport.
	tr := transport.NewTransportOnPort(int(*tcpPort))
	if err := tr.Listen(); err != nil {
		return fmt.Errorf("transport listen: %w", err)
	}
	log.Printf("[INFO ] listening for peers on UDP :%d", *udpPort)
	log.Printf("[INFO ] listening for peers on TCP :%d", *tcpPort)
	go func() {
		if err := tr.Run(ctx); err != nil && ctx.Err() == nil {
			log.Printf("[ERROR] transport: %v", err)
		}
	}()

	// Save dir for incoming files AND for the encrypted
	// chat log (chat.enc). Created on first use by the
	// Receiver and the Storage layer.
	resolvedSaveDir, err := resolveSaveDir(*saveDir)
	if err != nil {
		return fmt.Errorf("resolve save dir: %w", err)
	}
	log.Printf("[INFO ] incoming files save dir: %s", resolvedSaveDir)

	// M3: encrypted chat log. The Store derives its SM4
	// key from id.PrivateKeyD(), so the same device.key
	// is what decrypts chat.enc on next launch. If the
	// file is missing (first launch) or unreadable
	// (wrong key) we treat both as "no history yet" —
	// the chat log is best-effort, never blocking the
	// user from chatting.
	chatStore, err := storage.Open(resolvedSaveDir, id.PrivateKeyD())
	if err != nil {
		return fmt.Errorf("open chat log: %w", err)
	}
	defer func() {
		if err := chatStore.Close(); err != nil {
			log.Printf("[ERROR] close chat log: %v", err)
		}
	}()
	history, err := chatStore.ReadAll()
	if err != nil {
		log.Printf("[ERROR] read chat log: %v (starting with empty history)", err)
		history = nil
	}
	historyPtr := &history
	log.Printf("[INFO ] chat log: %d records loaded", len(history))

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
				go handleInbound(ctx, id, inbound, channels, resolvedSaveDir, chatStore, historyPtr)
			}
		}
	}()

	// When discovery reports a peer added, dial it.
	go func() {
		for ev := range ann.Events() {
			switch ev.Type {
			case discovery.PeerAdded:
				log.Printf("[PEER ] joined   peer=%s at %s", peerHex(ev.PeerID), ev.Peer.Addr)
				go dialAndHandshake(ctx, id, tr, ev.Peer, channels, resolvedSaveDir, chatStore, historyPtr)
			case discovery.PeerRemoved:
				log.Printf("[PEER ] left     peer=%s", peerHex(ev.PeerID))
			}
		}
	}()

	// Stdin command loop.
	go runStdinLoop(ctx, cancel, channels, chatStore, historyPtr, id, tr, resolvedSaveDir)

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
func dialAndHandshake(ctx context.Context, id *identity.Identity, tr *transport.Transport, p *discovery.Peer, reg *channelRegistry, saveDir string, chatStore *storage.Store, history *[]*storage.Record) {
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
	wrapChannel(ctx, conn, sess, reg, saveDir, chatStore, history, id)
}

// handleInbound is the responder counterpart: another peer
// dialed us, ran the handshake; we accept and wrap.
func handleInbound(ctx context.Context, id *identity.Identity, conn *transport.Conn, reg *channelRegistry, saveDir string, chatStore *storage.Store, history *[]*storage.Record) {
	hctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	sess, err := handshake.RunAsResponder(hctx, id, conn)
	if err != nil {
		log.Printf("[ERROR] handshake (responder) from %s: %v", conn.RemoteAddr(), err)
		return
	}
	log.Printf("[HANDS] ok       peer=%s (responder)", peerHex(sess.RemotePeerID))
	wrapChannel(ctx, conn, sess, reg, saveDir, chatStore, history, id)
}

// dialAddr is the manual-connect counterpart to
// dialAndHandshake: it skips the UDP discovery path
// and goes straight to transport.Dial + handshake.
// Returns immediately; the handshake runs in a
// background goroutine.
//
// Why this exists: the discovery layer deliberately
// skips loopback interfaces, so two innerlink
// instances on the same host (which is what the e2e
// tests in tests/e2e do) never see each other over
// UDP. The dial command lets a user / test force
// the connection. It's also a useful escape hatch
// for cross-subnet peers, where the broadcast
// yellow pages can't reach.
func dialAddr(ctx context.Context, id *identity.Identity, tr *transport.Transport, addr string, reg *channelRegistry, saveDir string, chatStore *storage.Store, history *[]*storage.Record) {
	go func() {
		dctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		conn, err := tr.Dial(dctx, addr)
		if err != nil {
			log.Printf("[ERROR] dial %s: %v", addr, err)
			return
		}
		sess, err := handshake.RunAsInitiator(dctx, id, conn)
		if err != nil {
			log.Printf("[ERROR] handshake (initiator) with %s: %v", addr, err)
			return
		}
		// We don't know the peerID until the handshake
		// finishes. Now we do. Use the same guard
		// dialAndHandshake uses (but inline, since we
		// don't have a *discovery.Peer).
		if reg.get(sess.RemotePeerID) != nil {
			return
		}
		log.Printf("[HANDS] ok       peer=%s (initiator) addr=%s", peerHex(sess.RemotePeerID), addr)
		wrapChannel(ctx, conn, sess, reg, saveDir, chatStore, history, id)
	}()
}

// wrapChannel takes a freshly-handed-shaked Conn+Session and
// constructs a Channel. Starts:
//   - a Recv pump for chat traffic (text/ping/pong),
//   - a filetransfer.Receiver in the background to accept
//     incoming file offers.
//
// saveDir is where completed incoming files land. If empty,
// defaults to <home>/Downloads/innerlink.
func wrapChannel(ctx context.Context, conn *transport.Conn, sess *handshake.Session, reg *channelRegistry, saveDir string, chatStore *storage.Store, history *[]*storage.Record, id *identity.Identity) {
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
				// Persist incoming text to the local
				// encrypted log. We record From = the
				// peer's PeerID (not our own), To = our
				// own, so the history reads naturally
				// when filtered by peer.
				rec := &storage.Record{
					Timestamp: time.Now().UTC(),
					From:      peerHexStr,
					To:        id.PeerIDHex(),
					Direction: "in",
					Body:      string(env.Payload),
					MsgID:     "", // M3 v0.1: not exposed
				}
				if err := chatStore.Append(rec); err != nil {
					log.Printf("[ERROR] chat log append: %v", err)
				}
				*history = append(*history, rec)
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
func runStdinLoop(ctx context.Context, cancel context.CancelFunc, reg *channelRegistry, chatStore *storage.Store, history *[]*storage.Record, id *identity.Identity, tr *transport.Transport, saveDir string) {
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
				sendTo(reg, parts[1], parts[2], chatStore, history, id)
			}
		case "sendfile":
			if len(parts) < 3 {
				log.Println("[USAGE] sendfile <peer-id-hex> <local-path>")
			} else {
				sendFile(reg, parts[1], parts[2])
			}
		case "history":
			showHistory(*history, parts[1:], id)
		case "ping":
			if len(parts) < 2 {
				log.Println("[USAGE] ping <peer-id-hex>")
			} else {
				pingPeer(reg, parts[1])
			}
		case "peers":
			log.Printf("[INFO ] no peer listing in v0.1; check the [PEER] log lines above")
		case "dial":
			// dial <ip:port>  -- bypass UDP discovery and
			// connect directly to a known peer. Useful in
			// two cases:
			//   1. e2e tests on a single host (loopback
			//      is not in the broadcast set; see
			//      internal/discovery.broadcastAddresses).
			//   2. cross-subnet peers (the discovery
			//      yellow-pages only work on the local
			//      broadcast domain). Production users
			//      can `dial 192.168.2.5:4748` to reach
			//      a peer on a different subnet.
			if len(parts) < 2 {
				log.Println("[USAGE] dial <ip:port>")
			} else {
				dialAddr(ctx, id, tr, parts[1], reg, saveDir, chatStore, history)
			}
		case "help":
			log.Println("[HELP ] send <peer-id-hex> <text>   -- send a chat message")
			log.Println("[HELP ] sendfile <peer-id-hex> <path> -- send a file")
			log.Println("[HELP ] history [peer-id-hex]         -- show recent chat (optionally with one peer)")
			log.Println("[HELP ] ping <peer-id-hex>           -- send a liveness probe")
			log.Println("[HELP ] dial <ip:port>               -- connect directly (skip discovery)")
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

func sendTo(reg *channelRegistry, peerHex, text string, chatStore *storage.Store, history *[]*storage.Record, id *identity.Identity) {
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
	// Persist the outgoing message to the encrypted
	// local log. We only get here on successful send
	// (SendText returned nil), so a write failure
	// is not "user typed in vain" — it means the
	// peer already saw the message, the disk just
	// didn't keep a copy. Log the failure but don't
	// surface it to the user (they can't do anything
	// about a write failure mid-REPL).
	rec := &storage.Record{
		Timestamp: time.Now().UTC(),
		From:      id.PeerIDHex(),
		To:        peerHex,
		Direction: "out",
		Body:      text,
		MsgID:     "", // M3 v0.1: not exposed in protocol yet
	}
	if err := chatStore.Append(rec); err != nil {
		log.Printf("[ERROR] chat log append: %v", err)
	}
	*history = append(*history, rec)
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
	// Run Send in a background goroutine so the REPL
	// stays responsive while the file is in flight. Send
	// blocks for as long as the transfer takes (could be
	// minutes for multi-GiB files) and the REPL's
	// bufio.Scanner is on the same goroutine as sendFile
	// — if Send ran inline here, every keystroke the
	// user typed during the transfer would sit unread in
	// the stdin buffer until Send returned. The user
	// would not be able to send chat, ping, or even
	// "quit" while a 2 GiB file was in flight. The cost
	// of running Send in a goroutine is one extra stack
	// frame and a slightly noisier log (send / done
	// interleaving with anything the user types), which
	// is the right trade.
	go func() {
		if err := filetransfer.Send(context.Background(), st.ch, path, progress, st.rcv.WaitForReply); err != nil {
			log.Printf("[ERROR] sendfile: %v", err)
			return
		}
		log.Printf("[FILE] done peer=%s path=%s", peerHex, path)
	}()
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
func showHistory(history []*storage.Record, args []string, id *identity.Identity) {
    // args is the slice after the "history" command
    // word. Empty = show all peers; one element =
    // filter to that peer-id-hex.
    var filterPeer string
    if len(args) >= 1 {
        pid, err := hexToBytes(args[0])
        if err != nil {
            log.Printf("[ERROR] bad peer id hex: %v", err)
            return
        }
        filterPeer = identityHex(pid)
    }
    if len(history) == 0 {
        log.Printf("[INFO ] no chat history yet")
        return
    }
    // Show the last 50 records, oldest first within
    // the slice (so the user reads top-down). If
    // filterPeer is set, also restrict to records
    // where the OTHER side is filterPeer �� we accept
    // both directions since the user may have typed
    // either From or To of the record.
    const limit = 50
    start := 0
    if len(history) > limit {
        start = len(history) - limit
    }
    shown := 0
    for i := start; i < len(history); i++ {
        r := history[i]
        if filterPeer != "" && r.From != filterPeer && r.To != filterPeer {
            continue
        }
        arrow := ">"
        if r.Direction == "in" {
            arrow = "<"
        }
        // We log with the timestamp in local time so
        // the user can map it to "this morning" / "last
        // night" without having to do TZ math in their
        // head. The on-disk format is UTC.
        local := r.Timestamp.Local()
        log.Printf("[HIST ] %s %s %s %s", local.Format("2006-01-02 15:04:05"), arrow, r.From, r.Body)
        shown++
    }
    if shown == 0 {
        if filterPeer != "" {
            log.Printf("[INFO ] no history with peer %s", filterPeer)
        }
    }
}
