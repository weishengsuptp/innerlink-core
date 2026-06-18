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
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/weishengsuptp/innerlink-core/internal/discovery"
	"github.com/weishengsuptp/innerlink-core/internal/filetransfer"
	"github.com/weishengsuptp/innerlink-core/internal/handshake"
	"github.com/weishengsuptp/innerlink-core/internal/identity"
	"github.com/weishengsuptp/innerlink-core/internal/logx"
	"github.com/weishengsuptp/innerlink-core/internal/paths"
	"github.com/weishengsuptp/innerlink-core/internal/protocol"
	"github.com/weishengsuptp/innerlink-core/internal/roster"
	"github.com/weishengsuptp/innerlink-core/internal/storage"
	"github.com/weishengsuptp/innerlink-core/internal/alias"
	"github.com/weishengsuptp/innerlink-core/internal/transport"
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("innerlink: %v", err)
	}
}

// defaultLogFile returns the default path of the innerlink
// log file. As of v0.5 this is just the cwd-relative path
// (the on-disk layout is owned by internal/paths). We keep
// this function as a thin shim so the flag default reads
// naturally: a future "innerlink.log under XDG state dir"
// change touches one place (paths.NewLayout), not every
// caller.
func defaultLogFile() string {
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
			"Empty disables file output. The default is "+
			"<cwd>/innerlink.log. The file is appended, so "+
			"successive runs share the same log.")
	udpPort := flag.Uint("udp-port", uint(discovery.DefaultPort),
		"UDP port for peer discovery. Default matches the "+
			"default discovery port. The e2e tests pick a free "+
			"port per node so multiple instances can run on "+
			"one machine.")
	tcpPort := flag.Uint("tcp-port", uint(transport.DefaultPort),
		"TCP port for incoming peer connections. Default "+
			"matches the default transport port. The e2e "+
			"tests pick a free port per node.")
	dataDir := flag.String("data-dir", "",
		"root directory for innerlink state (device.key, "+
			"aliases.json, chat.enc). Default: <cwd>/.innerlink. "+
			"Set this if you want a single shared state dir "+
			"across multiple invocations from different cwds.")
	deviceKey := flag.String("device-key", "",
		"path to the SM2 device key file. Default: "+
			"<data-dir>/device.key. The e2e tests use a "+
			"per-node temp file so two instances have "+
			"different PeerIDs and can talk to each other "+
			"without sharing a long-term identity.")
	saveDir := flag.String("save-dir", "",
		"directory for incoming files. Default: "+
			"<cwd>/received. The e2e tests use a per-node "+
			"temp dir so two instances don't share state.")
	bindIP := flag.String("bind", "0.0.0.0",
		"local IP to bind the UDP discovery socket to. "+
			"Default 0.0.0.0 (all interfaces). Set to a "+
			"specific IP (e.g. 127.0.0.1 on a dev box, or "+
			"192.168.40.5 for a single-NIC LAN host) so "+
			"the v0.5 roster publishes a routable address "+
			"instead of 0.0.0.0, which is not dialable.")
	flag.Parse()

	// All on-disk state and runtime files are described by a
	// single Layout. The flags above are overrides; everything
	// not overridden defaults to <cwd>/.innerlink for state and
	// <cwd>/received for incoming files. The Layout is the only
	// thing every subsystem needs to know about — no subsystem
	// should re-resolve its own paths from $HOME or hard-coded
	// constants.
	layout, err := paths.NewLayout("", paths.Overrides{
		DataDir:   *dataDir,
		DeviceKey: *deviceKey,
		SaveDir:   *saveDir,
		LogFile:   *logFile,
	})
	if err != nil {
		return fmt.Errorf("resolve paths: %w", err)
	}
	if err := layout.Ensure(); err != nil {
		return fmt.Errorf("create state dirs: %w", err)
	}
	log.Printf("[INFO ] data dir:        %s", layout.DataDir)
	log.Printf("[INFO ] incoming files:  %s", layout.Received)
	log.Printf("[INFO ] log file:        %s", layout.LogFile)

	if err := logx.Setup(logx.Options{
		Level:  logx.Level(*logLevel),
		File:   layout.LogFile,
		Stderr: true,
	}); err != nil {
		return fmt.Errorf("logx setup: %w", err)
	}
	defer logx.Close()

	// 1) Device identity.
	id, created, err := identity.LoadOrCreate(layout.DeviceKey)
	if err != nil {
		return fmt.Errorf("load identity: %w", err)
	}
	if created {
		log.Printf("[INFO ] device identity created peerID=%s", id.PeerIDHex())
	} else {
		log.Printf("[INFO ] device identity loaded  peerID=%s", id.PeerIDHex())
	}
	log.Printf("[INFO ] device key file: %s", layout.DeviceKey)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	// 2) UDP announcer.
	ann := discovery.NewAnnouncerOnPortBind(id, hostname(), uint16(*tcpPort), uint16(*udpPort), *bindIP)
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
	log.Printf("[INFO ] incoming files save dir: %s", layout.Received)

	// M3: encrypted chat log. The Store derives its SM4
	// key from id.PrivateKeyD(), so the same device.key
	// is what decrypts chat.enc on next launch. If the
	// file is missing (first launch) or unreadable
	// (wrong key) we treat both as "no history yet" —
	// the chat log is best-effort, never blocking the
	// user from chatting.
	//
	// Note: as of v0.5 the chat log lives inside the
	// data dir (<cwd>/.innerlink/chat.enc) rather than
	// next to received files. Splitting "internal state"
	// from "user-facing received files" makes the layout
	// easier to reason about and the test zone easier to
	// clean (rm -rf <test-dir>/.innerlink wipes state
	// without nuking received files).
	chatStore, err := storage.Open(layout.DataDir, id.PrivateKeyD())
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

	// M4: peer aliases. Lives next to the device key
	// inside the data dir. First launch creates the
	// file on the first Save; Open on a missing file
	// is fine.
	aliasStore, err := alias.Open(layout.Aliases)
	if err != nil {
		return fmt.Errorf("open alias file: %w", err)
	}
	defer func() {
		if err := aliasStore.Close(); err != nil {
			log.Printf("[ERROR] close alias file: %v", err)
		}
	}()
	log.Printf("[INFO ] alias file: %s", layout.Aliases)

	// M5: peer roster. The "phone book" of every peer
	// we've heard about on the LAN, kept loosely
	// consistent across nodes via gossip on every
	// channel-ready event. First launch creates the
	// file on the first Save; Open on a missing file
	// is fine.
	rosterStore, err := roster.Open(layout.Roster)
	if err != nil {
		return fmt.Errorf("open roster: %w", err)
	}
	defer func() {
		if err := rosterStore.Close(); err != nil {
			log.Printf("[ERROR] close roster: %v", err)
		}
	}()
	log.Printf("[INFO ] roster file: %s", layout.Roster)

	// Self entry. We always include ourselves in our
	// own roster so the first channel-ready send
	// already tells the other side "this is how you
	// reach me". The address is the local IP:port
	// the announcer is bound to — that's the address
	// remote peers will dial.
	selfEntry := roster.Entry{
		PeerID:   id.PeerIDHex(),
		Hostname: hostname(),
		Addrs:    []string{ann.LocalAddr()},
	}
	if _, err := rosterStore.Add(selfEntry); err != nil {
		return fmt.Errorf("roster: add self: %w", err)
	}
	log.Printf("[INFO ] self in roster: %s @ %s (%s)",
		selfEntry.PeerID, selfEntry.Hostname, selfEntry.Addrs[0])

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
				go handleInbound(ctx, id, inbound, channels, layout.Received, chatStore, historyPtr, aliasStore, rosterStore)
			}
		}
	}()

	// When discovery reports a peer added, dial it.
	go func() {
		for ev := range ann.Events() {
			switch ev.Type {
			case discovery.PeerAdded:
				log.Printf("[PEER ] joined   peer=%s at %s", peerHex(ev.PeerID), ev.Peer.Addr)
				aliasStore.Touch(peerHex(ev.PeerID))
				go dialAndHandshake(ctx, id, tr, ev.Peer, channels, layout.Received, chatStore, historyPtr, aliasStore, rosterStore)
			case discovery.PeerRemoved:
				log.Printf("[PEER ] left     peer=%s", peerHex(ev.PeerID))
			}
		}
	}()

	// Stdin command loop.
	go runStdinLoop(ctx, cancel, channels, chatStore, historyPtr, id, tr, layout.Received, aliasStore, rosterStore)

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
	ch     *protocol.Channel
	rcv    *filetransfer.Receiver
	peerID []byte // 16-byte raw peer id (key in the registry)
}

type channelRegistry struct {
	mu sync.Mutex
	m  map[string]*channelState
}

func newChannelRegistry() *channelRegistry {
	return &channelRegistry{m: make(map[string]*channelState)}
}

// snapshot returns a slice copy of all current channel
// states. Used by the M5 gossip fan-out (broadcast
// roster to every connected peer) and by any future
// "send to all" feature. The returned states are
// shallow copies of pointers — the underlying Channel
// is shared, so callers must not close them.
func (r *channelRegistry) snapshot() []*channelState {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*channelState, 0, len(r.m))
	for _, st := range r.m {
		out = append(out, st)
	}
	return out
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
func dialAndHandshake(ctx context.Context, id *identity.Identity, tr *transport.Transport, p *discovery.Peer, reg *channelRegistry, saveDir string, chatStore *storage.Store, history *[]*storage.Record, aliasStore *alias.Store, rosterStore *roster.Store) {
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
	wrapChannel(ctx, conn, sess, reg, saveDir, chatStore, history, id, aliasStore, rosterStore)
}

// handleInbound is the responder counterpart: another peer
// dialed us, ran the handshake; we accept and wrap.
func handleInbound(ctx context.Context, id *identity.Identity, conn *transport.Conn, reg *channelRegistry, saveDir string, chatStore *storage.Store, history *[]*storage.Record, aliasStore *alias.Store, rosterStore *roster.Store) {
	hctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	sess, err := handshake.RunAsResponder(hctx, id, conn)
	if err != nil {
		log.Printf("[ERROR] handshake (responder) from %s: %v", conn.RemoteAddr(), err)
		return
	}
	log.Printf("[HANDS] ok       peer=%s (responder)", peerHex(sess.RemotePeerID))
	wrapChannel(ctx, conn, sess, reg, saveDir, chatStore, history, id, aliasStore, rosterStore)
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
func dialAddr(ctx context.Context, id *identity.Identity, tr *transport.Transport, addr string, reg *channelRegistry, saveDir string, chatStore *storage.Store, history *[]*storage.Record, aliasStore *alias.Store, rosterStore *roster.Store) {
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
		wrapChannel(ctx, conn, sess, reg, saveDir, chatStore, history, id, aliasStore, rosterStore)
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
func wrapChannel(ctx context.Context, conn *transport.Conn, sess *handshake.Session, reg *channelRegistry, saveDir string, chatStore *storage.Store, history *[]*storage.Record, id *identity.Identity, aliasStore *alias.Store, rosterStore *roster.Store) {
	// M4: bump last_seen on every channel open. The
	// discovery layer also Touches on PeerAdded, so
	// a peer that announces but never connects still
	// shows up in the alias list with a recent
	// timestamp. Here we catch the case where a
	// peer connects (dial or accept) and we have a
	// confirmed handshake.
	aliasStore.Touch(peerHex(sess.RemotePeerID))

	// M5: same touch for the roster (the "phone book").
	// The handshake proves this peerID is real and
	// reachable; the roster is the long-term
	// "peers I've heard about" view, so an active
	// channel is the strongest possible signal that
	// the peer is current.
	rosterStore.Touch(peerHex(sess.RemotePeerID))

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
	if !reg.set(sess.RemotePeerID, &channelState{ch: ch, rcv: rcv, peerID: append([]byte(nil), sess.RemotePeerID...)}) {
		// Race lost: another Channel for this peer was installed
		// first. Close this one and bail without starting the
		// Recv goroutine — the winner's goroutine already owns
		// receive for this peer.
		log.Printf("[INFO ] channel superseded peer=%s (keeping existing)", peerHexStr)
		_ = ch.Close()
		return
	}
	log.Printf("[INFO ] channel ready peer=%s", peerHexStr)

	// M5 gossip: send our roster to the new peer
	// right now, so the LAN-wide peer directory
	// converges fast on connect. Both sides send,
	// both sides merge — a one-shot full-list
	// exchange is simpler than incremental diff
	// and the payload is tiny (a few KB even at
	// 100 peers).
	sendRosterSync(ctx, ch, rosterStore)
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
			aliasStore.Touch(peerHexStr)
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
				aliasStore.Touch(peerHexStr)
				_ = ch.SendPong(ctx) // reply with Pong, not another Ping
			case protocol.TypePong:
				// Receiver of the pong reply. Log it so
				// the user sees the round-trip, and bump
				// the alias last-seen timestamp.
				log.Printf("[MSG  ] in  <%s> pong", peerHexStr)
				aliasStore.Touch(peerHexStr)
			case protocol.TypeRosterSync:
				// M5: another node is telling us
				// about every peer it knows. We
				// merge the new entries into our
				// roster and log how many were
				// new. We don't act on the new
				// peers here (no auto-dial) —
				// that's the heartbeat's job, see
				// the periodic presence check in
				// run(). Triggering an immediate
				// dial would race the REPL and
				// surprise the user.
				var rs protocol.RosterSync
				if err := json.Unmarshal(env.Payload, &rs); err != nil {
					log.Printf("[ERROR] roster sync parse: %v", err)
					break
				}
				remote := make([]roster.Entry, 0, len(rs.Entries))
				for _, e := range rs.Entries {
					remote = append(remote, roster.Entry{
						PeerID:    e.PeerID,
						Hostname:  e.Hostname,
						Addrs:     e.Addrs,
						FirstSeen: e.FirstSeen,
					})
				}
				added, err := rosterStore.MergeFromGossip(remote)
				if err != nil {
					log.Printf("[ERROR] roster merge: %v", err)
					break
				}
				if err := rosterStore.Save(); err != nil {
					log.Printf("[ERROR] roster save: %v", err)
				}
				if len(added) > 0 {
					log.Printf("[ROSTER] sync from %s: %d new entries: %s",
						peerHexStr, len(added), strings.Join(added, ", "))
					// Push-on-change: we just learned
					// about new peers, so tell our
					// other connected peers too.
					// Without this, gossip only
					// propagates one hop per
					// channel-ready event.
					broadcastRosterToAll(ctx, reg, rosterStore, sess.RemotePeerID)
				} else {
					log.Printf("[ROSTER] sync from %s: 0 new (already known)", peerHexStr)
				}
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

// sendRosterSync encodes the local roster and ships
// it to one peer as a TypeRosterSync envelope. Called
// right after every channel-ready event so the LAN
// directory converges fast on the happy path
// (a fresh peer joins, a new direct connection
// happens). Errors are logged but not fatal — gossip
// is best-effort; missing one sync just delays
// convergence until the next channel opens.
func sendRosterSync(ctx context.Context, ch *protocol.Channel, store *roster.Store) {
	entries := store.List()
	wire := protocol.RosterSync{
		Entries: make([]protocol.RosterEntry, 0, len(entries)),
	}
	for _, e := range entries {
		wire.Entries = append(wire.Entries, protocol.RosterEntry{
			PeerID:    e.PeerID,
			Hostname:  e.Hostname,
			Addrs:     e.Addrs,
			FirstSeen: e.FirstSeen,
		})
	}
	payload, err := json.Marshal(wire)
	if err != nil {
		log.Printf("[ERROR] roster marshal: %v", err)
		return
	}
	if err := ch.Send(ctx, protocol.Envelope{
		Type:    protocol.TypeRosterSync,
		Payload: payload,
	}); err != nil {
		log.Printf("[ERROR] roster send: %v", err)
	}
}

// broadcastRosterToAll fans the local roster out to
// every active channel except the one we just
// received from. This is the "push-on-change" half of
// the gossip protocol: when B tells us about peer
// C, we now know C, so we tell A (and any other
// peers) too. Without this, gossip only propagates
// one hop per channel-ready event; with it, gossip
// spreads along the chain until every node knows
// every other node.
func broadcastRosterToAll(ctx context.Context, reg *channelRegistry, store *roster.Store, exclude []byte) {
	all := reg.snapshot()
	for _, st := range all {
		if bytes.Equal(st.peerID, exclude) {
			continue
		}
		sendRosterSync(ctx, st.ch, store)
	}
}

// runStdinLoop reads commands from stdin.
//
// Commands:
//   - send <peer-id-hex> <text>   send a chat message to a peer
//   - peers                        list known peers
//   - ping <peer-id-hex>           send a ping
//   - help                         list commands
//   - quit                         exit
func runStdinLoop(ctx context.Context, cancel context.CancelFunc, reg *channelRegistry, chatStore *storage.Store, history *[]*storage.Record, id *identity.Identity, tr *transport.Transport, saveDir string, aliasStore *alias.Store, rosterStore *roster.Store) {
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
				log.Println("[USAGE] send <peer-id-or-alias> <text>")
			} else {
				sendTo(reg, parts[1], parts[2], chatStore, history, id, aliasStore)
			}
		case "sendfile":
			if len(parts) < 3 {
				log.Println("[USAGE] sendfile <peer-id-or-alias> <local-path>")
			} else {
				sendFile(reg, parts[1], parts[2], aliasStore)
			}
		case "history":
			showHistory(*history, parts[1:], id, aliasStore)
		case "ping":
			if len(parts) < 2 {
				log.Println("[USAGE] ping <peer-id-or-alias>")
			} else {
				pingPeer(reg, parts[1], aliasStore)
			}
		case "alias":
			// alias <name> <peer-id-hex>  — assign
			// a friendly name to a peer. Names
			// are case-sensitive and must be
			// 1-64 chars (the alias package
			// validates). A peer can have at
			// most one alias; assigning a
			// second one overwrites the first.
			//
			// Bare `alias` (no args) lists all
			// aliases. `alias list` is also
			// accepted as an alias for the
			// listing command.
			switch len(parts) {
			case 1:
				listAliases(aliasStore)
			case 2:
				if parts[1] == "list" {
					listAliases(aliasStore)
				} else {
					log.Println("[USAGE] alias <name> <peer-id-hex>")
					log.Println("        alias    -- list all aliases")
				}
			default:
				if err := aliasStore.Set(parts[2], parts[1]); err != nil {
					log.Printf("[ERROR] alias: %v", err)
				} else {
					if err := aliasStore.Save(); err != nil {
						log.Printf("[ERROR] alias save: %v", err)
					} else {
						log.Printf("[INFO ] aliased %s -> %s", parts[1], parts[2])
					}
				}
			}
		case "unalias":
			// unalias <name-or-peer-id>  — drop
			// the alias for the given reference.
			// We resolve first because names
			// are easier to type than 32-char
			// hex, and the user usually
			// remembers the name.
			if len(parts) < 2 {
				log.Println("[USAGE] unalias <name-or-peer-id>")
			} else {
				pid, err := resolvePeerRef(aliasStore, parts[1])
				if err != nil {
					// Treat as raw peer id.
					pid = parts[1]
				}
				if err := aliasStore.Remove(pid); err != nil {
					log.Printf("[ERROR] unalias: %v", err)
				} else {
					if err := aliasStore.Save(); err != nil {
						log.Printf("[ERROR] alias save: %v", err)
					} else {
						log.Printf("[INFO ] unaliased %s", pid)
					}
				}
			}
		case "peers":
			showPeers(aliasStore)
		case "roster":
			// roster                        -- list every peer
			//                                in the LAN directory
			//                                (synced via gossip),
			//                                with online / offline
			//                                status per entry.
			// roster forget <peer-id-or-alias>
			//                              -- remove an entry
			//                                locally (we'll forget
			//                                we ever knew about
			//                                them; we won't gossip
			//                                this removal). To
			//                                permanently wipe from
			//                                all peers' views,
			//                                you'd need a removal
			//                                protocol — v0.5
			//                                doesn't have one.
			if len(parts) >= 2 && parts[1] == "forget" {
				if len(parts) < 3 {
					log.Println("[USAGE] roster forget <peer-id-or-alias>")
				} else {
					pid, err := resolvePeerRef(aliasStore, parts[2])
					if err != nil {
						// fall back: try the raw string as a peer id
						if len(parts[2]) != 32 {
							log.Printf("[ERROR] roster forget: %v", err)
						} else {
							pid = parts[2]
						}
					}
					if pid != "" {
						if err := rosterStore.Remove(pid); err != nil {
							log.Printf("[ERROR] roster forget: %v", err)
						} else {
							if err := rosterStore.Save(); err != nil {
								log.Printf("[ERROR] roster save: %v", err)
							} else {
								log.Printf("[INFO ] forgot %s from roster", pid)
							}
						}
					}
				}
			} else {
				showRoster(rosterStore, reg, id)
			}
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
				dialAddr(ctx, id, tr, parts[1], reg, saveDir, chatStore, history, aliasStore, rosterStore)
			}
		case "help":
			log.Println("[HELP ] send <peer-id-or-alias> <text> -- send a chat message")
			log.Println("[HELP ] sendfile <peer-id-or-alias> <path> -- send a file")
			log.Println("[HELP ] history [peer-id-or-alias]     -- show recent chat (filter by one peer)")
			log.Println("[HELP ] ping <peer-id-or-alias>         -- send a liveness probe")
			log.Println("[HELP ] alias                            -- show all aliases")
			log.Println("[HELP ] alias <name> <peer-id-hex>      -- name a peer")
			log.Println("[HELP ] unalias <name-or-peer-id>       -- drop an alias")
			log.Println("[HELP ] peers                            -- list known peers + aliases")
			log.Println("[HELP ] roster                           -- list LAN peer directory (M5 gossip)")
			log.Println("[HELP ] roster forget <peer-id-or-alias> -- drop a peer from the local directory")
			log.Println("[HELP ] dial <ip:port>                   -- connect directly (skip discovery)")
			log.Println("[HELP ] help                             -- this list")
			log.Println("[HELP ] quit                             -- exit")
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

func sendTo(reg *channelRegistry, peerRef, text string, chatStore *storage.Store, history *[]*storage.Record, id *identity.Identity, aliasStore *alias.Store) {
	// Accept either a 32-char hex peer id or a
	// user-typed alias. The cmd's REPL doesn't care
	// which one the user wrote; resolution is the
	// alias store's job.
	peerHex, err := resolvePeerRef(aliasStore, peerRef)
	if err != nil {
		log.Printf("[ERROR] %v", err)
		return
	}
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
func sendFile(reg *channelRegistry, peerRef, path string, aliasStore *alias.Store) {
	peerHex, err := resolvePeerRef(aliasStore, peerRef)
	if err != nil {
		log.Printf("[ERROR] %v", err)
		return
	}
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

func pingPeer(reg *channelRegistry, peerRef string, aliasStore *alias.Store) {
	peerHex, err := resolvePeerRef(aliasStore, peerRef)
	if err != nil {
		log.Printf("[ERROR] %v", err)
		return
	}
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

// resolvePeerRef maps a user-typed peer reference
// (either a 32-char hex peer id or a registered
// alias name) to a canonical 32-char hex peer id.
//
// The alias package does the heavy lifting; this
// wrapper just (1) returns friendly errors so the
// REPL can print them, and (2) treats a valid
// 32-char hex string as a no-op so power users
// don't have to register a name just to send a
// one-off message.
func resolvePeerRef(aliasStore *alias.Store, ref string) (string, error) {
	if aliasStore == nil {
		// Defensive: the cmd wires a non-nil
		// store at startup. If a future
		// refactor forgets, fall through
		// to the raw peer-id path.
		return ref, nil
	}
	if id, ok := aliasStore.ResolvePeerRef(ref); ok {
		return id, nil
	}
	return "", fmt.Errorf("unknown peer %q (use `peers` to list, `alias` to name)", ref)
}

// listAliases prints the alias table in a stable,
// human-friendly order. Used by `alias list` and
// also called internally by showPeers to keep the
// formatting consistent across REPL commands.
func listAliases(aliasStore *alias.Store) {
	rows := aliasStore.ListWithNames()
	if len(rows) == 0 {
		log.Printf("[INFO ] no aliases yet (use `alias <name> <peer-id-hex>` to add one)")
		return
	}
	for _, r := range rows {
		if r.Name == "" {
			// Placeholder row (Touch without
			// Set). Show it so the user
			// knows the peer exists; suggest
			// the alias command.
			log.Printf("[ALIAS] %s  (unnamed; alias it with: alias <name> %s)",
				r.PeerID, r.PeerID)
		} else {
			log.Printf("[ALIAS] %-32s  %s", r.PeerID, r.Name)
		}
	}
}

// showPeers prints the current alias table with a
// "last seen" timestamp per peer, sorted by recency
// desc so the most recent activity is at the top.
//
// Why a separate command from `alias list`:
// `peers` answers "who's out there right now?"
// while `alias list` answers "what names have I
// assigned?". They share the same backing table
// but the user's intent is different. We present
// `peers` in a "name + last_seen" two-column
// format because recency is the deciding factor
// showRoster prints the full M5 LAN peer directory —
// every peer we've heard about, whether or not we
// have an active channel to them right now. Each row
// shows the local presence state (online / offline
// / self) derived from the channelRegistry, plus the
// peerID and the address(es) we last heard for them.
//
// This is the "内网通/飞秋 user list" view: roster
// is the static phone book, presence is the live
// green-dot indicator. They are NOT synced from other
// nodes — your view of "who's online" is your own.
func showRoster(rosterStore *roster.Store, reg *channelRegistry, self *identity.Identity) {
	entries := rosterStore.List()
	if len(entries) == 0 {
		log.Printf("[INFO ] roster is empty (waiting for gossip from connected peers)")
		return
	}
	// Sort by peerID for stable output.
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].PeerID < entries[j].PeerID
	})
	selfID := self.PeerIDHex()
	online := 0
	log.Printf("[ROSTER] %d entries:", len(entries))
	for _, e := range entries {
		state := "offline"
		if e.PeerID == selfID {
			state = "self   "
		} else if reg.get([]byte(peerIDFromHex(e.PeerID))) != nil {
			state = "online "
			online++
		}
		hostname := e.Hostname
		if hostname == "" {
			hostname = "(no hostname)"
		}
		addrs := "(no addr)"
		if len(e.Addrs) > 0 {
			addrs = strings.Join(e.Addrs, ",")
		}
		log.Printf("[ROSTER] %s  %-20s  %s  %s",
			state, truncate(hostname, 20), truncate(addrs, 32), e.PeerID[:8]+"...")
	}
	log.Printf("[ROSTER] %d online / %d total", online, len(entries))
}

// peerIDFromHex is a tiny helper for showRoster —
// avoids duplicating the 16-byte slice conversion
// (the same dance that showPeers / peerHex already
// does elsewhere). Errors fall back to nil, which
// just means "not in the registry" — the row is
// marked offline. We don't propagate the error
// because a malformed roster entry from gossip
// should not crash the show command.
func peerIDFromHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != identity.PeerIDSize {
		return nil
	}
	return b
}

// truncate is the same line-length kludge that
// showPeers uses. Duplicated here rather than
// imported because helpers.go is the cmd-layer
// shared file and this is a one-liner.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 3 {
		return s[:n]
	}
	return s[:n-3] + "..."
}

// for "is this thing still online?".
func showPeers(aliasStore *alias.Store) {
	rows := aliasStore.ListWithNames()
	if len(rows) == 0 {
		log.Printf("[INFO ] no peers seen yet")
		return
	}
	// Sort by last_seen desc.
	sort.Slice(rows, func(i, j int) bool {
		return rows[i].LastSeen.After(rows[j].LastSeen)
	})
	log.Printf("[PEERS] %d known peer(s):", len(rows))
	for _, r := range rows {
		name := r.Name
		if name == "" {
			name = "(unnamed)"
		}
		// "5m ago" style is friendlier than
		// "2026-06-17T19:55:00Z" but we don't
		// want to pull in a fuzzy-time lib
		// just for this. Local time HH:MM:SS
		// is precise enough and matches the
		// user's wall clock.
		ago := r.LastSeen.Local().Format("2006-01-02 15:04:05")
		log.Printf("[PEERS] %-20s  last seen %s  (%s)", name, ago, r.PeerID)
	}
}
func showHistory(history []*storage.Record, args []string, id *identity.Identity, aliasStore *alias.Store) {
    // args is the slice after the "history" command
    // word. Empty = show all peers; one element =
    // filter to that peer (id or alias).
    var filterPeer string
    if len(args) >= 1 {
        var err error
        filterPeer, err = resolvePeerRef(aliasStore, args[0])
        if err != nil {
            log.Printf("[ERROR] %v", err)
            return
        }
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
