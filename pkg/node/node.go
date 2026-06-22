package node

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/weishengsuptp/innerlink-core/internal/alias"
	"github.com/weishengsuptp/innerlink-core/internal/discovery"
	"github.com/weishengsuptp/innerlink-core/internal/filetransfer"
	"github.com/weishengsuptp/innerlink-core/internal/handshake"
	"github.com/weishengsuptp/innerlink-core/internal/identity"
	"github.com/weishengsuptp/innerlink-core/internal/logx"
	"github.com/weishengsuptp/innerlink-core/internal/paths"
	"github.com/weishengsuptp/innerlink-core/internal/protocol"
	"github.com/weishengsuptp/innerlink-core/internal/roster"
	"github.com/weishengsuptp/innerlink-core/internal/storage"
	"github.com/weishengsuptp/innerlink-core/internal/transport"
)

// Node is the long-lived innerlink runtime.
//
// Construct one with New, start it with Start, drive it
// with SendText/SendFile/SubscribeMessages/etc., and stop
// it with Close. A Node is a single network identity: it
// owns one device.key, one chat.enc, one roster.json,
// one alias table, and one or more active encrypted
// channels (one per peer).
//
// A single process can run multiple Nodes if you give
// them distinct Options (different DataDir / DeviceKey
// / TCPPort). The default is one Node per process.
type Node struct {
	opts Options // user-provided, defaults applied

	// Persistent state (loaded from disk on New, written
	// back as needed).
	id          *identity.Identity
	layout      paths.Layout
	chatStore   *storage.Store
	aliasStore  *alias.Store
	rosterStore *roster.Store

	// Networking.
	ann       *discovery.Announcer
	tr        *transport.Transport
	channels  *channelRegistry
	autoScan  *autoScanState
	myIPs     []string // local IPs we treat as "self" for scan dedup

	// Lifecycle.
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	mu     sync.Mutex
	closed bool

	// Event channels for the public subscribe API.
	// messageCh receives every inbound + outbound chat
	// message as the dispatcher pump processes them.
	// peerEventCh receives peer add/remove/online/offline
	// transitions. Both are buffered to absorb short bursts
	// from gossip storms.
	messageCh   chan Message
	peerEventCh chan PeerEvent

	// In-memory chat history cache. Source of truth is
	// the encrypted chat.enc on disk; this slice is just
	// a fast lookup for History().
	historyMu sync.Mutex
	history   []*storage.Record
}

// New constructs a Node. It loads (or creates) the SM2
// device identity and opens the persistent state files
// (chat log, aliases, roster). It does NOT start any
// networking — call Start for that.
//
// Safe to call multiple times in one process with
// different opts (different DataDir / TCPPort); each
// Node owns its own goroutines and listeners.
func New(opts Options) (*Node, error) {
	opts = opts.applyDefaults()

	layout, err := paths.NewLayout("", paths.Overrides{
		DataDir:   opts.DataDir,
		DeviceKey: opts.DeviceKey,
		SaveDir:   opts.SaveDir,
		LogFile:   opts.LogFile,
	})
	if err != nil {
		return nil, fmt.Errorf("resolve paths: %w", err)
	}
	if err := layout.Ensure(); err != nil {
		return nil, fmt.Errorf("create state dirs: %w", err)
	}
	if err := logx.Setup(logx.Options{
		Level:  logx.Level(opts.LogLevel),
		File:   layout.LogFile,
		Stderr: true,
	}); err != nil {
		return nil, fmt.Errorf("logx setup: %w", err)
	}
	log.Printf("[INFO ] data dir:        %s", layout.DataDir)
	log.Printf("[INFO ] incoming files:  %s", layout.Received)
	log.Printf("[INFO ] log file:        %s", layout.LogFile)

	id, created, err := identity.LoadOrCreate(layout.DeviceKey)
	if err != nil {
		return nil, fmt.Errorf("load identity: %w", err)
	}
	if created {
		log.Printf("[INFO ] device identity created peerID=%s", id.PeerIDHex())
	} else {
		log.Printf("[INFO ] device identity loaded  peerID=%s", id.PeerIDHex())
	}
	log.Printf("[INFO ] device key file: %s", layout.DeviceKey)

	chatStore, err := storage.Open(layout.DataDir, id.PrivateKeyD())
	if err != nil {
		return nil, fmt.Errorf("open chat log: %w", err)
	}
	aliasStore, err := alias.Open(layout.Aliases)
	if err != nil {
		_ = chatStore.Close()
		return nil, fmt.Errorf("open alias file: %w", err)
	}
	rosterStore, err := roster.Open(layout.Roster)
	if err != nil {
		_ = chatStore.Close()
		_ = aliasStore.Close()
		return nil, fmt.Errorf("open roster: %w", err)
	}

	n := &Node{
		opts:        opts,
		id:          id,
		layout:      layout,
		chatStore:   chatStore,
		aliasStore:  aliasStore,
		rosterStore: rosterStore,
		channels:    newChannelRegistry(),
		messageCh:   make(chan Message, 64),
		peerEventCh: make(chan PeerEvent, 64),
	}

	// Self entry in the roster: always include ourselves
	// so the first channel-ready send already tells the
	// other side "this is how you reach me".
	announcer := discovery.NewAnnouncerOnPortBind(id, hostname(), uint16(opts.TCPPort), uint16(opts.UDPPort), opts.BindIP)
	selfEntry := roster.Entry{
		PeerID:   id.PeerIDHex(),
		Hostname: hostname(),
		Addrs:    []string{announcer.LocalAddr()},
	}
	if _, err := rosterStore.Add(selfEntry); err != nil {
		return nil, fmt.Errorf("roster: add self: %w", err)
	}
	log.Printf("[INFO ] self in roster: %s @ %s (%s)",
		selfEntry.PeerID, selfEntry.Hostname, selfEntry.Addrs[0])

	n.ann = announcer
	n.myIPs = []string{announcer.LocalAddr()}
	n.autoScan = newAutoScanState(n.myIPs)

	log.Printf("[INFO ] alias file: %s", layout.Aliases)
	log.Printf("[INFO ] roster file: %s", layout.Roster)
	log.Printf("[INFO ] chat log: %d records loaded", 0) // placeholder; filled in Start

	return n, nil
}

// Start launches the UDP announcer, TCP transport,
// inbound dispatcher, discovery-driven dials, and
// (if Options.AutoScan is set) the auto-scan loop.
// Returns once Listen succeeds; goroutines run until
// Close is called.
//
// The provided ctx is used as the parent context —
// canceling it is equivalent to calling Close.
func (n *Node) Start(ctx context.Context) error {
	if n.ann == nil {
		return fmt.Errorf("node: Start called before New")
	}
	if n.ctx != nil {
		return fmt.Errorf("node: already started")
	}
	n.ctx, n.cancel = context.WithCancel(ctx)

	// Load chat history now (after storage is open).
	history, err := n.chatStore.ReadAll()
	if err != nil {
		log.Printf("[ERROR] read chat log: %v (starting with empty history)", err)
		history = nil
	}
	n.historyMu.Lock()
	n.history = history
	n.historyMu.Unlock()
	log.Printf("[INFO ] chat log: %d records loaded", len(history))

	// 1) UDP announcer.
	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		if err := n.ann.Run(n.ctx); err != nil && n.ctx.Err() == nil {
			log.Printf("[ERROR] announcer: %v", err)
		}
	}()

	// 2) TCP transport. CRITICAL: bind + Listen BEFORE
	// printing the "listening for peers on TCP :N" log
	// line. The e2e tests (and the v0.6 CLI's `dial`
	// path) gate on that exact log line; if we log
	// before the bind syscall completes, a fast caller
	// can dial and hit "connectex: No connection could
	// be made" before the kernel finishes the bind.
	// The Windows CI runner is slow enough that this
	// race fires reliably; local Windows / Linux / macOS
	// have a 10-100x gap between log flush and bind,
	// which is why v0.6.x never caught it.
	n.tr = transport.NewTransportOnPortBind(n.opts.TCPPort, n.opts.BindIP)
	if err := n.tr.Listen(); err != nil {
		return fmt.Errorf("transport listen: %w", err)
	}
	log.Printf("[INFO ] listening for peers on UDP :%d", n.opts.UDPPort)
	log.Printf("[INFO ] listening for peers on TCP :%d", n.opts.TCPPort)
	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		if err := n.tr.Run(n.ctx); err != nil && n.ctx.Err() == nil {
			log.Printf("[ERROR] transport: %v", err)
		}
	}()

	// 3) Inbound dispatcher.
	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		for {
			select {
			case <-n.ctx.Done():
				return
			case inbound, ok := <-n.tr.Inbounds():
				if !ok {
					return
				}
				n.wg.Add(1)
				go func() {
					defer n.wg.Done()
					n.handleInbound(inbound)
				}()
			}
		}
	}()

	// 4) Discovery → dial.
	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		for ev := range n.ann.Events() {
			switch ev.Type {
			case discovery.PeerAdded:
				log.Printf("[PEER ] joined   peer=%s at %s", peerHex(ev.PeerID), ev.Peer.Addr)
				n.aliasStore.Touch(peerHex(ev.PeerID))
				n.publishPeerEvent(PeerEvent{Type: PeerAdded, PeerID: peerHex(ev.PeerID), Addr: ev.Peer.Addr.String()})
				n.wg.Add(1)
				go func() {
					defer n.wg.Done()
					n.dialAndHandshake(ev.Peer)
				}()
			case discovery.PeerRemoved:
				log.Printf("[PEER ] left     peer=%s", peerHex(ev.PeerID))
				n.publishPeerEvent(PeerEvent{Type: PeerRemoved, PeerID: peerHex(ev.PeerID)})
			}
		}
	}()

	// 5) Optional auto-scan loop.
	if n.opts.AutoScan {
		log.Printf("[INFO ] auto-scan: ENABLED (will probe new /24s as roster learns of them)")
		n.wg.Add(1)
		go func() {
			defer n.wg.Done()
			n.autoScanLoop()
		}()
	} else {
		log.Printf("[INFO ] auto-scan: disabled (use AutoScan=true to enable)")
	}

	return nil
}

// Close shuts down the Node: cancels context, closes
// listeners + channels, flushes persistent state.
// Safe to call multiple times.
func (n *Node) Close() error {
	n.mu.Lock()
	if n.closed {
		n.mu.Unlock()
		return nil
	}
	n.closed = true
	n.mu.Unlock()

	if n.cancel != nil {
		n.cancel()
	}
	n.channels.closeAll()
	if n.tr != nil {
		n.tr.Close()
	}
	// Announcer has no Close() — Run() exits when ctx is
	// canceled (defer conn.Close inside Run), so cancelling
	// n.ctx above is enough to bring it down.
	n.wg.Wait()

	if n.chatStore != nil {
		if err := n.chatStore.Close(); err != nil {
			log.Printf("[ERROR] close chat log: %v", err)
		}
	}
	if n.aliasStore != nil {
		if err := n.aliasStore.Close(); err != nil {
			log.Printf("[ERROR] close alias file: %v", err)
		}
	}
	if n.rosterStore != nil {
		if err := n.rosterStore.Close(); err != nil {
			log.Printf("[ERROR] close roster: %v", err)
		}
	}
	_ = logx.Close()
	close(n.messageCh)
	close(n.peerEventCh)
	return nil
}

// SelfPeerID returns our own 32-char hex PeerID.
func (n *Node) SelfPeerID() string {
	return n.id.PeerIDHex()
}

// --- internal orchestration (called by the dispatcher
//     pumps and the public methods) ---

// appendHistory adds a record to the in-memory history
// cache. Source of truth is the encrypted chat.enc file;
// this slice is a fast lookup for the History() public
// API and for the CLI's `history` command.
func (n *Node) appendHistory(rec *storage.Record) {
	n.historyMu.Lock()
	n.history = append(n.history, rec)
	n.historyMu.Unlock()
}

func (n *Node) publishMessage(msg Message) {
	select {
	case n.messageCh <- msg:
	default:
		// Channel full — drop the oldest by draining one
		// and retrying. The UI is best-effort and the
		// encrypted local log is the source of truth.
		select {
		case <-n.messageCh:
		default:
		}
		select {
		case n.messageCh <- msg:
		default:
		}
	}
}

func (n *Node) publishPeerEvent(ev PeerEvent) {
	select {
	case n.peerEventCh <- ev:
	default:
		select {
		case <-n.peerEventCh:
		default:
		}
		select {
		case n.peerEventCh <- ev:
		default:
		}
	}
}

// dialAndHandshake is the discovery-driven initiator:
// dials the peer's TCP endpoint, runs the handshake,
// wraps the resulting Channel. If a Channel already
// exists for this peer, this is a no-op (the announcer
// fires every announce interval, so the same peer can
// re-trigger PeerAdded; without this guard we'd
// double-handshake and tear down the first channel).
func (n *Node) dialAndHandshake(p *discovery.Peer) {
	if p.Addr == nil {
		return
	}
	if n.channels.get(p.PeerID) != nil {
		return
	}
	tcpAddr := fmt.Sprintf("%s:%d", p.Addr.IP.String(), transport.DefaultPort)
	dctx, cancel := context.WithTimeout(n.ctx, 5*time.Second)
	defer cancel()
	// Use Transport.Dial, NOT transport.DialStandalone. The
	// former registers the Conn in the transport's registry,
	// so the heartbeat loop sends keepalives to it.
	// DialStandalone would skip registration and the conn
	// would die from read-deadline timeout after 60s of idle.
	conn, err := n.tr.Dial(dctx, tcpAddr)
	if err != nil {
		log.Printf("[ERROR] dial %s: %v", tcpAddr, err)
		return
	}
	sess, err := handshake.RunAsInitiator(dctx, n.id, conn)
	if err != nil {
		log.Printf("[ERROR] handshake (initiator) with %s: %v", peerHex(p.PeerID), err)
		return
	}
	log.Printf("[HANDS] ok       peer=%s (initiator)", peerHex(p.PeerID))
	n.wrapChannel(conn, sess)
}

// handleInbound is the responder counterpart: another
// peer dialed us, ran the handshake; we accept and wrap.
func (n *Node) handleInbound(conn *transport.Conn) {
	hctx, cancel := context.WithTimeout(n.ctx, 5*time.Second)
	defer cancel()
	sess, err := handshake.RunAsResponder(hctx, n.id, conn)
	if err != nil {
		log.Printf("[ERROR] handshake (responder) from %s: %v", conn.RemoteAddr(), err)
		return
	}
	log.Printf("[HANDS] ok       peer=%s (responder)", peerHex(sess.RemotePeerID))
	n.wrapChannel(conn, sess)
}

// dialAddr is the manual-connect counterpart to
// dialAndHandshake: skips UDP discovery and goes
// straight to transport.Dial + handshake. Returns
// immediately; the handshake runs in a goroutine.
//
// Used by the CLI `dial <addr>` command and any
// future "force connect" UI button. Cross-VLAN /
// cross-subnet peers don't show up in the UDP
// yellow-pages, so this is the escape hatch.
func (n *Node) dialAddr(addr string) {
	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		dctx, cancel := context.WithTimeout(n.ctx, 5*time.Second)
		defer cancel()
		conn, err := n.tr.Dial(dctx, addr)
		if err != nil {
			log.Printf("[ERROR] dial %s: %v", addr, err)
			return
		}
		sess, err := handshake.RunAsInitiator(dctx, n.id, conn)
		if err != nil {
			log.Printf("[ERROR] handshake (initiator) with %s: %v", addr, err)
			return
		}
		if n.channels.get(sess.RemotePeerID) != nil {
			return
		}
		log.Printf("[HANDS] ok       peer=%s (initiator) addr=%s", peerHex(sess.RemotePeerID), addr)
		n.wrapChannel(conn, sess)
	}()
}

// wrapChannel takes a freshly-handed-shaked Conn+Session
// and constructs a Channel. Starts the dispatcher pump
// for inbound envelopes on that Channel.
func (n *Node) wrapChannel(conn *transport.Conn, sess *handshake.Session) {
	// M4: bump last_seen on every channel open.
	n.aliasStore.Touch(peerHex(sess.RemotePeerID))
	// M5: same touch for the roster.
	n.rosterStore.Touch(peerHex(sess.RemotePeerID))

	ch, err := protocol.NewChannel(conn, sess)
	if err != nil {
		log.Printf("[ERROR] new channel: %v", err)
		_ = conn.Close()
		return
	}
	// v0.5.2: mark this peer's /24 as known so auto-scan
	// doesn't re-enqueue it.
	n.autoScan.MarkConnectedSubnet(ch.RemoteAddr())

	peerHexStr := peerHex(sess.RemotePeerID)
	rcv, err := filetransfer.NewReceiver(ch, n.layout.Received, func(o filetransfer.FileOffer, _ string) error {
		log.Printf("[FILE] incoming peer=%s name=%q size=%d from=%s",
			peerHexStr, o.Name, o.Size, peerHexStr)
		return nil // accept everything by default; UI may add a confirmation hook
	}, peerHexStr)
	if err != nil {
		log.Printf("[ERROR] filetransfer receiver for %s: %v", peerHexStr, err)
		_ = ch.Close()
		return
	}
	if !n.channels.set(sess.RemotePeerID, &channelState{ch: ch, rcv: rcv, peerID: append([]byte(nil), sess.RemotePeerID...)}) {
		log.Printf("[INFO ] channel superseded peer=%s (keeping existing)", peerHexStr)
		_ = ch.Close()
		return
	}
	log.Printf("[INFO ] channel ready peer=%s", peerHexStr)
	n.publishPeerEvent(PeerEvent{Type: PeerOnline, PeerID: peerHexStr})

	// M5 gossip: send our roster to the new peer right now,
	// so the LAN-wide peer directory converges fast on connect.
	n.sendRosterSync(ch)
	// v0.5.3: also send our scan history.
	n.sendScanHistory(ch)

	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		defer n.channels.delete(sess.RemotePeerID)
		defer n.publishPeerEvent(PeerEvent{Type: PeerOffline, PeerID: peerHexStr})
		for {
			if n.ctx.Err() != nil {
				return
			}
			env, err := ch.Recv(n.ctx)
			if err != nil {
				log.Printf("[INFO ] channel closed peer=%s (%v)", peerHexStr, err)
				return
			}
			switch env.Type {
			case protocol.TypeText:
				log.Printf("[MSG  ] in  <%s> %s", peerHexStr, string(env.Payload))
				n.aliasStore.Touch(peerHexStr)
				rec := &storage.Record{
					Timestamp: time.Now().UTC(),
					From:      peerHexStr,
					To:        n.id.PeerIDHex(),
					Direction: "in",
					Body:      string(env.Payload),
					MsgID:     "",
				}
				if err := n.chatStore.Append(rec); err != nil {
					log.Printf("[ERROR] chat log append: %v", err)
				}
				n.appendHistory(rec)
				n.publishMessage(Message{
					PeerID: peerHexStr, Body: string(env.Payload),
					Timestamp: rec.Timestamp, Direction: "in",
				})
			case protocol.TypePing:
				log.Printf("[MSG  ] in  <%s> ping", peerHexStr)
				n.aliasStore.Touch(peerHexStr)
				_ = ch.SendPong(n.ctx)
			case protocol.TypePong:
				log.Printf("[MSG  ] in  <%s> pong", peerHexStr)
				n.aliasStore.Touch(peerHexStr)
			case protocol.TypeRosterSync:
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
				added, err := n.rosterStore.MergeFromGossip(remote)
				if err != nil {
					log.Printf("[ERROR] roster merge: %v", err)
					break
				}
				if err := n.rosterStore.Save(); err != nil {
					log.Printf("[ERROR] roster save: %v", err)
				}
				if len(added) > 0 {
					log.Printf("[ROSTER] sync from %s: %d new entries: %s",
						peerHexStr, len(added), strings.Join(added, ", "))
					n.broadcastRosterToAll(sess.RemotePeerID)
					if n.autoScan != nil {
						n.broadcastScanHistoryToAll(sess.RemotePeerID)
					}
					if n.autoScan != nil {
						for _, peerID := range added {
							entry, err := n.rosterStore.Get(peerID)
							if err == nil {
								n.autoScan.EnqueueIfNew(entry.Addrs)
							}
						}
					}
				} else {
					log.Printf("[ROSTER] sync from %s: 0 new (already known)", peerHexStr)
				}
			case protocol.TypeScanHistory:
				var sh protocol.ScanHistory
				if err := json.Unmarshal(env.Payload, &sh); err != nil {
					log.Printf("[ERROR] scan-history unmarshal: %v", err)
					break
				}
				if n.autoScan != nil {
					for _, c := range sh.Scanned {
						n.autoScan.MarkScanned(c)
					}
					if len(sh.Scanned) > 0 {
						log.Printf("[SCAN-HIST] learned %d scanned subnet(s) from %s",
							len(sh.Scanned), peerHexStr)
					}
				}
			default:
				// File traffic + anything else: hand off
				// to the file receiver. Handle() is also
				// the dispatch point for the Sender's
				// WaitForReply (Accept / Done / Abort).
				rcv.Handle(n.ctx, env)
			}
		}
	}()
}

// sendRosterSync encodes the local roster and ships it
// to a single peer.
func (n *Node) sendRosterSync(ch *protocol.Channel) {
	entries := n.rosterStore.List()
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
		log.Printf("[ERROR] roster sync marshal: %v", err)
		return
	}
	if err := ch.Send(n.ctx, protocol.Envelope{
		Type:    protocol.TypeRosterSync,
		Payload: payload,
	}); err != nil {
		log.Printf("[ERROR] roster sync send: %v", err)
	}
}

// broadcastRosterToAll fans the local roster out to
// every active channel except the one specified by
// exclude (the peer we just received from — pushing
// back to it is wasted bytes).
func (n *Node) broadcastRosterToAll(exclude []byte) {
	all := n.channels.snapshot()
	for _, st := range all {
		if string(st.peerID) == string(exclude) {
			continue
		}
		n.sendRosterSync(st.ch)
	}
}

// sendScanHistory sends the v0.5.3 scan-history gossip
// envelope to one peer.
func (n *Node) sendScanHistory(ch *protocol.Channel) {
	_, seen := n.autoScan.Queue().Snapshot()
	wire := protocol.ScanHistory{Scanned: seen}
	payload, err := json.Marshal(wire)
	if err != nil {
		log.Printf("[ERROR] scan-history marshal: %v", err)
		return
	}
	if err := ch.Send(n.ctx, protocol.Envelope{
		Type:    protocol.TypeScanHistory,
		Payload: payload,
	}); err != nil {
		log.Printf("[ERROR] scan-history send: %v", err)
	}
}

// broadcastScanHistoryToAll fans the local scan history
// out to every active channel except the one specified.
func (n *Node) broadcastScanHistoryToAll(exclude []byte) {
	all := n.channels.snapshot()
	for _, st := range all {
		if string(st.peerID) == string(exclude) {
			continue
		}
		n.sendScanHistory(st.ch)
	}
}

// autoScanLoop is the Node method that runs the auto-scan
// queue consumer. It calls Scan for each subnet the
// queue produces, then marks the subnet as known via
// MarkScanned so a future roster update doesn't re-enqueue.
//
// Single-goroutine by design — sequential scans prevent
// overloading the LAN when several /24s get gossiped at
// once. MarkScanned happens after the scan returns so
// a transient failure doesn't permanently skip the subnet.
func (n *Node) autoScanLoop() {
	for {
		select {
		case <-n.ctx.Done():
			return
		case cidr := <-n.autoScan.queue.ch:
			log.Printf("[AUTOSCAN] %s (triggered by new roster entry)", cidr)
			err := n.Scan(n.ctx, cidr)
			n.autoScan.MarkScanned(cidr)
			if err != nil && n.ctx.Err() == nil {
				log.Printf("[ERROR] auto-scan %s: %v", cidr, err)
			}
		}
	}
}

// --- shared bits moved out of cmd/innerlink/main.go ---

// defaultLogFile returns the default log file path.
// Kept here so flag default strings read naturally.
func defaultLogFile() string {
	return "innerlink.log"
}

// shutdownDelay gives in-flight ops a moment to drain
// after ctx is canceled. The CLI sleeps 200ms; we
// preserve that here for callers that want a graceful
// shutdown pause.
const shutdownDelay = 200 * time.Millisecond

// keep os import referenced.
var _ = os.Stderr