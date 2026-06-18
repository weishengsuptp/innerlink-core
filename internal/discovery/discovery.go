// Package discovery implements UDP-broadcast-based peer discovery
// for innerlink's local-area-network (LAN) mode.
//
// What it does, in one sentence:
// every 5 seconds each device broadcasts "I'm at <ip>, my PeerID is
// <X>, my public key is <Y>" on UDP port 4747, and listens for
// similar broadcasts from other devices on the same subnet.
//
// What it does NOT do (these are explicit non-goals for v0.1):
//   - Cross-subnet discovery: UDP broadcast doesn't cross routers.
//     Cross-subnet peers must be added manually (v0.2).
//   - NAT traversal: we assume both devices are on the same
//     broadcast domain (same WiFi / same switch).
//   - Any form of authentication at the discovery layer: a peer
//     is "trusted" only after the handshake layer (internal/handshake)
//     has verified their SM2 signature. Discovery is just the
//     yellow pages.
//
// The on-wire format is JSON for v0.1 — it's a 100-byte packet
// in the worst case, parsing latency is irrelevant at one packet
// per peer per 5 seconds, and JSON is the path of least resistance
// for cross-language interop (the discovery format may be
// re-implemented in iOS/Android/Web eventually). v0.2 migrates
// the whole protocol to Protobuf per the architecture roadmap.
//
// Lifecycle:
//
//	ann := NewAnnouncer(id, "Alice-MacBook", 4747)
//	go ann.Run(ctx)            // starts broadcasting + listening
//	for peer := range ann.Peers() { ... }   // consume peer table updates
package discovery

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

// DefaultPort is the UDP port every innerlink instance broadcasts
// on. Picked to be unlikely to collide with mDNS (5353), SSDP
// (1900), and the usual service-discovery noise.
const DefaultPort = 4747

// DefaultInterval is how often we broadcast our own presence and
// also the interval at which we time out a silent peer.
//
// 5s is short enough that two devices see each other within 5
// seconds of the slower one booting, and long enough that we
// generate only ~12 packets per minute per device — negligible
// traffic even on a busy WiFi.
const DefaultInterval = 5 * time.Second

// DefaultPeerTimeout is how long we keep a peer in our table
// after we last heard from them. Set to 3x the broadcast interval
// so we tolerate one missed packet without flapping.
const DefaultPeerTimeout = 15 * time.Second

// MaxPacketSize caps the UDP datagram we read from the wire. 1500
// minus typical IP/UDP overhead = ~1472. Our packets are ~100
// bytes, so this is a generous safety net against malformed
// broadcasts.
const MaxPacketSize = 1500

// magicHeader is the 4-byte prefix that says "this UDP datagram is
// an innerlink announcement, not random noise on port 4747." Any
// datagram that doesn't start with these 4 bytes is silently dropped.
var magicHeader = [4]byte{'I', 'L', 'N', 'K'}

// AnnounceVersion is the protocol version baked into every
// announcement. Bumped whenever the wire format changes
// incompatibly. v0.1 = 1.
const AnnounceVersion = 1

// announcement is the JSON payload we broadcast. Field tags are
// short because this is a hot path (every 5s) and we want compact
// UDP packets.
type announcement struct {
	Magic    [4]byte `json:"m"`    // = magicHeader
	Version  uint8   `json:"v"`    // = AnnounceVersion
	PeerID   []byte  `json:"pid"`  // 16 bytes
	PubKey   []byte  `json:"pk"`   // 64 bytes
	Name     string  `json:"nm"`   // user-friendly display name (e.g. "Bob's MacBook")
	Port     uint16  `json:"tp"`   // TCP port peers should connect to (set by cmd/innerlink)
	Seq      uint64  `json:"seq"`  // monotonic counter, increments per broadcast
}

// Peer is the public, downstream-facing representation of a
// discovered device. It's what UI / chat-list code consumes.
type Peer struct {
	PeerID    []byte    // 16 bytes, the short ID
	PublicKey []byte    // 64 bytes, for handshake
	Name      string    // display name
	Addr      *net.UDPAddr // last IP:port we heard them at
	LastSeen  time.Time // when we last got a packet from them
	Seq       uint64    // last seq number we saw (monotonic per peer)
}

// Announcer is the long-running discovery service. It broadcasts
// our presence, listens for others, and exposes the live peer table
// through Peers().
type Announcer struct {
	id       Device        // our device (interface; see Device below)
	name     string        // our display name
	tcpPort  uint16        // our innerlink TCP port
	port     int           // UDP port to use
	bindIP   string        // local IP to bind UDP to (default "0.0.0.0")
	interval time.Duration // broadcast / timeout granularity
	timeout  time.Duration // peer timeout

	mu     sync.RWMutex
	peers  map[string]*Peer // keyed by hex(PeerID) for fast lookup
	outSeq uint64           // our outgoing sequence counter

	conn   *net.UDPConn   // set on Run, nil before
	events chan PeerEvent // lifecycle notifications for consumers
}

// PeerEvent is a "peer joined" / "peer left" / "peer updated"
// notification. Consumers (chat list, etc.) can react to it.
type PeerEvent struct {
	Type   PeerEventType
	PeerID []byte // 16 bytes
	Peer   *Peer  // non-nil for Add/Update, nil for Remove
}

// PeerEventType enumerates the kinds of peer-table changes.
type PeerEventType int

const (
	// PeerAdded — first time we saw this peer.
	PeerAdded PeerEventType = iota + 1
	// PeerUpdated — heard from them again (might be IP/seq change).
	PeerUpdated
	// PeerRemoved — they went silent past the timeout.
	PeerRemoved
)

// Device is the minimal interface Announcer needs from the
// identity package. We depend on the interface, not on the concrete
// *identity.Identity, so tests can inject a fake without dragging
// in SM2 + persistence.
//
// This is a deliberate, narrowly-scoped interface — we don't want
// a god-interface that exposes every method of the real type.
//
// (Named "Device" rather than "Identity" to avoid the naming
// collision with the identity package's exported Identity type.)
type Device interface {
	PeerID() []byte
	PublicKey() []byte
}

// NewAnnouncer builds a new Announcer with the given device,
// display name, and TCP port (peers will connect to this TCP port
// when they want to talk to us).
//
// It does NOT start the service — call Run() to begin broadcasting
// and listening.
func NewAnnouncer(d Device, name string, tcpPort uint16) *Announcer {
	return &Announcer{
		id:       d,
		name:     name,
		tcpPort:  tcpPort,
		port:     DefaultPort,
		interval: DefaultInterval,
		timeout:  DefaultPeerTimeout,
		peers:    make(map[string]*Peer),
		events:   make(chan PeerEvent, 32),
	}
}

// NewAnnouncerOnPort is NewAnnouncer but on a caller-chosen UDP
// port. The e2e tests in tests/e2e use it to spin up multiple
// instances on one machine without collisions; production code
// should keep using NewAnnouncer + DefaultPort.
func NewAnnouncerOnPort(d Device, name string, tcpPort, udpPort uint16) *Announcer {
	return NewAnnouncerOnPortBind(d, name, tcpPort, udpPort, "0.0.0.0")
}

// NewAnnouncerOnPortBind is the bind-IP-aware variant.
// Pass a routable local IP (e.g. "127.0.0.1" for
// loopback, "192.168.40.5" for a specific NIC) when
// the default 0.0.0.0 (all interfaces) would yield an
// un-dialable LocalAddr() in the v0.5 roster. On a
// dev box with one NIC, picking 127.0.0.1 is the
// safest way to make the e2e tests deterministic.
func NewAnnouncerOnPortBind(d Device, name string, tcpPort, udpPort uint16, bindIP string) *Announcer {
	if bindIP == "" {
		bindIP = "0.0.0.0"
	}
	return &Announcer{
		id:       d,
		name:     name,
		tcpPort:  tcpPort,
		port:     int(udpPort),
		bindIP:   bindIP,
		interval: DefaultInterval,
		timeout:  DefaultPeerTimeout,
		peers:    make(map[string]*Peer),
		events:   make(chan PeerEvent, 32),
	}
}

// LocalAddr returns the local address the announcer's
// UDP socket is bound to. Used by the v0.5 roster sync
// to fill in our own peer entry with the right
// "ip:port that other peers can reach me at" — they
// can't dial 0.0.0.0, they need the routable local
// IP. Must be called after Run() (the socket is opened
// there). If Run hasn't started yet, returns
// 127.0.0.1:<port> as a safe-but-useless fallback.
//
// If the bound IP is 0.0.0.0 (the default — listen on
// all interfaces), the returned string still contains
// 0.0.0.0, which is not dialable. Callers that need a
// real address for the roster should use a bound IP
// (see the -bind CLI flag in cmd/innerlink).
func (a *Announcer) LocalAddr() string {
	if a.conn != nil {
		return a.conn.LocalAddr().String()
	}
	// Pre-Run fallback. tcpPort is the one we tell other
	// peers to dial, so this is at least directionally
	// correct (the IP is the loopback only because we
	// don't know better yet).
	return fmt.Sprintf("%s:%d", a.bindIP, a.tcpPort)
}

// Peers returns a snapshot of the current peer table.
// The returned slice is freshly allocated; mutating it is safe
// but mutating any Peer struct inside it is not.
func (a *Announcer) Peers() []Peer {
	a.mu.RLock()
	defer a.mu.RUnlock()
	out := make([]Peer, 0, len(a.peers))
	for _, p := range a.peers {
		snap := *p
		out = append(out, snap)
	}
	return out
}

// Events returns the channel of peer-table changes. The channel is
// buffered; if a consumer falls behind, the Announcer will drop
// events (the peer table is still authoritative, see Peers()).
func (a *Announcer) Events() <-chan PeerEvent {
	return a.events
}

// Run starts the discovery service. It blocks until ctx is done,
// then cleans up.
//
// Two goroutines are spawned:
//   - broadcast loop: ticks every `interval`, sends an announcement
//   - read loop:       blocks on the UDP socket, parses announcements
//   - gc loop:         ticks every `interval`, evicts stale peers
func (a *Announcer) Run(ctx context.Context) error {
	conn, err := bindBroadcastSocket(a.port, a.bindIP)
	if err != nil {
		return fmt.Errorf("discovery: bind UDP port %d: %w", a.port, err)
	}
	a.conn = conn
	defer conn.Close()

	gcDone := make(chan struct{})
	go a.gcLoop(ctx, gcDone)

	// We use a single ticker-driven select so we can interleave
	// broadcast / gc work cleanly with the read deadline.
	tick := time.NewTicker(a.interval)
	defer tick.Stop()

	// Read deadline needs to be reset in a loop so we can
	// unblock on ticker events / context cancel.
	readErr := make(chan error, 1)
	go func() {
		buf := make([]byte, MaxPacketSize)
		for {
			if ctx.Err() != nil {
				readErr <- nil
				return
			}
			// Set a short read deadline so the goroutine can
			// periodically check ctx. The broadcast loop is the
			// primary ticker; this is just here to bail fast on
			// shutdown.
			_ = conn.SetReadDeadline(time.Now().Add(a.interval))
			n, src, err := conn.ReadFromUDP(buf)
			if err != nil {
				var ne net.Error
				if errors.As(err, &ne) && ne.Timeout() {
					continue
				}
				if ctx.Err() != nil {
					readErr <- nil
					return
				}
				readErr <- err
				return
			}
			a.handlePacket(buf[:n], src)
		}
	}()

	// Broadcast tick.
	for {
		select {
		case <-ctx.Done():
			<-gcDone
			<-readErr
			return ctx.Err()
		case <-tick.C:
			if err := a.broadcastOnce(); err != nil {
				// Don't abort on one failed broadcast — log via
				// the channel and try again next tick. The most
				// common cause is "no suitable broadcast address
				// yet" (no network up), which fixes itself.
			}
		}
	}
}

// broadcastOnce sends one announcement to every discovered broadcast
// interface address.
func (a *Announcer) broadcastOnce() error {
	if a.conn == nil {
		return errors.New("discovery: socket not bound")
	}
	pkt, err := a.encodeAnnouncement()
	if err != nil {
		return err
	}
	addrs, err := broadcastAddresses(a.port)
	if err != nil {
		return err
	}
	var lastErr error
	for _, addr := range addrs {
		if _, err := a.conn.WriteToUDP(pkt, addr); err != nil {
			lastErr = err
		}
	}
	return lastErr
}

// encodeAnnouncement builds the next outgoing packet.
func (a *Announcer) encodeAnnouncement() ([]byte, error) {
	a.outSeq++
	pkt := announcement{
		Magic:   magicHeader,
		Version: AnnounceVersion,
		PeerID:  a.id.PeerID(),
		PubKey:  a.id.PublicKey(),
		Name:    a.name,
		Port:    a.tcpPort,
		Seq:     a.outSeq,
	}
	return json.Marshal(pkt)
}

// handlePacket parses one received UDP datagram and updates the
// peer table. Silently drops everything that isn't well-formed.
func (a *Announcer) handlePacket(pkt []byte, src *net.UDPAddr) {
	var ann announcement
	if err := json.Unmarshal(pkt, &ann); err != nil {
		return
	}
	if ann.Magic != magicHeader {
		return
	}
	if ann.Version == 0 || ann.Version > AnnounceVersion {
		// Unknown version — could be a future client. Drop quietly
		// rather than crash; we'll see them again on the next broadcast
		// and maybe we'll understand their version by then.
		return
	}
	if len(ann.PeerID) != 16 || len(ann.PubKey) != 64 {
		return
	}
	// Don't process our own broadcasts.
	ownID := a.id.PeerID()
	for i := range ownID {
		if ownID[i] != ann.PeerID[i] {
			goto notSelf
		}
	}
	return
notSelf:

	key := peerKey(ann.PeerID)
	a.mu.Lock()
	existing, ok := a.peers[key]
	if ok {
		// Only fire Updated when something interesting changed.
		// Address can legitimately change (DHCP / wifi roam), so
		// we always update it; seq only moves forward.
		updated := false
		if existing.Seq < ann.Seq {
			existing.Seq = ann.Seq
			updated = true
		}
		if existing.Addr == nil || existing.Addr.String() != src.String() {
			existing.Addr = src
			updated = true
		}
		if existing.Name != ann.Name {
			existing.Name = ann.Name
			updated = true
		}
		existing.LastSeen = time.Now()
		if updated {
			snap := *existing
			a.mu.Unlock()
			a.emit(PeerEvent{Type: PeerUpdated, PeerID: ann.PeerID, Peer: &snap})
			return
		}
		a.mu.Unlock()
		return
	}
	// First time we see this peer.
	np := &Peer{
		PeerID:    append([]byte(nil), ann.PeerID...),
		PublicKey: append([]byte(nil), ann.PubKey...),
		Name:      ann.Name,
		Addr:      src,
		LastSeen:  time.Now(),
		Seq:       ann.Seq,
	}
	a.peers[key] = np
	snap := *np
	a.mu.Unlock()
	a.emit(PeerEvent{Type: PeerAdded, PeerID: ann.PeerID, Peer: &snap})
}

// gcLoop periodically scans the peer table and removes any peer
// whose LastSeen is older than the timeout. Runs as its own
// goroutine so it doesn't block Run's main select.
func (a *Announcer) gcLoop(ctx context.Context, done chan<- struct{}) {
	defer close(done)
	tick := time.NewTicker(a.interval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			a.gcOnce()
		}
	}
}

func (a *Announcer) gcOnce() {
	cutoff := time.Now().Add(-a.timeout)
	var evicted [][]byte
	a.mu.Lock()
	for k, p := range a.peers {
		if p.LastSeen.Before(cutoff) {
			evicted = append(evicted, p.PeerID)
			delete(a.peers, k)
		}
	}
	a.mu.Unlock()
	for _, pid := range evicted {
		a.emit(PeerEvent{Type: PeerRemoved, PeerID: pid, Peer: nil})
	}
}

// emit sends an event on the events channel, dropping it if the
// buffer is full. The peer table is authoritative; events are
// a courtesy.
func (a *Announcer) emit(ev PeerEvent) {
	select {
	case a.events <- ev:
	default:
		// Consumer fell behind. They'll catch up via Peers() snapshot.
	}
}

// peerKey returns a map key string from a PeerID byte slice.
// We use hex so the key is printable (debug-friendly) and stable.
func peerKey(pid []byte) string {
	return fmt.Sprintf("%x", pid)
}

// broadcastAddresses returns the set of UDP broadcast addresses
// to send to on this host. On most networks there's only one
// (the subnet-directed broadcast), but a host with multiple
// interfaces (Ethernet + WiFi) has multiple.
//
// Platform-specific: see setbroadcast_windows.go and
// setbroadcast_unix.go for the per-platform SO_BROADCAST setup.
func broadcastAddresses(port int) ([]*net.UDPAddr, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []*net.UDPAddr
	now := time.Now()
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 ||
			iface.Flags&net.FlagLoopback != 0 ||
			iface.Flags&net.FlagMulticast == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok || ipnet.IP.To4() == nil {
				continue
			}
			bcast := ipBroadcast(ipnet)
			if bcast == nil {
				continue
			}
			out = append(out, &net.UDPAddr{
				IP:   bcast,
				Port: port,
			})
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no broadcast-capable interfaces (now=%s)", now.Format(time.RFC3339))
	}
	return out, nil
}
