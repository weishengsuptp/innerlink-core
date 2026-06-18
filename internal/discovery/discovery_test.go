package discovery

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"sync"
	"testing"
	"time"
)

// fakeDevice implements the Device interface without dragging in
// SM2 — keeps discovery tests fast and platform-independent.
type fakeDevice struct {
	peerID []byte
	pubKey []byte
}

func (f *fakeDevice) PeerID() []byte   { return f.peerID }
func (f *fakeDevice) PublicKey() []byte { return f.pubKey }

func newFakeDevice(seed byte) *fakeDevice {
	pid := bytes.Repeat([]byte{seed}, 16)
	pk := bytes.Repeat([]byte{seed}, 64)
	return &fakeDevice{peerID: pid, pubKey: pk}
}

func TestIPBroadcast(t *testing.T) {
	tests := []struct {
		ipnet string
		want  string
	}{
		{"192.168.1.10/24", "192.168.1.255"},
		{"10.0.0.1/8", "10.255.255.255"},
		{"172.16.5.7/24", "172.16.5.255"},
		{"192.168.1.0/30", "192.168.1.3"},
	}
	for _, tt := range tests {
		_, ipnet, err := net.ParseCIDR(tt.ipnet)
		if err != nil {
			t.Fatal(err)
		}
		got := ipBroadcast(ipnet)
		if got == nil {
			t.Errorf("ipBroadcast(%s) = nil", tt.ipnet)
			continue
		}
		if got.String() != tt.want {
			t.Errorf("ipBroadcast(%s) = %s, want %s", tt.ipnet, got, tt.want)
		}
	}
}

func TestAnnouncementJSONRoundtrip(t *testing.T) {
	dev := newFakeDevice(0xAA)
	a := NewAnnouncer(dev, "test-host", 4748)
	pkt, err := a.encodeAnnouncement()
	if err != nil {
		t.Fatal(err)
	}
	var ann announcement
	if err := json.Unmarshal(pkt, &ann); err != nil {
		t.Fatal(err)
	}
	if ann.Magic != magicHeader {
		t.Errorf("magic = %v, want %v", ann.Magic, magicHeader)
	}
	if ann.Version != AnnounceVersion {
		t.Errorf("version = %d, want %d", ann.Version, AnnounceVersion)
	}
	if !bytes.Equal(ann.PeerID, dev.PeerID()) {
		t.Error("PeerID mismatch")
	}
	if !bytes.Equal(ann.PubKey, dev.PublicKey()) {
		t.Error("PubKey mismatch")
	}
	if ann.Name != "test-host" {
		t.Errorf("name = %q, want %q", ann.Name, "test-host")
	}
	if ann.Port != 4748 {
		t.Errorf("port = %d, want 4748", ann.Port)
	}
	if ann.Seq != 1 {
		t.Errorf("seq = %d, want 1", ann.Seq)
	}
}

func TestEncodeAnnouncementIncrementsSeq(t *testing.T) {
	a := NewAnnouncer(newFakeDevice(0xBB), "x", 1234)
	for i := 1; i <= 5; i++ {
		pkt, _ := a.encodeAnnouncement()
		var ann announcement
		_ = json.Unmarshal(pkt, &ann)
		if ann.Seq != uint64(i) {
			t.Errorf("seq = %d, want %d", ann.Seq, i)
		}
	}
}

func TestHandlePacketIgnoresBadMagic(t *testing.T) {
	a := NewAnnouncer(newFakeDevice(0x01), "x", 1234)
	// Random bytes with no magic prefix.
	bad := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00}
	a.handlePacket(bad, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4747})
	if got := a.Peers(); len(got) != 0 {
		t.Errorf("peer table has %d entries, want 0", len(got))
	}
}

func TestHandlePacketIgnoresShortFields(t *testing.T) {
	a := NewAnnouncer(newFakeDevice(0x01), "x", 1234)
	ann := announcement{
		Magic:   magicHeader,
		Version: AnnounceVersion,
		PeerID:  make([]byte, 15), // wrong size
		PubKey:  make([]byte, 64),
		Name:    "evil",
		Port:    1,
	}
	pkt, _ := json.Marshal(ann)
	a.handlePacket(pkt, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4747})
	if got := a.Peers(); len(got) != 0 {
		t.Errorf("peer table has %d entries, want 0", len(got))
	}
}

func TestHandlePacketIgnoresOwnBroadcast(t *testing.T) {
	dev := newFakeDevice(0xCD)
	a := NewAnnouncer(dev, "self", 1234)
	ann := announcement{
		Magic:   magicHeader,
		Version: AnnounceVersion,
		PeerID:  dev.PeerID(),
		PubKey:  dev.PublicKey(),
		Name:    "self",
		Port:    1234,
		Seq:     1,
	}
	pkt, _ := json.Marshal(ann)
	a.handlePacket(pkt, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4747})
	if got := a.Peers(); len(got) != 0 {
		t.Errorf("peer table contains our own announcement: %d entries", len(got))
	}
}

func TestHandlePacketIgnoresUnknownVersion(t *testing.T) {
	a := NewAnnouncer(newFakeDevice(0x01), "x", 1234)
	ann := announcement{
		Magic:   magicHeader,
		Version: AnnounceVersion + 100, // future
		PeerID:  bytes.Repeat([]byte{0x02}, 16),
		PubKey:  bytes.Repeat([]byte{0x02}, 64),
		Name:    "future",
		Port:    1,
	}
	pkt, _ := json.Marshal(ann)
	a.handlePacket(pkt, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4747})
	if got := a.Peers(); len(got) != 0 {
		t.Errorf("peer table accepted unknown version: %d entries", len(got))
	}
}

func TestHandlePacketAddsPeer(t *testing.T) {
	me := newFakeDevice(0x01)
	a := NewAnnouncer(me, "me", 1234)
	other := newFakeDevice(0x02)
	ann := announcement{
		Magic:   magicHeader,
		Version: AnnounceVersion,
		PeerID:  other.PeerID(),
		PubKey:  other.PublicKey(),
		Name:    "alice",
		Port:    5555,
		Seq:     1,
	}
	pkt, _ := json.Marshal(ann)
	src := &net.UDPAddr{IP: net.IPv4(192, 168, 1, 100), Port: 4747}
	a.handlePacket(pkt, src)

	peers := a.Peers()
	if len(peers) != 1 {
		t.Fatalf("peer count = %d, want 1", len(peers))
	}
	if peers[0].Name != "alice" {
		t.Errorf("name = %q, want %q", peers[0].Name, "alice")
	}
	if peers[0].Addr.String() != src.String() {
		t.Errorf("addr = %s, want %s", peers[0].Addr, src)
	}
	if !bytes.Equal(peers[0].PublicKey, other.PublicKey()) {
		t.Error("public key mismatch")
	}
}

func TestHandlePacketUpdatesSeqAndEmitsEvent(t *testing.T) {
	me := newFakeDevice(0x01)
	a := NewAnnouncer(me, "me", 1234)
	other := newFakeDevice(0x02)
	src := &net.UDPAddr{IP: net.IPv4(192, 168, 1, 100), Port: 4747}

	// First broadcast.
	ann1 := announcement{
		Magic:   magicHeader,
		Version: AnnounceVersion,
		PeerID:  other.PeerID(),
		PubKey:  other.PublicKey(),
		Name:    "alice",
		Port:    5555,
		Seq:     1,
	}
	pkt1, _ := json.Marshal(ann1)
	a.handlePacket(pkt1, src)

	// Drain the Added event so it doesn't fill the buffer.
	select {
	case <-a.Events():
	case <-time.After(100 * time.Millisecond):
		t.Fatal("expected PeerAdded event")
	}

	// Second broadcast with higher seq.
	ann2 := ann1
	ann2.Seq = 2
	ann2.Name = "alice-renamed"
	pkt2, _ := json.Marshal(ann2)
	a.handlePacket(pkt2, src)

	select {
	case ev := <-a.Events():
		if ev.Type != PeerUpdated {
			t.Errorf("event type = %d, want PeerUpdated", ev.Type)
		}
		if ev.Peer.Seq != 2 {
			t.Errorf("seq = %d, want 2", ev.Peer.Seq)
		}
		if ev.Peer.Name != "alice-renamed" {
			t.Errorf("name = %q, want %q", ev.Peer.Name, "alice-renamed")
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("expected PeerUpdated event")
	}
}

func TestHandlePacketStaleSeqDoesNotEmit(t *testing.T) {
	me := newFakeDevice(0x01)
	a := NewAnnouncer(me, "me", 1234)
	other := newFakeDevice(0x02)
	src := &net.UDPAddr{IP: net.IPv4(192, 168, 1, 100), Port: 4747}

	// Add with seq=5.
	ann := announcement{
		Magic:   magicHeader,
		Version: AnnounceVersion,
		PeerID:  other.PeerID(),
		PubKey:  other.PublicKey(),
		Name:    "alice",
		Port:    5555,
		Seq:     5,
	}
	pkt, _ := json.Marshal(ann)
	a.handlePacket(pkt, src)
	<-a.Events()

	// Re-send with seq=3 (older). No Updated event should fire.
	ann.Seq = 3
	pkt, _ = json.Marshal(ann)
	a.handlePacket(pkt, src)

	select {
	case ev := <-a.Events():
		t.Errorf("got unexpected event for stale seq: %+v", ev)
	case <-time.After(50 * time.Millisecond):
		// expected
	}
}

func TestGCRemovesStalePeers(t *testing.T) {
	me := newFakeDevice(0x01)
	a := NewAnnouncer(me, "me", 1234)
	a.timeout = 50 * time.Millisecond
	a.interval = 25 * time.Millisecond

	other := newFakeDevice(0x02)
	src := &net.UDPAddr{IP: net.IPv4(192, 168, 1, 100), Port: 4747}
	ann := announcement{
		Magic:   magicHeader,
		Version: AnnounceVersion,
		PeerID:  other.PeerID(),
		PubKey:  other.PublicKey(),
		Name:    "alice",
		Port:    5555,
		Seq:     1,
	}
	pkt, _ := json.Marshal(ann)
	a.handlePacket(pkt, src)
	<-a.Events() // drain Add

	if len(a.Peers()) != 1 {
		t.Fatalf("expected 1 peer before GC")
	}

	// Wait long enough for the peer to time out.
	time.Sleep(100 * time.Millisecond)
	a.gcOnce()

	if len(a.Peers()) != 0 {
		t.Errorf("peer still in table after timeout")
	}

	select {
	case ev := <-a.Events():
		if ev.Type != PeerRemoved {
			t.Errorf("event type = %d, want PeerRemoved", ev.Type)
		}
	case <-time.After(50 * time.Millisecond):
		t.Fatal("expected PeerRemoved event after GC")
	}
}

func TestPeerKeyStable(t *testing.T) {
	pid := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}
	if got := peerKey(pid); got != "0102030405060708090a0b0c0d0e0f10" {
		t.Errorf("peerKey = %q", got)
	}
}

func TestPeersReturnsSnapshot(t *testing.T) {
	me := newFakeDevice(0x01)
	a := NewAnnouncer(me, "me", 1234)
	other := newFakeDevice(0x02)
	src := &net.UDPAddr{IP: net.IPv4(192, 168, 1, 100), Port: 4747}
	ann := announcement{
		Magic:   magicHeader,
		Version: AnnounceVersion,
		PeerID:  other.PeerID(),
		PubKey:  other.PublicKey(),
		Name:    "alice",
		Port:    5555,
		Seq:     1,
	}
	pkt, _ := json.Marshal(ann)
	a.handlePacket(pkt, src)

	// Mutate the returned snapshot — internal state must be unaffected.
	peers := a.Peers()
	peers[0].Name = "TAMPERED"
	if a.Peers()[0].Name == "TAMPERED" {
		t.Error("Peers() did not return a defensive copy")
	}
}

func TestRunCancelsCleanly(t *testing.T) {
	me := newFakeDevice(0x01)
	a := NewAnnouncer(me, "me", 1234)
	a.interval = 50 * time.Millisecond
	a.timeout = 100 * time.Millisecond
	a.port = 0 // ephemeral; pick a free one for the test

	// Use port 0: bindBroadcastSocket will pick a real port from the OS.
	// Then we have to remember that for cleanup, but the OS will reclaim
	// it when conn.Close() runs.

	// Override bindBroadcastSocket via a wrapper? Actually NewAnnouncer
	// doesn't bind — only Run does. So set port to 0 and let the OS pick.
	// But we need to capture the port back so we can release it cleanly.
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()
	time.Sleep(100 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Error("expected ctx.Err on Run return")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after ctx cancel")
	}
}

// twoAnnouncersLoopback exchanges a single announcement between two
// Announcers on a loopback socket pair, exercising the full parse +
// handle path without needing a real network.
func TestTwoAnnouncersLoopback(t *testing.T) {
	if testing.Short() {
		t.Skip("loopback test needs sockets")
	}
	me := newFakeDevice(0xAA)
	other := newFakeDevice(0xBB)

	// Set up two UDP sockets on a random port, exchange packets
	// in both directions.
	c1, c2 := loopbackPair(t)
	defer c1.Close()
	defer c2.Close()

	// Build an announcement packet from "other" and send it to c1.
	annA := NewAnnouncer(me, "me", 11111)
	otherAnn := NewAnnouncer(other, "other", 22222)
	_ = annA
	_ = otherAnn

	// Send a packet from c2 → c1, simulating a remote broadcast.
	pkt, err := makePacket(other, "other-host", 22222, 1)
	if err != nil {
		t.Fatal(err)
	}
	c1.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c2.WriteToUDP(pkt, c1.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1500)
	n, _, err := c1.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("loopback read: %v", err)
	}

	annA.handlePacket(buf[:n], &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 22222})

	peers := annA.Peers()
	if len(peers) != 1 {
		t.Fatalf("expected 1 peer, got %d", len(peers))
	}
	if peers[0].Name != "other-host" {
		t.Errorf("name = %q", peers[0].Name)
	}
}

// loopbackPair creates two UDP sockets on the same ephemeral port
// bound to 127.0.0.1, connected to each other. It's the smallest
// "fake network" we can build without external interfaces.
func loopbackPair(t *testing.T) (*net.UDPConn, *net.UDPConn) {
	t.Helper()
	a, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	b, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	// Cross-connect.
	aConn, err := net.DialUDP("udp4", nil, b.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	bConn, err := net.DialUDP("udp4", nil, a.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	_ = aConn
	_ = bConn
	return a, b
}

// makePacket builds a raw announcement packet for the given device.
func makePacket(d *fakeDevice, name string, tcpPort uint16, seq uint64) ([]byte, error) {
	ann := announcement{
		Magic:   magicHeader,
		Version: AnnounceVersion,
		PeerID:  d.PeerID(),
		PubKey:  d.PublicKey(),
		Name:    name,
		Port:    tcpPort,
		Seq:     seq,
	}
	return json.Marshal(ann)
}

// ---------------------------------------------------------------------------
// LocalAddr / pickLocalIPv4 — v0.5 "by default, just works on LAN"
// ---------------------------------------------------------------------------

// TestPickLocalIPv4_NotEmpty just sanity-checks the
// helper doesn't panic and returns something. On a
// developer box with at least one non-loopback NIC
// (which is every machine on a LAN), this returns a
// real IPv4. In a CI container with only loopback,
// it returns "0.0.0.0" — we still want a non-panic,
// non-error return so the caller can fall through.
func TestPickLocalIPv4_NotEmpty(t *testing.T) {
	ip := pickLocalIPv4()
	if ip == "" {
		t.Error("pickLocalIPv4 returned empty string")
	}
	// The returned string is either "0.0.0.0" (no
	// suitable NIC) or a real IPv4. Anything else
	// is a bug.
	if ip != "0.0.0.0" {
		parsed := net.ParseIP(ip)
		if parsed == nil {
			t.Errorf("pickLocalIPv4 = %q, not parseable as IP", ip)
		}
		if parsed.To4() == nil {
			t.Errorf("pickLocalIPv4 = %q, not an IPv4", ip)
		}
	}
}

// TestPickLocalIPv4_SkipsLoopbackAndLinkLocal confirms
// the helper filters out addresses that aren't
// routable for "dial in from another peer" purposes.
// We can't easily forge an interface list (it's
// derived from the OS), so this is a property check:
// if the test machine has a non-loopback IPv4 at all,
// the returned IP is not in 127.x.x.x or 169.254.x.x.
func TestPickLocalIPv4_SkipsLoopbackAndLinkLocal(t *testing.T) {
	ip := pickLocalIPv4()
	if ip == "0.0.0.0" {
		t.Skip("no non-loopback IPv4 on this machine")
	}
	parsed := net.ParseIP(ip)
	if parsed.IsLoopback() {
		t.Errorf("pickLocalIPv4 = %q, should not be loopback", ip)
	}
	if parsed.IsLinkLocalUnicast() {
		t.Errorf("pickLocalIPv4 = %q, should not be link-local (169.254.x.x)", ip)
	}
}

// TestAnnouncerLocalAddr_ExplicitBindWins is the
// "user passed -bind=192.168.40.5" path. Whatever
// pickLocalIPv4 would return, the explicit bindIP
// must take precedence — otherwise -bind is broken.
func TestAnnouncerLocalAddr_ExplicitBindWins(t *testing.T) {
	// We don't need to actually start the announcer
	// (Run binds the UDP socket). NewAnnouncerOnPortBind
	// sets bindIP; LocalAddr reads it.
	a := NewAnnouncerOnPortBind(nil, "test", 4748, 4747, "192.168.40.5")
	got := a.LocalAddr()
	want := "192.168.40.5:4748"
	if got != want {
		t.Errorf("LocalAddr = %q, want %q (explicit bind must win)", got, want)
	}
}

// TestAnnouncerLocalAddr_LoopbackBind works on a
// dev box that has no non-loopback IPv4 (CI
// containers, sometimes). The e2e tests use this
// to make tests deterministic. The picker is not
// called in this path because bindIP is set to
// 127.0.0.1 explicitly.
func TestAnnouncerLocalAddr_LoopbackBind(t *testing.T) {
	a := NewAnnouncerOnPortBind(nil, "test", 4748, 4747, "127.0.0.1")
	got := a.LocalAddr()
	want := "127.0.0.1:4748"
	if got != want {
		t.Errorf("LocalAddr = %q, want %q", got, want)
	}
}

// TestAnnouncerLocalAddr_AutoPick is the "by default,
// just works on a LAN" path. No -bind flag was set,
// so bindIP is "0.0.0.0". The helper should pick a
// real local IPv4 (or fall back to "0.0.0.0" on a
// machine with no NIC). We assert the result is one
// of those two — never an empty string, never with
// loopback.
func TestAnnouncerLocalAddr_AutoPick(t *testing.T) {
	a := NewAnnouncerOnPort(nil, "test", 4748, 4747) // default 0.0.0.0 bind
	got := a.LocalAddr()
	// The picked IP + port. Format: "ip:port".
	host, port, err := net.SplitHostPort(got)
	if err != nil {
		t.Fatalf("LocalAddr = %q, not host:port: %v", got, err)
	}
	if port != "4748" {
		t.Errorf("port = %q, want 4748", port)
	}
	// host is either "0.0.0.0" (no NIC found) or
	// a real IPv4. If it's a real IP, it must not
	// be loopback or link-local.
	if host != "0.0.0.0" {
		parsed := net.ParseIP(host)
		if parsed == nil {
			t.Errorf("LocalAddr host = %q, not parseable", host)
		} else {
			if parsed.IsLoopback() {
				t.Errorf("LocalAddr = %q, picker returned loopback (should skip 127.x.x.x)", got)
			}
			if parsed.IsLinkLocalUnicast() {
				t.Errorf("LocalAddr = %q, picker returned link-local (should skip 169.254.x.x)", got)
			}
		}
	}
}

// guard so unused import warnings don't break the build.
var _ = sync.Mutex{}
