package node

import (
	"strings"
	"time"

	"github.com/weishengsuptp/innerlink-core/internal/alias"
	"github.com/weishengsuptp/innerlink-core/internal/identity"
	"github.com/weishengsuptp/innerlink-core/internal/roster"
)

// PeerInfo is the public, UI-facing view of one peer.
// It merges three sources of truth into a single struct:
//
//   - the alias table (M4: human-readable name + last-seen)
//   - the LAN roster (M5: hostname + addresses from gossip)
//   - the channel registry (live "are we connected right now?")
//
// Updated on every relevant event (alias touch, roster merge,
// channel ready / closed). The fields are stable: a UI
// listing of peers can re-poll ListPeers() at any time
// without worrying about consistency.
type PeerInfo struct {
	// PeerID is the 32-char lowercase hex SM2-derived ID.
	PeerID string

	// Name is the user-assigned alias, or "" if unnamed.
	Name string

	// Hostname is the remote machine's hostname as
	// announced via M5 gossip. "" if unknown.
	Hostname string

	// Addrs is the list of "ip:port" strings the peer has
	// announced (via roster sync + UDP discovery). The first
	// entry is the most recent. May be empty if the peer is
	// only known via alias touch but never seen on the wire.
	Addrs []string

	// LastSeen is the most recent activity timestamp
	// (alias touch, channel-ready, or roster merge).
	LastSeen time.Time

	// Online is true iff we currently have an active
	// encrypted Channel to this peer.
	Online bool

	// IsSelf is true iff this entry is our own device
	// (always present in the roster so we can publish
	// "how to reach me" on the first channel-ready).
	IsSelf bool
}

// PeerEventType enumerates the kinds of transitions
// delivered on SubscribePeers.
type PeerEventType string

const (
	PeerAdded   PeerEventType = "added"   // discovery saw this peer for the first time
	PeerRemoved PeerEventType = "removed" // discovery timed out this peer
	PeerOnline  PeerEventType = "online"  // channel became ready
	PeerOffline PeerEventType = "offline" // channel closed
)

// PeerEvent is one transition. SubscribePeers() delivers
// these as they happen.
type PeerEvent struct {
	Type   PeerEventType
	PeerID string
	// Addr is set for PeerAdded only; empty for the others.
	Addr string
}

// SubscribePeers returns a channel of peer transitions.
// The channel is closed when Close() is called.
//
// Buffered to 64 events; drops oldest under sustained
// flood (the LAN directory converges on the next sync
// anyway, so missing one event is recoverable by
// re-polling ListPeers()).
func (n *Node) SubscribePeers() <-chan PeerEvent {
	return n.peerEventCh
}

// ListPeers returns the current view of every peer we
// know about. Combines the alias table (for names +
// last-seen) with the roster (for hostnames + addresses)
// and the channel registry (for live online state).
//
// Safe to call from any goroutine.
func (n *Node) ListPeers() []PeerInfo {
	// Build a map keyed by PeerID so we can merge the
	// three sources without losing entries that appear
	// in only one of them (e.g. alias-only with no
	// roster entry, or roster-only with no alias).
	out := make(map[string]*PeerInfo)

	// Source 1: alias table (gives Name + LastSeen for
	// any peer we've ever seen, including those we
	// haven't heard from in a while).
	for _, row := range n.aliasStore.ListWithNames() {
		info, ok := out[row.PeerID]
		if !ok {
			info = &PeerInfo{PeerID: row.PeerID}
			out[row.PeerID] = info
		}
		info.Name = row.Name
		info.LastSeen = row.LastSeen
	}

	// Source 2: roster (gives Hostname + Addrs).
	for _, e := range n.rosterStore.List() {
		info, ok := out[e.PeerID]
		if !ok {
			info = &PeerInfo{PeerID: e.PeerID}
			out[e.PeerID] = info
		}
		info.Hostname = e.Hostname
		info.Addrs = append([]string(nil), e.Addrs...)
	}

	// Source 3: channel registry (gives Online + isSelf
	// + RemoteAddr as a fallback for Addrs).
	selfHex := n.id.PeerIDHex()
	for _, st := range n.channels.snapshot() {
		ph := peerHex(st.peerID)
		info, ok := out[ph]
		if !ok {
			info = &PeerInfo{PeerID: ph}
			out[ph] = info
		}
		info.Online = true
		if info.LastSeen.IsZero() {
			info.LastSeen = time.Now()
		}
		if len(info.Addrs) == 0 && st.ch.RemoteAddr() != "" {
			info.Addrs = []string{st.ch.RemoteAddr()}
		}
	}

	// Mark self.
	if self, ok := out[selfHex]; ok {
		self.IsSelf = true
	} else {
		// Defensive: if for some reason self isn't in
		// the roster yet (race during construction),
		// synthesize it from identity.
		out[selfHex] = &PeerInfo{
			PeerID: selfHex, IsSelf: true,
			Hostname: localHostname(),
			Addrs:    []string{n.ann.LocalAddr()},
			LastSeen: time.Now(),
		}
	}

	// Stable order: sort by LastSeen desc, with self pinned first.
	infos := make([]PeerInfo, 0, len(out))
	for _, v := range out {
		infos = append(infos, *v)
	}
	sortPeers(infos)
	return infos
}

func sortPeers(p []PeerInfo) {
	// Self first, then by LastSeen desc.
	// (A future UI may want online-first; we don't have
	// that signal cheaply for entries not in the channel
	// registry, so recency is the next-best proxy.)
	for i := 0; i < len(p); i++ {
		for j := i + 1; j < len(p); j++ {
			pi, pj := p[i], p[j]
			switch {
			case pi.IsSelf && !pj.IsSelf:
				// pi stays before pj
			case !pi.IsSelf && pj.IsSelf:
				p[i], p[j] = p[j], p[i]
			case pi.LastSeen.After(pj.LastSeen):
				p[i], p[j] = p[j], p[i]
			}
		}
	}
}

func localHostname() string {
	return hostname()
}

// keep imports referenced for future expansion.
var (
	_ = identity.PeerIDSize
	_ = roster.Entry{}
	_ = alias.Open
	_ = strings.TrimSpace
)