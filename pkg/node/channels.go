package node

import (
	"sync"

	"github.com/weishengsuptp/innerlink-core/internal/filetransfer"
	"github.com/weishengsuptp/innerlink-core/internal/protocol"
)

// channelState is one active encrypted channel to a peer.
// Lives in pkg/node (not internal) because the Node
// methods need access to the underlying Channel and
// Receiver; making them unexported inside pkg/node is
// enough to keep them out of the public API surface.
type channelState struct {
	ch     *protocol.Channel
	rcv    *filetransfer.Receiver
	peerID []byte // 16-byte raw peer id (key in the registry)
}

// channelRegistry tracks active encrypted Channels, keyed
// by remote PeerID. Used so the dispatcher loop and the
// public API methods (SendText, SendFile, ListPeers) can
// find the right Channel to talk to.
//
// We also keep a per-channel Receiver so that SendFile can
// ask the Receiver to be its dispatcher-aware wait channel.
// This is the fix for the "sendfile silently hangs because
// the chat pump's Recv swallowed the Accept envelope" race:
// the Sender must not call ch.Recv directly when the
// dispatcher is also reading from the channel.
type channelRegistry struct {
	mu sync.Mutex
	m  map[string]*channelState
}

func newChannelRegistry() *channelRegistry {
	return &channelRegistry{m: make(map[string]*channelState)}
}

// snapshot returns a slice copy of all current channel
// states. Used by the M5 gossip fan-out (broadcast roster
// to every connected peer). The returned states are
// shallow copies of pointers — the underlying Channel is
// shared, so callers must not close them.
func (r *channelRegistry) snapshot() []*channelState {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*channelState, 0, len(r.m))
	for _, st := range r.m {
		out = append(out, st)
	}
	return out
}

// set installs state for peerID. If a Channel already
// exists for this peer, set() closes the new one and
// returns the existing one — the assumption is that the
// existing Channel was set up first and is in active use,
// and a concurrent re-handshake (caused by the
// announcer's periodic PeerAdded emissions) is the
// redundant one we want to drop.
//
// Returns true if state was installed, false if the
// existing one was kept.
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