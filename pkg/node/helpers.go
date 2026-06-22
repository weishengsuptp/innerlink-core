// Package node is the public runtime API of innerlink-core.
//
// innerlink-core is a LAN P2P encrypted chat + file transfer library.
// The pkg/node package exposes the long-lived runtime (UDP discovery,
// TCP transport, encrypted channels, peer roster, encrypted local
// chat log, peer aliases, on-demand scan, optional auto-scan) as a
// single Node value that any Go program can construct and drive.
//
// Typical usage from a CLI:
//
//	node, err := node.New(node.Options{ LogLevel: "info" })
//	if err != nil { log.Fatal(err) }
//	defer node.Close()
//	if err := node.Start(ctx); err != nil { log.Fatal(err) }
//	// ... drive REPL or whatever the host needs
//
// Typical usage from a desktop UI (Wails / Fyne / etc.):
//
//	node, _ := node.New(node.Options{ /* paths, log level, etc */ })
//	go node.Start(ctx)
//	defer node.Close()
//	peers := node.ListPeers()
//	node.SendText(peers[0].PeerID, "hello")
//	for msg := range node.SubscribeMessages() { /* render */ }
package node

import (
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"os"
	"strings"

	"github.com/weishengsuptp/innerlink-core/internal/identity"
)

// identityHex returns the 32-char lowercase hex of a 16-byte PeerID.
func identityHex(pid []byte) string {
	return fmt.Sprintf("%x", pid)
}

// hexToBytes parses a 32-char hex string back into a 16-byte PeerID.
// Used by callers that received a hex string from the API and want
// the raw bytes for storage.
func hexToBytes(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if len(s) != 2*identity.PeerIDSize {
		return nil, fmt.Errorf("peer id must be %d hex chars, got %d", 2*identity.PeerIDSize, len(s))
	}
	out := make([]byte, identity.PeerIDSize)
	for i := 0; i < identity.PeerIDSize; i++ {
		hi, err := unhex(s[2*i])
		if err != nil {
			return nil, fmt.Errorf("peer id char %d: %w", 2*i, err)
		}
		lo, err := unhex(s[2*i+1])
		if err != nil {
			return nil, fmt.Errorf("peer id char %d: %w", 2*i+1, err)
		}
		out[i] = hi<<4 | lo
	}
	return out, nil
}

func unhex(c byte) (byte, error) {
	switch {
	case '0' <= c && c <= '9':
		return c - '0', nil
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10, nil
	case 'A' <= c && c <= 'F':
		return c - 'A' + 10, nil
	}
	return 0, fmt.Errorf("not a hex digit: %q", c)
}

// peerHex returns a 32-char lowercase hex of a PeerID. If the input
// is the wrong length, fall back to fmt.Sprintf so the log line at
// least doesn't panic. This is the CLI / log-line formatting
// helper; for the public API surface use Node.SelfPeerID() and
// PeerInfo.PeerID (which are guaranteed 32-char hex).
func peerHex(pid []byte) string {
	if len(pid) == identity.PeerIDSize {
		return identityHex(pid)
	}
	return fmt.Sprintf("%x", pid)
}

// hostname returns the local hostname for the discovery
// announcer's "who am I" field. Returns "unknown" if lookup fails,
// never an error — the announcer treats this as informational only.
func hostname() string {
	h, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return h
}

// isDialLiteral reports whether ref looks like a literal
// network address we can pass straight to dialAddr. We
// accept "ip:port" (host:port) and bare IPs (the latter
// dialAddr will reject, but the error message is more
// useful than "unknown peer 1.2.3.4").
func isDialLiteral(ref string) bool {
	if strings.Contains(ref, ":") {
		return true
	}
	return net.ParseIP(ref) != nil
}

// resolveDialTarget maps a v0.6 user-typed dial
// reference to an "ip:port" string suitable for
// dialAddr. Accepts three forms:
//
//  1. Literal "ip:port" — e.g. "dial 192.168.2.5:4748".
//     Returned unchanged. Detected by the presence
//     of a colon (host:port syntax) OR by parseable
//     dotted-quad IP form.
//
//  2. Alias name — e.g. "dial alice". Resolved via
//     the alias store, then we look the peer up in
//     the roster to get their first known addr.
//
//  3. 32-char hex peer id. Same roster lookup as the
//     alias path, just keyed by the id directly.
//
// Returns an error if the ref is an alias or peer id
// but no addr is known.
func (n *Node) resolveDialTarget(ref string) (string, error) {
	if isDialLiteral(ref) {
		return ref, nil
	}
	pid, err := n.resolvePeerRef(ref)
	if err != nil {
		return "", err
	}
	for _, st := range n.channels.snapshot() {
		if peerHex(st.peerID) == pid {
			if ra := st.ch.RemoteAddr(); ra != "" {
				return ra, nil
			}
		}
	}
	entry, err := n.rosterStore.Get(pid)
	if err == nil && len(entry.Addrs) > 0 {
		return entry.Addrs[0], nil
	}
	return "", fmt.Errorf("peer %q has no known address (never seen on the wire?)", ref)
}

// DialAddr is the public entry for "dial <ref>" —
// connect directly to a peer by alias, peer-id, or
// ip:port, bypassing UDP discovery. Returns
// immediately; the dial + handshake runs in a
// background goroutine.
//
// This is the v0.6 escape hatch for cross-VLAN or
// single-host (loopback) connectivity where the UDP
// yellow-pages can't reach.
func (n *Node) DialAddr(ref string) error {
	if n.ctx == nil {
		return fmt.Errorf("node: not started")
	}
	target, err := n.resolveDialTarget(ref)
	if err != nil {
		return err
	}
	log.Printf("[DIAL ] %s -> %s", ref, target)
	n.dialAddr(target)
	return nil
}

// peerIDFromHex is a tiny helper used by tests and
// any caller that has a 32-char hex and wants the raw
// 16-byte PeerID. Errors fall back to nil (callers
// handle "not in registry" the same way).
func peerIDFromHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != identity.PeerIDSize {
		return nil
	}
	return b
}