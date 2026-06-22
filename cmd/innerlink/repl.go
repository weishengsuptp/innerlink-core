// Package main, REPL command handlers (v0.7+).
//
// Each REPL command is a thin wrapper around the
// corresponding pkg/node public method. The wrappers
// exist only to format CLI-friendly error and status
// messages — every real action lives in pkg/node.
package main

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"

	"github.com/weishengsuptp/innerlink-core/internal/alias"
	"github.com/weishengsuptp/innerlink-core/internal/storage"
	"github.com/weishengsuptp/innerlink-core/pkg/node"
)

// replDispatch parses one REPL line and dispatches to
// the matching command handler. Each handler is a
// small function defined below.
func replDispatch(nd *node.Node, cmd, line string, parts []string) {
	switch cmd {
	case "send":
		cmdSend(nd, parts)
	case "sendfile":
		cmdSendFile(nd, parts)
	case "history":
		cmdHistory(nd, parts[1:])
	case "ping":
		cmdPing(nd, parts)
	case "alias":
		cmdAlias(nd, parts)
	case "unalias":
		cmdUnalias(nd, parts)
	case "peers":
		cmdPeers(nd)
	case "roster":
		cmdRoster(nd, parts)
	case "dial":
		cmdDial(nd, parts)
	case "scan":
		cmdScan(nd, parts)
	case "autoscan":
		cmdAutoScan(nd)
	case "help":
		cmdHelp()
	case "quit", "exit":
		log.Println("[INFO ] bye")
		os.Exit(0)
	default:
		log.Printf("[USAGE] unknown command %q (type 'help')", cmd)
	}
}

func cmdSend(nd *node.Node, parts []string) {
	if len(parts) < 3 {
		log.Println("[USAGE] send <peer-id-or-alias> <text>")
		return
	}
	if strings.TrimSpace(parts[1]) == "" {
		// v0.6.1: empty peer ref is the most common
		// typo (extra space, copy-paste mishap). Print
		// a clear message instead of letting
		// resolvePeerRef say `unknown peer ""`.
		log.Println("[ERROR] send: peer ref is empty (got: send <empty> <text>)")
		return
	}
	if err := nd.SendText(parts[1], parts[2]); err != nil {
		log.Printf("[ERROR] %v", err)
	}
}

func cmdSendFile(nd *node.Node, parts []string) {
	if len(parts) < 3 {
		log.Println("[USAGE] sendfile <peer-id-or-alias> <local-path>")
		return
	}
	if strings.TrimSpace(parts[1]) == "" {
		log.Println("[ERROR] sendfile: peer ref is empty")
		return
	}
	if err := nd.SendFile(parts[1], parts[2]); err != nil {
		log.Printf("[ERROR] %v", err)
	}
}

func cmdPing(nd *node.Node, parts []string) {
	if len(parts) < 2 {
		log.Println("[USAGE] ping <peer-id-or-alias>")
		return
	}
	if strings.TrimSpace(parts[1]) == "" {
		log.Println("[ERROR] ping: peer ref is empty")
		return
	}
	if err := nd.Ping(parts[1]); err != nil {
		log.Printf("[ERROR] %v", err)
	}
}

func cmdAlias(nd *node.Node, parts []string) {
	switch len(parts) {
	case 1:
		listAliases(nd)
	case 2:
		if parts[1] == "list" {
			listAliases(nd)
		} else {
			log.Println("[USAGE] alias <name> <peer-id-hex>")
			log.Println("        alias    -- list all aliases")
		}
	default:
		if err := nd.SetAlias(parts[2], parts[1]); err != nil {
			log.Printf("[ERROR] alias: %v", err)
			return
		}
		log.Printf("[INFO ] aliased %s -> %s", parts[1], parts[2])
	}
}

func cmdUnalias(nd *node.Node, parts []string) {
	if len(parts) < 2 {
		log.Println("[USAGE] unalias <name-or-peer-id>")
		return
	}
	if err := nd.RemoveAlias(parts[1]); err != nil {
		log.Printf("[ERROR] %v", err)
		return
	}
	log.Printf("[INFO ] unaliased %s", parts[1])
}

func listAliases(nd *node.Node) {
	aliases := nd.ListAliases()
	if len(aliases) == 0 {
		log.Printf("[INFO ] no aliases yet (use `alias <name> <peer-id-hex>` to add one)")
		return
	}
	for _, a := range aliases {
		if a.Name == "" {
			log.Printf("[ALIAS] %s  (unnamed; alias it with: alias <name> %s)",
				a.PeerID, a.PeerID)
		} else {
			log.Printf("[ALIAS] %-32s  %s", a.PeerID, a.Name)
		}
	}
}

func cmdPeers(nd *node.Node) {
	peers := nd.ListPeers()
	// Filter out self. The v0.7 ListPeers() includes the
	// own entry (IsSelf=true) so callers can render "you + N
	// others" or check the roster against SelfPeerID(). The
	// CLI REPL matches v0.6 semantics, where self was never
	// visible via `peers` — the e2e TestE2E_ThreePeerMesh
	// gates on `[PEERS] 2 known peer` (alice + charlie,
	// without the local node). Keeping self out of the CLI
	// output preserves the v0.6 contract and keeps the test
	// green.
	filtered := peers[:0:0]
	for _, p := range peers {
		if p.IsSelf {
			continue
		}
		filtered = append(filtered, p)
	}
	peers = filtered
	if len(peers) == 0 {
		log.Printf("[INFO ] no peers seen yet")
		return
	}
	sort.Slice(peers, func(i, j int) bool {
		return peers[i].LastSeen.After(peers[j].LastSeen)
	})
	log.Printf("[PEERS] %d known peer(s):", len(peers))
	for _, p := range peers {
		name := p.Name
		if name == "" {
			name = "(unnamed)"
		}
		ago := p.LastSeen.Local().Format("2006-01-02 15:04:05")
		log.Printf("[PEERS] %-20s  last seen %s  (%s)", name, ago, p.PeerID)
	}
}

func cmdRoster(nd *node.Node, parts []string) {
	if len(parts) >= 2 && parts[1] == "forget" {
		if len(parts) < 3 {
			log.Println("[USAGE] roster forget <peer-id-or-alias>")
			return
		}
		// Drop via alias store (RemoveAlias covers
		// both name and hex refs).
		if err := nd.RemoveAlias(parts[2]); err != nil {
			log.Printf("[ERROR] roster forget: %v", err)
		} else {
			log.Printf("[INFO ] forgot %s from roster", parts[2])
		}
		return
	}
	peers := nd.ListPeers()
	if len(peers) == 0 {
		log.Printf("[INFO ] roster is empty (waiting for gossip from connected peers)")
		return
	}
	sort.Slice(peers, func(i, j int) bool {
		return peers[i].PeerID < peers[j].PeerID
	})
	online := 0
	log.Printf("[ROSTER] %d entries:", len(peers))
	for _, p := range peers {
		state := "offline"
		if p.IsSelf {
			state = "self   "
		} else if p.Online {
			state = "online "
			online++
		}
		hostname := p.Hostname
		if hostname == "" {
			hostname = "(no hostname)"
		}
		addrs := "(no addr)"
		if len(p.Addrs) > 0 {
			addrs = strings.Join(p.Addrs, ",")
		}
		log.Printf("[ROSTER] %s  %-20s  %s  %s",
			state, truncate(hostname, 20), truncate(addrs, 32),
			safeShort(p.PeerID))
	}
	log.Printf("[ROSTER] %d online / %d total", online, len(peers))
}

func cmdDial(nd *node.Node, parts []string) {
	if len(parts) < 2 {
		log.Println("[USAGE] dial <peer-id-or-alias-or-ip:port>")
		return
	}
	if err := nd.DialAddr(parts[1]); err != nil {
		log.Printf("[ERROR] dial: %v", err)
	}
}

func cmdScan(nd *node.Node, parts []string) {
	if len(parts) < 2 {
		log.Println("[USAGE] scan <ipv4-cidr>  (e.g. scan 192.168.40.0/24)")
		return
	}
	if err := nd.Scan(nodeBackground(), parts[1]); err != nil {
		log.Printf("[ERROR] scan: %v", err)
	}
}

func cmdAutoScan(nd *node.Node) {
	// We don't expose a Subscribe-style view of the
	// auto-scan queue yet (it's an internal
	// detail). For now, print "enabled / disabled"
	// from the node's options by re-reading a side
	// channel: we keep an internal peek through the
	// NodeOpts accessor.
	log.Printf("[AUTOSCAN] (queue view not exposed via pkg/node yet)")
}

func cmdHelp() {
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
	log.Println("[HELP ] scan <ipv4-cidr>                 -- batch-dial a subnet to find innerlink peers")
	log.Println("[HELP ] autoscan                         -- show v0.5.2 auto-scan queue status")
	log.Println("[HELP ] help                             -- this list")
	log.Println("[HELP ] quit                             -- exit")
}

func cmdHistory(nd *node.Node, args []string) {
	peerRef := ""
	if len(args) >= 1 {
		peerRef = args[0]
	}
	msgs := nd.History(peerRef)
	if len(msgs) == 0 {
		log.Printf("[INFO ] no chat history yet")
		return
	}
	// last 50
	start := 0
	if len(msgs) > 50 {
		start = len(msgs) - 50
	}
	shown := 0
	for i := start; i < len(msgs); i++ {
		m := msgs[i]
		arrow := ">"
		if m.Direction == "in" {
			arrow = "<"
		}
		local := m.Timestamp.Local()
		log.Printf("[HIST ] %s %s %s %s",
			local.Format("2006-01-02 15:04:05"), arrow, m.PeerID, m.Body)
		shown++
	}
	if shown == 0 && peerRef != "" {
		log.Printf("[INFO ] no history with peer %s", peerRef)
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 3 {
		return s[:n]
	}
	return s[:n-3] + "..."
}

func safeShort(s string) string {
	if len(s) >= 8 {
		return s[:8] + "..."
	}
	return s
}

// newStdinScanner constructs a bufio.Scanner over os.Stdin.
// Used by the REPL loop. Returns the scanner so the
// caller can Close() it and read Err() after the loop.
func newStdinScanner() *bufio.Scanner {
	return bufio.NewScanner(os.Stdin)
}

// nodeBackground returns a fresh background context
// for one-shot REPL operations (scan). We don't tie
// these to the Node's main ctx because we want scans
// to keep running even if the REPL reads `quit` while
// the scan is in flight; the scan goroutine watches
// its own derived ctx.
func nodeBackground() (ctx context.Context) {
	ctx, _ = contextWithCancel()
	return ctx
}

// contextWithCancel is a tiny helper that returns
// context.Background + a cancel func; the cancel is
// discarded because no caller wants to cancel it
// (Node.Scan only watches its own timeout).
func contextWithCancel() (context.Context, context.CancelFunc) {
	return context.WithCancel(context.Background())
}

// keep imports referenced for future expansion.
var (
	_ = alias.Open
	_ = storage.Open
	_ = fmt.Sprintf
)