// scan implements the v0.5.1 "scan <cidr>" REPL command.
// It batch-dials a user-specified IPv4 subnet, attempting
// a handshake against every host:port, and reports which
// hosts spoke innerlink. The matched hosts become normal
// channels (so chat / file / roster work the moment scan
// finishes) and M5 gossip pushes them to the rest of the
// LAN.
//
// Why batch-dial rather than broadcast?
//
// UDP discovery (the default path) only reaches one
// L2 broadcast domain — a /24 in the same VLAN, same
// switch, no router in between. For the cross-VLAN
// case (e.g. a laptop on the WiFi VLAN talking to
// servers on the wired VLAN), the only practical way
// to find peers is to TCP-probe their addresses
// directly. That's what scan does.
//
// All parameters are conservative on purpose: scan is
// user-initiated, single-CIDR, hard-capped at 1024
// hosts (rejects /16 and larger), concurrent but
// polite (16 workers, 1.5s per-host timeout). We do
// NOT want this to be a foot-gun: a `scan 0.0.0.0/0`
// would otherwise knock on every IPv4 on earth.
package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/weishengsuptp/innerlink-core/internal/alias"
	"github.com/weishengsuptp/innerlink-core/internal/handshake"
	"github.com/weishengsuptp/innerlink-core/internal/identity"
	"github.com/weishengsuptp/innerlink-core/internal/roster"
	"github.com/weishengsuptp/innerlink-core/internal/storage"
	"github.com/weishengsuptp/innerlink-core/internal/transport"
)

// scanMaxHosts caps the number of addresses scan will
// touch in a single invocation. 1024 (= a /22) is large
// for any real LAN and small enough to finish in well
// under a minute at our concurrency level. Larger inputs
// are rejected with a USAGE error so the user has to be
// explicit ("you really want to scan 65k hosts? use
// multiple smaller scans").
const scanMaxHosts = 1024

// scanWorkers bounds concurrency. 16 in-flight TCP dials
// is enough to saturate a /24 (254 hosts) in ~10s on a
// fast LAN without overwhelming a single peer's listen
// backlog. The Linux default somaxconn is 4096, so 16
// in-flight is well under that.
const scanWorkers = 16

// scanPerHostTimeout bounds how long a single host gets
// before we give up. 1.5s is generous: TCP connect on a
// LAN sub-millisecond, handshake ~10ms. The extra
// headroom absorbs retry effects and slow VMs.
const scanPerHostTimeout = 1500 * time.Millisecond

// parseScanCIDR parses the user-supplied CIDR string and
// returns the network + a list of usable host addresses.
// IPv4 only (IPv6 is out of scope for v0.5.1 — no one
// runs innerlink over link-local IPv6 today, and the
// address-enumeration math is different).
//
// Returns (nil, error) for: invalid syntax, IPv6, host
// count above scanMaxHosts, /0 (would scan the whole
// internet). On success the returned slice contains
// every address in the CIDR except the network and
// broadcast (so a /24 yields 254 entries, not 256).
func parseScanCIDR(s string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(s)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR %q: %w", s, err)
	}
	// Force IPv4. net.ParseCIDR accepts both; we only
	// want v4 because the rest of innerlink is v4-only
	// (UDP discovery, TCP transport, etc.).
	if ip.To4() == nil {
		return nil, fmt.Errorf("only IPv4 subnets supported, got %q", s)
	}
	if ones, bits := ipnet.Mask.Size(); bits == 32 && ones == 0 {
		return nil, fmt.Errorf("refusing to scan the default route (/0)")
	}

	// Enumerate every host in the network. The
	// size math:
	//   /< 31: skip network (all-zeros host) and
	//          broadcast (all-ones host). Total =
	//          2^(32-ones) - 2.
	//   />=31: every address is usable (RFC 3021
	//          point-to-point / host route). Total =
	//          2^(32-ones).
	// Compute total first so we can enforce the
	// scanMaxHosts cap before allocating the slice.
	ones, _ := ipnet.Mask.Size()
	total := 1 << uint(32-ones)
	skipNetworkAndBroadcast := ones < 31
	if skipNetworkAndBroadcast {
		total -= 2
	}
	if total > scanMaxHosts {
		return nil, fmt.Errorf("CIDR %q yields %d hosts, max is %d "+
			"(scan a smaller range; e.g. /22 or smaller)", s, total, scanMaxHosts)
	}
	if total < 1 {
		// /32 with ones==32 gives total=1 (no skip),
		// but defensively guard against any future
		// "total==0" case (e.g. /0 was rejected above,
		// so this branch is dead, but cheap to keep).
		return nil, fmt.Errorf("CIDR %q yields 0 hosts", s)
	}

	out := make([]string, 0, total)
	cur := ipnet.IP.Mask(ipnet.Mask).To4() // network address
	v := uint32(cur[0])<<24 | uint32(cur[1])<<16 | uint32(cur[2])<<8 | uint32(cur[3])
	if skipNetworkAndBroadcast {
		// For /<31, the first host is one past the
		// network address. We pre-advance so the
		// loop body can be uniform: write current,
		// then advance.
		v++
	}
	for i := 0; i < total; i++ {
		out = append(out, fmt.Sprintf("%d.%d.%d.%d",
			byte(v>>24), byte(v>>16), byte(v>>8), byte(v)))
		// Advance for the next iteration, except
		// after the very last add (we'd be writing
		// the broadcast address for /<31, which we
		// deliberately skip). Setting v to one past
		// the last host is fine because we never
		// read it again.
		if i < total-1 {
			v++
		}
	}
	return out, nil
}

// localIPs returns the set of IP addresses this node is
// bound to. Used to skip "scan myself" entries — we
// never want to dial our own TCP port from ourselves.
// For the v0.5.1 default (no -bind), the set is the
// first non-loopback, non-link-local IPv4 (see
// pickLocalIPv4) plus the loopback itself (for e2e
// tests that bind to 127.0.0.x).
func localIPs() map[string]bool {
	out := map[string]bool{"127.0.0.1": true} // always include loopback
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil {
				continue
			}
			if ip4 := ip.To4(); ip4 != nil && !ip4.IsLoopback() && !ip4.IsLinkLocalUnicast() {
				out[ip4.String()] = true
			}
		}
	}
	return out
}

// runScan is the REPL handler for `scan <cidr>`. It
// parses the CIDR, filters out self + already-connected
// peers, then dials the rest with bounded concurrency.
// Successful handshakes become channels (via the same
// wrapChannel path single-dial uses); failures are
// silent in the registry but logged per-host so the
// user can see what happened.
//
// scanTcpPort is the local TCP port the innerlink
// instance is listening on; other innerlink instances
// are presumed to be on the same port (the default
// 4748). The e2e test pins all nodes to a single
// port, and production users typically don't change
// the default, so this is the right default. A future
// `-scan-port` flag could let the user override.
//
// The function returns when the scan finishes (or
// context is canceled). REPL is single-threaded, so
// the user is blocked from typing during the scan —
// that is intentional: we don't want interleaved
// `send` racing with a half-finished scan.
func runScan(ctx context.Context, cidr string, scanTcpPort int,
	tr *transport.Transport,
	reg *channelRegistry, saveDir string,
	chatStore *storage.Store, history *[]*storage.Record,
	id *identity.Identity, aliasStore *alias.Store,
	rosterStore *roster.Store, autoScan *autoScanState,
) error {
	ips, err := parseScanCIDR(cidr)
	if err != nil {
		return err
	}
	self := localIPs()
	// Filter out self IPs and any IPs the registry
	// already has a channel to (avoid double-dial).
	filtered := make([]string, 0, len(ips))
	for _, ip := range ips {
		if self[ip] {
			continue
		}
		// Cheap pre-check: if we already have a
		// channel whose TCP remote matches this IP,
		// skip. protocol.Channel.RemoteAddr gives
		// us "ip:port"; we compare just the IP
		// portion (the port is the same on all
		// nodes, but if it ever isn't, this should
		// still skip on full match).
		skip := false
		for _, st := range reg.snapshot() {
			ra := st.ch.RemoteAddr()
			if ra == "" {
				continue
			}
			if host, _, _ := net.SplitHostPort(ra); host == ip {
				skip = true
				break
			}
		}
		if skip {
			continue
		}
		filtered = append(filtered, ip)
	}
	log.Printf("[SCAN] target %s, %d hosts (after skip self+known: %d)",
		cidr, len(ips), len(filtered))
	if len(filtered) == 0 {
		log.Printf("[SCAN] nothing to do (all hosts are self or already known)")
		return nil
	}

	// Worker pool. The dial+handshake happens in a
	// per-host goroutine; results are reported as
	// they come in via a shared atomic counter and a
	// logged line per result.
	var (
		ok      atomic.Int64
		failed  atomic.Int64
		start   = time.Now()
		results = make(chan scanResult, len(filtered))
		wg      sync.WaitGroup
	)

	jobs := make(chan string)
	for w := 0; w < scanWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range jobs {
				addr := net.JoinHostPort(ip, strconv.Itoa(scanTcpPort))
				res := scanOne(ctx, tr, addr, id, saveDir, chatStore, history, aliasStore, rosterStore, reg, autoScan)
				results <- res
			}
		}()
	}
	go func() {
		for _, ip := range filtered {
			select {
			case jobs <- ip:
			case <-ctx.Done():
				close(jobs)
				wg.Wait()
				close(results)
				return
			}
		}
		close(jobs)
		wg.Wait()
		close(results)
	}()

	for r := range results {
		if r.err != nil {
			failed.Add(1)
			log.Printf("[SCAN] %-22s %s", r.addr, scanErrorLabel(r.err))
		} else {
			ok.Add(1)
			log.Printf("[SCAN] %-22s OK   peerID=%s", r.addr, r.peerID)
		}
	}
	log.Printf("[SCAN] %d ok, %d failed, %d total in %s",
		ok.Load(), failed.Load(), len(filtered), time.Since(start).Round(time.Millisecond))
	return nil
}

// scanResult is the per-host outcome of runScan.
type scanResult struct {
	addr   string // "ip:port"
	peerID string // hex, set on success
	err    error
}

// scanOne does a single dial+handshake against addr and
// reports the result. On success, it registers the
// channel in reg (so chat/file/roster work for the
// duration of the session) and returns the peerID.
//
// This duplicates a few lines of dialAddr because we
// need the synchronous result here. Keeping it inline
// is simpler than refactoring dialAddr to return
// (peerID, error) — that's a bigger API change for
// one caller. If a third caller wants the same
// synchronous result, we can extract a shared
// dialAndHandshakeSync helper at that point.
func scanOne(ctx context.Context, tr *transport.Transport, addr string,
	id *identity.Identity, saveDir string,
	chatStore *storage.Store, history *[]*storage.Record,
	aliasStore *alias.Store, rosterStore *roster.Store,
	reg *channelRegistry, autoScan *autoScanState,
) scanResult {
	// Per-host timeout. We use a derived context so
	// one slow host doesn't blow the whole scan's
	// context budget; the parent ctx still kills
	// everything on REPL quit.
	dctx, cancel := context.WithTimeout(ctx, scanPerHostTimeout)
	defer cancel()

	conn, err := tr.Dial(dctx, addr)
	if err != nil {
		return scanResult{addr: addr, err: err}
	}
	defer conn.Close()
	sess, err := handshake.RunAsInitiator(dctx, id, conn)
	if err != nil {
		return scanResult{addr: addr, err: err}
	}
	// Handshake OK — register the channel. This is
	// the same path dialAddr uses, but we capture
	// the peerID before launching the Recv pump.
	pid := hex.EncodeToString(sess.RemotePeerID)
	wrapChannel(ctx, conn, sess, reg, saveDir, chatStore, history, id, aliasStore, rosterStore, autoScan)
	return scanResult{addr: addr, peerID: pid}
}

// scanErrorLabel maps a dial/handshake error to a
// short, scannable label for the log line. We don't
// need to preserve the full error — the user can
// re-scan with `-v` later if we add verbose. The
// current categories:
//
//	refused : TCP RST (no listener on that port)
//	timeout : TCP SYN never ACKed
//	no route: network unreachable
//	other   : anything else (handshake fail, EOF, etc.)
func scanErrorLabel(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	switch {
	case strings.Contains(s, "refused") || strings.Contains(s, "actively refused"):
		return "refused"
	case strings.Contains(s, "timeout") || strings.Contains(s, "i/o timeout") || strings.Contains(s, "deadline exceeded"):
		return "timeout"
	case strings.Contains(s, "no route") || strings.Contains(s, "unreachable") || strings.Contains(s, "no such host"):
		return "no route"
	default:
		return "other: " + s
	}
}

// sortIPs sorts IP addresses in ascending order so the
// scan output is stable and easy to read. Used by the
// unit test (which compares the full slice, not a
// set) and by any future debug log that wants
// predictable order. Currently runScan doesn't sort
// because Go map iteration over the self/known sets
// is not deterministic; the e2e test relies on the
// order being "first match wins", not "lowest IP
// first". Keeping this function around for tests
// and future callers that want stable order.
func sortIPs(s []string) {
	sort.Slice(s, func(i, j int) bool {
		a := net.ParseIP(s[i]).To4()
		b := net.ParseIP(s[j]).To4()
		if a == nil || b == nil {
			return s[i] < s[j]
		}
		ai := uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])
		bi := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
		return ai < bi
	})
}
