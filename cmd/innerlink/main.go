// Package main is the innerlink-core CLI. As of v0.7 it
// is a thin wrapper around the public pkg/node API:
//
//   - parse flags
//   - construct a node.Options
//   - call node.New + node.Start
//   - run the REPL command loop on stdin
//   - on quit, call node.Close
//
// All real logic (discovery, transport, channel pump,
// scan, roster gossip, scan-history gossip, chat log,
// aliases) lives in pkg/node and is shared by every
// other consumer (the Wails UI in weishengsuptp/innerlink-desktop,
// future mobile clients, etc.).
package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/weishengsuptp/innerlink-core/pkg/node"
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("innerlink: %v", err)
	}
}

// run wires the CLI's flags into node.Options, brings up
// the runtime, runs the REPL, and tears down on signal.
// Returns the first fatal error (paths/logx failures,
// transport listen errors). REPL commands themselves
// are non-fatal — they print errors and continue.
func run() error {
	var (
		logLevel = flag.String("log-level", "info",
			"log verbosity: debug | info | warn | error. "+
				"debug includes per-chunk [FILE recv chunk ...] and "+
				"per-100ms [FILE sending ... %] lines, which are "+
				"noisy during multi-GiB transfers.")
		logFile = flag.String("log-file", defaultLogFile(),
			"path of the log file (in addition to stderr). "+
				"Empty disables file output. The default is "+
				"<cwd>/innerlink.log. The file is appended, so "+
				"successive runs share the same log.")
		udpPort = flag.Uint("udp-port", 0,
			"UDP port for peer discovery. 0 = default. "+
				"The e2e tests pick a free port per node so "+
				"multiple instances can run on one machine.")
		tcpPort = flag.Uint("tcp-port", 0,
			"TCP port for incoming peer connections. 0 = default. "+
				"The e2e tests pick a free port per node.")
		dataDir = flag.String("data-dir", "",
			"root directory for innerlink state (device.key, "+
				"aliases.json, chat.enc). Default: <cwd>/.innerlink. "+
				"Set this if you want a single shared state dir "+
				"across multiple invocations from different cwds.")
		deviceKey = flag.String("device-key", "",
			"path to the SM2 device key file. Default: "+
				"<data-dir>/device.key. The e2e tests use a "+
				"per-node temp file so two instances have "+
				"different PeerIDs.")
		saveDir = flag.String("save-dir", "",
			"directory for incoming files. Default: "+
				"<cwd>/received. The e2e tests use a per-node "+
				"temp dir so two instances don't share state.")
		bindIP = flag.String("bind", "",
			"local IP to bind the UDP discovery socket to. "+
				"Default 0.0.0.0 (all interfaces). Set to a "+
				"specific IP (e.g. 127.0.0.1 on a dev box, or "+
				"192.168.40.5 for a single-NIC LAN host) so "+
				"the v0.5 roster publishes a routable address "+
				"instead of 0.0.0.0, which is not dialable.")
		autoScanFlag = flag.Bool("auto-scan", false,
			"v0.5.2: when the M5 roster learns about a peer "+
				"from a /24 we don't have a connection to, "+
				"auto-trigger a one-shot scan of that /24. "+
				"Default OFF. Manual `scan <cidr>` is always "+
				"available regardless of this flag.")
	)
	flag.Parse()

	opts := node.Options{
		DataDir:   *dataDir,
		DeviceKey: *deviceKey,
		SaveDir:   *saveDir,
		LogFile:   *logFile,
		LogLevel:  *logLevel,
		BindIP:    *bindIP,
		UDPPort:   int(*udpPort),
		TCPPort:   int(*tcpPort),
		AutoScan:  *autoScanFlag,
	}

	nd, err := node.New(opts)
	if err != nil {
		return err
	}
	defer nd.Close()

	// SIGINT/SIGTERM cancels Start's context, which
	// tears down all goroutines, then nd.Close() in
	// the defer does a final flush.
	sigCtx, stop := signal.NotifyContext(
		nodeBackground(), os.Interrupt, syscall.SIGTERM,
	)
	defer stop()
	if err := nd.Start(sigCtx); err != nil {
		return err
	}

	// REPL runs in its own goroutine because v0.6.x's
	// `go runStdinLoop(...)` had the same shape. We
	// used to call runREPL synchronously here, but
	// that turned a stdin-EOF (which happens on the
	// e2e tests' child processes that never receive
	// a command) into an immediate main exit, which
	// triggered nd.Close() — and the in-flight TCP
	// listener for the rest of the e2e scenario
	// died before the test could dial it. Run the
	// REPL in the background and wait on sigCtx so
	// signal/Close() paths still drive shutdown.
	go runREPL(nd)
	<-sigCtx.Done()
	return nil
}

// runREPL reads stdin line-by-line and dispatches to the
// innerlink REPL command set. Lives in cmd/innerlink
// because it formats output to stderr (a UI concern);
// the underlying actions (SendText, Scan, SetAlias, ...)
// are pkg/node methods called on nd.
func runREPL(nd *node.Node) {
	scanner := newStdinScanner()
	printPrompt()
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			printPrompt()
			continue
		}
		parts := strings.SplitN(line, " ", 3)
		cmd := parts[0]
		replDispatch(nd, cmd, line, parts)
		printPrompt()
	}
	if err := scanner.Err(); err != nil {
		log.Printf("[ERROR] stdin: %v", err)
	}
}

func printPrompt() {
	os.Stderr.Write([]byte("> "))
}

// defaultLogFile returns the default path of the innerlink
// log file. As of v0.5 this is just the cwd-relative path
// (the on-disk layout is owned by internal/paths). Kept
// here so flag default strings read naturally.
func defaultLogFile() string {
	return "innerlink.log"
}