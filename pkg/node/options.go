package node

import (
	"github.com/weishengsuptp/innerlink-core/internal/discovery"
	"github.com/weishengsuptp/innerlink-core/internal/transport"
)

// Options configures a Node.
//
// Zero value gives a node with all defaults: data dir
// <cwd>/.innerlink/, incoming files <cwd>/received/, log
// file <cwd>/innerlink.log, info-level logging, default
// UDP/TCP ports, no auto-scan. Set the fields you want
// to override; leave the rest at zero.
type Options struct {
	// DataDir is the root for device.key, aliases.json,
	// chat.enc, roster.json. "" defaults to <cwd>/.innerlink.
	DataDir string

	// DeviceKey is the path to the SM2 long-term key file.
	// "" defaults to <DataDir>/device.key. Set this if you
	// want multiple Nodes on the same machine with different
	// identities (e2e tests do this).
	DeviceKey string

	// SaveDir is where incoming files are written.
	// "" defaults to <cwd>/received.
	SaveDir string

	// LogFile is the path of the log file (in addition to
	// stderr). "" disables file logging (stderr only).
	// "" otherwise defaults to <cwd>/innerlink.log.
	LogFile string

	// LogLevel: "debug" | "info" | "warn" | "error".
	// "" defaults to "info".
	LogLevel string

	// BindIP is the local address the UDP announcer and
	// TCP transport bind to. "" defaults to "0.0.0.0"
	// (all interfaces). Set to a specific IP if you have
	// multiple NICs and want the v0.5 roster to publish a
	// routable address (e.g. "192.168.40.5" instead of
	// 0.0.0.0, which is not dialable).
	BindIP string

	// UDPPort is the UDP port for peer discovery.
	// 0 defaults to discovery.DefaultPort.
	UDPPort int

	// TCPPort is the TCP port for incoming peer connections.
	// 0 defaults to transport.DefaultPort.
	TCPPort int

	// AutoScan enables v0.5.2 auto-scan: when the roster
	// learns about a peer from a /24 we don't have a
	// connection to, queue a one-shot scan of that /24.
	// Default false (opt-in).
	AutoScan bool
}

// applyDefaults fills zero fields with their default values.
// Called once inside New so the rest of the runtime can rely
// on every field being non-zero (or its documented zero
// meaning — e.g. LogFile == "" means stderr only).
func (o Options) applyDefaults() Options {
	if o.BindIP == "" {
		o.BindIP = "0.0.0.0"
	}
	if o.UDPPort == 0 {
		o.UDPPort = discovery.DefaultPort
	}
	if o.TCPPort == 0 {
		o.TCPPort = transport.DefaultPort
	}
	if o.LogLevel == "" {
		o.LogLevel = "info"
	}
	return o
}