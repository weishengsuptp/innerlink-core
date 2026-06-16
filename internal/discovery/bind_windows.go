//go:build windows

package discovery

import (
	"fmt"
	"net"
)

// bindBroadcastSocket creates a UDP socket on the given port and
// configures it for broadcasting.
//
// On Windows the SO_BROADCAST option is set via syscall (or, more
// portably, the SetSocketOpt API on the raw conn). Windows allows
// broadcast sends by default for unbound UDP sockets, but we set
// the option explicitly so the behavior matches POSIX and we don't
// depend on undocumented defaults.
func bindBroadcastSocket(port int) (*net.UDPConn, error) {
	addr := &net.UDPAddr{IP: net.IPv4zero, Port: port}
	conn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		return nil, err
	}
	if err := setBroadcastWindows(conn); err != nil {
		conn.Close()
		return nil, fmt.Errorf("discovery: enable SO_BROADCAST: %w", err)
	}
	return conn, nil
}

// setBroadcastWindows turns on SO_BROADCAST on the underlying socket.
// We use the standard library's SyscallConn API rather than reaching
// for golang.org/x/sys/windows directly, so we keep the dependency
// footprint minimal.
func setBroadcastWindows(conn *net.UDPConn) error {
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var setErr error
	if err := raw.Control(func(fd uintptr) {
		// windows: SO_BROADCAST = 0x0020
		// We use the standard library's SetSockoptInt through
		// golang.org/x/sys/windows; that import is local to this
		// file (build-tagged to windows only) so it doesn't leak
		// into other platforms.
		setErr = setSockoptBroadcastWindows(fd)
	}); err != nil {
		return err
	}
	return setErr
}
