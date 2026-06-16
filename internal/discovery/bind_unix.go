//go:build !windows

package discovery

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// bindBroadcastSocket creates a UDP socket on the given port and
// configures it for broadcasting.
//
// On POSIX (Linux / macOS), we need to explicitly enable
// SO_BROADCAST — without it, the kernel refuses to send to
// broadcast addresses with EACCES.
func bindBroadcastSocket(port int) (*net.UDPConn, error) {
	addr := &net.UDPAddr{IP: net.IPv4zero, Port: port}
	conn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		return nil, err
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("discovery: get raw conn: %w", err)
	}
	var setErr error
	if err := raw.Control(func(fd uintptr) {
		setErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_BROADCAST, 1)
	}); err != nil {
		conn.Close()
		return nil, fmt.Errorf("discovery: control fd: %w", err)
	}
	if setErr != nil {
		conn.Close()
		return nil, fmt.Errorf("discovery: enable SO_BROADCAST: %w", setErr)
	}
	return conn, nil
}
