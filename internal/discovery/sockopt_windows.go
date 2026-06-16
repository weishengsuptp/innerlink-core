//go:build windows

package discovery

import (
	"syscall"
)

// setSockoptBroadcastWindows enables SO_BROADCAST on the given
// socket file descriptor. The constant 0x0020 is the Windows
// value of SO_BROADCAST, defined in WinSock2.h.
//
// We use raw syscall.SetsockoptInt rather than
// golang.org/x/sys/windows so this file's dependency footprint
// is zero — important for the discovery package, which is
// already heavy on platform-specific code.
func setSockoptBroadcastWindows(fd uintptr) error {
	// syscall.SetsockoptInt expects a Handle (which is uintptr on
	// windows) and the level + name as int.
	const SOL_SOCKET = 0xffff
	const SO_BROADCAST = 0x0020
	return syscall.SetsockoptInt(syscall.Handle(fd), SOL_SOCKET, SO_BROADCAST, 1)
}
