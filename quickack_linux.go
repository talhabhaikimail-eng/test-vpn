//go:build linux

package main

import (
	"net"
	"syscall"
)

// tcpQuickAck is the Linux TCP_QUICKACK socket option (value 12), not exported
// by the stdlib syscall package.
const tcpQuickAck = 0x0C

// setQuickAck disables delayed ACKs on the socket so interactive SSH packets
// are acknowledged immediately instead of waiting up to ~40ms to piggyback.
// It is one-shot per socket on Linux; re-armed when forward() starts streaming.
func setQuickAck(c *net.TCPConn) {
	rc, err := c.SyscallConn()
	if err != nil {
		return
	}
	_ = rc.Control(func(fd uintptr) {
		_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, tcpQuickAck, 1)
	})
}
