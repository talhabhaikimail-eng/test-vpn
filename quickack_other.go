//go:build !linux

package main

import "net"

// setQuickAck is a no-op on non-Linux platforms (TCP_QUICKACK is Linux-only).
// The proxy runs on Linux GitHub runners; this stub only keeps local builds green.
func setQuickAck(*net.TCPConn) {}
