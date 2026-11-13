//go:build !darwin && !linux

package control

import "net"

// peerIsMe: no peer credentials here; the socket's permissions decide.
func peerIsMe(*net.UnixConn) bool { return true }
