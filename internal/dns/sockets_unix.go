//go:build !windows

package dns

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"syscall"

	"golang.org/x/sys/unix"
)

// Listen opens the engine's UDP and TCP sockets on 127.0.0.1, on one port
// number (the firewall redirects both protocols there).
func Listen() (net.PacketConn, net.Listener, uint16, error) {
	for range 20 {
		pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			return nil, nil, 0, err
		}
		port := uint16(pc.LocalAddr().(*net.UDPAddr).Port)
		ln, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", port))
		if err == nil {
			return pc, ln, port, nil
		}
		_ = pc.Close() // TCP port taken: try another number
	}
	return nil, nil, 0, fmt.Errorf("no free port for the DNS listener")
}

// ListenBypass opens the forwarder's UDP socket and returns its port, which
// the firewall driver lets through, and a TCP dialer that connects from the
// same port.
func ListenBypass() (net.PacketConn, uint16, func(context.Context, netip.AddrPort) (net.Conn, error), error) {
	pc, err := net.ListenPacket("udp4", "0.0.0.0:0")
	if err != nil {
		return nil, 0, nil, err
	}
	port := uint16(pc.LocalAddr().(*net.UDPAddr).Port)
	d := net.Dialer{
		LocalAddr: &net.TCPAddr{Port: int(port)},
		// Several connections (to different servers) share the port.
		Control: func(_, _ string, rc syscall.RawConn) error {
			var serr error
			err := rc.Control(func(fd uintptr) {
				if serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); serr != nil {
					return
				}
				serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
			})
			if err != nil {
				return err
			}
			return serr
		},
	}
	dial := func(ctx context.Context, server netip.AddrPort) (net.Conn, error) {
		return d.DialContext(ctx, "tcp4", server.String())
	}
	return pc, port, dial, nil
}
