package dns

import (
	"context"
	"errors"
	"net"
	"net/netip"
)

var errUnsupported = errors.New("DNS capture is not implemented on Windows yet")

// Listen is not implemented on Windows yet.
func Listen() (net.PacketConn, net.Listener, uint16, error) { return nil, nil, 0, errUnsupported }

// ListenBypass is not implemented on Windows yet.
func ListenBypass() (net.PacketConn, uint16, func(context.Context, netip.AddrPort) (net.Conn, error), error) {
	return nil, 0, nil, errUnsupported
}
