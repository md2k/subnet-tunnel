// Package capture sets up transparent capture: the root helper creates a
// utun interface with routes for the requested CIDRs, and a userspace TCP/IP
// stack on that interface forwards every connection through the tunnel.
package capture

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"

	"github.com/md2k/subnet-tunnel/internal/netstack"
	"github.com/md2k/subnet-tunnel/internal/privhelper"
	"github.com/md2k/subnet-tunnel/internal/transport"
	"github.com/md2k/subnet-tunnel/internal/tundev"
)

const (
	// MTU 9000 more than doubled upload in the October utun measurements:
	// the cost is per packet. It only applies between the kernel and our
	// stack; the tunnel carries TCP streams, so nothing is fragmented.
	MTU = 9000
	// TunAddr is the utun's own (point-to-point) address. 198.18.0.0/15 is
	// reserved for benchmarking (RFC 2544) and never routed publicly.
	TunAddr = "198.18.249.1"
)

// Capture is a running utun capture.
type Capture struct {
	Name  string // utunN
	stack *netstack.Stack
}

// Close stops the stack and closes the utun; macOS removes the interface
// and its routes.
func (c *Capture) Close() error { return c.stack.Close() }

// CheckLoop refuses CIDRs that would route the carrier's own connection
// into the tunnel.
func CheckLoop(cidrs []netip.Prefix, endpoints []netip.Addr) error {
	for _, ep := range endpoints {
		for _, p := range cidrs {
			if p.Contains(ep) {
				return fmt.Errorf("%s contains %s, which subtun itself connects to (API server / Docker daemon): "+
					"routing it into the tunnel would cut the tunnel; use narrower CIDRs", p, ep)
			}
		}
	}
	return nil
}

// Start asks sudo for the helper, creates the utun with routes for cidrs and
// starts the stack, forwarding connections through dialer.
func Start(ctx context.Context, cidrs []netip.Prefix, dialer netstack.Dialer, log *slog.Logger) (*Capture, error) {
	addr, err := privhelper.ValidateTunAddr(TunAddr)
	if err != nil {
		return nil, err
	}
	h, err := privhelper.Start(ctx, &transport.LineLog{Log: log, Prefix: "helper: "}, log)
	if err != nil {
		return nil, err
	}
	name, f, err := h.CreateTun(MTU, addr)
	if err != nil {
		_ = h.Close()
		return nil, err
	}
	for _, p := range cidrs {
		if err := h.AddRoute(p); err != nil {
			_ = f.Close()
			_ = h.Close() // helper removes the routes it added and the utun
			return nil, err
		}
	}
	if err := h.Done(); err != nil {
		_ = f.Close()
		return nil, err
	}

	dev, err := tundev.FromFile(f)
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	st, err := netstack.New(dev, dialer, netstack.Options{Logger: log})
	if err != nil {
		_ = dev.Close()
		return nil, err
	}
	s := make([]string, len(cidrs))
	for i, p := range cidrs {
		s[i] = p.String()
	}
	log.Info("capturing", "utun", name, "cidrs", strings.Join(s, ","), "mtu", dev.MTU())
	return &Capture{Name: name, stack: st}, nil
}
