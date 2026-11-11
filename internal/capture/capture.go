// Package capture sets up transparent capture: the root helper creates a
// utun interface with routes, and a userspace TCP/IP stack on that interface
// forwards every connection through the tunnel.
package capture

import (
	"context"
	"log/slog"
	"net/netip"

	"github.com/md2k/subnet-tunnel/internal/netstack"
	"github.com/md2k/subnet-tunnel/internal/privhelper"
	"github.com/md2k/subnet-tunnel/internal/transport"
	"github.com/md2k/subnet-tunnel/internal/tundev"
)

const (
	// DefaultMTU: 9000 more than doubled upload in the October utun
	// measurements (the cost is per packet). It only applies between the
	// kernel and our stack; the tunnel carries TCP streams, so nothing is
	// fragmented.
	DefaultMTU = 9000
	// DefaultTunAddr is the utun's own (point-to-point) address.
	// 198.18.0.0/15 is reserved for benchmarking (RFC 2544): real networks,
	// VPN clients and corporate address plans don't use it.
	DefaultTunAddr = "198.18.249.1"
)

// Options configures the utun.
type Options struct {
	TunAddr netip.Addr // validated by the caller (privhelper.ValidateTunAddr)
	MTU     int
}

// Capture is a running utun capture.
type Capture struct {
	Name  string // utunN
	stack *netstack.Stack
}

// Close stops the stack and closes the utun; macOS removes the interface
// and its routes.
func (c *Capture) Close() error { return c.stack.Close() }

// Start asks sudo for the helper, creates the utun with the given routes
// (already planned and checked) and starts the stack, forwarding connections
// through dialer.
func Start(ctx context.Context, prefixes []netip.Prefix, opts Options, dialer netstack.Dialer, log *slog.Logger) (*Capture, error) {
	h, err := privhelper.Start(ctx, &transport.LineLog{Log: log, Prefix: "helper: "}, log)
	if err != nil {
		return nil, err
	}
	name, f, err := h.CreateTun(opts.MTU, opts.TunAddr)
	if err != nil {
		_ = h.Close()
		return nil, err
	}
	for _, p := range prefixes {
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
	log.Info("capturing", "utun", name, "routes", len(prefixes), "mtu", dev.MTU(), "addr", opts.TunAddr)
	return &Capture{Name: name, stack: st}, nil
}
