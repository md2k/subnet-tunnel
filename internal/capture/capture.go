// Package capture sets up transparent capture: the root helper creates a
// utun interface with routes, and a userspace TCP/IP stack on that interface
// forwards every connection through the tunnel. With DNS capture, the helper
// also redirects the system's DNS queries to subtun's DNS engine and stays
// up for the session to remove that redirect again.
package capture

import (
	"context"
	"log/slog"
	"net/netip"
	"time"

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

// Options configures the utun and, optionally, DNS capture.
type Options struct {
	TunAddr netip.Addr // validated by the caller (privhelper.ValidateTunAddr)
	MTU     int
	DNS     *DNSOptions
}

// Capture is a running utun capture.
type Capture struct {
	Name   string // utunN
	stack  *netstack.Stack
	helper *privhelper.Client // session mode only (DNS capture)
	dns    *dnsRuntime
	stop   context.CancelFunc
}

// HelperExited is closed if the root helper of a DNS capture session goes
// away; nil (never ready) without DNS capture.
func (c *Capture) HelperExited() <-chan struct{} {
	if c.helper == nil {
		return nil
	}
	return c.helper.Exited()
}

// Close undoes the capture in order: firewall rules first (the helper
// removes them when we disconnect), then the DNS engine, then the stack and
// utun; macOS removes the interface and its routes.
func (c *Capture) Close() error {
	c.stop() // stops following DNS server changes
	if c.helper != nil {
		_ = c.helper.Close()
	}
	if c.dns != nil {
		c.dns.close()
	}
	return c.stack.Close()
}

// Start asks sudo for the helper, creates the utun with the given routes
// (already planned and checked), sets up DNS capture if asked, and starts
// the stack, forwarding connections through dialer.
func Start(ctx context.Context, prefixes []netip.Prefix, opts Options, dialer netstack.Dialer, log *slog.Logger) (_ *Capture, err error) {
	ctx, stop := context.WithCancel(ctx)
	defer func() {
		if err != nil {
			stop()
		}
	}()

	// The DNS engine listens before any rule points at it.
	var dr *dnsRuntime
	if opts.DNS != nil {
		if dr, err = startDNS(ctx, opts.DNS, log); err != nil {
			return nil, err
		}
		defer func() {
			if err != nil {
				dr.close()
			}
		}()
	}

	h, err := privhelper.Start(ctx, &transport.LineLog{Log: log, Prefix: "helper: "}, log)
	if err != nil {
		return nil, err
	}
	name, f, err := h.CreateTun(opts.MTU, opts.TunAddr)
	if err != nil {
		_ = h.Close()
		return nil, err
	}
	fail := func(err error) (*Capture, error) {
		_ = f.Close()
		_ = h.Close() // helper removes its firewall rules, routes and the utun
		return nil, err
	}
	for _, p := range prefixes {
		if err := h.AddRoute(p); err != nil {
			return fail(err)
		}
	}
	session := false
	if dr != nil {
		if err := h.ApplyFirewall(dr.rules()); err != nil {
			return fail(err)
		}
		if err := h.DoneSession(); err != nil {
			return fail(err)
		}
		session = true
	} else if err := h.Done(); err != nil {
		_ = f.Close()
		return nil, err
	}

	dev, err := tundev.FromFile(f)
	if err != nil {
		_ = f.Close()
		if session {
			_ = h.Close()
		}
		return nil, err
	}
	st, err := netstack.New(dev, dialer, netstack.Options{Logger: log})
	if err != nil {
		_ = dev.Close()
		if session {
			_ = h.Close()
		}
		return nil, err
	}
	log.Info("capturing", "utun", name, "routes", len(prefixes), "mtu", dev.MTU(), "addr", opts.TunAddr)

	c := &Capture{Name: name, stack: st, dns: dr, stop: stop}
	if session {
		c.helper = h
		dr.logReady(log)
		if opts.DNS.Auto {
			go dr.follow(ctx, 5*time.Second, h, log)
		}
	}
	return c, nil
}
