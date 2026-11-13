// Package capture sets up transparent capture: the root helper creates a
// utun interface with routes, and a userspace TCP/IP stack on that interface
// forwards every connection through the tunnel. With DNS capture, a kill
// switch or IPv6 blocking, the helper also loads firewall rules and stays up
// for the session to remove them again (or, for the kill switch, leave the
// blocking ones in place when the tunnel goes away).
package capture

import (
	"context"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/md2k/subnet-tunnel/internal/netstack"
	"github.com/md2k/subnet-tunnel/internal/platform"
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

	// followEvery is how often the DNS servers and local networks are
	// checked for changes.
	followEvery = 5 * time.Second
)

// Options configures the utun and, optionally, DNS capture and the
// firewall guards.
type Options struct {
	TunAddr netip.Addr // validated by the caller (privhelper.ValidateTunAddr)
	MTU     int
	DNS     *DNSOptions

	// KillSwitch: "" or off; on: blocking rules stay after a crash or a lost
	// tunnel; lockdown: also after a deliberate stop.
	KillSwitch string
	Guarded    []netip.Prefix // what the kill switch blocks outside the tunnel
	AllowDNS   bool           // DNS stays allowed while the kill switch holds
	BlockIPv6  bool
	// Locals reads the machine's networks. With a kill switch the guard
	// follows them (see guardState); nil: it stays as given.
	Locals func() []netip.Prefix

	// Helper, if set, was started earlier (to take over an earlier session's
	// rules before connecting) and is used instead of starting one.
	Helper *privhelper.Client
}

func (o Options) killSwitch() bool { return o.KillSwitch == "on" || o.KillSwitch == "lockdown" }

// Capture is a running utun capture.
type Capture struct {
	Name     string // utunN
	stack    *netstack.Stack
	helper   *privhelper.Client // session mode only (firewall rules)
	dns      *dnsRuntime
	stop     context.CancelFunc
	lockdown bool
	keeps    bool // rules stay behind when the tunnel goes away
}

// HelperExited is closed if the root helper of a session goes away; nil
// (never ready) without firewall rules.
func (c *Capture) HelperExited() <-chan struct{} {
	if c.helper == nil {
		return nil
	}
	return c.helper.Exited()
}

// Stop undoes the capture in order: firewall rules first, then the DNS
// engine, then the stack and utun (macOS removes the interface and its
// routes). deliberate is a stop the user asked for (Ctrl-C): the kill
// switch's rules go, unless in lockdown. Any other end (lost tunnel,
// errors) leaves them in place. It reports whether rules were left behind.
func (c *Capture) Stop(deliberate bool) (leftBehind bool) {
	c.stop() // stops following DNS server changes
	if c.helper != nil {
		leftBehind = c.keeps && (!deliberate || c.lockdown)
		if deliberate {
			_ = c.helper.End(c.lockdown)
		}
		_ = c.helper.Close() // without End: the helper applies the crash policy
	}
	if c.dns != nil {
		c.dns.close()
	}
	_ = c.stack.Close()
	return leftBehind
}

// Start creates the utun with the given routes (already planned and
// checked) through the root helper (sudo), sets up DNS capture and the
// firewall guards if asked, and starts the stack, forwarding connections
// through dialer.
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

	h := opts.Helper
	if h == nil {
		if h, err = privhelper.Start(ctx, &transport.LineLog{Log: log, Prefix: "helper: "}, log); err != nil {
			return nil, err
		}
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
	running, persist := rules(opts, name, dr)
	session := !running.Empty()
	if session {
		if err := h.ApplyFirewall(running, persist); err != nil {
			return fail(err)
		}
		if err := h.DoneSession(); err != nil {
			return fail(err)
		}
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
	st, err := netstack.New(dev, dialer, netstack.Options{Logger: log, TunAddr: opts.TunAddr})
	if err != nil {
		_ = dev.Close()
		if session {
			_ = h.Close()
		}
		return nil, err
	}
	log.Info("capturing", "utun", name, "routes", len(prefixes), "mtu", dev.MTU(), "addr", opts.TunAddr)

	c := &Capture{Name: name, stack: st, dns: dr, stop: stop, lockdown: opts.KillSwitch == "lockdown", keeps: persist != nil}
	if session {
		c.helper = h
		if opts.killSwitch() {
			hold := "allowed"
			if dr != nil && !opts.AllowDNS {
				hold = "blocked"
			}
			log.Info("kill switch on", "mode", opts.KillSwitch, "guarded_prefixes", len(opts.Guarded), "dns_while_holding", hold)
		}
		if opts.BlockIPv6 {
			log.Info("outgoing IPv6 blocked (link-local, multicast and loopback still allowed)")
		}
		// The DNS servers and the local networks are followed separately;
		// both re-send the whole rule set, one at a time.
		guard := &guardState{prefixes: opts.Guarded}
		var applyMu sync.Mutex
		apply := func() error {
			applyMu.Lock()
			defer applyMu.Unlock()
			o := opts
			o.Guarded = guard.get()
			running, persist := rules(o, name, dr)
			return h.ApplyFirewall(running, persist)
		}
		if dr != nil {
			dr.logReady(log)
			if opts.DNS.Auto {
				go dr.follow(ctx, followEvery, log, apply)
			}
		}
		if opts.killSwitch() && len(opts.Guarded) > 0 && opts.Locals != nil {
			go followLocals(ctx, followEvery, prefixes, opts.Locals, guard, apply, log)
		}
	}
	return c, nil
}

// rules builds the firewall rules for the session, and the ones that stay
// when the tunnel goes away (nil without a kill switch).
func rules(opts Options, iface string, dr *dnsRuntime) (running platform.Rules, persist *platform.Rules) {
	var servers []netip.Addr
	if dr != nil {
		running.DNS = dr.redirect()
		servers = running.DNS.Servers
	}
	running.BlockIPv6 = opts.BlockIPv6
	if !opts.killSwitch() || len(opts.Guarded) == 0 {
		return running, nil
	}
	running.KillSwitch = &platform.KillSwitch{TunIface: iface, Prefixes: opts.Guarded}
	persist = &platform.Rules{KillSwitch: &platform.KillSwitch{Prefixes: opts.Guarded}, BlockIPv6: opts.BlockIPv6}
	if dr != nil && !opts.AllowDNS {
		persist.DNSBlock = servers
	}
	return running, persist
}
