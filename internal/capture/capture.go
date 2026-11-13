// Package capture sets up transparent capture: the root helper creates a
// utun interface with routes, and a userspace TCP/IP stack on that interface
// forwards every connection through the tunnel. With DNS capture, a kill
// switch or IPv6 blocking, the helper also loads firewall rules and stays up
// for the session to remove them again (or, for the kill switch, leave the
// blocking ones in place when the tunnel goes away).
package capture

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
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
	// tunnel; lockdown: also after a deliberate stop. Guard says what is
	// guarded, and which part is in lockdown (several tunnels can mix).
	KillSwitch string
	Guard      Guard
	AllowDNS   bool // DNS stays allowed while the kill switch holds
	BlockIPv6  bool
	// Locals reads the machine's networks: they stay out of the guard, which
	// follows them (see guardState). nil: none.
	Locals func() []netip.Prefix

	// Session keeps the root helper up even without firewall rules, so
	// routes can change while running (Update; several tunnels).
	Session bool

	// OnRefuse is told about connections the loop guard refuses.
	OnRefuse func(dst string)

	// Helper, if set, was started earlier (to take over an earlier session's
	// rules before connecting) and is used instead of starting one.
	Helper *privhelper.Client
}

func (o Options) killSwitch() bool { return o.KillSwitch == "on" || o.KillSwitch == "lockdown" }

func (o Options) locals() []netip.Prefix {
	if o.Locals == nil {
		return nil
	}
	return o.Locals()
}

// sessionHelper is what a running capture asks of the root helper.
type sessionHelper interface {
	AddRoute(netip.Prefix) error
	DeleteRoute(netip.Prefix) error
	ApplyFirewall(platform.Rules, *platform.Rules) error
	ClearFirewall() error
	FlushDNSCache() error
	End(keep bool) error
	Close() error
	Exited() <-chan struct{}
}

// Capture is a running utun capture.
type Capture struct {
	Name   string // utunN
	stack  *netstack.Stack
	helper sessionHelper // session mode only
	dns    *dnsRuntime
	stop   context.CancelFunc
	opts   Options
	guard  *guardState // with a kill switch
	log    *slog.Logger

	mu      sync.Mutex     // firewall updates and route changes, one at a time
	routes  []netip.Prefix // on the utun
	dirty   bool           // the guard changed but applying it failed: retry
	stopped bool           // stopping: no more firewall updates
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
// switch's rules go, except the lockdown part. Any other end (lost tunnel,
// errors) leaves them all in place. It reports whether rules were left
// behind.
func (c *Capture) Stop(deliberate bool) (leftBehind bool) {
	c.stop() // stops following DNS server and network changes
	leftBehind = c.stopHelper(deliberate)
	if c.dns != nil {
		c.dns.close()
	}
	_ = c.stack.Close()
	return leftBehind
}

// stopHelper ends the session helper, if any, and reports whether rules
// stay behind. Firewall updates still queued (network or DNS server
// changes) are dropped from here on, so they can't undo the narrowing.
func (c *Capture) stopHelper(deliberate bool) (leftBehind bool) {
	if c.helper == nil {
		return false
	}
	c.mu.Lock()
	c.stopped = true
	if deliberate {
		leftBehind = c.narrowForStop()
	} else {
		leftBehind = c.guard != nil && len(c.guard.get()) > 0
	}
	c.mu.Unlock()
	if deliberate {
		_ = c.helper.End(leftBehind)
	}
	_ = c.helper.Close() // without End: the helper applies the crash policy
	return leftBehind
}

// narrowForStop makes the rules that stay after a deliberate stop the
// lockdown part of the guard, and reports whether any stay. c.mu is held.
func (c *Capture) narrowForStop() bool {
	if c.guard == nil {
		return false
	}
	guarded, lockdown := c.guard.get(), c.guard.getLockdown()
	if len(lockdown) == 0 || slices.Equal(lockdown, guarded) && !c.dirty {
		return len(lockdown) > 0
	}
	running, persist := rules(c.opts, guarded, lockdown, c.Name, c.dns)
	if err := c.helper.ApplyFirewall(running, persist); err != nil {
		c.log.Warn("kill switch: keeping the whole guard after the stop, narrowing it to the lockdown profiles failed", "err", err)
	}
	return true
}

// Update replaces the utun's routes and the kill switch's guard (several
// tunnels: profiles come and go). Routes are added first, then the
// firewall rules follow the guard, then routes go, so no address leaves the
// tunnel in between. A route that can't be added or removed doesn't hold
// up the others; if the guard can't be applied, nothing is removed. The
// next Update tries again. It needs a session (Options.Session).
func (c *Capture) Update(prefixes []netip.Prefix, g Guard) error {
	if c.helper == nil {
		return errors.New("route changes need the session helper")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.stopped {
		return errors.New("stopping")
	}
	var errs []error
	for _, p := range prefixes {
		if slices.Contains(c.routes, p) {
			continue
		}
		if err := c.helper.AddRoute(p); err != nil {
			errs = append(errs, err) // the others still go in; tried again next time
			continue
		}
		c.routes = append(c.routes, p)
	}
	if c.guard != nil {
		changed, err := c.guard.setBase(g)
		if err != nil {
			return errors.Join(append(errs, err)...)
		}
		if changed || c.dirty {
			if err := c.applyLocked(); err != nil {
				c.dirty = true
				return errors.Join(append(errs, fmt.Errorf("updating the kill switch: %w", err))...)
			}
			c.dirty = false
		}
	}
	for _, p := range slices.Clone(c.routes) {
		if slices.Contains(prefixes, p) {
			continue
		}
		if err := c.helper.DeleteRoute(p); err != nil {
			errs = append(errs, err) // kept, tried again next time
			continue
		}
		c.routes = slices.DeleteFunc(c.routes, func(q netip.Prefix) bool { return q == p })
	}
	return errors.Join(errs...)
}

// AddDNSTunnel adds a tunnel to the running DNS engine (a profile added
// while running), as the next target; before the matcher's names point at
// it. Without DNS capture it does nothing.
func (c *Capture) AddDNSTunnel(t DNSTunnel) {
	if c.dns != nil {
		c.dns.eng.AddTunnel(t.engineTunnel(c.dns.log))
	}
}

// FlushDNSCache has the system forget cached DNS answers: some came from a
// tunnel that is gone, or are failures from while it was down. Only with
// DNS capture (a session); a no-op once stopping.
func (c *Capture) FlushDNSCache() error {
	if c.helper == nil || c.dns == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.stopped {
		return nil
	}
	return c.helper.FlushDNSCache()
}

// BlockingIPv6 reports whether outgoing IPv6 is blocked (it is skipped
// when subtun's own connection may use IPv6).
func (c *Capture) BlockingIPv6() bool { return c.helper != nil && c.opts.BlockIPv6 }

// Guarding reports whether the capture has a kill switch guard (a profile
// had a kill switch when it started): only then can profiles with one join.
func (c *Capture) Guarding() bool { return c.guard != nil }

// HoldsDNS reports whether DNS to the captured servers stays blocked while
// the kill switch holds.
func (c *Capture) HoldsDNS() bool { return c.dns != nil && c.opts.killSwitch() && !c.opts.AllowDNS }

// GuardCounts returns how many prefixes the kill switch guards now, and how
// many of them stay after a deliberate stop.
func (c *Capture) GuardCounts() (guarded, lockdown int) {
	if c.guard == nil {
		return 0, 0
	}
	return len(c.guard.get()), len(c.guard.getLockdown())
}

// DNS returns the captured DNS servers now and where unmatched names go;
// nothing without DNS capture.
func (c *Capture) DNS() (servers []netip.Addr, fallback []netip.AddrPort) {
	if c.dns == nil {
		return nil, nil
	}
	return c.dns.current()
}

// Session reports whether the root helper stays up, so routes can change
// (Update).
func (c *Capture) Session() bool { return c.helper != nil }

// Routes returns the routes on the utun.
func (c *Capture) Routes() []netip.Prefix {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.routes)
}

// apply re-sends the whole firewall rule set (DNS servers, local networks
// or the guard changed).
func (c *Capture) apply() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.stopped {
		return nil
	}
	return c.applyLocked()
}

func (c *Capture) applyLocked() error {
	var guarded []netip.Prefix
	if c.guard != nil {
		guarded = c.guard.get()
	}
	running, persist := rules(c.opts, guarded, guarded, c.Name, c.dns)
	if running.Empty() {
		// The kill switch's profiles all stopped, and nothing else needs
		// rules: none stay (a later update applies them again).
		return c.helper.ClearFirewall()
	}
	return c.helper.ApplyFirewall(running, persist)
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
	var guard *guardState
	if opts.killSwitch() {
		if guard, err = newGuardState(opts.Guard, opts.locals()); err != nil {
			return fail(err)
		}
	}
	var guarded []netip.Prefix
	if guard != nil {
		guarded = guard.get()
	}
	running, persist := rules(opts, guarded, guarded, name, dr)
	session := !running.Empty() || opts.Session
	if session {
		if !running.Empty() {
			if err := h.ApplyFirewall(running, persist); err != nil {
				return fail(err)
			}
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
	st, err := netstack.New(dev, dialer, netstack.Options{Logger: log, TunAddr: opts.TunAddr, OnRefuse: opts.OnRefuse})
	if err != nil {
		_ = dev.Close()
		if session {
			_ = h.Close()
		}
		return nil, err
	}
	log.Info("capturing", "utun", name, "routes", len(prefixes), "mtu", dev.MTU(), "addr", opts.TunAddr)

	c := &Capture{Name: name, stack: st, dns: dr, stop: stop, opts: opts, guard: guard, log: log,
		routes: slices.Clone(prefixes)}
	if !session {
		return c, nil
	}
	c.helper = h
	if guard != nil {
		hold := "allowed"
		switch {
		case dr == nil:
			hold = "no DNS capture"
		case !opts.AllowDNS:
			hold = "blocked"
		}
		log.Info("kill switch on", "mode", opts.KillSwitch, "guarded_prefixes", len(guarded),
			"lockdown_prefixes", len(guard.getLockdown()), "dns_while_holding", hold)
		if opts.Locals != nil {
			go followLocals(ctx, followEvery, opts.Locals, guard, c.apply, log)
		}
	}
	if opts.BlockIPv6 {
		log.Info("outgoing IPv6 blocked (link-local, multicast and loopback still allowed)")
	}
	// The DNS servers and the local networks are followed separately;
	// both re-send the whole rule set, one at a time.
	if dr != nil {
		dr.logReady(log)
		if opts.DNS.Auto {
			go dr.follow(ctx, followEvery, log, c.apply)
		}
	}
	return c, nil
}

// rules builds the firewall rules for the session, and the ones that stay
// when the tunnel goes away (nil without a kill switch): guarded is
// guarded while running, kept stays blocked.
func rules(opts Options, guarded, kept []netip.Prefix, iface string, dr *dnsRuntime) (running platform.Rules, persist *platform.Rules) {
	var servers []netip.Addr
	if dr != nil {
		running.DNS = dr.redirect()
		servers = running.DNS.Servers
	}
	running.BlockIPv6 = opts.BlockIPv6
	if !opts.killSwitch() || len(guarded) == 0 {
		return running, nil
	}
	running.KillSwitch = &platform.KillSwitch{TunIface: iface, Prefixes: guarded}
	if len(kept) == 0 {
		return running, nil
	}
	persist = &platform.Rules{KillSwitch: &platform.KillSwitch{Prefixes: kept}, BlockIPv6: opts.BlockIPv6}
	if dr != nil && !opts.AllowDNS {
		persist.DNSBlock = servers
	}
	return running, persist
}
