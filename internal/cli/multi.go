package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/md2k/subnet-tunnel/internal/capture"
	"github.com/md2k/subnet-tunnel/internal/config"
	"github.com/md2k/subnet-tunnel/internal/dns"
	"github.com/md2k/subnet-tunnel/internal/privhelper"
	"github.com/md2k/subnet-tunnel/internal/routes"
	"github.com/md2k/subnet-tunnel/internal/socks"
	"github.com/md2k/subnet-tunnel/internal/transport"
	"github.com/md2k/subnet-tunnel/internal/tunnel"
)

// resolveEndpoint looks up a target's endpoint addresses; replaced in tests.
var resolveEndpoint = transport.ResolveEndpoint

// tunnelSpec is one profile of a run with several.
type tunnelSpec struct {
	name     string
	s        settings
	cfg      config.Profile // as configured (defaults applied): which shared values it sets
	connect  connectFunc
	endpoint func() (string, error) // the target's endpoint, without connecting
}

// multiPlan is the validated setup of a run with several profiles. Index i
// of every slice is profile i.
type multiPlan struct {
	specs    []*tunnelSpec
	policies []reconnectPolicy
	ks       []string     // kill switch per profile: off, on, lockdown
	rps      []*routePlan // nil: SOCKS only
	finals   []atomic.Pointer[[]netip.Prefix]

	mu        sync.Mutex
	endpoints []netip.Addr // every target's: excluded from every route

	tunAddr   netip.Addr
	mtu       int
	dns       *capture.DNSOptions // nil: no DNS capture
	dnsNames  []dns.Names
	unrouted  []string
	allowDNS  bool
	blockIPv6 bool
	ipv6Why   string
	warns     []string
}

func (mp *multiPlan) final(i int) []netip.Prefix {
	if p := mp.finals[i].Load(); p != nil {
		return *p
	}
	return nil
}

func (mp *multiPlan) hasRoutes() bool {
	return slices.ContainsFunc(mp.rps, func(rp *routePlan) bool { return rp != nil })
}

// planMulti validates several profiles together before anything connects
// or asks for sudo: each profile's own settings, the shared ones, and the
// rules for combining them.
func planMulti(ctx context.Context, specs []*tunnelSpec) (*multiPlan, error) {
	n := len(specs)
	mp := &multiPlan{specs: specs, policies: make([]reconnectPolicy, n), ks: make([]string, n),
		rps: make([]*routePlan, n), finals: make([]atomic.Pointer[[]netip.Prefix], n),
		dnsNames: make([]dns.Names, n), unrouted: make([]string, n)}
	note := func(name, msg string) { mp.warns = append(mp.warns, name+": "+msg) }

	// Shared settings that can't be merged: the values profiles set must agree.
	tunAddr, err := agree(specs, "tun.address", func(p config.Profile) string { return p.Tun.Address })
	if err != nil {
		return nil, err
	}
	mtu, err := agree(specs, "tun.mtu", func(p config.Profile) string {
		if p.Tun.MTU == 0 {
			return ""
		}
		return fmt.Sprint(p.Tun.MTU)
	})
	if err != nil {
		return nil, err
	}
	fallback, err := agree(specs, "dns.fallback", func(p config.Profile) string { return p.DNS.Fallback })
	if err != nil {
		return nil, err
	}
	socksBy := map[string]string{}
	for i, sp := range specs {
		if tunAddr != "" {
			sp.s.tunAddr = tunAddr
		}
		if mtu != "" {
			sp.s.mtu, _ = strconv.Atoi(mtu) // the config checked it
		}
		sp.s.dnsFallback = fallback
		if a := sp.s.socks; a != "" {
			if other, ok := socksBy[a]; ok {
				return nil, fmt.Errorf("profiles %s and %s both want the SOCKS address %s", other, sp.name, a)
			}
			socksBy[a] = sp.name
		}
		p := reconnectPolicy{attempts: sp.s.reconnectAttempts, delay: sp.s.reconnectDelay, maxDelay: sp.s.reconnectMaxDelay}
		if err := p.validate(); err != nil {
			return nil, fmt.Errorf("profile %s: %w", sp.name, err)
		}
		mp.policies[i] = p
	}

	// Every target's endpoint stays out of every route, so no tunnel's own
	// connection runs inside another tunnel (or its own).
	for _, sp := range specs {
		host, err := sp.endpoint()
		if err != nil {
			return nil, fmt.Errorf("profile %s: %w", sp.name, err)
		}
		for _, a := range resolveEndpoint(ctx, host) {
			if !slices.Contains(mp.endpoints, a) {
				mp.endpoints = append(mp.endpoints, a)
			}
		}
	}

	// Each profile's routes, DNS names and guards.
	var participants []int
	for i, sp := range specs {
		rp, warns, err := planRoutes(sp.s)
		if err != nil {
			return nil, fmt.Errorf("profile %s: %w", sp.name, err)
		}
		for _, w := range warns {
			note(sp.name, w)
		}
		mp.rps[i] = rp
		if rp != nil {
			final, _, err := carveEndpoints(rp, mp.endpoints)
			if err != nil {
				return nil, fmt.Errorf("profile %s: %w", sp.name, err)
			}
			mp.finals[i].Store(&final)
		}
		gp, notes, err := planGuard(sp.s, rp)
		if err != nil {
			return nil, fmt.Errorf("profile %s: %w", sp.name, err)
		}
		for _, w := range notes {
			note(sp.name, w)
		}
		mp.ks[i] = "off"
		if gp != nil {
			mp.ks[i] = gp.killSwitch
			if gp.blockIPv6 && !mp.blockIPv6 {
				mp.blockIPv6, mp.ipv6Why = true, fmt.Sprintf("%s, profile %s", gp.ipv6Why, sp.name)
			}
		}
		if mp.unrouted[i], err = dns.ParseUnrouted(sp.s.dnsUnrouted); err != nil {
			return nil, fmt.Errorf("profile %s: %w", sp.name, err)
		}
		switch sp.s.dnsCapture {
		case "", "firewall", "off":
		default:
			return nil, fmt.Errorf("profile %s: DNS capture %q: use firewall or off", sp.name, sp.s.dnsCapture)
		}
		if len(sp.s.dnsDomains) == 0 && len(sp.s.dnsPatterns) == 0 || sp.s.dnsCapture == "off" {
			continue
		}
		if rp == nil {
			note(sp.name, "DNS settings ignored: DNS capture works together with the utun capture, and this profile has no routes (CIDRs)")
			continue
		}
		mp.dnsNames[i] = dns.Names{Domains: sp.s.dnsDomains, Patterns: sp.s.dnsPatterns}
		participants = append(participants, i)
	}
	if err := checkOverlaps(mp); err != nil {
		return nil, err
	}

	// The kill switch's DNS hold: blocked if any profile with a kill switch
	// wants it blocked.
	anyKS := false
	mp.allowDNS = true
	for i, sp := range specs {
		if mp.ks[i] == "off" {
			continue
		}
		anyKS = true
		if sp.s.killSwitchDNS != "allow" {
			mp.allowDNS = false
		}
	}
	if !anyKS {
		mp.allowDNS = false
	}
	if mp.hasRoutes() {
		if mp.tunAddr, err = privhelper.ValidateTunAddr(specs[0].s.tunAddr); err != nil {
			return nil, err
		}
		mp.mtu = specs[0].s.mtu
	}
	if len(participants) > 0 {
		if err := planMultiDNS(mp, participants); err != nil {
			return nil, err
		}
	}
	return mp, nil
}

// agree returns the value profiles set for a shared setting that can't be
// merged ("" if none sets it), or an error naming the profiles that differ.
func agree(specs []*tunnelSpec, key string, get func(config.Profile) string) (string, error) {
	var val, by string
	for _, sp := range specs {
		v := get(sp.cfg)
		if v == "" {
			continue
		}
		if val != "" && v != val {
			return "", fmt.Errorf("%s differs between profiles %s (%s) and %s (%s): it is shared by every profile of a run; set it once, in defaults", key, by, val, sp.name, v)
		}
		val, by = v, sp.name
	}
	return val, nil
}

// checkOverlaps refuses the same CIDR in two profiles: routes split by
// destination address, and nothing says which tunnel would get it.
func checkOverlaps(mp *multiPlan) error {
	owner := map[netip.Prefix]string{}
	for i, rp := range mp.rps {
		if rp == nil {
			continue
		}
		name := mp.specs[i].name
		seen := map[netip.Prefix]bool{}
		for _, p := range append(slices.Clone(rp.includes), mp.final(i)...) {
			if seen[p] {
				continue
			}
			seen[p] = true
			if other, ok := owner[p]; ok {
				return fmt.Errorf("%s is routed by both profiles %s and %s: a CIDR can belong to one profile only", p, other, name)
			}
			owner[p] = name
		}
	}
	return nil
}

// planMultiDNS sets up DNS for the profiles that take part: one matcher,
// each profile its own target; the captured servers are the union.
func planMultiDNS(mp *multiPlan, participants []int) error {
	m, err := dns.NewMultiMatcher(mp.dnsNames)
	if err != nil {
		return err
	}
	if m.CatchAll() {
		search, _ := systemSearch()
		m.SetLocal(search, localPrefixes())
	}
	opts := &capture.DNSOptions{Match: m, Tunnels: make([]capture.DNSTunnel, len(mp.specs))}
	if m.CatchAll() {
		opts.Locals = localPrefixes
	}
	for i, sp := range mp.specs {
		opts.Tunnels[i] = capture.DNSTunnel{Name: sp.name, Unrouted: mp.unrouted[i]}
	}
	auto := false
	for _, i := range participants {
		list := mp.specs[i].s.dnsServers
		if len(list) == 0 || len(list) == 1 && list[0] == "auto" {
			auto = true
			continue
		}
		pinned, err := parseServers(list)
		if err != nil {
			return fmt.Errorf("profile %s: %w", mp.specs[i].name, err)
		}
		for _, a := range pinned {
			if !slices.Contains(opts.Pinned, a) {
				opts.Pinned = append(opts.Pinned, a)
			}
		}
	}
	opts.Servers = slices.Clone(opts.Pinned)
	if auto {
		servers, notes, err := systemDNS()
		if err != nil {
			return fmt.Errorf("reading the system's DNS servers: %w", err)
		}
		mp.warns = append(mp.warns, notes...)
		for _, a := range servers {
			if !slices.Contains(opts.Servers, a) {
				opts.Servers = append(opts.Servers, a)
			}
		}
		if len(servers) == 0 && len(opts.Pinned) == 0 {
			return fmt.Errorf("no IPv4 DNS server in %s to capture; set the servers explicitly", dns.ResolvConf)
		}
		opts.Auto = true
	} else {
		opts.Pinned = nil // the servers are all there is; nothing to follow
	}
	if f := mp.specs[0].s.dnsFallback; f != "" && f != "system" {
		ap, err := parseResolver(f)
		if err != nil {
			return err
		}
		opts.Fallback = []netip.AddrPort{ap}
	}
	mp.dns = opts
	return nil
}

// tunnelState is where a profile's tunnel is.
type tunnelState int

const (
	stateConnecting   tunnelState = iota // first connection not made yet
	stateUp                              // connected
	stateReconnecting                    // lost, trying again
	stateGaveUp                          // out of attempts
)

// active reports whether profile i's routes and names are in use: while its
// tunnel is up or reconnecting, and always with a kill switch (its traffic
// is refused rather than leaking).
func (mp *multiPlan) active(i int, st tunnelState) bool {
	if mp.rps[i] == nil {
		return false
	}
	return mp.ks[i] != "off" || st == stateUp || st == stateReconnecting
}

// layout is what the capture needs for the profiles in use: the routes on
// the utun, the router's table, and the kill switch's guard.
func (mp *multiPlan) layout(states []tunnelState, lives []*liveTunnel) ([]netip.Prefix, []routeEntry, capture.Guard, error) {
	var all []netip.Prefix
	var entries []routeEntry
	var ks, plain, lock, notLock []netip.Prefix
	for i := range mp.specs {
		if !mp.active(i, states[i]) {
			continue
		}
		f := mp.final(i)
		for _, p := range f {
			if !slices.Contains(all, p) {
				all = append(all, p)
			}
			entries = append(entries, routeEntry{prefix: p, tunnel: lives[i]})
		}
		if mp.ks[i] == "off" {
			plain = append(plain, f...)
		} else {
			ks = append(ks, f...)
		}
		if mp.ks[i] == "lockdown" {
			lock = append(lock, f...)
		} else {
			notLock = append(notLock, f...)
		}
	}
	var g capture.Guard
	if len(ks) > 0 {
		base, err := routes.Compute(ks, plain)
		if err != nil {
			return nil, nil, g, err
		}
		g.Base = base.Routes
	}
	if len(lock) > 0 {
		l, err := routes.Compute(lock, notLock)
		if err != nil {
			return nil, nil, g, err
		}
		g.Lockdown = l.Routes
	}
	return all, entries, g, nil
}

// ksMode is the kill switch mode for the capture's log: lockdown if every
// profile with one is in lockdown, on if any has one.
func (mp *multiPlan) ksMode() string {
	mode := "off"
	for _, k := range mp.ks {
		switch {
		case k == "on":
			return "on"
		case k == "lockdown":
			mode = "lockdown"
		}
	}
	return mode
}

// carveEndpoints takes endpoint addresses the routes cover out of them.
func carveEndpoints(rp *routePlan, endpoints []netip.Addr) (final []netip.Prefix, hit []netip.Prefix, err error) {
	for _, p := range routes.HostPrefixes(endpoints) {
		if _, ok := rp.plan.Routed(p.Addr()); ok {
			hit = append(hit, p)
		}
	}
	if len(hit) == 0 {
		return rp.plan.Routes, nil, nil
	}
	plan, err := routes.Compute(rp.includes, append(slices.Clone(rp.excludes), hit...))
	if err != nil {
		return nil, nil, err
	}
	reserved := make([]routes.Reserved, len(endpoints))
	for i, a := range endpoints {
		reserved[i] = routes.Reserved{Addr: a, What: "subtun's own endpoint"}
	}
	if errs, _ := routes.Check(plan, reserved, nil); len(errs) > 0 {
		return nil, nil, errors.New(strings.Join(errs, "; "))
	}
	return plan.Routes, hit, nil
}

// addEndpoints excludes endpoint addresses found after connecting (the API
// server's name resolved to a new address) from every route, and reports
// whether any route changed.
func (mp *multiPlan) addEndpoints(addrs []netip.Addr) (bool, error) {
	mp.mu.Lock()
	defer mp.mu.Unlock()
	var added bool
	for _, a := range addrs {
		if !slices.Contains(mp.endpoints, a) {
			mp.endpoints = append(mp.endpoints, a)
			added = true
		}
	}
	if !added {
		return false, nil
	}
	changed := false
	for i, rp := range mp.rps {
		if rp == nil {
			continue
		}
		final, _, err := carveEndpoints(rp, mp.endpoints)
		if err != nil {
			return changed, err
		}
		if !slices.Equal(final, mp.final(i)) {
			mp.finals[i].Store(&final)
			changed = true
		}
	}
	return changed, nil
}

func printMultiPlan(w io.Writer, mp *multiPlan) {
	for i, sp := range mp.specs {
		fmt.Fprintf(w, "profile %s:\n", sp.name)
		if rp := mp.rps[i]; rp != nil {
			f := mp.final(i)
			fmt.Fprintf(w, "  routes (%d, from %d given):\n", len(f), len(rp.includes))
			for _, p := range f {
				fmt.Fprintf(w, "    %s%s\n", p, takenBy(mp, i, p))
			}
			for _, n := range rp.plan.Redundant {
				fmt.Fprintf(w, "  dropped: %s\n", n)
			}
		} else {
			fmt.Fprintln(w, "  no routes")
		}
		if sp.s.socks != "" {
			fmt.Fprintf(w, "  SOCKS5 proxy on %s\n", sp.s.socks)
		}
		if names := mp.dnsNames[i]; mp.dns != nil && (len(names.Domains) > 0 || len(names.Patterns) > 0) {
			what := strings.Join(names.Domains, ", ")
			if len(names.Patterns) > 0 {
				if what != "" {
					what += ", "
				}
				what += fmt.Sprintf("%d pattern(s)", len(names.Patterns))
			}
			fmt.Fprintf(w, "  DNS through this tunnel: %s (unrouted answers: %s)\n", what, mp.unrouted[i])
		}
		switch mp.ks[i] {
		case "on":
			fmt.Fprintln(w, "  kill switch: on (routes stay, refused, if it gives up; blocks stay after a crash)")
		case "lockdown":
			fmt.Fprintln(w, "  kill switch: lockdown (as on; blocks also stay after Ctrl-C)")
		default:
			if mp.rps[i] != nil {
				fmt.Fprintln(w, "  routes added when its tunnel is up, removed if it gives up")
			}
		}
		fmt.Fprintf(w, "  reconnect: %s\n", mp.policies[i])
	}
	if mp.dns != nil {
		servers := make([]string, len(mp.dns.Servers))
		for i, a := range mp.dns.Servers {
			servers[i] = a.String()
		}
		fmt.Fprintf(w, "DNS capture (firewall): queries to %s are answered by subtun\n", strings.Join(servers, ", "))
		if mp.dns.Match.CatchAll() {
			fmt.Fprintf(w, "  names under %s stay local (list one to send it through a tunnel)\n", strings.Join(mp.dns.Match.Local(), ", "))
		}
		if mp.dns.Fallback != nil {
			fmt.Fprintf(w, "  other names: %s\n", mp.dns.Fallback[0])
		} else {
			fmt.Fprintln(w, "  other names: the captured servers")
		}
		if mp.dns.Auto {
			fmt.Fprintln(w, "  servers follow the system's when the network changes")
		}
		if mp.ksMode() != "off" {
			if mp.allowDNS {
				fmt.Fprintln(w, "  DNS stays allowed while a kill switch holds")
			} else {
				fmt.Fprintln(w, "  DNS to the captured servers is blocked too while a kill switch holds")
			}
		}
	}
	if mp.blockIPv6 {
		fmt.Fprintf(w, "IPv6: outgoing IPv6 blocked (%s); link-local, multicast and loopback still allowed\n", mp.ipv6Why)
	}
	for _, wn := range mp.warns {
		fmt.Fprintf(w, "warning: %s\n", wn)
	}
	if mp.hasRoutes() {
		fmt.Fprintf(w, "utun %s, MTU %d; the root helper stays up so routes can follow the profiles. Endpoints excluded from every route: %v\n",
			mp.tunAddr, mp.mtu, mp.endpoints)
	}
}

// takenBy notes when a route of profile i lies inside another profile's
// broader route (most specific wins).
func takenBy(mp *multiPlan, i int, p netip.Prefix) string {
	for j := range mp.specs {
		if j == i {
			continue
		}
		for _, q := range mp.final(j) {
			if q.Bits() < p.Bits() && q.Contains(p.Addr()) {
				return fmt.Sprintf("  (taken from %s's %s)", mp.specs[j].name, q)
			}
		}
	}
	return ""
}

// tunnelEvent is a profile's tunnel changing state.
type tunnelEvent struct {
	i       int
	state   tunnelState
	carrier *transport.Carrier // stateUp
	err     error              // stateGaveUp
}

// runTunnel keeps one profile's tunnel connected by its reconnect policy:
// the first connection too may be retried.
func runTunnel(ctx context.Context, i int, live *liveTunnel, policy reconnectPolicy,
	try func(context.Context) (*session, error), send func(tunnelEvent) bool, log *slog.Logger) {
	var cur *session
	defer func() {
		live.set(nil)
		if cur != nil {
			cur.close()
		}
	}()
	s, err := try(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return
		}
		log.Warn("connecting failed", "err", err, "policy", policy.String())
		if s, err = reconnect(ctx, policy, nil, try, log); err != nil {
			if ctx.Err() == nil {
				send(tunnelEvent{i: i, state: stateGaveUp, err: err})
			}
			return
		}
	}
	for {
		cur = s
		live.set(s.client)
		if !send(tunnelEvent{i: i, state: stateUp, carrier: s.carrier}) {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-s.client.Done():
		}
		live.set(nil)
		cur.close()
		cur = nil
		if policy.attempts == 0 {
			send(tunnelEvent{i: i, state: stateGaveUp, err: errors.New("connection to the agent was lost")})
			return
		}
		log.Warn("connection to the agent lost; reconnecting", "policy", policy.String())
		if !send(tunnelEvent{i: i, state: stateReconnecting}) {
			return
		}
		if s, err = reconnect(ctx, policy, nil, try, log); err != nil {
			if ctx.Err() == nil {
				send(tunnelEvent{i: i, state: stateGaveUp, err: err})
			}
			return
		}
	}
}

// runMulti runs several profiles at once: one utun, helper and rule set,
// each profile's tunnel connecting and reconnecting on its own. It ends on
// Ctrl-C, or when every profile has given up.
func runMulti(ctx context.Context, out io.Writer, g *globalOpts, specs []*tunnelSpec, dryRun bool, maxDuration time.Duration) error {
	log := newLogger(g.verbose)
	if maxDuration < 0 {
		return errors.New("--max-duration must be positive")
	}
	mp, err := planMulti(ctx, specs)
	if err != nil {
		return err
	}
	if dryRun {
		printMultiPlan(out, mp)
		return nil
	}
	ctx, done := withMaxDuration(ctx, maxDuration, log)
	defer done() // last: the watchdog covers stopping
	for i, rp := range mp.rps {
		if rp == nil {
			continue
		}
		for _, n := range rp.plan.Redundant {
			log.Info("route rule dropped", "tunnel", specs[i].name, "rule", n.String())
		}
	}
	for _, wn := range mp.warns {
		log.Warn(wn)
	}
	agents, err := loadAgents("")
	if err != nil {
		return err
	}

	n := len(specs)
	lives := make([]*liveTunnel, n)
	logs := make([]*slog.Logger, n)
	for i, sp := range specs {
		lives[i], logs[i] = &liveTunnel{}, log.With("tunnel", sp.name)
	}

	// Listen before connecting, so a busy port fails fast.
	errc := make(chan error, n)
	var listeners []net.Listener
	defer func() {
		for _, ln := range listeners {
			_ = ln.Close()
		}
	}()
	for i, sp := range specs {
		if sp.s.socks == "" {
			continue
		}
		ln, err := net.Listen("tcp", sp.s.socks)
		if err != nil {
			return fmt.Errorf("profile %s: SOCKS listener: %w", sp.name, err)
		}
		listeners = append(listeners, ln)
		if host, _, _ := net.SplitHostPort(sp.s.socks); !isLoopback(host) {
			logs[i].Warn("SOCKS proxy is reachable from other hosts and has no authentication", "addr", ln.Addr())
		}
		srv := &socks.Server{Dialer: lives[i], Logger: logs[i]}
		go func() { errc <- srv.Serve(ctx, ln) }()
		logs[i].Info("SOCKS5 proxy ready", "addr", ln.Addr().String())
	}

	// The tunnels run until this returns; firewall rules and routes go
	// first (deferred below), then the tunnels.
	tctx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	defer func() {
		cancel()
		wg.Wait()
	}()

	states := make([]tunnelState, n)
	rt := &router{}
	var c *capture.Capture
	var helperExited <-chan struct{}
	deliberate := false
	if mp.hasRoutes() {
		marker := &leftovers{mark: privhelper.MarkLeftovers, clear: privhelper.ClearLeftovers}
		if c, err = startMultiCapture(ctx, mp, states, lives, rt, marker, log); err != nil {
			return err
		}
		defer func() {
			leftBehind := c.Stop(deliberate)
			marker.stopped(leftBehind)
			if leftBehind {
				log.Warn("kill switch: blocking rules stay in place; the next subtun run takes them over, or remove them with: subtun cleanup")
			}
		}()
		helperExited = c.HelperExited()
	}

	events := make(chan tunnelEvent)
	send := func(ev tunnelEvent) bool {
		select {
		case events <- ev:
			return true
		case <-tctx.Done():
			return false
		}
	}
	started := make([]time.Time, n)
	for i, sp := range specs {
		try := func(ctx context.Context) (*session, error) {
			carrier, err := sp.connect(ctx, agents, logs[i])
			if err != nil {
				return nil, err
			}
			hctx, hcancel := context.WithTimeout(ctx, 30*time.Second)
			client, err := tunnel.NewClient(hctx, carrier, tunnel.Options{ExpectSHA256: carrier.SHA256, Logger: logs[i]})
			hcancel()
			if err != nil {
				return nil, fmt.Errorf("starting agent in %s: %w", carrier.Desc, err)
			}
			return &session{carrier: carrier, client: client}, nil
		}
		started[i] = time.Now()
		wg.Add(1)
		go func() {
			defer wg.Done()
			runTunnel(tctx, i, lives[i], mp.policies[i], try, send, logs[i])
		}()
	}

	helperGone := func() error {
		select {
		case <-ctx.Done():
			deliberate = true
			logShutdown(ctx, log)
			return nil
		case <-time.After(300 * time.Millisecond):
		}
		return errors.New("the root helper exited unexpectedly; its firewall rules may still be in place: the next subtun run takes them over, or remove them with: subtun cleanup")
	}
	for {
		select {
		case <-ctx.Done():
			deliberate = true
			logShutdown(ctx, log)
			return nil
		case err := <-errc:
			return fmt.Errorf("SOCKS listener: %w", err)
		case <-helperExited:
			return helperGone()
		case ev := <-events:
			tl := logs[ev.i]
			prev := states[ev.i]
			states[ev.i] = ev.state
			switch ev.state {
			case stateUp:
				if prev == stateConnecting {
					tl.Info("tunnel up", "via", ev.carrier.Desc, "took", time.Since(started[ev.i]).Round(time.Millisecond))
				} else {
					tl.Info("reconnected", "via", ev.carrier.Desc)
				}
				if ev.carrier.Local && routesInternet(mp.final(ev.i)) {
					tl.Warn(localLoopWarning)
				}
				if changed, err := mp.addEndpoints(ev.carrier.Endpoints); err != nil {
					tl.Warn("excluding subtun's own endpoint from the routes failed", "err", err)
				} else if changed {
					tl.Info("excluded from routes: subtun's own connection goes there", "addrs", ev.carrier.Endpoints)
				}
			case stateGaveUp:
				what := "its routes and names are removed"
				switch {
				case mp.rps[ev.i] == nil:
					what = "its SOCKS proxy fails until subtun restarts"
				case mp.ks[ev.i] != "off":
					what = "kill switch: its routes stay, and its traffic is refused until subtun restarts"
				}
				tl.Warn("gave up: "+what, "err", ev.err)
			}
			if !slices.ContainsFunc(states, func(s tunnelState) bool { return s != stateGaveUp }) {
				return errors.New("every profile gave up")
			}
			if c != nil {
				if err := applyLayout(c, mp, states, lives, rt); err != nil {
					log.Warn("updating the routes failed", "err", err)
				}
			}
		}
	}
}

// startMultiCapture starts the capture before any tunnel connects: the
// helper stays up for the session, and the routes of the profiles in use
// (those with a kill switch, at first) follow as tunnels come and go.
func startMultiCapture(ctx context.Context, mp *multiPlan, states []tunnelState, lives []*liveTunnel, rt *router,
	marker *leftovers, log *slog.Logger) (*capture.Capture, error) {
	var early *privhelper.Client
	if privhelper.LeftoversMarked() {
		log.Info("firewall rules from another subtun session may be in place; checking with the root helper")
		h, err := privhelper.Start(ctx, &transport.LineLog{Log: log, Prefix: "helper: "}, log)
		if err != nil {
			return nil, startErr(ctx, err)
		}
		res, err := h.Adopt()
		if err != nil {
			_ = h.Close()
			return nil, fmt.Errorf("taking over firewall rules: %w", err)
		}
		log.Info(res.Message)
		marker.adopted(res)
		early = h
	}
	all, entries, guard, err := mp.layout(states, lives)
	if err != nil {
		if early != nil {
			_ = early.Close()
		}
		return nil, err
	}
	rt.set(entries)
	opts := capture.Options{TunAddr: mp.tunAddr, MTU: mp.mtu, Session: true, Helper: early,
		KillSwitch: mp.ksMode(), Guard: guard, AllowDNS: mp.allowDNS, BlockIPv6: mp.blockIPv6, Locals: localPrefixes}
	if opts.BlockIPv6 {
		if a, ok := ipv6Endpoint(mp.endpoints); ok {
			log.Warn("not blocking IPv6: subtun's own connection may use it", "endpoint", a)
			opts.BlockIPv6 = false
		}
	}
	if mp.dns != nil {
		for i := range mp.specs {
			mp.dns.Tunnels[i].Upstream = dns.UpstreamFunc(lives[i].ExchangeDNS)
			mp.dns.Tunnels[i].Unreachable = func(a netip.Addr) bool { return unreachable(mp.final(i))(a) }
			mp.dns.Match.SetOn(i, mp.active(i, states[i]))
		}
		opts.DNS = mp.dns
	}
	if opts.DNS != nil || opts.KillSwitch != "off" || opts.BlockIPv6 {
		marker.firewall()
	}
	c, err := capture.Start(ctx, all, opts, rt, log)
	if err != nil {
		marker.startFailed()
		return nil, startErr(ctx, fmt.Errorf("utun capture: %w", err))
	}
	return c, nil
}

// applyLayout brings the router, the DNS matcher and the capture's routes
// and guard in line with the profiles in use. New routes reach the router
// before the utun; removed ones leave the utun last (Capture.Update).
func applyLayout(c *capture.Capture, mp *multiPlan, states []tunnelState, lives []*liveTunnel, rt *router) error {
	all, entries, guard, err := mp.layout(states, lives)
	if err != nil {
		return err
	}
	rt.set(entries)
	if mp.dns != nil {
		for i := range mp.specs {
			mp.dns.Match.SetOn(i, mp.active(i, states[i]))
		}
	}
	return c.Update(all, guard)
}
