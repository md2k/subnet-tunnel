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

// lookupEndpoint looks up a target's endpoint addresses; replaced in tests.
var lookupEndpoint = transport.LookupEndpoint

const (
	// layoutRetry is how soon a failed route update is tried again; the
	// wait doubles while the same error repeats, up to a minute.
	layoutRetry = 5 * time.Second
	// firstRoundWait bounds the wait for every profile's first attempt
	// before the capture starts; one still connecting carries on.
	firstRoundWait = 30 * time.Second
)

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
	hosts    []string     // each target's endpoint as configured
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
// rules for combining them. It looks nothing up: the endpoints' addresses
// come later (lookupEndpoints), after rules an earlier session left (which
// may block DNS) are taken over.
func planMulti(specs []*tunnelSpec) (*multiPlan, error) {
	n := len(specs)
	mp := &multiPlan{specs: specs, policies: make([]reconnectPolicy, n), ks: make([]string, n),
		rps: make([]*routePlan, n), hosts: make([]string, n), finals: make([]atomic.Pointer[[]netip.Prefix], n),
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
		return strconv.Itoa(p.Tun.MTU)
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
		if mp.hosts[i], err = sp.endpoint(); err != nil {
			return nil, fmt.Errorf("profile %s: %w", sp.name, err)
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
			final := rp.plan.Routes
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

// checkOverlaps refuses the same CIDR in the routes of two profiles: the
// most specific route decides which profile carries an address, and two
// equal ones leave it undecided.
func checkOverlaps(mp *multiPlan) error {
	owner := map[netip.Prefix]string{}
	for i, rp := range mp.rps {
		if rp == nil {
			continue
		}
		name := mp.specs[i].name
		for _, p := range rp.includes {
			if other, ok := owner[p]; ok && other != name {
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
		m.SetLocal(search, dnsLocals(mp.tunAddr)())
	}
	// The targets' own names must resolve while their tunnels are down.
	own := make([]string, len(mp.hosts))
	for i, h := range mp.hosts {
		own[i] = transport.HostName(h)
	}
	m.SetOwn(own)
	opts := &capture.DNSOptions{Match: m, Tunnels: make([]capture.DNSTunnel, len(mp.specs))}
	if m.CatchAll() {
		opts.Locals = dnsLocals(mp.tunAddr)
	}
	for i, sp := range mp.specs {
		opts.Tunnels[i] = capture.DNSTunnel{Name: sp.name, Unrouted: mp.unrouted[i]}
	}
	auto := false
	var pinned []netip.Addr
	for _, i := range participants {
		list := mp.specs[i].s.dnsServers
		if len(list) == 0 || len(list) == 1 && list[0] == "auto" {
			auto = true
			continue
		}
		servers, err := parseServers(list)
		if err != nil {
			return fmt.Errorf("profile %s: %w", mp.specs[i].name, err)
		}
		for _, a := range servers {
			if !slices.Contains(pinned, a) {
				pinned = append(pinned, a)
			}
		}
	}
	if auto {
		// The system's first, then the pinned ones: the order the capture
		// keeps when it follows the system's servers.
		servers, notes, err := systemDNS()
		if err != nil {
			return fmt.Errorf("reading the system's DNS servers: %w", err)
		}
		mp.warns = append(mp.warns, notes...)
		opts.Servers = slices.Clone(servers)
		for _, a := range pinned {
			if !slices.Contains(opts.Servers, a) {
				opts.Servers = append(opts.Servers, a)
			}
		}
		if len(opts.Servers) == 0 {
			return fmt.Errorf("no IPv4 DNS server in %s to capture; set the servers explicitly", dns.ResolvConf)
		}
		opts.Auto, opts.Pinned = true, pinned
	} else {
		opts.Servers = pinned
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

// lookupEndpoints finds the targets' endpoint addresses and takes them out
// of every route. A failed lookup is reported: that profile's own
// connection may then go into a tunnel.
func (mp *multiPlan) lookupEndpoints(ctx context.Context) []string {
	var warns []string
	var addrs []netip.Addr
	for i, host := range mp.hosts {
		a, err := lookupEndpoint(ctx, host)
		if err != nil {
			warns = append(warns, fmt.Sprintf("%s: looking up %s failed (%v); if its address lies inside the routes, this profile's own connection goes into a tunnel and can't connect", mp.specs[i].name, transport.HostName(host), err))
		}
		addrs = append(addrs, a...)
	}
	if _, err := mp.addEndpoints(addrs); err != nil {
		warns = append(warns, fmt.Sprintf("excluding the targets' endpoints from the routes: %v", err))
	}
	return warns
}

// addEndpoints takes endpoint addresses out of every route (found before
// connecting, or after: the API server's name resolved to a new address),
// and reports whether any route changed.
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
		final, err := carveEndpoints(rp, mp.endpoints)
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

// endpointList returns the endpoints found so far.
func (mp *multiPlan) endpointList() []netip.Addr {
	mp.mu.Lock()
	defer mp.mu.Unlock()
	return slices.Clone(mp.endpoints)
}

// carveEndpoints takes endpoint addresses the routes cover out of them.
func carveEndpoints(rp *routePlan, endpoints []netip.Addr) ([]netip.Prefix, error) {
	var hit []netip.Prefix
	for _, p := range routes.HostPrefixes(endpoints) {
		if _, ok := rp.plan.Routed(p.Addr()); ok {
			hit = append(hit, p)
		}
	}
	if len(hit) == 0 {
		return rp.plan.Routes, nil
	}
	plan, err := routes.Compute(rp.includes, append(slices.Clone(rp.excludes), hit...))
	if err != nil {
		return nil, err
	}
	reserved := make([]routes.Reserved, len(endpoints))
	for i, a := range endpoints {
		reserved[i] = routes.Reserved{Addr: a, What: "subtun's own endpoint"}
	}
	if errs, _ := routes.Check(plan, reserved, nil); len(errs) > 0 {
		return nil, errors.New(strings.Join(errs, "; "))
	}
	return plan.Routes, nil
}

// tunnelState is where a profile's tunnel is.
type tunnelState int

const (
	stateConnecting   tunnelState = iota // first connection not made yet
	stateUp                              // connected
	stateReconnecting                    // lost, trying again
	stateGaveUp                          // out of attempts
)

// activeSet reports which profiles' routes and names are in use: while
// their tunnel is up or reconnecting, and always with a kill switch (the
// traffic is refused rather than leaking).
func (mp *multiPlan) activeSet(states []tunnelState) []bool {
	active := make([]bool, len(mp.specs))
	for i, st := range states {
		active[i] = mp.rps[i] != nil && (mp.ks[i] != "off" || st == stateUp || st == stateReconnecting)
	}
	return active
}

// dnsFlushNeeded reports whether profile i changing from prev to now
// leaves answers in the system's DNS cache that no longer hold: failures
// from while its tunnel was down (it came back), answers from before its
// names went through a tunnel (it came up after the capture started), or
// answers its tunnel gave (it gave up, and its names go elsewhere now).
func (mp *multiPlan) dnsFlushNeeded(i int, prev, now tunnelState, capturing bool) bool {
	names := mp.dnsNames[i]
	if mp.dns == nil || !capturing || len(names.Domains) == 0 && len(names.Patterns) == 0 {
		return false
	}
	switch {
	case now == stateUp:
		return prev == stateReconnecting || prev == stateConnecting
	case now == stateGaveUp:
		return mp.ks[i] == "off" // with a kill switch its names stay (and fail)
	}
	return false
}

// owned is a prefix and the profile that carries it.
type owned struct {
	prefix netip.Prefix
	i      int
}

// owner returns the profile that carries address a: of the active profiles
// whose own routes (after their excludes) cover it, the one with the most
// specific configured route containing it. -1: none.
func (mp *multiPlan) owner(a netip.Addr, active []bool) int {
	best, bits := -1, -1
	for i, on := range active {
		if !on || !slices.ContainsFunc(mp.final(i), func(p netip.Prefix) bool { return p.Contains(a) }) {
			continue
		}
		for _, inc := range mp.rps[i].includes {
			if inc.Bits() > bits && inc.Contains(a) {
				best, bits = i, inc.Bits()
			}
		}
	}
	return best
}

// ownership splits the addresses the active profiles route into prefixes,
// each carried by one profile (see owner). Within a prefix that no route
// or route piece lies strictly inside, every address has the same owner.
func (mp *multiPlan) ownership(active []bool) []owned {
	var bounds, roots []netip.Prefix
	for i, on := range active {
		if !on {
			continue
		}
		bounds = append(append(bounds, mp.rps[i].includes...), mp.final(i)...)
		roots = append(roots, mp.final(i)...)
	}
	// Start from the pieces no other piece contains.
	var tops []netip.Prefix
	for _, r := range roots {
		inside := slices.ContainsFunc(roots, func(q netip.Prefix) bool {
			return q.Bits() < r.Bits() && q.Contains(r.Addr())
		})
		if !inside && !slices.Contains(tops, r) {
			tops = append(tops, r)
		}
	}
	var out []owned
	var walk func(p netip.Prefix)
	walk = func(p netip.Prefix) {
		split := slices.ContainsFunc(bounds, func(b netip.Prefix) bool {
			return b.Bits() > p.Bits() && p.Contains(b.Addr())
		})
		if split {
			lo, hi := halves(p)
			walk(lo)
			walk(hi)
			return
		}
		if i := mp.owner(p.Addr(), active); i >= 0 {
			out = append(out, owned{p, i})
		}
	}
	for _, t := range tops {
		walk(t)
	}
	return out
}

// halves splits an IPv4 prefix in two.
func halves(p netip.Prefix) (netip.Prefix, netip.Prefix) {
	b := p.Addr().As4()
	v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	v |= 1 << (31 - p.Bits())
	hi := netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
	return netip.PrefixFrom(p.Addr(), p.Bits()+1), netip.PrefixFrom(hi, p.Bits()+1)
}

// layout is what the capture needs for the profiles in use: the routes on
// the utun, the router's table, and the kill switch's guard (the addresses
// profiles with a kill switch carry, and those in lockdown).
func (mp *multiPlan) layout(active []bool, lives []*liveTunnel) ([]netip.Prefix, []routeEntry, capture.Guard, error) {
	var all []netip.Prefix
	for i, on := range active {
		if !on {
			continue
		}
		for _, p := range mp.final(i) {
			if !slices.Contains(all, p) {
				all = append(all, p)
			}
		}
	}
	var entries []routeEntry
	var ks, lock []netip.Prefix
	for _, o := range mp.ownership(active) {
		entries = append(entries, routeEntry{prefix: o.prefix, tunnel: lives[o.i], i: o.i})
		switch mp.ks[o.i] {
		case "lockdown":
			lock = append(lock, o.prefix)
			fallthrough
		case "on":
			ks = append(ks, o.prefix)
		}
	}
	var g capture.Guard
	merge := func(ps []netip.Prefix) ([]netip.Prefix, error) {
		if len(ps) == 0 {
			return nil, nil
		}
		p, err := routes.Compute(ps, nil)
		return p.Routes, err
	}
	var err error
	if g.Base, err = merge(ks); err != nil {
		return nil, nil, g, err
	}
	if g.Lockdown, err = merge(lock); err != nil {
		return nil, nil, g, err
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

func printMultiPlan(w io.Writer, mp *multiPlan) {
	everyone := make([]bool, len(mp.specs))
	for i := range everyone {
		everyone[i] = mp.rps[i] != nil
	}
	carried := map[netip.Prefix]int{}
	for _, o := range mp.ownership(everyone) {
		carried[o.prefix] = o.i
	}
	for i, sp := range mp.specs {
		fmt.Fprintf(w, "profile %s:\n", sp.name)
		if rp := mp.rps[i]; rp != nil {
			f := mp.final(i)
			fmt.Fprintf(w, "  routes (%d, from %d given):\n", len(f), len(rp.includes))
			for _, p := range f {
				fmt.Fprintf(w, "    %s%s\n", p, carriedBy(mp, i, p, carried))
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
		if own := mp.dns.Match.Own(); len(own) > 0 {
			fmt.Fprintf(w, "  %s (subtun's own endpoints) never go through a tunnel\n", strings.Join(own, ", "))
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

// carriedBy notes when a route piece of profile i, or parts of it, go to
// another profile whose route is more specific.
func carriedBy(mp *multiPlan, i int, p netip.Prefix, carried map[netip.Prefix]int) string {
	var others []string
	mine := false
	for q, j := range carried {
		if q.Bits() < p.Bits() || !p.Contains(q.Addr()) {
			continue
		}
		if j == i {
			mine = true
		} else if !slices.Contains(others, mp.specs[j].name) {
			others = append(others, mp.specs[j].name)
		}
	}
	if len(others) == 0 {
		return ""
	}
	slices.Sort(others)
	if !mine {
		return fmt.Sprintf("  (carried by %s: a more specific route)", strings.Join(others, ", "))
	}
	return fmt.Sprintf("  (parts carried by %s: more specific routes)", strings.Join(others, ", "))
}

// tunnelEvent is a profile's tunnel changing state.
type tunnelEvent struct {
	i       int
	state   tunnelState
	carrier *transport.Carrier // stateUp
	agent   string             // stateUp: the agent's version
	err     error              // stateGaveUp, or stateConnecting after the first attempt failed
}

// runTunnel keeps one profile's tunnel connected by its reconnect policy.
// With retryFirst the first connection too is retried (several profiles);
// without, a failed first connection gives up at once (one profile).
func runTunnel(ctx context.Context, i int, live *liveTunnel, policy reconnectPolicy, retryFirst bool,
	try func(context.Context) (*session, error), send func(tunnelEvent) bool, log *slog.Logger) {
	var cur *session
	defer func() {
		live.set(nil)
		if cur != nil {
			cur.close()
		}
	}()
	gaveUp := func(err error) {
		live.gone.Store(true)
		if ctx.Err() == nil {
			send(tunnelEvent{i: i, state: stateGaveUp, err: err})
		}
	}
	s, err := try(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return
		}
		if !retryFirst {
			gaveUp(err)
			return
		}
		log.Warn("connecting failed", "err", err, "policy", policy.String())
		if !send(tunnelEvent{i: i, state: stateConnecting, err: err}) {
			return
		}
		if s, err = reconnect(ctx, policy, nil, try, log); err != nil {
			gaveUp(fmt.Errorf("could not connect; %w", err))
			return
		}
	}
	for {
		cur = s
		live.set(s.client)
		if !send(tunnelEvent{i: i, state: stateUp, carrier: s.carrier, agent: s.client.Agent().Version}) {
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
			gaveUp(errors.New("connection to the agent was lost"))
			return
		}
		log.Warn("connection to the agent lost; reconnecting", "policy", policy.String())
		if !send(tunnelEvent{i: i, state: stateReconnecting}) {
			return
		}
		if s, err = reconnect(ctx, policy, nil, try, log); err != nil {
			gaveUp(fmt.Errorf("connection to the agent was lost; %w", err))
			return
		}
	}
}

// runMulti plans several profiles and runs them (runEngine), or prints
// the plan.
func runMulti(ctx context.Context, out io.Writer, g *globalOpts, specs []*tunnelSpec, dryRun bool, maxDuration time.Duration) error {
	if maxDuration < 0 {
		return errors.New("--max-duration must be positive")
	}
	mp, err := planMulti(specs)
	if err != nil {
		return err
	}
	if dryRun {
		mp.warns = append(mp.warns, mp.lookupEndpoints(ctx)...)
		printMultiPlan(out, mp)
		return nil
	}
	return runEngine(ctx, g, mp, engineOpts{maxDuration: maxDuration})
}

// engineOpts are what differs between one profile and several.
type engineOpts struct {
	// single: one profile, as subtun has always run one: a failed first
	// connection exits at once, the root helper is one-shot unless
	// firewall rules need a session, log lines name no tunnel.
	single      bool
	maxDuration time.Duration
	agentFile   string // development: upload this agent binary
	dnsListen   string // development: answer DNS here instead of capturing it (one profile)
}

// runEngine runs a plan: one utun, helper and rule set, each profile's
// tunnel connecting and reconnecting on its own. Every tunnel tries to
// connect once before the capture (and sudo) starts. It ends on Ctrl-C, or
// when every profile has given up.
func runEngine(ctx context.Context, g *globalOpts, mp *multiPlan, eo engineOpts) error {
	log := newLogger(g.verbose)
	specs := mp.specs
	ctx, done := withMaxDuration(ctx, eo.maxDuration, log)
	defer done() // last: the watchdog covers stopping

	n := len(specs)
	lives := make([]*liveTunnel, n)
	logs := make([]*slog.Logger, n)
	for i, sp := range specs {
		lives[i], logs[i] = &liveTunnel{}, log.With("tunnel", sp.name)
		if eo.single {
			logs[i] = log
		}
	}
	for i, rp := range mp.rps {
		if rp == nil {
			continue
		}
		for _, n := range rp.plan.Redundant {
			logs[i].Info("route rule dropped", "rule", n.String())
		}
	}
	for _, wn := range mp.warns {
		log.Warn(wn)
	}
	agents, err := loadAgents(eo.agentFile)
	if err != nil {
		return err
	}
	// The development DNS listener answers instead of the capture.
	devDNS := mp.dns
	if eo.dnsListen != "" {
		mp.dns = nil
	} else {
		devDNS = nil
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
			if eo.single {
				return fmt.Errorf("SOCKS listener: %w", err)
			}
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

	// Rules an earlier session may have left (kill switch, a killed helper)
	// can block DNS, which connecting and finding the endpoints need: take
	// them over first.
	marker := &leftovers{mark: privhelper.MarkLeftovers, clear: privhelper.ClearLeftovers}
	var early *privhelper.Client
	if privhelper.LeftoversMarked() {
		if !mp.hasRoutes() {
			log.Warn("firewall rules from another subtun session may be in place; if networking misbehaves and none is running, run: subtun cleanup")
		} else {
			log.Info("firewall rules from another subtun session may be in place; checking with the root helper before connecting")
			if early, err = privhelper.Start(ctx, &transport.LineLog{Log: log, Prefix: "helper: "}, log); err != nil {
				return startErr(ctx, err)
			}
			res, err := early.Adopt()
			if err != nil {
				_ = early.Close()
				return fmt.Errorf("taking over firewall rules: %w", err)
			}
			log.Info(res.Message)
			marker.adopted(res)
			// Until the capture takes it, closing it puts the rules back.
			defer func() {
				if early != nil {
					_ = early.Close()
				}
			}()
		}
	}
	for _, wn := range mp.lookupEndpoints(ctx) {
		log.Warn(wn)
	}

	// The tunnels run until this returns; firewall rules and routes go
	// first (the capture's stop is deferred after this), then the tunnels.
	// So a signal doesn't stop them by itself: it ends this loop.
	tctx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	var wg sync.WaitGroup
	defer func() {
		cancel()
		wg.Wait()
	}()
	var c *capture.Capture
	type startResult struct {
		c   *capture.Capture
		err error
	}
	var starting chan startResult // the capture is starting (sudo may be asking)
	deliberate := false           // the user stopped subtun (signal), as opposed to a failure
	defer func() {
		if c == nil && starting != nil {
			// A start still under way is waited for, so it is undone too.
			if r := <-starting; r.err == nil {
				c = r.c
			}
		}
		if c == nil {
			return
		}
		leftBehind := c.Stop(deliberate)
		marker.stopped(leftBehind)
		if leftBehind {
			log.Warn("kill switch: blocking rules stay in place; the next subtun run takes them over, or remove them with: subtun cleanup")
		}
	}()

	events := make(chan tunnelEvent)
	send := func(ev tunnelEvent) bool {
		select {
		case events <- ev:
			return true
		case <-tctx.Done():
			return false
		}
	}
	started := time.Now()
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
		wg.Add(1)
		go func() {
			defer wg.Done()
			runTunnel(tctx, i, lives[i], mp.policies[i], !eo.single, try, send, logs[i])
		}()
	}

	states := make([]tunnelState, n)
	tried := make([]bool, n)     // the first attempt is over
	lost := make([]time.Time, n) // when each tunnel was lost
	rt := &router{}
	var helperExited <-chan struct{}
	var retry <-chan time.Time
	retryWait, lastErr := layoutRetry, ""
	// Several profiles wait at most firstRoundWait for every first
	// attempt; one profile always connects before the capture starts.
	var firstRound <-chan time.Time
	if !eo.single {
		firstRound = time.After(firstRoundWait)
	}
	roundOver, anyUp, devStarted, flushDNS := false, false, false, false
	// A stop the user asked for (or --max-duration) is deliberate. Before
	// anything was up (connecting, the sudo prompt), --max-duration also
	// says so as an error.
	stop := func() error {
		deliberate = true
		logShutdown(ctx, log)
		up := anyUp || c != nil // several profiles: a tunnel was up
		if eo.single && mp.hasRoutes() {
			up = c != nil // one profile with routes: up once capturing, as always
		}
		if !up && maxDurationReached(ctx) {
			return startErr(ctx, errMaxDuration)
		}
		return nil
	}
	ownNames := func() *dns.Matcher {
		switch {
		case mp.dns != nil:
			return mp.dns.Match
		case devDNS != nil:
			return devDNS.Match
		}
		return nil
	}
	for {
		select {
		case <-ctx.Done():
			return stop()
		case err := <-errc:
			if ctx.Err() != nil {
				return stop() // Ctrl-C closed the listener
			}
			return fmt.Errorf("SOCKS listener: %w", err)
		case <-helperExited:
			select {
			case <-ctx.Done():
				return stop() // Ctrl-C reaches the helper too
			case <-time.After(300 * time.Millisecond):
			}
			return errors.New("the root helper exited unexpectedly; its firewall rules may still be in place: the next subtun run takes them over, or remove them with: subtun cleanup")
		case <-retry:
			retry = nil
		case <-firstRound:
			firstRound, roundOver = nil, true
			if c == nil && starting == nil && slices.Contains(tried, false) && mp.hasRoutes() {
				log.Info("starting the capture while some profiles are still connecting", "waited", firstRoundWait)
			}
		case r := <-starting:
			starting = nil
			if r.err != nil {
				return r.err
			}
			c, helperExited = r.c, r.c.HelperExited()
			// Below: catch up with what changed while it started.
		case ev := <-events:
			tl := logs[ev.i]
			prev := states[ev.i]
			states[ev.i], tried[ev.i] = ev.state, true
			flushDNS = flushDNS || mp.dnsFlushNeeded(ev.i, prev, ev.state, c != nil)
			switch ev.state {
			case stateUp:
				anyUp = true
				if m := ownNames(); m != nil {
					// Reconnecting must resolve the API server or Docker
					// daemon while the tunnel is down.
					m.SetOwn(append(m.Own(), transport.HostName(ev.carrier.Host)))
				}
				if prev == stateConnecting {
					tl.Info("tunnel up", "via", ev.carrier.Desc, "agent", ev.agent, "took", time.Since(started).Round(time.Millisecond))
					if devDNS != nil && !devStarted {
						devStarted = true
						devDNS.Tunnels[0].Upstream = dns.UpstreamFunc(lives[0].ExchangeDNS)
						if mp.rps[0] != nil {
							devDNS.Tunnels[0].Unreachable = unreachable(mp.final(0))
						}
						stopDNS, err := serveDNSDev(ctx, eo.dnsListen, devDNS, log)
						if err != nil {
							return err
						}
						defer stopDNS()
					}
				} else {
					tl.Info("reconnected", "via", ev.carrier.Desc, "after", time.Since(lost[ev.i]).Round(100*time.Millisecond))
				}
				if prev == stateConnecting && ev.carrier.Local && routesInternet(mp.final(ev.i)) {
					tl.Warn(localLoopWarning)
				}
				if changed, err := mp.addEndpoints(ev.carrier.Endpoints); err != nil {
					tl.Warn("excluding subtun's own endpoint from the routes failed", "err", err)
				} else if changed && c != nil && !c.Session() {
					// One-shot helper (one profile, no firewall rules): routes can't change.
					tl.Warn("after reconnecting, subtun's own connection goes to an address the routes cover, which may cut it; restart subtun to exclude it", "addrs", ev.carrier.Endpoints)
				} else if changed {
					tl.Info("excluded from routes: subtun's own connection goes there", "addrs", ev.carrier.Endpoints)
				}
			case stateReconnecting:
				lost[ev.i] = time.Now()
			case stateGaveUp:
				if eo.single {
					return ev.err // as subtun has always ended (a kill switch holds)
				}
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
		}
		if !mp.hasRoutes() {
			continue
		}
		if c == nil {
			if starting != nil || !roundOver && slices.Contains(tried, false) {
				continue // starting, or the first round isn't over
			}
			// Off this loop: sudo may ask for a while, and tunnels must
			// keep reporting (and reconnecting) meanwhile.
			active, e := mp.activeSet(states), early
			early = nil
			starting = make(chan startResult, 1)
			go func() {
				c, err := startMultiCapture(ctx, mp, active, lives, rt, e, marker, !eo.single, log)
				starting <- startResult{c, err}
			}()
			continue
		}
		if !c.Session() {
			continue // one-shot helper: routes can't change (warned above)
		}
		if err := applyLayout(c, mp, states, lives, rt); err != nil {
			if err.Error() != lastErr {
				log.Warn("updating the routes failed; trying again", "err", err, "in", retryWait)
			} else {
				log.Debug("updating the routes failed again", "err", err, "in", retryWait)
			}
			lastErr = err.Error()
			retry = time.After(retryWait)
			retryWait = min(2*retryWait, time.Minute)
		} else if lastErr != "" {
			log.Info("routes updated")
			lastErr, retryWait, retry = "", layoutRetry, nil
		}
		if flushDNS {
			flushDNS = false
			if err := c.FlushDNSCache(); err != nil {
				log.Warn("flushing the DNS cache failed", "err", err)
			}
		}
	}
}

// startMultiCapture starts the capture for the profiles in use. With
// session, the helper stays up and the routes follow as tunnels come and
// go; without (one profile), it stays only if firewall rules need it.
func startMultiCapture(ctx context.Context, mp *multiPlan, active []bool, lives []*liveTunnel, rt *router,
	early *privhelper.Client, marker *leftovers, session bool, log *slog.Logger) (*capture.Capture, error) {
	all, entries, guard, err := mp.layout(active, lives)
	if err != nil {
		if early != nil {
			_ = early.Close()
		}
		return nil, err
	}
	rt.set(entries)
	opts := capture.Options{TunAddr: mp.tunAddr, MTU: mp.mtu, Session: session, Helper: early,
		KillSwitch: mp.ksMode(), Guard: guard, AllowDNS: mp.allowDNS, BlockIPv6: mp.blockIPv6, Locals: localPrefixes}
	if opts.KillSwitch != "off" {
		if g, err := guardPrefixes(guard.Base, localPrefixes()); err == nil && len(g) == 0 {
			log.Warn("kill switch has nothing to guard: every route is a local network")
		}
	}
	if opts.BlockIPv6 {
		if a, ok := ipv6Endpoint(mp.endpointList()); ok {
			log.Warn("not blocking IPv6: subtun's own connection may use it", "endpoint", a)
			opts.BlockIPv6 = false
		}
	}
	if mp.dns != nil {
		for i := range mp.specs {
			mp.dns.Tunnels[i].Upstream = dns.UpstreamFunc(lives[i].ExchangeDNS)
			// A private address another profile carries, or none, is out of
			// this tunnel's reach.
			mp.dns.Tunnels[i].Unreachable = func(a netip.Addr) bool { return dns.Private(a) && rt.pickIndex(a) != i }
			mp.dns.Match.SetOn(i, active[i])
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
// and guard in line with the profiles in use. A profile's names stop
// before its routes go, and start once all its routes are in (even if
// another profile's route failed).
func applyLayout(c *capture.Capture, mp *multiPlan, states []tunnelState, lives []*liveTunnel, rt *router) error {
	active := mp.activeSet(states)
	all, entries, guard, err := mp.layout(active, lives)
	if err != nil {
		return err
	}
	rt.set(entries)
	if mp.dns != nil {
		for i, on := range active {
			if !on {
				mp.dns.Match.SetOn(i, false)
			}
		}
	}
	err = c.Update(all, guard)
	if mp.dns != nil {
		in := c.Routes()
		for i, on := range active {
			if on && !slices.ContainsFunc(mp.final(i), func(p netip.Prefix) bool { return !slices.Contains(in, p) }) {
				mp.dns.Match.SetOn(i, true)
			}
		}
	}
	return err
}
