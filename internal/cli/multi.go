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
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/md2k/subnet-tunnel/internal/capture"
	"github.com/md2k/subnet-tunnel/internal/config"
	"github.com/md2k/subnet-tunnel/internal/control"
	"github.com/md2k/subnet-tunnel/internal/dns"
	"github.com/md2k/subnet-tunnel/internal/meter"
	"github.com/md2k/subnet-tunnel/internal/privhelper"
	"github.com/md2k/subnet-tunnel/internal/routes"
	"github.com/md2k/subnet-tunnel/internal/socks"
	"github.com/md2k/subnet-tunnel/internal/transport"
	"github.com/md2k/subnet-tunnel/internal/tunnel"
)

// Replaced in tests: looking up a target's endpoint addresses, whether an
// earlier session left firewall rules, and starting the capture.
var (
	lookupEndpoint  = transport.LookupEndpoint
	leftoversMarked = privhelper.LeftoversMarked
	startCapture    = startMultiCapture
)

const (
	// layoutRetry is how soon a failed route update is tried again; the
	// wait doubles while the same error repeats, up to a minute.
	layoutRetry = 5 * time.Second
	// firstRoundWait bounds the wait for every profile's first attempt
	// before the capture starts; one still connecting carries on.
	firstRoundWait = 30 * time.Second
)

// tunnelSpec is one profile of a run.
type tunnelSpec struct {
	name     string
	s        settings       // as running: changes through the control socket included
	base     settings       // as started (or reloaded): status shows what changed since
	cfg      config.Profile // as configured (defaults applied): which shared values it sets
	connect  connectFunc
	endpoint func() (string, error) // the target's endpoint, without connecting
	// reload reads the profile from the config file again, as the run read
	// it at start (profile start --reload); nil: not from a config file.
	reload func() (*tunnelSpec, error)
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

	// smu guards what status reads while the engine's loop changes it
	// (control: full): specs (the slice's elements) and dnsNames. The loop
	// writes under it, and reads without.
	smu sync.RWMutex

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
	tunAddr, mtu, fallback, err := agreeShared(specs)
	if err != nil {
		return nil, err
	}
	socksBy := map[string]string{}
	for i, sp := range specs {
		applyShared(sp, tunAddr, mtu, fallback)
		sp.base = sp.s
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
func checkOverlaps(mp *multiPlan) error { return checkOverlapsOf(mp.specs, mp.rps) }

func checkOverlapsOf(specs []*tunnelSpec, rps []*routePlan) error {
	owner := map[netip.Prefix]string{}
	for i, rp := range rps {
		if rp == nil {
			continue
		}
		name := specs[i].name
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
	// Locals too without ".": one may be added while running.
	opts := &capture.DNSOptions{Match: m, Tunnels: make([]capture.DNSTunnel, len(mp.specs)), Locals: dnsLocals(mp.tunAddr)}
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
	stateStopped                         // stopped through the control socket (profile stop)
)

// activeSet reports which profiles' routes and names are in use: while
// their tunnel is up or reconnecting, and always with a kill switch (the
// traffic is refused rather than leaking). A stopped profile is as after
// Ctrl-C: only lockdown keeps its share.
func (mp *multiPlan) activeSet(states []tunnelState) []bool {
	active := make([]bool, len(mp.specs))
	for i, st := range states {
		switch {
		case mp.rps[i] == nil:
		case st == stateStopped:
			active[i] = mp.ks[i] == "lockdown"
		default:
			active[i] = mp.ks[i] != "off" || st == stateUp || st == stateReconnecting
		}
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
	case now == stateStopped:
		return mp.ks[i] != "lockdown" // in lockdown its names stay (and fail)
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
func (mp *multiPlan) layout(active []bool, dialers []meter.Dialer) ([]netip.Prefix, []routeEntry, capture.Guard, error) {
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
		entries = append(entries, routeEntry{prefix: o.prefix, tunnel: dialers[o.i], i: o.i})
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
	gen     int // the runner's: events of a runner since replaced are ignored
	state   tunnelState
	carrier *transport.Carrier // stateUp
	agent   string             // stateUp: the agent's version
	err     error              // stateGaveUp, or stateConnecting after the first attempt failed
}

// startMode is how a tunnel's runner starts.
type startMode int

const (
	startOnce      startMode = iota // one profile's first connection: a failure gives up at once
	startRetry                      // a failed first connection is retried by the policy (several profiles, profile start)
	startReconnect                  // profile reconnect: connect again now, then retry by the policy
)

// runTunnel keeps one profile's tunnel connected by its reconnect policy,
// starting as mode says.
func runTunnel(ctx context.Context, i int, live *liveTunnel, policy reconnectPolicy, mode startMode,
	try func(context.Context) (*session, error), send func(tunnelEvent) bool, log *slog.Logger,
	progress func(attempt int, next time.Time, err error)) {
	live.gone.Store(false)
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
		switch mode {
		case startOnce:
			gaveUp(err)
			return
		case startRetry:
			log.Warn("connecting failed", "err", err, "policy", policy.String())
			if !send(tunnelEvent{i: i, state: stateConnecting, err: err}) {
				return
			}
			if s, err = reconnect(ctx, policy, nil, try, log, progress); err != nil {
				gaveUp(fmt.Errorf("could not connect; %w", err))
				return
			}
		case startReconnect:
			log.Warn("reconnecting failed", "err", err, "policy", policy.String())
			if s, err = reconnect(ctx, policy, nil, try, log, progress); err != nil {
				gaveUp(fmt.Errorf("reconnecting failed; %w", err))
				return
			}
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
		if s, err = reconnect(ctx, policy, nil, try, log, progress); err != nil {
			gaveUp(fmt.Errorf("connection to the agent was lost; %w", err))
			return
		}
	}
}

// runMulti plans several profiles and runs them (runEngine), or prints
// the plan.
func runMulti(ctx context.Context, out io.Writer, g *globalOpts, specs []*tunnelSpec, dryRun bool, maxDuration time.Duration, control string) error {
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
	return runEngine(ctx, g, mp, engineOpts{maxDuration: maxDuration, control: control})
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
	control     string // status (default) or off: the control socket
}

// runEngine runs a plan: one utun, helper and rule set, each profile's
// tunnel connecting and reconnecting on its own. Every tunnel tries to
// connect once before the capture (and sudo) starts. It ends on Ctrl-C, or
// when every profile has given up. With control: full, changes through the
// control socket (routes, DNS names, profiles) are made by its loop.
func runEngine(ctx context.Context, g *globalOpts, mp *multiPlan, eo engineOpts) error {
	log, ring := newRunLogger(g.verbose)
	ctx, done := withMaxDuration(ctx, eo.maxDuration, log)
	defer done() // last: the watchdog covers stopping

	n := len(mp.specs)
	lives := make([]*liveTunnel, n)
	logs := make([]*slog.Logger, n)
	for i, sp := range mp.specs {
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

	// Status: counters per tunnel, its state, the control socket.
	es := newEngineStatus(mp, eo.control)
	utun := make([]meter.Dialer, n)
	for i := range n {
		utun[i] = es.meters[i].Dialer(meter.ViaUtun, lives[i])
	}
	for _, d := range []*capture.DNSOptions{mp.dns, devDNS} {
		if d == nil {
			continue
		}
		es.dnsOpts, es.devDNS = d, d == devDNS
		d.FallbackCounts = es.fallback
		for i := range d.Tunnels {
			d.Tunnels[i].Counts = es.dnsCounts[i]
		}
	}
	// Changes (control: full) are made by the loop below, one at a time.
	changes := make(chan changeRequest)
	loopDone := make(chan struct{})
	defer close(loopDone)
	if eo.control == controlFull {
		es.change = func(rctx context.Context, ch control.Change) (control.Result, error) {
			req := changeRequest{ch: ch, reply: make(chan changeReply, 1)}
			select {
			case changes <- req:
			case <-rctx.Done():
				return control.Result{}, rctx.Err()
			case <-loopDone:
				return control.Result{}, errors.New("subtun is stopping")
			}
			select {
			case r := <-req.reply:
				return r.res, r.err
			case <-rctx.Done():
				return control.Result{}, rctx.Err()
			}
		}
	}
	sctx, stopStatus := context.WithCancel(context.WithoutCancel(ctx))
	defer stopStatus()
	go es.sample(sctx)
	if eo.control != controlOff && eo.control != "" { // "": tests, internal callers
		startControl(sctx, es, ring, log)
	}

	// Listen before connecting, so a busy port fails fast. A listener is
	// replaced when a reloaded profile moves its SOCKS address.
	errc := make(chan error, n)
	socksLns := make([]*socksListener, n)
	defer func() {
		for _, l := range socksLns {
			l.close()
		}
	}()
	listenSOCKS := func(i int, addr string) (*socksListener, error) {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return nil, err
		}
		if host, _, _ := net.SplitHostPort(addr); !isLoopback(host) {
			logs[i].Warn("SOCKS proxy is reachable from other hosts and has no authentication", "addr", ln.Addr())
		}
		lctx, lcancel := context.WithCancel(ctx)
		srv := &socks.Server{Dialer: es.meters[i].Dialer(meter.ViaSOCKS, lives[i]), Logger: logs[i]}
		go func() {
			if err := srv.Serve(lctx, ln); err != nil { // nil: Ctrl-C, or replaced
				select {
				case errc <- err:
				default:
				}
			}
		}()
		logs[i].Info("SOCKS5 proxy ready", "addr", ln.Addr().String())
		return &socksListener{ln: ln, cancel: lcancel}, nil
	}
	for i, sp := range mp.specs {
		if sp.s.socks == "" {
			continue
		}
		l, err := listenSOCKS(i, sp.s.socks)
		if err != nil {
			if eo.single {
				return fmt.Errorf("SOCKS listener: %w", err)
			}
			return fmt.Errorf("profile %s: SOCKS listener: %w", sp.name, err)
		}
		socksLns[i] = l
	}

	// Rules an earlier session may have left (kill switch, a killed helper)
	// can block DNS, which connecting and finding the endpoints need: take
	// them over first.
	marker := &leftovers{mark: privhelper.MarkLeftovers, clear: privhelper.ClearLeftovers}
	var early *privhelper.Client
	if leftoversMarked() {
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

	// Each profile's tunnel runs in its own goroutine (its runner). A
	// profile stopped, started or reconnected through the control socket
	// gets a new runner, which waits for the old one to finish; events of a
	// runner since stopped or replaced are ignored.
	events := make(chan tunnelEvent)
	started := time.Now()
	runners := make([]runner, n)
	startRunner := func(i int, mode startMode) {
		r := &runners[i]
		if r.cancel != nil {
			r.cancel()
		}
		prev := r.done
		r.gen++
		gen := r.gen
		rctx, rcancel := context.WithCancel(tctx)
		done := make(chan struct{})
		r.cancel, r.done = rcancel, done
		sp, policy, live, tl := mp.specs[i], mp.policies[i], lives[i], logs[i]
		try := func(ctx context.Context) (*session, error) {
			carrier, err := sp.connect(ctx, agents, tl)
			if err != nil {
				return nil, err
			}
			hctx, hcancel := context.WithTimeout(ctx, 30*time.Second)
			client, err := tunnel.NewClient(hctx, carrier, tunnel.Options{ExpectSHA256: carrier.SHA256, Logger: tl})
			hcancel()
			if err != nil {
				return nil, fmt.Errorf("starting agent in %s: %w", carrier.Desc, err)
			}
			return &session{carrier: carrier, client: client}, nil
		}
		send := func(ev tunnelEvent) bool {
			ev.gen = gen
			select {
			case events <- ev:
				return true
			case <-rctx.Done():
				return false
			}
		}
		progress := func(attempt int, next time.Time, err error) {
			if rctx.Err() != nil {
				return
			}
			es.infos[i].update(func(t *tunnelInfo) {
				t.attempt, t.attempts, t.nextTry = attempt, policy.attempts, next
				if err != nil {
					t.lastErr = err.Error()
				}
			})
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer close(done)
			if prev != nil {
				<-prev // its last act clears the live tunnel
			}
			runTunnel(rctx, i, live, policy, mode, try, send, tl, progress)
		}()
	}
	stopRunner := func(i int) {
		r := &runners[i]
		if r.cancel != nil {
			r.cancel()
			r.cancel = nil
		}
		r.gen++
	}
	first := startRetry
	if eo.single {
		first = startOnce
	}
	for i := range n {
		startRunner(i, first)
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
	// relayout brings the capture's routes and guard, the router and the
	// DNS matcher in line with the plan and the tunnels' states. A failure
	// is tried again from the loop.
	relayout := func() error {
		if c == nil || !c.Session() {
			return nil // not capturing yet (it starts as the plan is then), or one-shot: routes can't change
		}
		err := applyLayout(c, mp, states, utun, rt)
		es.routesOn(mp.activeSet(states), c.Routes())
		if err != nil {
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
		return err
	}

	// Changes through the control socket.
	setState := func(i int, st tunnelState, lastErr string) {
		states[i] = st
		es.infos[i].update(func(t *tunnelInfo) {
			t.state, t.since, t.attempt, t.nextTry = st, time.Now(), 0, time.Time{}
			if lastErr != "" {
				t.lastErr = lastErr
			}
		})
	}
	reloadPlan := func(i int) (*reloadChange, error) {
		sp := mp.specs[i]
		if sp.reload == nil {
			return nil, errors.New("--reload: this run's profile doesn't come from the config file (subtun k8s, subtun docker); restart subtun instead")
		}
		ns, err := sp.reload()
		if err != nil {
			return nil, err
		}
		host, err := ns.endpoint()
		if err != nil {
			return nil, err
		}
		var addrs []netip.Addr
		var warns []string
		if host != mp.hosts[i] { // a new target: keep its endpoint out of the routes before it connects
			lctx, lcancel := context.WithTimeout(ctx, 3*time.Second)
			addrs, err = lookupEndpoint(lctx, host)
			lcancel()
			if err != nil {
				warns = append(warns, fmt.Sprintf("looking up %s failed (%v); if its address lies inside the routes, its connection goes into a tunnel and can't connect", transport.HostName(host), err))
			}
		}
		rl, err := mp.planReload(i, ns, host, addrs, es.matcher())
		if err != nil {
			return nil, err
		}
		rl.warns = append(warns, rl.warns...)
		return rl, nil
	}
	applyReload := func(rl *reloadChange) error {
		i := rl.i
		if was, now := mp.specs[i].s.socks, rl.spec.s.socks; was != now {
			var l *socksListener
			if now != "" {
				var err error
				if l, err = listenSOCKS(i, now); err != nil {
					return fmt.Errorf("SOCKS listener: %w", err)
				}
			}
			socksLns[i].close()
			socksLns[i] = l
		}
		return mp.applyReload(rl, es.matcher())
	}
	handleChange := func(req control.Change) (control.Result, error) {
		i, err := mp.profileIndex(req.Profile)
		if err != nil {
			return control.Result{}, err
		}
		sp := mp.specs[i]
		res := control.Result{Profile: sp.name, DryRun: req.DryRun}
		plan := req.Kind != control.KindProfile || req.Op == "start" && req.Reload
		if plan && starting != nil && !req.DryRun {
			return res, errors.New("the capture is starting (sudo may be asking for a password in subtun's terminal); try again once it runs")
		}
		switch req.Kind {
		case control.KindRoute:
			rc, err := mp.planRouteChange(i, req)
			if err != nil {
				return res, err
			}
			res.Changed, res.Message, res.Warnings = rc.changed, rc.message, rc.warns
			if req.DryRun || !rc.changed {
				return res, nil
			}
			mp.applyRouteChange(rc)
			logs[i].Info("control: "+rc.logMsg, "profile", sp.name, "cidrs", rc.cidrs)
		case control.KindDNS:
			m := es.matcher()
			dc, err := mp.planDNSChange(i, req, m)
			if err != nil {
				return res, err
			}
			res.Changed, res.Message, res.Warnings = dc.changed, dc.message, dc.warns
			if req.DryRun || !dc.changed {
				return res, nil
			}
			if err := mp.applyDNSChange(dc, m); err != nil {
				return res, err
			}
			flushDNS = true // answers cached for these names went elsewhere
			logs[i].Info("control: "+dc.logMsg, "profile", sp.name, "domains", dc.domains, "patterns", len(dc.patterns))
		case control.KindProfile:
			label, arg := profileWords(sp.name)
			switch req.Op {
			case "stop":
				if states[i] == stateStopped {
					res.Message = "already stopped"
					return res, nil
				}
				res.Changed, res.Message = true, "stopped: "+mp.stopEffect(i)
				if req.DryRun {
					res.Message = "would stop it: " + mp.stopEffect(i)
					return res, nil
				}
				stopRunner(i)
				lives[i].stopped.Store(true)
				prev := states[i]
				setState(i, stateStopped, "")
				tried[i] = true
				flushDNS = flushDNS || mp.dnsFlushNeeded(i, prev, stateStopped, c != nil)
				logs[i].Info("control: stopped", "profile", sp.name)
			case "start":
				if st := states[i]; st != stateStopped && st != stateGaveUp {
					return res, fmt.Errorf("%s is %s; to connect it again now: subtun profile reconnect%s", label, st, arg)
				}
				var rl *reloadChange
				if req.Reload {
					if rl, err = reloadPlan(i); err != nil {
						return res, err
					}
					res.Warnings = rl.warns
				}
				res.Changed, res.Message = true, "starting: connecting to its target"
				if rl != nil {
					res.Message = "reloaded from the config file and starting: " + rl.summary
				}
				if req.DryRun {
					res.Message = "would start it"
					if rl != nil {
						res.Message = "would reload it from the config file and start it: " + rl.summary
					}
					return res, nil
				}
				if rl != nil {
					if err := applyReload(rl); err != nil {
						return res, err
					}
					flushDNS = true // its names may have changed
					if _, err := mp.addEndpoints(rl.addrs); err != nil {
						res.Warnings = append(res.Warnings, fmt.Sprintf("excluding its endpoint from the routes failed: %v", err))
					}
				}
				lives[i].stopped.Store(false)
				setState(i, stateConnecting, "")
				startRunner(i, startRetry)
				logs[i].Info("control: starting", "profile", sp.name, "reloaded", rl != nil)
			case "reconnect":
				if st := states[i]; st == stateStopped || st == stateGaveUp {
					return res, fmt.Errorf("%s is %s; start it with: subtun profile start%s", label, st, arg)
				}
				res.Changed, res.Message = true, "reconnecting now"
				if req.DryRun {
					res.Message = "would reconnect it now"
					return res, nil
				}
				startRunner(i, startReconnect)
				if states[i] == stateUp {
					setState(i, stateReconnecting, "reconnect asked for")
					lost[i] = time.Now()
				}
				logs[i].Info("control: reconnecting", "profile", sp.name)
			default:
				return res, fmt.Errorf("profile %q: use stop, start or reconnect", req.Op)
			}
		default:
			return res, fmt.Errorf("unknown change %q", req.Kind)
		}
		if err := relayout(); err != nil {
			res.Warnings = append(res.Warnings, fmt.Sprintf("applying it failed, subtun tries again: %v", err))
		}
		if req.Kind != control.KindProfile && !mp.activeSet(states)[i] {
			res.Warnings = append(res.Warnings, fmt.Sprintf("it is %s: its routes and names are used once its tunnel is up", states[i]))
		}
		if plan && c == nil && mp.hasRoutes() {
			res.Warnings = append(res.Warnings, "the capture hasn't started yet (connecting, or sudo is asking): it starts with this")
		}
		return res, nil
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
		case req := <-changes:
			res, err := handleChange(req.ch)
			req.reply <- changeReply{res, err}
			continue
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
			es.capt.Store(c)
			es.routesOn(mp.activeSet(states), c.Routes())
			// Below: catch up with what changed while it started.
		case ev := <-events:
			if ev.gen != runners[ev.i].gen {
				continue // a runner since stopped or replaced
			}
			tl := logs[ev.i]
			prev := states[ev.i]
			states[ev.i], tried[ev.i] = ev.state, true
			es.infos[ev.i].update(func(t *tunnelInfo) {
				t.state, t.since = ev.state, time.Now()
				switch ev.state {
				case stateUp:
					t.target, t.agent, t.attempt, t.nextTry = ev.carrier.Desc, ev.agent, 0, time.Time{}
				case stateReconnecting:
					t.lastErr = "connection to the agent lost"
				}
				if ev.err != nil {
					t.lastErr = ev.err.Error()
				}
			})
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
		if c == nil {
			if !mp.hasRoutes() || starting != nil || !roundOver && slices.Contains(tried, false) {
				continue // nothing to capture, starting, or the first round isn't over
			}
			// Off this loop: sudo may ask for a while, and tunnels must
			// keep reporting (and reconnecting) meanwhile.
			active, e := mp.activeSet(states), early
			early = nil
			starting = make(chan startResult, 1)
			onRefuse := func(dst string) {
				if ap, err := netip.ParseAddrPort(dst); err == nil {
					if i := rt.pickIndex(ap.Addr()); i >= 0 {
						es.meters[i].Refused()
					}
				}
			}
			session := !eo.single || eo.control == controlFull // routes can change while running
			go func() {
				c, err := startCapture(ctx, mp, active, lives, utun, rt, e, marker, session, onRefuse, log)
				starting <- startResult{c, err}
			}()
			continue
		}
		_ = relayout()
	}
}

// startMultiCapture starts the capture for the profiles in use. With
// session, the helper stays up and the routes follow as tunnels come and
// go; without (one profile), it stays only if firewall rules need it.
func startMultiCapture(ctx context.Context, mp *multiPlan, active []bool, lives []*liveTunnel, dialers []meter.Dialer, rt *router,
	early *privhelper.Client, marker *leftovers, session bool, onRefuse func(string), log *slog.Logger) (*capture.Capture, error) {
	all, entries, guard, err := mp.layout(active, dialers)
	if err != nil {
		if early != nil {
			_ = early.Close()
		}
		return nil, err
	}
	rt.set(entries)
	opts := capture.Options{TunAddr: mp.tunAddr, MTU: mp.mtu, Session: session, Helper: early,
		KillSwitch: mp.ksMode(), Guard: guard, AllowDNS: mp.allowDNS, BlockIPv6: mp.blockIPv6, Locals: localPrefixes,
		OnRefuse: onRefuse}
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
func applyLayout(c *capture.Capture, mp *multiPlan, states []tunnelState, dialers []meter.Dialer, rt *router) error {
	active := mp.activeSet(states)
	all, entries, guard, err := mp.layout(active, dialers)
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
