package cli

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/md2k/subnet-tunnel/internal/config"
	"github.com/md2k/subnet-tunnel/internal/control"
	"github.com/md2k/subnet-tunnel/internal/dns"
	"github.com/md2k/subnet-tunnel/internal/routes"
	"github.com/md2k/subnet-tunnel/internal/transport"
)

// Changes while running (control: full). The engine's loop makes them one
// at a time: these functions plan and check a change as the run planned
// its profiles at start, without touching anything; the loop applies it.
// Changes last until the run ends.

// changeRequest is a change through the control socket on its way to the
// engine's loop.
type changeRequest struct {
	ch    control.Change
	reply chan changeReply
}

type changeReply struct {
	res control.Result
	err error
}

// runner is a profile's tunnel goroutine.
type runner struct {
	gen    int                // events of other generations are ignored
	cancel context.CancelFunc // nil: stopped
	done   chan struct{}      // closed once it has finished
}

// socksListener is a profile's SOCKS proxy.
type socksListener struct {
	ln     net.Listener
	cancel context.CancelFunc
}

// close stops the proxy; nil is fine.
func (l *socksListener) close() {
	if l == nil {
		return
	}
	l.cancel()
	_ = l.ln.Close()
}

// profileIndex finds the profile a change is for: by name, or the only one
// when none is named.
func (mp *multiPlan) profileIndex(name string) (int, error) {
	if name == "" && len(mp.specs) == 1 {
		return 0, nil
	}
	var names []string
	for i, sp := range mp.specs {
		if name != "" && sp.name == name {
			return i, nil
		}
		names = append(names, profileName(sp.name))
	}
	switch {
	case name == "":
		return -1, fmt.Errorf("this run has %d profiles (%s): say which one", len(names), strings.Join(names, ", "))
	case len(mp.specs) == 1 && mp.specs[0].name == "":
		return -1, fmt.Errorf("no profile %q: this run's tunnel has no profile name (subtun up --k8s, --docker); leave the name out", name)
	}
	return -1, fmt.Errorf("no profile %q in this run (it has: %s)", name, strings.Join(names, ", "))
}

// profileWords names a profile in messages, and as a command argument.
func profileWords(name string) (label, arg string) {
	if name == "" {
		return "the tunnel", ""
	}
	return "profile " + name, " " + name
}

// stopEffect says what stopping profile i does to its traffic: as Ctrl-C
// does for a whole run.
func (mp *multiPlan) stopEffect(i int) string {
	sp := mp.specs[i]
	var parts []string
	switch {
	case mp.rps[i] == nil:
	case mp.ks[i] == "lockdown":
		parts = append(parts, "kill switch lockdown: its routes stay and its traffic is refused until it starts again")
	default:
		what := "routes are"
		if names := mp.dnsNames[i]; mp.dns != nil && len(names.Domains)+len(names.Patterns) > 0 {
			what = "routes and DNS names are"
		}
		parts = append(parts, "its "+what+" removed")
		if mp.ks[i] == "on" {
			parts = append(parts, "its kill switch (on) lifts its blocks")
		}
	}
	if sp.s.socks != "" {
		parts = append(parts, "its SOCKS proxy refuses connections until it starts again")
	}
	if len(parts) == 0 {
		return "nothing else changes"
	}
	return strings.Join(parts, "; ")
}

// routeChange is a checked change to one profile's routes or excludes.
type routeChange struct {
	i                int
	routes, excludes []string // the profile's, with the change
	rp               *routePlan
	final            []netip.Prefix
	changed          bool
	cidrs            []string // as given, normalized
	message, logMsg  string
	warns            []string
}

// planRouteChange checks adding or removing routes (or excludes, with
// Exclude) of profile i, as at start: parsed, planned against the machine's
// networks now, endpoints carved out, no CIDR in two profiles.
func (mp *multiPlan) planRouteChange(i int, req control.Change) (*routeChange, error) {
	sp := mp.specs[i]
	label, arg := profileWords(sp.name)
	switch {
	case req.Op != "add" && req.Op != "del":
		return nil, fmt.Errorf("route %q: use add or del", req.Op)
	case len(req.CIDRs) == 0:
		return nil, errors.New("no CIDRs given")
	case mp.rps[i] == nil:
		return nil, fmt.Errorf("%s has no routes (SOCKS only): routes can be added only to a profile that started with routes", label)
	}
	rc := &routeChange{i: i, routes: slices.Clone(sp.s.routes), excludes: slices.Clone(sp.s.excludes)}
	list, parse, what := &rc.routes, routes.ParseRoute, "route"
	if req.Exclude {
		list, parse, what = &rc.excludes, routes.ParsePrefix, "exclude"
	}
	var have []netip.Prefix
	for _, v := range *list {
		p, err := parse(v)
		if err != nil {
			return nil, fmt.Errorf("%s's %s %s: %w", label, what, v, err) // checked at start
		}
		have = append(have, p)
	}
	var already []string
	for _, v := range req.CIDRs {
		p, err := parse(strings.TrimSpace(v))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", what, err)
		}
		at := slices.Index(have, p)
		switch {
		case req.Op == "add" && at >= 0:
			already = append(already, p.String())
			continue
		case req.Op == "add":
			have = append(have, p)
			*list = append(*list, p.String())
		case at < 0:
			msg := fmt.Sprintf("%s isn't one of %s's %ss (%s)", p, label, what, listOrNone(*list))
			if !req.Exclude && slices.ContainsFunc(have, func(q netip.Prefix) bool { return q.Bits() < p.Bits() && q.Contains(p.Addr()) }) {
				msg += fmt.Sprintf("; to stop routing part of a route, exclude it: subtun route add -x %s", p)
			}
			return nil, errors.New(msg)
		default:
			for at >= 0 { // listed more than once: all go
				have = slices.Delete(have, at, at+1)
				*list = slices.Delete(*list, at, at+1)
				at = slices.Index(have, p)
			}
		}
		rc.cidrs = append(rc.cidrs, p.String())
	}
	if len(rc.cidrs) == 0 {
		rc.message = fmt.Sprintf("nothing to change: it already has the %s %s", plural(what, len(already)), strings.Join(already, ", "))
		return rc, nil
	}
	s := sp.s
	s.routes, s.excludes = rc.routes, rc.excludes
	rp, warns, err := planRoutes(s)
	if err != nil {
		return nil, err
	}
	if rp == nil {
		return nil, fmt.Errorf("that removes %s's last route; stop it instead: subtun profile stop%s", label, arg)
	}
	final, err := carveEndpoints(rp, mp.endpointList())
	if err != nil {
		return nil, err
	}
	rps := slices.Clone(mp.rps)
	rps[i] = rp
	if err := checkOverlapsOf(mp.specs, rps); err != nil {
		return nil, err
	}
	for _, n := range rp.plan.Redundant {
		if slices.Contains(rc.cidrs, n.Prefix.String()) {
			warns = append(warns, n.String())
		}
	}
	if gp, _, err := planGuard(s, rp); err == nil && gp.blockIPv6 && !mp.blockIPv6 {
		warns = append(warns, "outgoing IPv6 isn't blocked: this run started without it (a full tunnel blocks it); restart subtun to block it")
	}
	if len(already) > 0 {
		warns = append(warns, fmt.Sprintf("it already had %s", strings.Join(already, ", ")))
	}
	verb, logVerb := "added", "added"
	if req.Op == "del" {
		verb, logVerb = "removed", "removed"
	}
	if req.DryRun {
		verb = map[string]string{"add": "would add", "del": "would remove"}[req.Op]
	}
	rc.rp, rc.final, rc.warns, rc.changed = rp, final, warns, true
	rc.message = fmt.Sprintf("%s %s %s; its routes %s: %s", verb, plural(what, len(rc.cidrs)), strings.Join(rc.cidrs, ", "),
		map[bool]string{false: "now", true: "would be"}[req.DryRun], summary(prefixStrings(final), 8))
	rc.logMsg = plural(what, len(rc.cidrs)) + " " + logVerb
	return rc, nil
}

// applyRouteChange makes a planned route change part of the plan; the
// loop then brings the capture in line.
func (mp *multiPlan) applyRouteChange(rc *routeChange) {
	sp := mp.specs[rc.i]
	mp.smu.Lock()
	sp.s.routes, sp.s.excludes = rc.routes, rc.excludes
	sp.noteChanges(time.Now())
	mp.smu.Unlock()
	mp.rps[rc.i] = rc.rp
	final := rc.final
	mp.finals[rc.i].Store(&final)
}

// dnsChange is a checked change to one profile's DNS domains or patterns.
type dnsChange struct {
	i                 int
	domains, patterns []string    // the profile's, with the change
	names             []dns.Names // every profile's, with the change
	changed           bool
	gotDomains        []string // as given, normalized
	gotPatterns       []string
	message, logMsg   string
	warns             []string
}

// planDNSChange checks adding or removing DNS domains and patterns of
// profile i, by the rules at start (a domain, or ".", in one profile only).
// m is the run's matcher; nil: the run captures no DNS.
func (mp *multiPlan) planDNSChange(i int, req control.Change, m *dns.Matcher) (*dnsChange, error) {
	sp := mp.specs[i]
	label, _ := profileWords(sp.name)
	switch {
	case req.Op != "add" && req.Op != "del":
		return nil, fmt.Errorf("dns %q: use add or del", req.Op)
	case len(req.Domains)+len(req.Patterns) == 0:
		return nil, errors.New("no domains or patterns given")
	case m == nil:
		return nil, errors.New("this run doesn't capture DNS (no profile had DNS names when it started, or DNS capture is off): names can't be added while it runs; restart subtun with them")
	case mp.rps[i] == nil:
		return nil, fmt.Errorf("%s has no routes: DNS capture works together with the utun capture", label)
	case sp.s.dnsCapture == "off":
		return nil, fmt.Errorf("%s has dns.capture: off", label)
	}
	dc := &dnsChange{i: i, domains: slices.Clone(sp.s.dnsDomains), patterns: slices.Clone(sp.s.dnsPatterns)}
	norm := func(d string) string {
		if n, err := dns.NormalizeDomain(d); err == nil {
			return n
		}
		return d
	}
	var already []string
	for _, d := range req.Domains {
		n, err := dns.NormalizeDomain(d)
		if err != nil {
			return nil, err
		}
		match := func(x string) bool { return norm(x) == n }
		at := slices.IndexFunc(dc.domains, match)
		switch {
		case req.Op == "add" && at >= 0:
			already = append(already, n)
			continue
		case req.Op == "add":
			dc.domains = append(dc.domains, n)
		case at < 0:
			return nil, fmt.Errorf("%s isn't one of %s's DNS domains (%s)", n, label, listOrNone(dc.domains))
		default:
			dc.domains = slices.DeleteFunc(dc.domains, match)
		}
		dc.gotDomains = append(dc.gotDomains, n)
	}
	for _, p := range req.Patterns {
		if _, err := regexp.Compile(p); err != nil {
			return nil, fmt.Errorf("DNS pattern %q: %w", p, err)
		}
		at := slices.Index(dc.patterns, p)
		switch {
		case req.Op == "add" && at >= 0:
			already = append(already, "pattern "+p)
			continue
		case req.Op == "add":
			dc.patterns = append(dc.patterns, p)
		case at < 0:
			return nil, fmt.Errorf("%q isn't one of %s's DNS patterns (%s)", p, label, listOrNone(dc.patterns))
		default:
			dc.patterns = slices.DeleteFunc(dc.patterns, func(x string) bool { return x == p })
		}
		dc.gotPatterns = append(dc.gotPatterns, p)
	}
	given := slices.Clone(dc.gotDomains)
	for _, p := range dc.gotPatterns {
		given = append(given, "pattern "+p)
	}
	if len(given) == 0 {
		dc.message = fmt.Sprintf("nothing to change: it already has %s", strings.Join(already, ", "))
		return dc, nil
	}
	dc.names = slices.Clone(mp.dnsNames)
	dc.names[i] = dns.Names{Domains: dc.domains, Patterns: dc.patterns}
	if _, err := dns.NewMultiMatcher(dc.names); err != nil {
		return nil, err
	}
	if req.Op == "add" {
		if err := mp.dnsServersCaptured(sp.s); err != nil {
			return nil, fmt.Errorf("%s: %w", label, err)
		}
	}
	if len(already) > 0 {
		dc.warns = append(dc.warns, fmt.Sprintf("it already had %s", strings.Join(already, ", ")))
	}
	if req.Op == "add" && slices.Contains(dc.gotDomains, ".") {
		dc.warns = append(dc.warns, "names under the search domains and the local networks' reverse zones stay local")
	}
	verb, logVerb := "added", "added"
	if req.Op == "del" {
		verb, logVerb = "removed", "removed"
	}
	if req.DryRun {
		verb = map[string]string{"add": "would add", "del": "would remove"}[req.Op]
	}
	now := listOrNone(namesText(dc.names[i]))
	dc.changed = true
	dc.message = fmt.Sprintf("%s DNS %s; names through its tunnel %s: %s", verb, strings.Join(given, ", "),
		map[bool]string{false: "now", true: "would be"}[req.DryRun], now)
	dc.logMsg = "DNS names " + logVerb
	return dc, nil
}

// dnsServersCaptured checks that the DNS servers a profile's names are
// asked of are among those the run captures: which servers are captured,
// and whether the system's are followed, was decided at start by the
// profiles that had names then.
func (mp *multiPlan) dnsServersCaptured(s settings) error {
	d := mp.dns
	if d == nil {
		return nil // the development listener: nothing is captured
	}
	list := s.dnsServers
	if len(list) == 0 || len(list) == 1 && list[0] == "auto" {
		if !d.Auto {
			return errors.New("its names would be asked of the system's DNS servers (dns.servers: auto), and this run captures only the servers set in the config; restart subtun to capture the system's too")
		}
		return nil
	}
	servers, err := parseServers(list)
	if err != nil {
		return err
	}
	for _, a := range servers {
		if !slices.Contains(d.Servers, a) && !slices.Contains(d.Pinned, a) {
			return fmt.Errorf("its DNS server %s isn't captured by this run (it captures the servers of the profiles that had DNS names at start); restart subtun to capture it", a)
		}
	}
	return nil
}

// applyDNSChange makes a planned DNS change part of the plan and the
// matcher.
func (mp *multiPlan) applyDNSChange(dc *dnsChange, m *dns.Matcher) error {
	if err := mp.setNames(dc.names, m); err != nil {
		return err
	}
	sp := mp.specs[dc.i]
	mp.smu.Lock()
	sp.s.dnsDomains, sp.s.dnsPatterns = dc.domains, dc.patterns
	sp.noteChanges(time.Now())
	mp.smu.Unlock()
	return nil
}

// setNames gives the matcher every profile's names; a "." new to the run
// gets the names it leaves local.
func (mp *multiPlan) setNames(names []dns.Names, m *dns.Matcher) error {
	wasAll := m.CatchAll()
	if err := m.SetNames(names); err != nil {
		return err
	}
	if m.CatchAll() && !wasAll {
		search, _ := systemSearch()
		m.SetLocal(search, dnsLocals(mp.tunAddr)())
	}
	mp.smu.Lock()
	mp.dnsNames = names
	mp.smu.Unlock()
	mp.noteDomains()
	return nil
}

// reloadChange is a profile read from the config file again, checked.
type reloadChange struct {
	i       int
	spec    *tunnelSpec
	policy  reconnectPolicy
	rp      *routePlan
	final   []netip.Prefix
	names   []dns.Names // every profile's
	host    string      // the target's endpoint
	addrs   []netip.Addr
	summary string
	warns   []string
	undo    func() // undoes what planning it changed (the new endpoint's own name)
}

// fixedChanges lists the settings a reload can't change: the run shares
// them, or set them up at start.
func fixedChanges(was, now settings) []string {
	was, now = fixedDefaults(was), fixedDefaults(now)
	var out []string
	add := func(changed bool, key string) {
		if changed {
			out = append(out, key)
		}
	}
	add(was.tunAddr != now.tunAddr, "tun.address")
	add(was.mtu != now.mtu, "tun.mtu")
	add(was.dnsCapture != now.dnsCapture, "dns.capture")
	add(!slices.Equal(was.dnsServers, now.dnsServers), "dns.servers")
	add(was.dnsFallback != now.dnsFallback, "dns.fallback")
	add(was.dnsUnrouted != now.dnsUnrouted, "dns.unrouted")
	add(was.killSwitch != now.killSwitch, "killSwitch.mode")
	add(was.killSwitchDNS != now.killSwitchDNS, "killSwitch.dns")
	add(was.blockIPv6 != now.blockIPv6, "blockIPv6")
	return out
}

// sharedDiff is a shared setting a profile's config sets otherwise than
// the run.
type sharedDiff struct{ key, got, run string }

// inheritShared gives a profile the run's values of the settings every
// profile shares (tun.address, tun.mtu, dns.fallback: they may come from
// the run's flags or another profile), and lists those its config sets
// otherwise.
func inheritShared(ns *tunnelSpec, run settings) []sharedDiff {
	var out []sharedDiff
	if ns.cfg.Tun.Address != "" && ns.s.tunAddr != run.tunAddr {
		out = append(out, sharedDiff{"tun.address", ns.s.tunAddr, run.tunAddr})
	}
	if ns.cfg.Tun.MTU != 0 && ns.s.mtu != run.mtu {
		out = append(out, sharedDiff{"tun.mtu", strconv.Itoa(ns.s.mtu), strconv.Itoa(run.mtu)})
	}
	if f, rf := fixedDefaults(ns.s).dnsFallback, fixedDefaults(run).dnsFallback; ns.cfg.DNS.Fallback != "" && f != rf {
		out = append(out, sharedDiff{"dns.fallback", f, rf})
	}
	ns.s.tunAddr, ns.s.mtu, ns.s.dnsFallback = run.tunAddr, run.mtu, run.dnsFallback
	return out
}

// fixedDefaults spells out the defaults of the settings fixedChanges
// compares, so leaving one out and writing its default are the same.
func fixedDefaults(s settings) settings {
	def := func(v *string, d string) {
		if *v == "" {
			*v = d
		}
	}
	def(&s.dnsCapture, "firewall")
	def(&s.dnsFallback, "system")
	def(&s.dnsUnrouted, "warn")
	def(&s.killSwitch, "off")
	def(&s.killSwitchDNS, "block")
	def(&s.blockIPv6, "auto")
	if len(s.dnsServers) == 0 {
		s.dnsServers = []string{"auto"}
	}
	return s
}

// planReload checks profile i as read from the config file again (ns),
// against the run as at start: settings the run shares or set up at start
// must not change; routes, DNS names and the SOCKS address must not clash
// with the other profiles. host and addrs are its target's endpoint.
func (mp *multiPlan) planReload(i int, ns *tunnelSpec, host string, addrs []netip.Addr, m *dns.Matcher) (*reloadChange, error) {
	old := mp.specs[i]
	label, _ := profileWords(old.name)
	ns.name = old.name
	specs := slices.Clone(mp.specs)
	specs[i] = ns
	for _, d := range inheritShared(ns, old.s) {
		return nil, fmt.Errorf("%s: %s changed in the config file (%s; the run uses %s), which needs a subtun restart", label, d.key, d.got, d.run)
	}
	if fixed := fixedChanges(old.s, ns.s); len(fixed) > 0 {
		return nil, fmt.Errorf("%s: %s changed in the config file, which needs a subtun restart (a reload takes the target, agent, routes, excludes, DNS domains and patterns, SOCKS address and reconnect settings)",
			label, strings.Join(fixed, ", "))
	}
	policy := reconnectPolicy{attempts: ns.s.reconnectAttempts, delay: ns.s.reconnectDelay, maxDelay: ns.s.reconnectMaxDelay}
	if err := policy.validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", label, err)
	}
	if a := ns.s.socks; a != "" && a != old.s.socks {
		for j, sp := range mp.specs {
			if j != i && sp.s.socks == a {
				return nil, fmt.Errorf("profiles %s and %s both want the SOCKS address %s", sp.name, ns.name, a)
			}
		}
	}
	rp, warns, err := planRoutes(ns.s)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", label, err)
	}
	switch {
	case rp == nil && mp.rps[i] != nil:
		return nil, fmt.Errorf("%s has no routes in the config file now, which needs a subtun restart", label)
	case rp != nil && mp.rps[i] == nil:
		return nil, fmt.Errorf("%s has routes in the config file now and started without, which needs a subtun restart", label)
	}
	rl := &reloadChange{i: i, spec: ns, policy: policy, rp: rp, host: host, addrs: addrs, undo: func() {}}
	if rp != nil {
		if rl.final, err = carveEndpoints(rp, append(mp.endpointList(), addrs...)); err != nil {
			return nil, fmt.Errorf("%s: %w", label, err)
		}
		rps := slices.Clone(mp.rps)
		rps[i] = rp
		if err := checkOverlapsOf(specs, rps); err != nil {
			return nil, err
		}
		if gp, _, err := planGuard(ns.s, rp); err == nil && gp.blockIPv6 && !mp.blockIPv6 {
			warns = append(warns, "outgoing IPv6 isn't blocked: this run started without it (a full tunnel blocks it); restart subtun to block it")
		}
	}
	rl.names = slices.Clone(mp.dnsNames)
	rl.names[i] = dns.Names{}
	if len(ns.s.dnsDomains)+len(ns.s.dnsPatterns) > 0 && ns.s.dnsCapture != "off" {
		switch {
		case rp == nil:
			warns = append(warns, "DNS settings ignored: DNS capture works together with the utun capture, and this profile has no routes (CIDRs)")
		case m == nil:
			warns = append(warns, "DNS names ignored: this run doesn't capture DNS; restart subtun to capture them")
		default:
			if err := mp.dnsServersCaptured(ns.s); err != nil {
				return nil, fmt.Errorf("%s: %w", label, err)
			}
			rl.names[i] = dns.Names{Domains: ns.s.dnsDomains, Patterns: ns.s.dnsPatterns}
		}
	}
	if m != nil {
		if _, err := dns.NewMultiMatcher(rl.names); err != nil {
			return nil, fmt.Errorf("%s: %w", label, err)
		}
	}
	rl.warns = warns
	rl.summary = reloadSummary(old, ns, mp.final(i), rl.final, mp.dnsNames[i], rl.names[i])
	return rl, nil
}

// reloadSummary says what a reload changes.
func reloadSummary(old, ns *tunnelSpec, wasFinal, nowFinal []netip.Prefix, wasNames, nowNames dns.Names) string {
	var changed []string
	add := func(diff bool, what string) {
		if diff {
			changed = append(changed, what)
		}
	}
	oldHost, _ := old.endpoint()
	newHost, _ := ns.endpoint()
	add(oldHost != newHost || targetKey(old.cfg.Target) != targetKey(ns.cfg.Target), "target")
	add(old.s.agent != ns.s.agent || old.s.agentDir != ns.s.agentDir, "agent")
	add(!slices.Equal(wasFinal, nowFinal), "routes")
	add(!slices.Equal(namesText(wasNames), namesText(nowNames)), "DNS names")
	add(old.s.socks != ns.s.socks, "SOCKS address")
	add(old.s.reconnectAttempts != ns.s.reconnectAttempts || old.s.reconnectDelay != ns.s.reconnectDelay || old.s.reconnectMaxDelay != ns.s.reconnectMaxDelay, "reconnect")
	out := "the config file changes nothing"
	if len(changed) > 0 {
		out = "new " + strings.Join(changed, ", ")
	}
	if len(runtimeChanges(old.base, old.s)) > 0 {
		out += "; the changes made while running are dropped"
	}
	return out
}

// targetKey is a target's settings, comparable.
func targetKey(t config.Target) string {
	switch {
	case t.K8s != nil:
		return fmt.Sprintf("k8s %+v", *t.K8s)
	case t.Docker != nil:
		return fmt.Sprintf("docker %+v", *t.Docker)
	}
	return ""
}

// applyReload makes a reloaded profile part of the plan; the caller has
// moved its SOCKS proxy, and then takes its endpoint out of the routes.
func (mp *multiPlan) applyReload(rl *reloadChange, m *dns.Matcher) error {
	i := rl.i
	if m != nil {
		if err := mp.setNames(rl.names, m); err != nil {
			return err
		}
		m.SetOwn(append(m.Own(), transport.HostName(rl.host)))
	}
	rl.spec.base = rl.spec.s
	mp.smu.Lock()
	mp.specs[i] = rl.spec
	mp.smu.Unlock()
	mp.rps[i] = rl.rp
	if rl.rp != nil {
		final := rl.final
		mp.finals[i].Store(&final)
	}
	mp.policies[i] = rl.policy
	mp.hosts[i] = rl.host
	return nil
}

// noteChanges records when each of the profile's runtime changes was made
// (for status); the caller holds mp.smu.
func (sp *tunnelSpec) noteChanges(now time.Time) {
	next := map[string]time.Time{}
	for _, c := range runtimeChanges(sp.base, sp.s) {
		if t, ok := sp.changedAt[c]; ok {
			next[c] = t
		} else {
			next[c] = now
		}
	}
	sp.changedAt = next
}

// runtimeChanges lists what changed in a profile's routes and DNS names
// since it started (or was reloaded): "+route 10.9.0.0/16", "-dns x.com".
func runtimeChanges(base, cur settings) []string {
	var out []string
	diff := func(what string, was, now []string, key func(string) string) {
		keys := func(list []string) []string {
			out := make([]string, 0, len(list))
			for _, v := range list {
				if k := key(v); !slices.Contains(out, k) {
					out = append(out, k)
				}
			}
			return out
		}
		w, n := keys(was), keys(now)
		for _, k := range n {
			if !slices.Contains(w, k) {
				out = append(out, "+"+what+" "+k)
			}
		}
		for _, k := range w {
			if !slices.Contains(n, k) {
				out = append(out, "-"+what+" "+k)
			}
		}
	}
	prefix := func(parse func(string) (netip.Prefix, error)) func(string) string {
		return func(v string) string {
			if p, err := parse(v); err == nil {
				return p.String()
			}
			return v
		}
	}
	diff("route", base.routes, cur.routes, prefix(routes.ParseRoute))
	diff("exclude", base.excludes, cur.excludes, prefix(routes.ParsePrefix))
	diff("dns", base.dnsDomains, cur.dnsDomains, func(d string) string {
		if n, err := dns.NormalizeDomain(d); err == nil {
			return n
		}
		return d
	})
	diff("pattern", base.dnsPatterns, cur.dnsPatterns, func(p string) string { return p })
	return out
}

// agreeShared returns the values the profiles set for the settings every
// profile of a run shares (see agree).
func agreeShared(specs []*tunnelSpec) (tunAddr, mtu, fallback string, err error) {
	if tunAddr, err = agree(specs, "tun.address", func(p config.Profile) string { return p.Tun.Address }); err != nil {
		return
	}
	if mtu, err = agree(specs, "tun.mtu", func(p config.Profile) string {
		if p.Tun.MTU == 0 {
			return ""
		}
		return strconv.Itoa(p.Tun.MTU)
	}); err != nil {
		return
	}
	fallback, err = agree(specs, "dns.fallback", func(p config.Profile) string { return p.DNS.Fallback })
	return
}

// applyShared puts the shared values into a profile's settings.
func applyShared(sp *tunnelSpec, tunAddr, mtu, fallback string) {
	if tunAddr != "" {
		sp.s.tunAddr = tunAddr
	}
	if mtu != "" {
		sp.s.mtu, _ = strconv.Atoi(mtu) // the config checked it
	}
	sp.s.dnsFallback = fallback
}

// namesText is a profile's DNS names for people.
func namesText(n dns.Names) []string {
	out := slices.Clone(n.Domains)
	for _, p := range n.Patterns {
		out = append(out, "pattern "+p)
	}
	return out
}

func prefixStrings(ps []netip.Prefix) []string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = p.String()
	}
	return out
}

func listOrNone(items []string) string {
	if len(items) == 0 {
		return "none"
	}
	return strings.Join(items, ", ")
}

func plural(word string, n int) string {
	if n == 1 {
		return word
	}
	return word + "s"
}

// hasProfile reports whether the run has a profile of that name.
func (mp *multiPlan) hasProfile(name string) bool {
	return slices.ContainsFunc(mp.specs, func(sp *tunnelSpec) bool { return sp.name == name })
}

// captureState is what a running capture can still take.
type captureState struct {
	started      bool // the capture runs (else it starts later with the plan as it is then)
	guarding     bool // it has a kill switch guard
	holdsDNS     bool // DNS to the captured servers is blocked while the kill switch holds
	blockingIPv6 bool
}

// addChange is a profile from the config file, checked to join the run.
type addChange struct {
	spec     *tunnelSpec
	policy   reconnectPolicy
	rp       *routePlan
	final    []netip.Prefix
	ks       string
	unrouted string
	names    []dns.Names // every profile's, the new one last
	host     string
	addrs    []netip.Addr
	// Shared values a capture not started yet takes.
	allowDNS  bool
	blockIPv6 bool
	ipv6Why   string
	summary   string
	warns     []string
}

// planAdd checks a profile from the config file (ns) to join the run, as if
// it had been started with the others: the settings every profile shares
// must agree with the run's, its routes, DNS names and SOCKS address must
// not clash, and what the running capture set up at start must fit it.
// host and addrs are its target's endpoint.
func (mp *multiPlan) planAdd(ns *tunnelSpec, host string, addrs []netip.Addr, m *dns.Matcher, cs captureState) (*addChange, error) {
	label := "profile " + ns.name
	if mp.specs[0].name == "" {
		return nil, errors.New("this run's tunnel has no profile name (subtun up --k8s, --docker), so it couldn't be told apart from added ones: add profiles to a run started with subtun up")
	}
	for _, d := range inheritShared(ns, mp.specs[0].s) {
		return nil, fmt.Errorf("%s: %s %s differs from the run's (%s): it is shared by every profile of a run", label, d.key, d.got, d.run)
	}
	ns.base = ns.s
	ac := &addChange{spec: ns, host: host, addrs: addrs, allowDNS: mp.allowDNS, blockIPv6: mp.blockIPv6, ipv6Why: mp.ipv6Why}
	ac.policy = reconnectPolicy{attempts: ns.s.reconnectAttempts, delay: ns.s.reconnectDelay, maxDelay: ns.s.reconnectMaxDelay}
	if err := ac.policy.validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", label, err)
	}
	if a := ns.s.socks; a != "" {
		for _, sp := range mp.specs {
			if sp.s.socks == a {
				return nil, fmt.Errorf("profiles %s and %s both want the SOCKS address %s", profileName(sp.name), ns.name, a)
			}
		}
	}
	var err error
	var warns []string
	if ac.unrouted, err = dns.ParseUnrouted(ns.s.dnsUnrouted); err != nil {
		return nil, fmt.Errorf("%s: %w", label, err)
	}
	switch ns.s.dnsCapture {
	case "", "firewall", "off":
	default:
		return nil, fmt.Errorf("%s: DNS capture %q: use firewall or off", label, ns.s.dnsCapture)
	}
	if ac.rp, warns, err = planRoutes(ns.s); err != nil {
		return nil, fmt.Errorf("%s: %w", label, err)
	}
	if ac.rp != nil && !mp.hasRoutes() {
		return nil, fmt.Errorf("%s has routes, and this run has no utun capture (no profile had routes when it started); restart subtun with it", label)
	}
	gp, notes, err := planGuard(ns.s, ac.rp)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", label, err)
	}
	warns = append(warns, notes...)
	ac.ks = "off"
	if gp != nil {
		ac.ks = gp.killSwitch
	}
	specs := append(slices.Clone(mp.specs), ns)
	if ac.rp != nil {
		if ac.final, err = carveEndpoints(ac.rp, append(mp.endpointList(), addrs...)); err != nil {
			return nil, fmt.Errorf("%s: %w", label, err)
		}
		if err := checkOverlapsOf(specs, append(slices.Clone(mp.rps), ac.rp)); err != nil {
			return nil, err
		}
	}
	if ac.ks != "off" {
		if cs.started && !cs.guarding {
			return nil, fmt.Errorf("%s has a kill switch, and this run's capture has none (no profile had one when it started); restart subtun with it", label)
		}
		wantsAllow := ns.s.killSwitchDNS == "allow"
		switch {
		case !cs.started:
			// The capture starts with the stricter hold of every profile with a kill switch.
			anyKS := slices.ContainsFunc(mp.ks, func(k string) bool { return k != "off" })
			ac.allowDNS = wantsAllow && (!anyKS || mp.allowDNS)
		case mp.dns != nil && !wantsAllow && !cs.holdsDNS:
			warns = append(warns, "DNS stays allowed while its kill switch holds: this run's setting since it started (killSwitch.dns: allow)")
		case mp.dns != nil && wantsAllow && cs.holdsDNS:
			warns = append(warns, "DNS to the captured servers stays blocked while its kill switch holds: another profile's setting")
		}
	}
	if gp != nil && gp.blockIPv6 && !mp.blockIPv6 {
		if cs.started {
			warns = append(warns, "outgoing IPv6 isn't blocked: this run started without it (a full tunnel blocks it); restart subtun to block it")
		} else {
			ac.blockIPv6, ac.ipv6Why = true, fmt.Sprintf("%s, profile %s", gp.ipv6Why, ns.name)
		}
	}
	if a, ok := ipv6Endpoint(addrs); ok && cs.blockingIPv6 {
		return nil, fmt.Errorf("%s: its endpoint %s is an IPv6 address, and this run blocks outgoing IPv6, which would cut its connection; restart subtun instead", label, a)
	}
	ac.names = append(slices.Clone(mp.dnsNames), dns.Names{})
	if len(ns.s.dnsDomains)+len(ns.s.dnsPatterns) > 0 && ns.s.dnsCapture != "off" {
		switch {
		case ac.rp == nil:
			warns = append(warns, "DNS settings ignored: DNS capture works together with the utun capture, and this profile has no routes (CIDRs)")
		case m == nil:
			warns = append(warns, "DNS names ignored: this run doesn't capture DNS; restart subtun to capture them")
		default:
			if err := mp.dnsServersCaptured(ns.s); err != nil {
				return nil, fmt.Errorf("%s: %w", label, err)
			}
			ac.names[len(ac.names)-1] = dns.Names{Domains: ns.s.dnsDomains, Patterns: ns.s.dnsPatterns}
			if _, err := dns.NewMultiMatcher(ac.names); err != nil {
				return nil, fmt.Errorf("%s: %w", label, err)
			}
		}
	}
	ac.warns = warns
	var what []string
	if ac.rp != nil {
		what = append(what, "routes "+summary(prefixStrings(ac.final), 6))
	}
	if n := ac.names[len(ac.names)-1]; len(n.Domains)+len(n.Patterns) > 0 {
		what = append(what, "DNS "+strings.Join(namesText(n), ", "))
	}
	if ns.s.socks != "" {
		what = append(what, "SOCKS "+ns.s.socks)
	}
	if ac.ks != "off" {
		what = append(what, "kill switch "+ac.ks)
	}
	ac.summary = strings.Join(what, "; ")
	return ac, nil
}

// profileName names a profile in a message ("the tunnel" without a name).
func profileName(name string) string {
	if name == "" {
		return "the tunnel"
	}
	return name
}
