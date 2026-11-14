package cli

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/md2k/subnet-tunnel/internal/agentbin"
	"github.com/md2k/subnet-tunnel/internal/capture"
	"github.com/md2k/subnet-tunnel/internal/config"
	"github.com/md2k/subnet-tunnel/internal/control"
	"github.com/md2k/subnet-tunnel/internal/logring"
	"github.com/md2k/subnet-tunnel/internal/meter"
	"github.com/md2k/subnet-tunnel/internal/privhelper"
	"github.com/md2k/subnet-tunnel/internal/transport"
)

func routeReq(op, profile string, cidrs ...string) control.Change {
	return control.Change{Kind: control.KindRoute, Op: op, Profile: profile, CIDRs: cidrs}
}

// Route changes are planned as at start: endpoints carved out, no CIDR in
// two profiles, a profile keeps at least one route.
func TestPlanRouteChange(t *testing.T) {
	mp := multiPlanFor(t, "work", "dev") // work: 10.0.0.0/8, 203.0.113.0/24; dev: 10.50.0.0/16
	rc, err := mp.planRouteChange(1, routeReq("add", "dev", "10.70.0.0/16", "10.71.0.5"))
	if err != nil {
		t.Fatal(err)
	}
	if !rc.changed || !covers(rc.final, "10.70.1.1") || !covers(rc.final, "10.71.0.5") || covers(rc.final, "10.71.0.6") ||
		!strings.Contains(rc.message, "added routes 10.70.0.0/16, 10.71.0.5/32; its routes now: ") {
		t.Fatalf("add: %+v", rc)
	}
	if covers(mp.final(1), "10.70.1.1") {
		t.Fatal("planning changed the plan")
	}
	mp.applyRouteChange(rc)
	if !covers(mp.final(1), "10.70.1.1") || !slices.Contains(mp.specs[1].s.routes, "10.70.0.0/16") {
		t.Fatalf("applied: %v %v", mp.final(1), mp.specs[1].s.routes)
	}
	// Who carries 10.70.1.1 follows: dev's /16 is more specific than work's /8.
	if i := mp.owner(netip.MustParseAddr("10.70.1.1"), []bool{true, true}); i != 1 {
		t.Errorf("10.70.1.1 carried by %d", i)
	}
	if got := runtimeChanges(mp.specs[1].base, mp.specs[1].s); !slices.Equal(got, []string{"+route 10.70.0.0/16", "+route 10.71.0.5/32"}) {
		t.Errorf("runtime changes: %v", got)
	}

	if rc, err := mp.planRouteChange(1, routeReq("add", "dev", "10.70.0.0/16")); err != nil || rc.changed || !strings.Contains(rc.message, "nothing to change") {
		t.Errorf("add again: %+v %v", rc, err)
	}
	// An exclude carves part of a route; work's endpoint stays out whatever is added.
	rc, err = mp.planRouteChange(0, control.Change{Op: "add", CIDRs: []string{"10.1.0.0/16"}, Exclude: true})
	if err != nil || covers(rc.final, "10.1.2.3") || !covers(rc.final, "10.2.0.1") {
		t.Errorf("exclude: %+v %v", rc, err)
	}
	if rc, err := mp.planRouteChange(0, routeReq("add", "work", "203.0.113.200")); err != nil || covers(rc.final, "203.0.113.200") {
		t.Errorf("work's own endpoint routed: %+v %v", rc, err)
	}
	for name, tc := range map[string]struct {
		i    int
		req  control.Change
		want string
	}{
		"in two profiles": {0, routeReq("add", "work", "10.50.0.0/16"), "10.50.0.0/16 is routed by both profiles"},
		"not a route":     {1, routeReq("del", "dev", "10.99.0.0/16"), "10.99.0.0/16 isn't one of profile dev's routes (10.50.0.0/16, 10.70.0.0/16, 10.71.0.5/32)"},
		"part of a route": {1, routeReq("del", "dev", "10.50.1.0/24"), "exclude it: subtun route add -x 10.50.1.0/24"},
		"bad CIDR":        {1, routeReq("add", "dev", "10.50.0.0/33"), "route"},
		"no CIDRs":        {1, routeReq("add", "dev"), "no CIDRs given"},
		"bad op":          {1, routeReq("move", "dev", "10.9.0.0/16"), `route "move": use add or del`},
		"the gateway":     {1, routeReq("add", "dev", "192.168.77.1"), "default gateway"},
	} {
		if _, err := mp.planRouteChange(tc.i, tc.req); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", name, err, tc.want)
		}
	}
	rc, err = mp.planRouteChange(1, routeReq("del", "dev", "10.70.0.0/16", "10.71.0.5"))
	if err != nil {
		t.Fatal(err)
	}
	mp.applyRouteChange(rc)
	if _, err := mp.planRouteChange(1, routeReq("del", "dev", "10.50.0.0/16")); err == nil || !strings.Contains(err.Error(), "last route; stop it instead: subtun profile stop dev") {
		t.Errorf("last route: %v", err)
	}
	if got := runtimeChanges(mp.specs[1].base, mp.specs[1].s); len(got) != 0 {
		t.Errorf("after removing what was added: %v", got)
	}

	// A profile without routes takes none.
	mp = multiPlanFor(t, "work", "socks-dev")
	if _, err := mp.planRouteChange(1, routeReq("add", "socks-dev", "10.80.0.0/16")); err == nil || !strings.Contains(err.Error(), "no routes (SOCKS only)") {
		t.Errorf("SOCKS-only profile: %v", err)
	}
}

// DNS names change by the rules at start.
func TestPlanDNSChange(t *testing.T) {
	mp := multiPlanFor(t, "work", "dev", "vault") // work: ., corp.example; dev: cluster.local; vault: none
	m := mp.dns.Match
	dc, err := mp.planDNSChange(2, control.Change{Op: "add", Domains: []string{"Vault.Example."}, Patterns: []string{`^db[0-9]+\.`}}, m)
	if err != nil {
		t.Fatal(err)
	}
	if !dc.changed || !strings.Contains(dc.message, "added DNS vault.example, pattern ^db[0-9]+\\.; names through its tunnel now: vault.example, pattern") {
		t.Fatalf("add: %+v", dc)
	}
	if tg, _ := m.Pick("x.vault.example"); tg == 2 {
		t.Fatal("planning changed the matcher")
	}
	if err := mp.applyDNSChange(dc, m); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]int{"x.vault.example": 2, "db7.svc": 2, "x.cluster.local": 1, "github.com": 0} {
		if tg, _ := m.Pick(name); tg != want {
			t.Errorf("%s: %d, want %d", name, tg, want)
		}
	}
	if len(mp.dnsNames[2].Domains) != 1 || !slices.Contains(runtimeChanges(mp.specs[2].base, mp.specs[2].s), "+dns vault.example") {
		t.Errorf("plan: %+v, changes %v", mp.dnsNames[2], runtimeChanges(mp.specs[2].base, mp.specs[2].s))
	}
	for name, tc := range map[string]struct {
		i    int
		req  control.Change
		m    bool
		want string
	}{
		"another's domain":   {1, control.Change{Op: "add", Domains: []string{"corp.example"}}, true, `"corp.example" is listed for two tunnels`},
		"a second catch-all": {1, control.Change{Op: "add", Domains: []string{"."}}, true, "only one tunnel can resolve all names"},
		"not its domain":     {1, control.Change{Op: "del", Domains: []string{"corp.example"}}, true, "corp.example isn't one of profile dev's DNS domains (cluster.local)"},
		"a regex as domain":  {1, control.Change{Op: "add", Domains: []string{"^x"}}, true, "looks like a regular expression"},
		"a bad pattern":      {1, control.Change{Op: "add", Patterns: []string{"("}}, true, `DNS pattern "("`},
		"nothing":            {1, control.Change{Op: "add"}, true, "no domains or patterns"},
		"no DNS capture":     {1, control.Change{Op: "add", Domains: []string{"x.example"}}, false, "this run doesn't capture DNS"},
	} {
		var mm = m
		if !tc.m {
			mm = nil
		}
		if _, err := mp.planDNSChange(tc.i, tc.req, mm); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", name, err, tc.want)
		}
	}
	// Names asked of servers the run doesn't capture would never reach the
	// tunnel: every profile pins 192.0.2.53 here, so the system's aren't
	// captured.
	mp.specs[2].s.dnsServers = nil // auto
	if _, err := mp.planDNSChange(2, control.Change{Op: "add", Domains: []string{"v2.example"}}, m); err == nil || !strings.Contains(err.Error(), "dns.servers: auto") {
		t.Errorf("auto servers, not captured: %v", err)
	}
	mp.specs[2].s.dnsServers = []string{"192.0.2.99"}
	if _, err := mp.planDNSChange(2, control.Change{Op: "add", Domains: []string{"v2.example"}}, m); err == nil || !strings.Contains(err.Error(), "192.0.2.99 isn't captured") {
		t.Errorf("another server: %v", err)
	}
	if _, err := mp.planDNSChange(2, control.Change{Op: "del", Domains: []string{"vault.example"}}, m); err != nil {
		t.Errorf("removing names needs no captured server: %v", err)
	}
	mp.specs[2].s.dnsServers = []string{"192.0.2.53"}

	// Moving "." from work to dev: off work first, then onto dev.
	dc, err = mp.planDNSChange(0, control.Change{Op: "del", Domains: []string{"."}}, m)
	if err != nil {
		t.Fatal(err)
	}
	if err := mp.applyDNSChange(dc, m); err != nil || m.CatchAll() {
		t.Fatalf("del .: %v, catch-all %v", err, m.CatchAll())
	}
	if dc, err = mp.planDNSChange(1, control.Change{Op: "add", Domains: []string{"."}}, m); err != nil {
		t.Fatal(err)
	}
	if err := mp.applyDNSChange(dc, m); err != nil || !m.CatchAll() || !slices.Contains(m.Local(), "lan") {
		t.Fatalf("add . to dev: %v, catch-all %v, local %v", err, m.CatchAll(), m.Local())
	}
	if tg, _ := m.Pick("github.com"); tg != 1 {
		t.Errorf("github.com: %d", tg)
	}
}

// writeConfig writes a config file for a reload test.
func writeConfig(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

const reloadBase = `defaults:
  dns:
    servers: [192.0.2.53]
profiles:
  a:
    target: {docker: {host: "tcp://203.0.113.10:2376", container: a}}
    routes: [10.0.0.0/8]
    dns: {domains: [a.example]}
  b:
    target: {docker: {host: "tcp://203.0.113.20:2376", container: b}}
    routes: [10.50.0.0/16]
    killSwitch: {mode: "on"}
`

// A profile read again from the config file takes its new routes, names
// and target; settings fixed at start, or a clash, are refused.
func TestPlanReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	writeConfig(t, path, reloadBase)
	f, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	var base settings
	cmd := &cobra.Command{}
	base.register(cmd)
	var specs []*tunnelSpec
	for _, n := range []string{"a", "b"} {
		sp, err := profileSpec(f, path, n, base, nil, cmd.Flags(), &globalOpts{})
		if err != nil {
			t.Fatal(err)
		}
		specs = append(specs, sp)
	}
	mp, err := planMulti(specs)
	if err != nil {
		t.Fatal(err)
	}
	mp.lookupEndpoints(context.Background())
	// A change made while running, dropped by the reload.
	rc, err := mp.planRouteChange(1, routeReq("add", "b", "10.51.0.0/16"))
	if err != nil {
		t.Fatal(err)
	}
	mp.applyRouteChange(rc)

	reload := func(i int) (*reloadChange, error) {
		ns, err := mp.specs[i].reload()
		if err != nil {
			return nil, err
		}
		host, err := ns.endpoint()
		if err != nil {
			return nil, err
		}
		addrs, _ := lookupEndpoint(context.Background(), host)
		return mp.planReload(i, ns, host, addrs, mp.dns.Match)
	}
	// The file as it was: only the change made while running goes. Writing
	// out a default is no change either.
	writeConfig(t, path, strings.Replace(reloadBase, `    killSwitch: {mode: "on"}`, "    killSwitch: {mode: \"on\", dns: block}\n    blockIPv6: auto\n    dns: {capture: firewall}", 1))
	rl0, err := reload(1)
	if err != nil {
		t.Fatal(err)
	}
	if rl0.summary != "new routes; the changes made while running are dropped" {
		t.Errorf("unchanged file: %q", rl0.summary)
	}
	writeConfig(t, path, reloadBase)
	if rl0, err = reload(0); err != nil || rl0.summary != "the config file changes nothing" {
		t.Errorf("profile a, unchanged: %+v %v", rl0, err)
	}

	writeConfig(t, path, strings.Replace(strings.Replace(reloadBase,
		"routes: [10.50.0.0/16]", "routes: [10.50.0.0/16, 10.52.0.0/16]\n    dns: {domains: [b.example]}", 1),
		"203.0.113.20", "203.0.113.21", 1))
	rl, err := reload(1)
	if err != nil {
		t.Fatal(err)
	}
	if rl.summary != "new target, routes, DNS names; the changes made while running are dropped" ||
		!covers(rl.final, "10.52.0.1") || covers(rl.final, "10.51.0.1") || rl.host != "tcp://203.0.113.21:2376" {
		t.Fatalf("reload: %q %v %s", rl.summary, rl.final, rl.host)
	}
	if err := mp.applyReload(rl, mp.dns.Match); err != nil {
		t.Fatal(err)
	}
	if _, err := mp.addEndpoints(rl.addrs); err != nil {
		t.Fatal(err)
	}
	if tg, _ := mp.dns.Match.Pick("x.b.example"); tg != 1 || len(runtimeChanges(mp.specs[1].base, mp.specs[1].s)) != 0 || mp.hosts[1] != "tcp://203.0.113.21:2376" {
		t.Errorf("applied: pick %d, changes %v, host %s", tg, runtimeChanges(mp.specs[1].base, mp.specs[1].s), mp.hosts[1])
	}
	if slices.Contains(mp.dns.Match.Own(), "203.0.113.21") {
		t.Error("an IP literal among the own names")
	}

	for name, tc := range map[string]struct {
		edit func(string) string
		want string
	}{
		"kill switch": {func(s string) string { return strings.Replace(s, `mode: "on"`, "mode: lockdown", 1) }, "killSwitch.mode changed in the config file, which needs a subtun restart"},
		"utun address": {func(s string) string {
			return strings.Replace(s, "defaults:\n", "defaults:\n  tun: {address: 198.18.250.1}\n", 1)
		}, "tun.address changed"},
		"same CIDR as a": {func(s string) string { return strings.Replace(s, "routes: [10.50.0.0/16]", "routes: [10.0.0.0/8]", 1) }, "10.0.0.0/8 is routed by both profiles a and b"},
		"a's domain": {func(s string) string {
			return strings.Replace(s, "routes: [10.50.0.0/16]", "routes: [10.50.0.0/16]\n    dns: {domains: [a.example]}", 1)
		}, `"a.example" is listed for two tunnels`},
		"no routes left": {func(s string) string {
			return strings.Replace(s, "routes: [10.50.0.0/16]", "socks: 127.0.0.1:1090", 1)
		}, "has no routes in the config file now"},
		"gone": {func(s string) string { return strings.Replace(s, "  b:\n", "  c:\n", 1) }, `no profile "b"`},
	} {
		writeConfig(t, path, tc.edit(reloadBase))
		if _, err := reload(1); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", name, err, tc.want)
		}
	}
}

// A stopped profile is as after Ctrl-C: only lockdown keeps its routes,
// and its names (in use) stay.
func TestStoppedProfile(t *testing.T) {
	mp := multiPlanFor(t, "work", "dev", "vault") // kill switch on, off, lockdown
	active := mp.activeSet([]tunnelState{stateStopped, stateStopped, stateStopped})
	if !slices.Equal(active, []bool{false, false, true}) {
		t.Errorf("active: %v", active)
	}
	two := multiPlanFor(t, "work", "dev") // kill switch on, off
	if nothingToCapture(mp, []tunnelState{stateStopped, stateStopped, stateStopped}) || nothingToCapture(mp, []tunnelState{stateStopped, stateUp, stateStopped}) ||
		!nothingToCapture(two, []tunnelState{stateStopped, stateStopped}) || !nothingToCapture(two, []tunnelState{stateStopped, stateGaveUp}) ||
		nothingToCapture(two, []tunnelState{stateGaveUp, stateStopped}) || nothingToCapture(two, []tunnelState{stateStopped, stateConnecting}) {
		t.Error("nothingToCapture: wrong while a profile runs, connects or holds its routes")
	}
	if !mp.dnsFlushNeeded(1, stateUp, stateStopped, true) || !mp.dnsFlushNeeded(0, stateUp, stateStopped, true) {
		t.Error("a stopped profile's names go elsewhere: the cache must be flushed")
	}
	if !strings.Contains(mp.stopEffect(0), "kill switch (on) lifts its blocks") ||
		!strings.Contains(mp.stopEffect(1), "routes and DNS names are removed; its SOCKS proxy refuses") ||
		!strings.Contains(mp.stopEffect(2), "lockdown: its routes stay") {
		t.Errorf("effects: %q / %q / %q", mp.stopEffect(0), mp.stopEffect(1), mp.stopEffect(2))
	}
	l := &liveTunnel{}
	l.gone.Store(true)
	l.stopped.Store(true)
	if _, err := l.DialContext(context.Background(), "tcp", "10.0.0.1:1"); !errors.Is(err, errStopped) {
		t.Errorf("dial while stopped: %v", err)
	}
}

// profile reconnect connects again at once, then by the policy; no
// "connecting" event (the loop already says reconnecting).
func TestRunTunnelReconnectNow(t *testing.T) {
	tries := 0
	try := func(context.Context) (*session, error) { tries++; return nil, errors.New("refused") }
	var got []tunnelEvent
	send := func(ev tunnelEvent) bool { got = append(got, ev); return true }
	p := reconnectPolicy{attempts: 1, delay: time.Millisecond, maxDelay: time.Millisecond}
	l := &liveTunnel{}
	l.gone.Store(true) // gave up before: a new runner starts clean
	runTunnel(context.Background(), 0, l, p, startReconnect, try, send, discardLogger(), nil)
	if tries != 2 || len(got) != 1 || got[0].state != stateGaveUp || !strings.Contains(got[0].err.Error(), "reconnecting failed; gave up after 1") {
		t.Fatalf("tries %d, events %+v", tries, got)
	}
}

func TestProfileIndex(t *testing.T) {
	mp := multiPlanFor(t, "work", "dev")
	if i, err := mp.profileIndex("dev"); i != 1 || err != nil {
		t.Errorf("dev: %d %v", i, err)
	}
	if _, err := mp.profileIndex(""); err == nil || !strings.Contains(err.Error(), "this run has 2 profiles (work, dev): say which one") {
		t.Errorf("unnamed: %v", err)
	}
	if _, err := mp.profileIndex("nope"); err == nil || !strings.Contains(err.Error(), `no profile "nope" in this run (it has: work, dev)`) {
		t.Errorf("unknown: %v", err)
	}
	one := &multiPlan{specs: []*tunnelSpec{{}}}
	if i, err := one.profileIndex(""); i != 0 || err != nil {
		t.Errorf("one unnamed: %d %v", i, err)
	}
	if _, err := one.profileIndex("x"); err == nil || !strings.Contains(err.Error(), "leave the name out") {
		t.Errorf("one, named: %v", err)
	}
}

// Changes reach the engine's loop: routes and names change, profiles stop,
// start and reconnect. The tunnels never connect, and the capture (sudo)
// never starts.
func TestEngineChanges(t *testing.T) {
	origCtl, origCap, origLeft := startControl, startCapture, leftoversMarked
	t.Cleanup(func() { startControl, startCapture, leftoversMarked = origCtl, origCap, origLeft })
	ready := make(chan *engineStatus, 1)
	startControl = func(_ context.Context, es *engineStatus, _ *logring.Ring, _ *slog.Logger) { ready <- es }
	leftoversMarked = func() bool { return false }
	startCapture = func(context.Context, *multiPlan, []bool, []*liveTunnel, []meter.Dialer, *router, *privhelper.Client, *leftovers, bool, func(string), *slog.Logger) (*capture.Capture, error) {
		t.Error("the capture started")
		return nil, errors.New("no capture in tests")
	}
	mp := multiPlanFor(t, "work", "dev")
	connects := make(chan string, 16)
	for _, sp := range mp.specs {
		sp.s.socks = "" // no listening sockets in tests
		name := sp.name
		sp.connect = func(ctx context.Context, _ []agentbin.Binary, _ *slog.Logger) (*transport.Carrier, error) {
			connects <- name
			<-ctx.Done()
			return nil, ctx.Err()
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runEngine(ctx, &globalOpts{}, mp, engineOpts{control: controlFull}) }()
	es := <-ready
	for range 2 {
		<-connects
	}
	change := func(ch control.Change) (control.Result, error) {
		t.Helper()
		cctx, ccancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer ccancel()
		return es.change(cctx, ch)
	}
	state := func(i int) string { return es.status().Tunnels[i].State }

	if _, err := change(routeReq("add", "", "10.70.0.0/16")); err == nil || !strings.Contains(err.Error(), "say which one") {
		t.Errorf("no profile named: %v", err)
	}
	res, err := change(routeReq("add", "dev", "10.70.0.0/16"))
	if err != nil || !res.Changed || res.Profile != "dev" || !slices.Contains(res.Warnings, "the capture hasn't started yet (connecting, or sudo is asking): it starts with this") {
		t.Fatalf("route add: %+v %v", res, err)
	}
	if got := es.status().Tunnels[1]; got.ChangedAt["+route 10.70.0.0/16"].IsZero() {
		t.Errorf("no time for the change: %v", got.ChangedAt)
	}
	if got := es.status().Tunnels[1]; !slices.Contains(got.Routes, "10.70.0.0/16") || !slices.Equal(got.Changes, []string{"+route 10.70.0.0/16"}) {
		t.Errorf("status after route add: %v %v", got.Routes, got.Changes)
	}
	res, err = change(control.Change{Kind: control.KindDNS, Op: "add", Profile: "dev", Domains: []string{"corp2.example"}, DryRun: true})
	if err != nil || !res.DryRun || !strings.HasPrefix(res.Message, "would add DNS corp2.example") {
		t.Errorf("dns dry run: %+v %v", res, err)
	}
	if tg, _ := mp.dns.Match.Pick("x.corp2.example"); tg == 1 {
		t.Error("a dry run changed the names")
	}
	if _, err := change(control.Change{Kind: control.KindDNS, Op: "add", Profile: "dev", Domains: []string{"corp2.example"}}); err != nil {
		t.Fatal(err)
	}
	if tg, _ := mp.dns.Match.Pick("x.corp2.example"); tg != 1 {
		t.Errorf("x.corp2.example: %d", tg)
	}

	res, err = change(control.Change{Kind: control.KindProfile, Op: "stop", Profile: "dev"})
	if err != nil || !strings.HasPrefix(res.Message, "stopped: its routes and DNS names are removed") || state(1) != "stopped" {
		t.Fatalf("stop: %+v %v, state %s", res, err, state(1))
	}
	if res, _ := change(control.Change{Kind: control.KindProfile, Op: "stop", Profile: "dev"}); res.Changed || res.Message != "already stopped" {
		t.Errorf("stop again: %+v", res)
	}
	if _, err := change(control.Change{Kind: control.KindProfile, Op: "reconnect", Profile: "dev"}); err == nil || !strings.Contains(err.Error(), "profile dev is stopped; start it with: subtun profile start dev") {
		t.Errorf("reconnect while stopped: %v", err)
	}
	if _, err := change(control.Change{Kind: control.KindProfile, Op: "start", Profile: "work"}); err == nil || !strings.Contains(err.Error(), "profile work is connecting; to connect it again now: subtun profile reconnect work") {
		t.Errorf("start while running: %v", err)
	}
	if res, err := change(control.Change{Kind: control.KindProfile, Op: "start", Profile: "dev"}); err != nil || res.Message != "starting: connecting to its target" || state(1) != "connecting" {
		t.Fatalf("start: %+v %v, state %s", res, err, state(1))
	}
	if name := <-connects; name != "dev" {
		t.Errorf("started %s", name)
	}
	if res, err := change(control.Change{Kind: control.KindProfile, Op: "reconnect", Profile: "work"}); err != nil || res.Message != "reconnecting now" {
		t.Fatalf("reconnect: %+v %v", res, err)
	}
	if name := <-connects; name != "work" {
		t.Errorf("reconnected %s", name)
	}
	if _, err := change(control.Change{Kind: control.KindProfile, Op: "start", Profile: "dev", Reload: true}); err == nil || !strings.Contains(err.Error(), "is connecting") {
		t.Errorf("reload while running: %v", err)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("runEngine: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("runEngine didn't stop")
	}
	if _, err := es.change(context.Background(), routeReq("add", "dev", "10.80.0.0/16")); err == nil || err.Error() != "subtun is stopping" {
		t.Errorf("after the run: %v", err)
	}
}

// A stop that ends the first round starts the capture at once, unless
// every profile is stopped (nothing to capture). The capture is a stub.
func TestEngineStopEndsFirstRound(t *testing.T) {
	origCtl, origCap, origLeft := startControl, startCapture, leftoversMarked
	t.Cleanup(func() { startControl, startCapture, leftoversMarked = origCtl, origCap, origLeft })
	leftoversMarked = func() bool { return false }
	for _, stopBoth := range []bool{false, true} {
		ready := make(chan *engineStatus, 1)
		startControl = func(_ context.Context, es *engineStatus, _ *logring.Ring, _ *slog.Logger) { ready <- es }
		started := make(chan struct{}, 1)
		startCapture = func(context.Context, *multiPlan, []bool, []*liveTunnel, []meter.Dialer, *router, *privhelper.Client, *leftovers, bool, func(string), *slog.Logger) (*capture.Capture, error) {
			started <- struct{}{}
			return nil, errors.New("capture stub")
		}
		mp := multiPlanFor(t, "work", "dev")
		blocked := make(chan struct{}, 8)
		for i, sp := range mp.specs {
			sp.s.socks = ""
			tries := 0
			sp.connect = func(ctx context.Context, _ []agentbin.Binary, _ *slog.Logger) (*transport.Carrier, error) {
				tries++
				blocked <- struct{}{}
				if i == 0 && !stopBoth && tries == 1 {
					// work's first attempt fails: it is tried, and retries by its policy.
					return nil, errors.New("refused (test)")
				}
				<-ctx.Done()
				return nil, ctx.Err()
			}
		}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- runEngine(ctx, &globalOpts{}, mp, engineOpts{control: controlFull}) }()
		es := <-ready
		<-blocked
		<-blocked
		stop := func(name string) {
			if _, err := es.change(context.Background(), control.Change{Kind: control.KindProfile, Op: "stop", Profile: name}); err != nil {
				t.Fatal(err)
			}
		}
		if stopBoth {
			stop("work")
			stop("dev")
			select {
			case <-started:
				t.Error("every profile stopped, and the capture started")
			case <-time.After(300 * time.Millisecond):
			}
			cancel()
			if err := <-done; err != nil {
				t.Errorf("runEngine: %v", err)
			}
			continue
		}
		for i := 0; es.status().Tunnels[0].LastError == "" && i < 300; i++ {
			time.Sleep(10 * time.Millisecond) // until work's failure reached the loop
		}
		stop("dev")
		select {
		case <-started:
		case <-time.After(3 * time.Second):
			t.Fatal("the capture didn't start once the first round was over")
		}
		if err := <-done; err == nil || err.Error() != "capture stub" {
			t.Errorf("runEngine: %v", err)
		}
		cancel()
	}
}

// A profile from the config file joins the run only if it fits what the
// run shares and what its capture set up at start.
func TestPlanAdd(t *testing.T) {
	spec := func(name string) *tunnelSpec {
		t.Helper()
		ns, err := configSpecs("testdata/multi.yaml", &globalOpts{})(name)
		if err != nil {
			t.Fatal(err)
		}
		return ns
	}
	mp := multiPlanFor(t, "dev") // no kill switch, DNS cluster.local
	m := mp.dns.Match
	ac, err := mp.planAdd(spec("vault"), "tcp://198.51.100.201:2376", nil, m, captureState{})
	if err != nil {
		t.Fatal(err)
	}
	if ac.ks != "lockdown" || !covers(ac.final, "10.60.0.1") || len(ac.names) != 2 || ac.allowDNS || ac.summary != "routes 10.60.0.0/16; kill switch lockdown" {
		t.Errorf("vault: %+v", ac)
	}
	// A kill switch can't join a running capture that has no guard.
	if _, err := mp.planAdd(spec("vault"), "", nil, m, captureState{started: true}); err == nil || !strings.Contains(err.Error(), "this run's capture has none") {
		t.Errorf("kill switch, no guard: %v", err)
	}
	// A full tunnel blocks IPv6 if the capture hasn't started; else a warning.
	if ac, err := mp.planAdd(spec("full"), "", nil, m, captureState{}); err != nil || !ac.blockIPv6 {
		t.Errorf("full, before the capture: %+v %v", ac, err)
	}
	if ac, err := mp.planAdd(spec("full"), "", nil, m, captureState{started: true, guarding: true}); err != nil || ac.blockIPv6 ||
		!slices.ContainsFunc(ac.warns, func(w string) bool { return strings.Contains(w, "IPv6 isn't blocked") }) {
		t.Errorf("full, capturing: %+v %v", ac, err)
	}
	if _, err := mp.planAdd(spec("work"), "", []netip.Addr{netip.MustParseAddr("2001:db8::1")}, m, captureState{started: true, guarding: true, blockingIPv6: true}); err == nil ||
		!strings.Contains(err.Error(), "IPv6 address") {
		t.Errorf("IPv6 endpoint while blocked: %v", err)
	}
	for name, want := range map[string]string{
		"dup":       "10.50.0.0/16 is routed by both profiles dev and dup",
		"other-tun": "tun.address 198.18.250.1 differs from the run's (198.18.249.1)",
	} {
		if _, err := mp.planAdd(spec(name), "", nil, m, captureState{}); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v, want %q", name, err, want)
		}
	}
	mp = multiPlanFor(t, "work", "dev")
	if _, err := mp.planAdd(spec("all-names"), "", nil, mp.dns.Match, captureState{}); err == nil || !strings.Contains(err.Error(), "only one tunnel can resolve all names") {
		t.Errorf("a second catch-all: %v", err)
	}
	if _, err := mp.planAdd(spec("socks-dev"), "", nil, mp.dns.Match, captureState{}); err == nil || !strings.Contains(err.Error(), "both want the SOCKS address 127.0.0.1:1081") {
		t.Errorf("SOCKS address: %v", err)
	}
}

// Profiles added while running: they show up, take their part of DNS, and
// count for the run's end. Nothing connects, no capture starts.
func TestEngineAddProfile(t *testing.T) {
	origCtl, origCap, origLeft, origSpecs := startControl, startCapture, leftoversMarked, newSpecs
	t.Cleanup(func() { startControl, startCapture, leftoversMarked, newSpecs = origCtl, origCap, origLeft, origSpecs })
	ready := make(chan *engineStatus, 1)
	startControl = func(_ context.Context, es *engineStatus, _ *logring.Ring, _ *slog.Logger) { ready <- es }
	leftoversMarked = func() bool { return false }
	startCapture = func(context.Context, *multiPlan, []bool, []*liveTunnel, []meter.Dialer, *router, *privhelper.Client, *leftovers, bool, func(string), *slog.Logger) (*capture.Capture, error) {
		t.Error("the capture started")
		return nil, errors.New("no capture in tests")
	}
	connects := make(chan string, 16)
	block := func(name string) connectFunc {
		return func(ctx context.Context, _ []agentbin.Binary, _ *slog.Logger) (*transport.Carrier, error) {
			connects <- name
			<-ctx.Done()
			return nil, ctx.Err()
		}
	}
	newSpecs = func(path string, g *globalOpts) func(string) (*tunnelSpec, error) {
		build := configSpecs(path, g)
		return func(name string) (*tunnelSpec, error) {
			sp, err := build(name)
			if err == nil {
				sp.connect = block(name) // never the network
			}
			return sp, err
		}
	}
	mp := multiPlanFor(t, "work", "dev")
	for _, sp := range mp.specs {
		sp.s.socks = ""
		sp.connect = block(sp.name)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- runEngine(ctx, &globalOpts{config: "testdata/multi.yaml"}, mp, engineOpts{control: controlFull})
	}()
	es := <-ready
	<-connects
	<-connects
	start := func(name string, dry bool) (control.Result, error) {
		return es.change(context.Background(), control.Change{Kind: control.KindProfile, Op: "start", Profile: name, DryRun: dry})
	}

	if res, err := start("vault", true); err != nil || !strings.HasPrefix(res.Message, "would add it to the run and start it: routes 10.60.0.0/16; kill switch lockdown") {
		t.Fatalf("dry run: %+v %v", res, err)
	}
	if len(es.status().Tunnels) != 2 {
		t.Fatal("a dry run added the profile")
	}
	res, err := start("vault", false)
	if err != nil || res.Profile != "vault" || !strings.HasPrefix(res.Message, "added to the run and starting: routes 10.60.0.0/16") {
		t.Fatalf("add: %+v %v", res, err)
	}
	if name := <-connects; name != "vault" {
		t.Errorf("connecting %s", name)
	}
	st := es.status()
	if len(st.Tunnels) != 3 || st.Tunnels[2].Name != "vault" || st.Tunnels[2].State != "connecting" || st.Tunnels[2].KillSwitch != "lockdown" ||
		!slices.Contains(st.Tunnels[2].Routes, "10.60.0.0/16") || st.KillSwitch == nil {
		t.Errorf("status after the add: %+v", st.Tunnels)
	}
	if len(mp.dns.Tunnels) != 3 || mp.dns.Tunnels[2].Name != "vault" {
		t.Errorf("DNS tunnels: %d", len(mp.dns.Tunnels))
	}
	// The added profile takes changes like the others.
	if _, err := es.change(context.Background(), control.Change{Kind: control.KindDNS, Op: "add", Profile: "vault", Domains: []string{"vault.example"}}); err != nil {
		t.Fatal(err)
	}
	if res, err := start("vault", false); err == nil || !strings.Contains(err.Error(), "profile vault is connecting") {
		t.Errorf("start again: %+v %v", res, err)
	}
	for name, want := range map[string]string{
		"dup":       "10.50.0.0/16 is routed by both profiles dev and dup",
		"all-names": "only one tunnel can resolve all names",
		"nope":      `no profile "nope"`,
	} {
		if _, err := start(name, false); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v, want %q", name, err, want)
		}
	}
	if n := len(es.status().Tunnels); n != 3 {
		t.Errorf("refused adds changed the run: %d profiles", n)
	}
	cancel()
	if err := <-done; err != nil {
		t.Errorf("runEngine: %v", err)
	}

	// A run of one profile becomes a run of several: the original profile,
	// still on its first try, is retried as with several (a new runner).
	mp = multiPlanFor(t, "dev")
	mp.specs[0].s.socks = ""
	mp.specs[0].connect = block("dev")
	ctx, cancel = context.WithCancel(context.Background())
	go func() {
		done <- runEngine(ctx, &globalOpts{config: "testdata/multi.yaml"}, mp, engineOpts{single: true, control: controlFull})
	}()
	es = <-ready
	if name := <-connects; name != "dev" {
		t.Fatalf("connecting %s", name)
	}
	if _, err := start("vault", false); err != nil {
		t.Fatal(err)
	}
	got := map[string]int{}
	for range 2 {
		select {
		case name := <-connects:
			got[name]++
		case <-time.After(3 * time.Second):
			t.Fatalf("connects after the add: %v", got)
		}
	}
	if got["dev"] != 1 || got["vault"] != 1 {
		t.Errorf("connects after the add: %v (dev's first try retried by a new runner, vault started)", got)
	}
	cancel()
	if err := <-done; err != nil {
		t.Errorf("runEngine, one profile and an added one: %v", err)
	}
}

// A profile takes the run's shared settings, whether they came from the
// run's flags or another profile; only one its config sets otherwise is
// a clash.
func TestInheritShared(t *testing.T) {
	run := settings{tunAddr: "198.18.249.1", mtu: 9000, dnsFallback: "192.0.2.9"}
	ns := &tunnelSpec{s: settings{tunAddr: "198.18.249.1", mtu: 9000}}
	if d := inheritShared(ns, run); len(d) != 0 || ns.s.dnsFallback != "192.0.2.9" {
		t.Errorf("unset in its config: %v %+v", d, ns.s)
	}
	ns = &tunnelSpec{s: settings{tunAddr: "198.18.250.1", mtu: 9000, dnsFallback: "system"}}
	ns.cfg.Tun.Address, ns.cfg.DNS.Fallback = "198.18.250.1", "system"
	d := inheritShared(ns, run)
	if len(d) != 2 || d[0].key != "tun.address" || d[1].key != "dns.fallback" || ns.s.tunAddr != run.tunAddr {
		t.Errorf("set otherwise: %+v %+v", d, ns.s)
	}
}

// Commands without a profile name pick the only profile, never an unnamed
// one among several; adds need a named run.
func TestUnnamedTunnel(t *testing.T) {
	mp := &multiPlan{specs: []*tunnelSpec{{}, {name: "dev"}}}
	if _, err := mp.profileIndex(""); err == nil || !strings.Contains(err.Error(), "(the tunnel, dev): say which one") {
		t.Errorf("unnamed among several: %v", err)
	}
	one := multiPlanFor(t, "dev")
	one.specs[0].name = ""
	ns, err := configSpecs("testdata/multi.yaml", &globalOpts{})("vault")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := one.planAdd(ns, "", nil, one.dns.Match, captureState{}); err == nil || !strings.Contains(err.Error(), "has no profile name") {
		t.Errorf("add to an unnamed run: %v", err)
	}
	m := one.dns.Match
	m.SetOn(7, true) // a target it doesn't have: ignored, no panic
	if tg, ok := m.Pick("x.cluster.local"); !ok || tg != 0 {
		t.Errorf("pick: %d %v", tg, ok)
	}
}
