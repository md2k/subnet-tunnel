package cli

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/md2k/subnet-tunnel/internal/config"
	"github.com/md2k/subnet-tunnel/internal/routes"
)

func multiPlanFor(t *testing.T, names ...string) *multiPlan {
	t.Helper()
	f, err := config.Load("testdata/multi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var s settings
	cmd := &cobra.Command{}
	s.register(cmd) // the flag defaults
	var specs []*tunnelSpec
	for _, n := range names {
		p, err := f.Profile(n)
		if err != nil {
			t.Fatal(err)
		}
		sp := &tunnelSpec{name: n, s: s, cfg: p}
		sp.s.applyProfile(p, cmd.Flags())
		sp.connect, sp.endpoint = profileTarget(p, &sp.s, &globalOpts{})
		specs = append(specs, sp)
	}
	mp, err := planMulti(specs)
	if err != nil {
		t.Fatal(err)
	}
	if w := mp.lookupEndpoints(context.Background()); len(w) > 0 {
		t.Fatalf("endpoints: %v", w)
	}
	return mp
}

func TestUpSeveralDryRun(t *testing.T) {
	out, err := runCLI(t, "--config", "testdata/multi.yaml", "up", "work", "--profile", "dev,vault", "--dry-run")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"profile work:\n",
		"    10.0.0.0/8  (parts carried by dev, vault: more specific routes)\n",
		"    203.0.113.128/26\n", // work's /24 minus its own endpoint 203.0.113.200
		"profile dev:\n",
		"    10.50.0.0/16\n",
		"  SOCKS5 proxy on 127.0.0.1:1081\n",
		"  DNS through this tunnel: cluster.local (unrouted answers: warn)\n",
		"  routes added when its tunnel is up, removed if it gives up\n",
		"  kill switch: on",
		"  kill switch: lockdown",
		"DNS capture (firewall): queries to 192.0.2.53 are answered by subtun\n",
		"  names under local, lan, 77.168.192.in-addr.arpa",
		"IPv6",
		"utun 198.18.249.1, MTU 9000; the root helper stays up",
	} {
		if want == "IPv6" {
			if strings.Contains(out, want) {
				t.Errorf("IPv6 blocked without a full tunnel:\n%s", out)
			}
			continue
		}
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
	if strings.Contains(out, "203.0.113.200/32\n") || strings.Contains(out, "    203.0.113.0/24\n") {
		t.Errorf("work's endpoint is routed:\n%s", out)
	}
}

func TestUpSeveralRefuses(t *testing.T) {
	for name, tc := range map[string]struct {
		args []string
		want string
	}{
		"same CIDR":       {[]string{"--profile", "dev,dup"}, "10.50.0.0/16 is routed by both profiles dev and dup"},
		"two catch-alls":  {[]string{"--profile", "work,all-names"}, `only one tunnel can resolve all names`},
		"utun address":    {[]string{"--profile", "work,other-tun,other-tun2"}, "tun.address differs between profiles other-tun (198.18.250.1) and other-tun2 (198.18.251.1)"},
		"same SOCKS":      {[]string{"--profile", "dev,socks-dev"}, "both want the SOCKS address 127.0.0.1:1081"},
		"CIDRs":           {[]string{"work", "10.1.0.0/16", "--profile", "dev"}, "CIDRs come from the config file"},
		"setting flags":   {[]string{"--profile", "work,dev", "--socks", "127.0.0.1:9", "-x", "10.1.0.0/16"}, "--exclude, --socks only works with one profile"},
		"unknown profile": {[]string{"--profile", "work,nope"}, `no profile "nope"`},
	} {
		t.Run(name, func(t *testing.T) {
			args := append([]string{"--config", "testdata/multi.yaml", "up", "--dry-run"}, tc.args...)
			if _, err := runCLI(t, args...); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("%v, want %q", err, tc.want)
			}
		})
	}
}

// One profile through --profile is the single-profile path.
func TestUpOneProfileFlag(t *testing.T) {
	out, err := runCLI(t, "--config", "testdata/multi.yaml", "up", "--profile", "dev", "--dry-run")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "routes on the utun (1, from 1 given, 0 excluded):\n  10.50.0.0/16\n") {
		t.Errorf("got\n%s", out)
	}
}

func covers(ps []netip.Prefix, a string) bool {
	return slices.ContainsFunc(ps, func(p netip.Prefix) bool { return p.Contains(netip.MustParseAddr(a)) })
}

// Routes, router and guard follow the profiles in use.
func TestLayoutFollowsProfiles(t *testing.T) {
	mp := multiPlanFor(t, "work", "dev", "vault")
	lives := []*liveTunnel{{}, {}, {}}
	work, dev, vault := lives[0], lives[1], lives[2]
	rt := &router{}
	check := func(states []tunnelState, devRouted bool) {
		t.Helper()
		all, entries, guard, err := mp.layout(mp.activeSet(states), lives)
		if err != nil {
			t.Fatal(err)
		}
		rt.set(entries)
		// work and vault have a kill switch: in from the start.
		if !covers(all, "10.1.1.1") || !covers(all, "10.60.0.1") || covers(all, "203.0.113.200") {
			t.Errorf("%v: routes %v", states, all)
		}
		if got := rt.pick(netip.MustParseAddr("10.60.0.1")); got != vault {
			t.Errorf("%v: 10.60.0.1 goes to the wrong tunnel", states)
		}
		want := work
		if devRouted {
			want = dev
		}
		if got := rt.pick(netip.MustParseAddr("10.50.0.1")); got != want {
			t.Errorf("%v: 10.50.0.1 goes to the wrong tunnel", states)
		}
		// dev has no kill switch: its share leaves the guard while it's in use.
		if covers(guard.Base, "10.50.0.1") == devRouted || !covers(guard.Base, "10.1.1.1") {
			t.Errorf("%v: guard %v", states, guard.Base)
		}
		// Only vault is in lockdown.
		if !covers(guard.Lockdown, "10.60.0.1") || covers(guard.Lockdown, "10.1.1.1") {
			t.Errorf("%v: lockdown %v", states, guard.Lockdown)
		}
	}
	check([]tunnelState{stateConnecting, stateConnecting, stateConnecting}, false)
	check([]tunnelState{stateUp, stateUp, stateConnecting}, true)
	check([]tunnelState{stateUp, stateReconnecting, stateUp}, true)
	check([]tunnelState{stateUp, stateGaveUp, stateUp}, false)
	if mp.dns.Match.CatchAll() != true {
		t.Error(`work's "." is lost`)
	}
}

// A new endpoint address after connecting is taken out of every route.
func TestAddEndpoints(t *testing.T) {
	mp := multiPlanFor(t, "work", "dev")
	changed, err := mp.addEndpoints([]netip.Addr{netip.MustParseAddr("10.50.7.7"), netip.MustParseAddr("2001:db8::1")})
	if err != nil || !changed {
		t.Fatalf("addEndpoints: %v %v", changed, err)
	}
	if covers(mp.final(1), "10.50.7.7") || !covers(mp.final(1), "10.50.7.8") {
		t.Errorf("dev: %v", mp.final(1))
	}
	if changed, _ := mp.addEndpoints([]netip.Addr{netip.MustParseAddr("10.50.7.7")}); changed {
		t.Error("the same endpoint changed the routes again")
	}
}

// A profile that can't connect retries by its policy, then gives up.
func TestRunTunnelGivesUp(t *testing.T) {
	tries := 0
	try := func(context.Context) (*session, error) { tries++; return nil, errors.New("refused") }
	var got []tunnelEvent
	send := func(ev tunnelEvent) bool { got = append(got, ev); return true }
	p := reconnectPolicy{attempts: 2, delay: time.Millisecond, maxDelay: time.Millisecond}
	runTunnel(context.Background(), 3, &liveTunnel{}, p, true, try, send, discardLogger())
	// The first failure is reported (the first round is over), then the give-up.
	if tries != 3 || len(got) != 2 || got[0].state != stateConnecting || got[0].err == nil ||
		got[1].i != 3 || got[1].state != stateGaveUp || got[1].err == nil {
		t.Fatalf("tries %d, events %+v", tries, got)
	}
}

func discardLogger() *slog.Logger { return slog.New(slog.DiscardHandler) }

// Who carries an address follows the configured routes: of the profiles
// whose own routes cover it, the most specific configured route wins, not
// the pieces left after excludes.
func TestOwnershipFollowsConfiguredRoutes(t *testing.T) {
	carrier := func(mp *multiPlan, a string) string {
		active := mp.activeSet([]tunnelState{stateUp, stateUp})
		if i := mp.owner(netip.MustParseAddr(a), active); i >= 0 {
			return mp.specs[i].name
		}
		return "none"
	}
	// The LAN (192.168.77.0/24, stubbed) is taken out of both: the pieces
	// left are identical in both profiles, which is fine.
	mp := multiPlanFor(t, "full", "calico")
	for a, want := range map[string]string{"192.168.5.5": "calico", "192.168.77.5": "none", "8.8.8.8": "full"} {
		if got := carrier(mp, a); got != want {
			t.Errorf("full+calico, %s: %s, want %s", a, got, want)
		}
	}
	active := mp.activeSet([]tunnelState{stateUp, stateUp})
	_, entries, guard, err := mp.layout(active, []*liveTunnel{{}, {}})
	if err != nil {
		t.Fatal(err)
	}
	rt := &router{}
	rt.set(entries)
	if rt.pickIndex(netip.MustParseAddr("192.168.200.1")) != 1 || rt.pickIndex(netip.MustParseAddr("1.1.1.1")) != 0 {
		t.Error("router disagrees with owner")
	}
	if covers(guard.Base, "192.168.5.5") || !covers(guard.Base, "8.8.8.8") || covers(guard.Base, "192.168.77.5") {
		t.Errorf("guard: %v", guard.Base)
	}

	// One profile's exclude doesn't hand another profile's addresses to it.
	mp = multiPlanFor(t, "work-x", "dev")
	for a, want := range map[string]string{"10.50.3.5": "dev", "10.50.1.5": "dev", "10.1.1.1": "work-x"} {
		if got := carrier(mp, a); got != want {
			t.Errorf("work-x+dev, %s: %s, want %s", a, got, want)
		}
	}

	// An endpoint carved out of both after connecting changes nothing else.
	mp = multiPlanFor(t, "work", "dev")
	if _, err := mp.addEndpoints([]netip.Addr{netip.MustParseAddr("10.50.7.7")}); err != nil {
		t.Fatal(err)
	}
	for a, want := range map[string]string{"10.50.3.3": "dev", "10.50.7.7": "none", "10.1.1.1": "work"} {
		if got := carrier(mp, a); got != want {
			t.Errorf("work+dev after the endpoint, %s: %s, want %s", a, got, want)
		}
	}
}

// A target's API server named by hostname: its name never goes through a
// tunnel, and its address stays out of the routes.
func TestNamedEndpoint(t *testing.T) {
	mp := multiPlanFor(t, "named", "dev")
	if !slices.Equal(mp.dns.Match.Own(), []string{"api.named.example.test"}) {
		t.Errorf("own names: %v", mp.dns.Match.Own())
	}
	if _, ok := mp.dns.Match.Pick("api.named.example.test"); ok {
		t.Error("the API server's name goes through a tunnel")
	}
	if covers(mp.final(0), "172.24.9.9") || !covers(mp.final(0), "172.24.9.10") {
		t.Errorf("named's routes: %v", mp.final(0))
	}
}

// A failed endpoint lookup is reported.
func TestEndpointLookupFailureWarns(t *testing.T) {
	mp := multiPlanFor(t, "work", "dev")
	mp.hosts[1] = "https://nowhere.example.test:6443"
	w := mp.lookupEndpoints(context.Background())
	if len(w) != 1 || !strings.Contains(w[0], "dev: looking up nowhere.example.test failed") {
		t.Fatalf("warnings: %v", w)
	}
}

// subtun's own utun address isn't a local network for DNS: once the utun
// exists, its reverse zone would join the names "." leaves local.
func TestDNSLocalsSkipTheUtun(t *testing.T) {
	orig := localNetworks
	t.Cleanup(func() { localNetworks = orig })
	localNetworks = func() []routes.Local {
		return []routes.Local{
			{Iface: "en0", Network: netip.MustParsePrefix("192.168.77.0/24")},
			{Iface: "utun9", Network: netip.MustParsePrefix("198.18.249.1/32")},
		}
	}
	got := dnsLocals(netip.MustParseAddr("198.18.249.1"))()
	if !slices.Equal(got, []netip.Prefix{netip.MustParsePrefix("192.168.77.0/24")}) {
		t.Fatalf("locals: %v", got)
	}
	if got := dnsLocals(netip.Addr{})(); len(got) != 2 {
		t.Fatalf("without a utun address: %v", got)
	}
}
