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
	mp, err := planMulti(context.Background(), specs)
	if err != nil {
		t.Fatal(err)
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
		"    10.0.0.0/8\n",
		"    203.0.113.128/26\n", // work's /24 minus its own endpoint 203.0.113.200
		"profile dev:\n",
		"    10.50.0.0/16  (taken from work's 10.0.0.0/8)\n",
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
		all, entries, guard, err := mp.layout(states, lives)
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
	runTunnel(context.Background(), 3, &liveTunnel{}, p, try, send, discardLogger())
	if tries != 3 || len(got) != 1 || got[0].i != 3 || got[0].state != stateGaveUp || got[0].err == nil {
		t.Fatalf("tries %d, events %+v", tries, got)
	}
}

func discardLogger() *slog.Logger { return slog.New(slog.DiscardHandler) }
