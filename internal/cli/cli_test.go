package cli

import (
	"bytes"
	"net/netip"
	"strings"
	"testing"

	"github.com/md2k/subnet-tunnel/internal/privhelper"
)

// runCLI executes subtun with args and returns stdout and the error. Only
// dry runs and config listing here: nothing connects or asks for sudo.
func runCLI(t *testing.T, args ...string) (string, error) {
	t.Helper()
	root := newRoot()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs(args)
	err := root.Execute()
	return out.String(), err
}

func TestUpListsProfiles(t *testing.T) {
	out, err := runCLI(t, "--config", "testdata/config.yaml", "up")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "dev\n  dns\n  socks-only") {
		t.Fatalf("got %q", out)
	}
}

func TestUpDryRun(t *testing.T) {
	out, err := runCLI(t, "--config", "testdata/config.yaml", "up", "dev", "--dry-run")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"routes on the utun (2, from 3 given, 1 excluded):\n  198.51.100.0/24\n  203.0.113.0/25\n",
		"route 203.0.113.7/32: already covered by 203.0.113.0/24",
		"utun 198.18.249.1, MTU 9000",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
}

func TestUpFlagsOverrideAndAdd(t *testing.T) {
	out, err := runCLI(t, "--config", "testdata/config.yaml", "up", "dev", "192.0.2.0/24",
		"-x", "198.51.100.0/25", "--tun-addr", "198.18.250.1", "--mtu", "4000", "--dry-run")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"  192.0.2.0/24\n",            // added on the command line
		"  198.51.100.128/25\n",       // profile route minus command-line exclude
		"  203.0.113.0/25\n",          // profile exclude still applies
		"utun 198.18.250.1, MTU 4000", // flags override the profile
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
}

func TestUpErrors(t *testing.T) {
	if _, err := runCLI(t, "--config", "testdata/config.yaml", "up", "nope"); err == nil || !strings.Contains(err.Error(), "dev, dns, socks-only") {
		t.Errorf("unknown profile: %v", err)
	}
	if _, err := runCLI(t, "--config", "testdata/missing.yaml", "up"); err == nil {
		t.Error("missing config accepted")
	}
}

func TestK8sDryRunWithoutConfig(t *testing.T) {
	out, err := runCLI(t, "k8s", "debug", "203.0.113.0/24", "-x", "203.0.113.5", "--dry-run")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "routes on the utun (8, from 1 given, 1 excluded)") {
		t.Fatalf("got\n%s", out)
	}
}

func TestRouteSafetyChecks(t *testing.T) {
	cases := map[string][]string{
		"bad tun address":     {"k8s", "debug", "203.0.113.0/24", "--tun-addr", "127.0.0.1", "--dry-run"},
		"bad MTU":             {"k8s", "debug", "203.0.113.0/24", "--mtu", "100", "--dry-run"},
		"host bits":           {"k8s", "debug", "203.0.113.1/24", "--dry-run"},
		"excludes remove all": {"k8s", "debug", "203.0.113.0/24", "-x", "203.0.113.0/24", "--dry-run"},
		"nothing to do":       {"k8s", "debug", "--dry-run"},
	}
	for name, args := range cases {
		if _, err := runCLI(t, args...); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestExcludeEndpoints(t *testing.T) {
	rp, _, err := planRoutes(settings{routes: []string{"203.0.113.0/24"}, tunAddr: "198.18.249.1", mtu: 9000})
	if err != nil {
		t.Fatal(err)
	}
	log := newLogger(false)

	// API server outside the routes: nothing changes.
	got, err := excludeEndpoints(rp, []netip.Addr{netip.MustParseAddr("192.0.2.10")}, log)
	if err != nil || len(got) != 1 || got[0].String() != "203.0.113.0/24" {
		t.Fatalf("outside: %v %v", got, err)
	}
	// API server inside: carved out, everything else still routed.
	api := netip.MustParseAddr("203.0.113.10")
	got, err = excludeEndpoints(rp, []netip.Addr{api}, log)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 8 {
		t.Fatalf("want the /24 minus one address = 8 routes, got %v", got)
	}
	for _, p := range got {
		if p.Contains(api) {
			t.Fatalf("API server %s still routed via %s", api, p)
		}
	}
}

// A full tunnel: two /1 halves (never merged into 0.0.0.0/0), with subtun's
// own address carved out automatically instead of refused.
func TestFullTunnelDryRun(t *testing.T) {
	out, err := runCLI(t, "k8s", "debug", "0.0.0.0/1", "128.0.0.0/1", "--dry-run")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"198.18.249.1/32: subtun's own utun address, excluded automatically",
		"224.0.0.0/3: multicast, reserved and broadcast, stays out of the tunnel (excluded automatically)",
		"127.0.0.0/8: loopback, stays out",
		"192.168.77.0/24: local network on en0, stays out",
		"  1.0.0.0/8\n", "  126.0.0.0/8\n", "  128.0.0.0/3\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
	// Every route must be one the root helper accepts, and none may reach
	// into the LAN.
	lan := netip.MustParsePrefix("192.168.77.0/24")
	for _, r := range routeLines(out) {
		if _, err := privhelper.ParseCIDR(r.String()); err != nil {
			t.Errorf("route the helper refuses: %v", err)
		}
		if r.Overlaps(lan) {
			t.Errorf("route %s reaches into the LAN", r)
		}
	}
}

// Excluding an address inside the LAN (the API server, say) used to split
// the routes into pieces more specific than the LAN's own route.
func TestLANStaysLocal(t *testing.T) {
	out, err := runCLI(t, "k8s", "debug", "0.0.0.0/1", "128.0.0.0/1", "-x", "192.168.77.50", "--dry-run")
	if err != nil {
		t.Fatal(err)
	}
	lan := netip.MustParsePrefix("192.168.77.0/24")
	for _, r := range routeLines(out) {
		if r.Overlaps(lan) {
			t.Errorf("route %s reaches into the LAN:\n%s", r, out)
		}
	}
	// A route more specific than the LAN is an explicit choice: it stays,
	// with the warning.
	out, err = runCLI(t, "k8s", "debug", "192.168.77.128/25", "--dry-run")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "  192.168.77.128/25\n") || !strings.Contains(out, "takes over part of 192.168.77.0/24") {
		t.Fatalf("explicit LAN route:\n%s", out)
	}
}

// routeLines parses the routes a dry run lists.
func routeLines(out string) []netip.Prefix {
	var ps []netip.Prefix
	in := false
	for _, l := range strings.Split(out, "\n") {
		switch {
		case strings.HasPrefix(l, "routes on the utun"):
			in = true
		case in && strings.HasPrefix(l, "  "):
			if p, err := netip.ParsePrefix(strings.TrimSpace(l)); err == nil {
				ps = append(ps, p)
			}
		default:
			in = false
		}
	}
	return ps
}

// fakeSystemDNS stands in for /etc/resolv.conf.
func fakeSystemDNS(t *testing.T) {
	t.Helper()
	old := systemDNS
	systemDNS = func() ([]netip.Addr, []string, error) {
		return []netip.Addr{netip.MustParseAddr("192.0.2.53")}, []string{"IPv6 DNS server 2001:db8::53 is not captured (IPv4 only so far)"}, nil
	}
	t.Cleanup(func() { systemDNS = old })
}

func TestDNSDryRunFollowsSystem(t *testing.T) {
	fakeSystemDNS(t)
	out, err := runCLI(t, "k8s", "debug", "203.0.113.0/24", "--dns-domain", "svc.cluster.local,company.com", "--dns-pattern", `^db-[0-9]+\.`, "--dry-run")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"DNS capture (firewall): queries to 192.0.2.53 are answered by subtun",
		"through the tunnel: svc.cluster.local, company.com, 1 pattern(s)",
		"other names: the captured servers",
		"servers follow the system's",
		"warning: IPv6 DNS server 2001:db8::53 is not captured",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
}

func TestDNSProfileAndFlags(t *testing.T) {
	out, err := runCLI(t, "--config", "testdata/config.yaml", "up", "dns", "--dns-domain", "company.com", "--dns-fallback", "198.51.100.53:5353", "--dry-run")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"queries to 203.0.113.53 are answered", // pinned in the profile
		"through the tunnel: svc.cluster.local, company.com\n",
		"other names: 198.51.100.53:5353", // flag overrides the profile's fallback
		"warning: fallback DNS server 198.51.100.53 is inside the routed 198.51.100.0/24",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
	if strings.Contains(out, "follow the system") {
		t.Error("pinned servers must not follow the system's")
	}
	off, err := runCLI(t, "--config", "testdata/config.yaml", "up", "dns", "--dns-capture", "off", "--dry-run")
	if err != nil || strings.Contains(off, "DNS capture") {
		t.Errorf("--dns-capture off: %v\n%s", err, off)
	}
}

func TestDNSErrors(t *testing.T) {
	fakeSystemDNS(t)
	cases := map[string][]string{
		"together with utun capture": {"k8s", "debug", "--socks", "127.0.0.1:1080", "--dns-domain", "company.com"},
		"use firewall or off":        {"k8s", "debug", "203.0.113.0/24", "--dns-domain", "company.com", "--dns-capture", "magic"},
		"unicast IPv4":               {"k8s", "debug", "203.0.113.0/24", "--dns-domain", "company.com", "--dns-servers", "127.0.0.1"},
		"want system, IP or IP:port": {"k8s", "debug", "203.0.113.0/24", "--dns-domain", "company.com", "--dns-fallback", "dns.google"},
		"regular expression":         {"k8s", "debug", "203.0.113.0/24", "--dns-domain", `.*\.company\.com`},
	}
	for want, args := range cases {
		if _, err := runCLI(t, append(args, "--dry-run")...); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%v: got %v, want %q", args, err, want)
		}
	}
}

func TestGuardDryRun(t *testing.T) {
	fakeSystemDNS(t)
	cases := []struct {
		args    []string
		want    []string
		notWant []string
	}{
		{ // full tunnel: IPv6 blocked automatically
			args: []string{"k8s", "debug", "0.0.0.0/1", "128.0.0.0/1"},
			want: []string{"IPv6: outgoing IPv6 blocked (full tunnel)"}, notWant: []string{"kill switch"},
		},
		{ // split routes: no IPv6 block unless asked
			args: []string{"k8s", "debug", "203.0.113.0/24"}, notWant: []string{"IPv6", "kill switch"},
		},
		{
			args: []string{"k8s", "debug", "203.0.113.0/24", "--block-ipv6", "true"},
			want: []string{"IPv6: outgoing IPv6 blocked (asked for)"},
		},
		{
			args: []string{"k8s", "debug", "0.0.0.0/1", "128.0.0.0/1", "--block-ipv6", "false"}, notWant: []string{"IPv6"},
		},
		{
			args: []string{"k8s", "debug", "203.0.113.0/24", "--kill-switch", "on", "--dns-domain", "cluster.local"},
			want: []string{"kill switch: on: traffic for 1 guarded prefixes", "Ctrl-C removes them", "DNS to the captured servers is blocked too"},
		},
		{
			args: []string{"k8s", "debug", "203.0.113.0/24", "--kill-switch", "lockdown", "--kill-switch-dns", "allow", "--dns-domain", "cluster.local"},
			want: []string{"kill switch: lockdown:", "after subtun stops for any reason", "DNS stays allowed"},
		},
	}
	for _, c := range cases {
		out, err := runCLI(t, append(c.args, "--dry-run")...)
		if err != nil {
			t.Errorf("%v: %v", c.args, err)
			continue
		}
		for _, w := range c.want {
			if !strings.Contains(out, w) {
				t.Errorf("%v: missing %q in\n%s", c.args, w, out)
			}
		}
		for _, w := range c.notWant {
			if strings.Contains(out, w) {
				t.Errorf("%v: unexpected %q in\n%s", c.args, w, out)
			}
		}
	}
}

func TestGuardProfileAndErrors(t *testing.T) {
	out, err := runCLI(t, "--config", "testdata/config.yaml", "up", "dns", "--dry-run")
	if err != nil || !strings.Contains(out, "kill switch: lockdown") {
		t.Errorf("profile kill switch: %v\n%s", err, out)
	}
	out, err = runCLI(t, "--config", "testdata/config.yaml", "up", "dns", "--kill-switch", "off", "--dry-run")
	if err != nil || strings.Contains(out, "kill switch") {
		t.Errorf("--kill-switch off overrides the profile: %v\n%s", err, out)
	}
	cases := map[string][]string{
		"give routes as well":        {"k8s", "debug", "--socks", "127.0.0.1:1080", "--kill-switch", "on"},
		"use off, on or lockdown":    {"k8s", "debug", "203.0.113.0/24", "--kill-switch", "always"},
		"use block or allow":         {"k8s", "debug", "203.0.113.0/24", "--kill-switch-dns", "maybe"},
		"use auto, true or false":    {"k8s", "debug", "203.0.113.0/24", "--block-ipv6", "sometimes"},
		"together with utun capture": {"k8s", "debug", "--socks", "127.0.0.1:1080", "--block-ipv6", "true"},
	}
	for want, args := range cases {
		if _, err := runCLI(t, append(args, "--dry-run")...); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%v: got %v, want %q", args, err, want)
		}
	}
}

// The kill switch guards the routes minus local networks more specific
// than them; routes more specific than a local network stay guarded.
func TestGuardPrefixes(t *testing.T) {
	pp := func(ss ...string) []netip.Prefix {
		var out []netip.Prefix
		for _, s := range ss {
			out = append(out, netip.MustParsePrefix(s))
		}
		return out
	}
	full, err := guardPrefixes(pp("0.0.0.0/1", "128.0.0.0/1"), pp("192.168.1.0/24", "100.64.0.0/16"))
	if err != nil {
		t.Fatal(err)
	}
	covered := func(set []netip.Prefix, a string) bool {
		for _, p := range set {
			if p.Contains(netip.MustParseAddr(a)) {
				return true
			}
		}
		return false
	}
	if !covered(full, "8.8.8.8") || covered(full, "192.168.1.20") || covered(full, "100.64.3.4") {
		t.Errorf("full tunnel guard: %v", full)
	}
	cgnat, err := guardPrefixes(pp("100.64.5.0/24"), pp("100.64.0.0/16"))
	if err != nil || len(cgnat) != 1 || cgnat[0].String() != "100.64.5.0/24" {
		t.Errorf("route inside a VPN's network: %v, %v", cgnat, err)
	}
}

func TestIPv6Endpoint(t *testing.T) {
	v4 := []netip.Addr{netip.MustParseAddr("203.0.113.10"), netip.MustParseAddr("::1"), netip.MustParseAddr("fe80::1")}
	if _, ok := ipv6Endpoint(v4); ok {
		t.Error("IPv4, loopback and link-local endpoints don't need IPv6")
	}
	if a, ok := ipv6Endpoint(append(v4, netip.MustParseAddr("2001:db8::10"))); !ok || a.String() != "2001:db8::10" {
		t.Error("global IPv6 endpoint not found")
	}
}

// The leftovers marker is shared between runs: only a run that loaded
// firewall rules, or took over the ones it was set for, removes it.
func TestLeftoversMarker(t *testing.T) {
	type tc struct {
		name       string
		adopt      *privhelper.AdoptResult // nil: no marker at start
		firewall   bool
		startFails bool
		leftBehind bool
		want       bool // marker present at the end
	}
	cases := []tc{
		{name: "routes only, no marker", want: false},
		{name: "routes only beside a running firewall session", adopt: &privhelper.AdoptResult{Running: true}, want: true},
		{name: "firewall session ends cleanly", firewall: true, want: false},
		{name: "kill switch leaves blocks", firewall: true, leftBehind: true, want: true},
		{name: "firewall start fails", firewall: true, startFails: true, want: false},
		{name: "took over, start fails: blocks put back", adopt: &privhelper.AdoptResult{Kept: true}, firewall: true, startFails: true, want: true},
		{name: "took over, session without firewall removes them", adopt: &privhelper.AdoptResult{Kept: true}, want: false},
		{name: "nothing was left", adopt: &privhelper.AdoptResult{}, want: false},
		{name: "refused beside a running session", adopt: &privhelper.AdoptResult{Running: true}, firewall: true, startFails: true, want: true},
	}
	for _, c := range cases {
		present := c.adopt != nil
		l := &leftovers{mark: func() error { present = true; return nil }, clear: func() { present = false }}
		if c.adopt != nil {
			l.adopted(*c.adopt)
		}
		if c.firewall {
			l.firewall()
		}
		if c.startFails {
			l.startFailed()
		} else {
			l.stopped(c.leftBehind)
		}
		if present != c.want {
			t.Errorf("%s: marker present = %v, want %v", c.name, present, c.want)
		}
	}
}

func TestImportSSHuttle(t *testing.T) {
	out, err := runCLI(t, "import", "sshuttle", "../importer/testdata/sshuttle.conf", "--name", "work", "--k8s", "debug", "-n", "tools", "--context", "dev")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"  work:\n    target: {k8s: {context: 'dev', namespace: 'tools', pod: 'debug'}}",
		"    routes:\n      - 203.0.113.0/24",
		"      domains:\n        - 'example.com'",
		"imported 4 routes, 1 excludes, 2 DNS domains, 1 patterns",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
	if _, err := runCLI(t, "import", "sshuttle", "../importer/testdata/sshuttle.conf", "--name", "Work Profile"); err == nil {
		t.Error("bad profile name accepted")
	}
	if _, err := runCLI(t, "import", "sshuttle", "../importer/testdata/sshuttle.conf", "--k8s", "p", "--docker", "c"); err == nil {
		t.Error("two targets accepted")
	}
}

func TestDNSCatchAllLeavesLocal(t *testing.T) {
	fakeSystemDNS(t)
	out, err := runCLI(t, "k8s", "debug", "203.0.113.0/24", "--dns-domain", ".", "--dry-run")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "except names under local, lan (local network") {
		t.Fatalf("no local exception in\n%s", out)
	}
	out, err = runCLI(t, "k8s", "debug", "203.0.113.0/24", "--dns-domain", "cluster.local", "--dry-run")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "except names under") {
		t.Fatalf("local exception without a catch-all:\n%s", out)
	}
}

func TestDNSUnroutedSetting(t *testing.T) {
	fakeSystemDNS(t)
	base := []string{"k8s", "debug", "203.0.113.0/24", "--dns-domain", "company.com", "--dry-run"}
	for flag, want := range map[string]string{"": "warn", "fallback": "fallback", "block": "block"} {
		args := base
		if flag != "" {
			args = append(append([]string{}, base...), "--dns-unrouted", flag)
		}
		out, err := runCLI(t, args...)
		if err != nil {
			t.Fatalf("%q: %v", flag, err)
		}
		if !strings.Contains(out, "private addresses no route covers: "+want+"\n") {
			t.Errorf("%q: missing mode %s in\n%s", flag, want, out)
		}
	}
	if _, err := runCLI(t, append(append([]string{}, base...), "--dns-unrouted", "tunnel")...); err == nil {
		t.Error("unbuilt mode accepted")
	}
}

func TestUnreachable(t *testing.T) {
	f := unreachable([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")})
	for s, want := range map[string]bool{"10.1.2.3": false, "100.64.1.1": true, "192.168.77.5": true, "140.82.112.3": false} {
		if got := f(netip.MustParseAddr(s)); got != want {
			t.Errorf("unreachable(%s) = %v", s, got)
		}
	}
}
