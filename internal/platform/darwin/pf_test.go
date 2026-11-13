//go:build darwin

package darwin

import (
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/md2k/subnet-tunnel/internal/platform"
)

const altq = "No ALTQ support in kernel\nALTQ related functions disabled\n"

// fakePfctl answers like pfctl on a stock macOS and records each call.
type fakePfctl struct {
	calls      []string
	stdin      []string
	lo0        string
	rules      string
	ours       string // our anchor's current NAT rules ("" = anchor never loaded)
	disabled   bool   // pf status
	oursFilter string // and filter rules
	fail       string // fail calls starting with this
}

func (f *fakePfctl) run(stdin string, args ...string) (string, error) {
	call := strings.Join(args, " ")
	f.calls = append(f.calls, call)
	if stdin != "" {
		f.stdin = append(f.stdin, stdin)
	}
	if f.fail != "" && strings.HasPrefix(call, f.fail) {
		return altq, errors.New("pfctl: " + call + ": failed")
	}
	switch call {
	case "-s rules":
		if f.rules != "" {
			return altq + f.rules, nil
		}
		return altq + "scrub-anchor \"com.apple/*\" all fragment reassemble\nanchor \"com.apple/*\" all\n", nil
	case "-s nat":
		return altq + "nat-anchor \"com.apple/*\" all\nrdr-anchor \"com.apple/*\" all\n", nil
	case "-s Interfaces -i lo0 -v":
		if f.lo0 != "" {
			return altq + f.lo0, nil
		}
		return altq + "lo0\n", nil
	case "-a com.apple/subtun -s nat":
		if f.ours == "" {
			return altq + "pfctl: DIOCGETRULES: Invalid argument\n", errors.New("exit status 1")
		}
		return altq + f.ours, nil
	case "-a com.apple/subtun -s rules":
		return altq + f.oursFilter, nil
	case "-s Anchors":
		return altq + "  com.apple\n  com.example.vpn\n", nil
	case "-E":
		return altq + "pf enabled\nToken : 10168373383532413219\n", nil
	case "-s info":
		if f.disabled {
			return altq + "Status: Disabled for 0 days 00:00:05           Debug: Urgent\n", nil
		}
		return altq + "Status: Enabled for 0 days 00:10:00            Debug: Urgent\n", nil
	}
	return altq, nil
}

func dnsRules() platform.Rules {
	return platform.Rules{DNS: &platform.DNSRedirect{
		Servers:    []netip.Addr{netip.MustParseAddr("192.168.1.1"), netip.MustParseAddr("192.168.1.2")},
		ListenPort: 53530,
		BypassPort: 53531,
	}}
}

func TestPFApplyAndFlush(t *testing.T) {
	f := &fakePfctl{}
	p := &PF{Run: f.run}
	if err := p.Apply(dnsRules()); err != nil {
		t.Fatal(err)
	}
	// Servers changed (network switch): rules replaced, pf not enabled again.
	r := dnsRules()
	r.DNS.Servers = []netip.Addr{netip.MustParseAddr("10.0.0.1")}
	if err := p.Apply(r); err != nil {
		t.Fatal(err)
	}
	if err := p.Flush(); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"-s rules", "-s nat", "-s Interfaces -i lo0 -v", "-s Anchors",
		"-a com.apple/subtun -f /dev/stdin", "-E",
		"-a com.apple/subtun -f /dev/stdin",
		"-a com.apple/subtun -F rules", "-a com.apple/subtun -F nat", "-a com.apple/subtun -F Tables",
		"-X 10168373383532413219",
	}
	if !slices.Equal(f.calls, want) {
		t.Fatalf("pfctl calls:\n got %q\nwant %q", f.calls, want)
	}
	wantRules := `table <subtun_dns> const { 192.168.1.1 192.168.1.2 }
rdr pass on lo0 inet proto { udp tcp } from any to <subtun_dns> port 53 -> 127.0.0.1 port 53530
pass out quick inet proto { udp tcp } from any port 53531 to <subtun_dns> port 53 keep state
pass out quick route-to lo0 inet proto { udp tcp } from any to <subtun_dns> port 53 keep state
`
	if f.stdin[0] != wantRules {
		t.Fatalf("rules:\n%s\nwant:\n%s", f.stdin[0], wantRules)
	}
	if !strings.Contains(f.stdin[1], "{ 10.0.0.1 }") {
		t.Fatalf("second ruleset: %s", f.stdin[1])
	}
	// Flushing again (nothing applied) must not release a token twice.
	f.calls = nil
	_ = p.Flush()
	if slices.ContainsFunc(f.calls, func(c string) bool { return strings.HasPrefix(c, "-X") }) {
		t.Fatal("token released twice")
	}
}

func TestPFRefusesUnusableSetups(t *testing.T) {
	cases := map[string]*fakePfctl{
		"com.apple/* anchors": {rules: "anchor \"custom\" all\n"},
		"skip lo0":            {lo0: "lo0 (skip)\n"},
	}
	for want, f := range cases {
		err := (&PF{Run: f.run}).Apply(dnsRules())
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("got %v, want error about %q", err, want)
		}
		if slices.Contains(f.calls, "-E") {
			t.Errorf("%s: pf enabled anyway", want)
		}
	}
	// A failed load enables nothing.
	f := &fakePfctl{fail: "-a com.apple/subtun -f"}
	if err := (&PF{Run: f.run}).Apply(dnsRules()); err == nil || slices.Contains(f.calls, "-E") {
		t.Fatalf("load failure: %v, calls %q", err, f.calls)
	}
}

func TestPFRulesValidation(t *testing.T) {
	bad := []platform.DNSRedirect{
		{ListenPort: 1, BypassPort: 2},
		{Servers: []netip.Addr{netip.MustParseAddr("127.0.0.1")}, ListenPort: 1, BypassPort: 2},
		{Servers: []netip.Addr{netip.MustParseAddr("fd00::1")}, ListenPort: 1, BypassPort: 2},
		{Servers: []netip.Addr{netip.MustParseAddr("192.168.1.1")}, ListenPort: 5, BypassPort: 5},
		{Servers: []netip.Addr{netip.MustParseAddr("192.168.1.1")}, ListenPort: 0, BypassPort: 5},
	}
	for _, d := range bad {
		if text, err := pfRules(platform.Rules{DNS: &d}); err == nil {
			t.Errorf("%+v accepted:\n%s", d, text)
		}
	}
	if text, err := pfRules(platform.Rules{}); err != nil || text != "" {
		t.Errorf("empty rules: %q, %v", text, err)
	}
}

func TestPFBusyAndAdopt(t *testing.T) {
	// Never loaded: pfctl fails for the anchor, which is "not busy".
	if busy, err := (&PF{Run: (&fakePfctl{}).run}).Busy(); busy || err != nil {
		t.Fatalf("fresh anchor: busy=%v err=%v", busy, err)
	}
	f := &fakePfctl{ours: " ", oursFilter: "block return out quick inet from any to <subtun_guard>\n"}
	p := &PF{Run: f.run}
	if busy, _ := p.Busy(); !busy {
		t.Fatal("anchor with a block rule: not busy")
	}
	// Taking over an earlier session's reference: no second pfctl -E, and
	// Flush releases the adopted token.
	p.Adopt("42")
	if err := p.Apply(dnsRules()); err != nil {
		t.Fatal(err)
	}
	if slices.Contains(f.calls, "-E") || p.Token() != "42" {
		t.Fatalf("calls %q, token %q", f.calls, p.Token())
	}
	_ = p.Flush()
	if f.calls[len(f.calls)-1] != "-X 42" || p.Token() != "" {
		t.Fatalf("last call %q", f.calls[len(f.calls)-1])
	}

	// pf was disabled since: the adopted reference is stale, enable again.
	f = &fakePfctl{disabled: true}
	p = &PF{Run: f.run}
	p.Adopt("42")
	if err := p.Apply(dnsRules()); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(f.calls, "-E") || p.Token() != "10168373383532413219" {
		t.Fatalf("stale reference: calls %q, token %q", f.calls, p.Token())
	}
}

func TestPFKillSwitchAndIPv6Rules(t *testing.T) {
	guard := []netip.Prefix{netip.MustParsePrefix("0.0.0.0/1"), netip.MustParsePrefix("128.0.0.0/2")}
	running := dnsRules()
	running.KillSwitch = &platform.KillSwitch{TunIface: "utun10", Prefixes: guard}
	running.BlockIPv6 = true
	got, err := pfRules(running)
	if err != nil {
		t.Fatal(err)
	}
	want := `table <subtun_dns> const { 192.168.1.1 192.168.1.2 }
table <subtun_guard> const { 0.0.0.0/1 128.0.0.0/2 }
rdr pass on lo0 inet proto { udp tcp } from any to <subtun_dns> port 53 -> 127.0.0.1 port 53530
pass out quick inet proto { udp tcp } from any port 53531 to <subtun_dns> port 53 keep state
pass out quick route-to lo0 inet proto { udp tcp } from any to <subtun_dns> port 53 keep state
pass out quick on utun10 inet from any to <subtun_guard>
block return out quick inet from any to <subtun_guard>
pass out quick on lo0 inet6 all
pass out quick inet6 from any to { fe80::/10, ff00::/8 }
block return out quick inet6 all
`
	if got != want {
		t.Fatalf("running rules:\n%s\nwant:\n%s", got, want)
	}

	// What stays behind when the tunnel is gone: everything blocked.
	left := platform.Rules{
		DNSBlock:   []netip.Addr{netip.MustParseAddr("192.168.1.1")},
		KillSwitch: &platform.KillSwitch{Prefixes: guard},
		BlockIPv6:  true,
	}
	got, err = pfRules(left)
	if err != nil {
		t.Fatal(err)
	}
	want = `table <subtun_dns> const { 192.168.1.1 }
table <subtun_guard> const { 0.0.0.0/1 128.0.0.0/2 }
block return out quick inet proto { udp tcp } from any to <subtun_dns> port 53
block return out quick inet from any to <subtun_guard>
pass out quick on lo0 inet6 all
pass out quick inet6 from any to { fe80::/10, ff00::/8 }
block return out quick inet6 all
`
	if got != want {
		t.Fatalf("left-behind rules:\n%s\nwant:\n%s", got, want)
	}

	bad := []platform.Rules{
		{DNS: dnsRules().DNS, DNSBlock: []netip.Addr{netip.MustParseAddr("192.168.1.1")}},
		{KillSwitch: &platform.KillSwitch{}},
		{KillSwitch: &platform.KillSwitch{Prefixes: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}}},
		{KillSwitch: &platform.KillSwitch{Prefixes: []netip.Prefix{netip.MustParsePrefix("fd00::/8")}}},
		{KillSwitch: &platform.KillSwitch{TunIface: "en0", Prefixes: guard}},
		{DNSBlock: []netip.Addr{netip.MustParseAddr("127.0.0.1")}},
	}
	for _, r := range bad {
		if text, err := pfRules(r); err == nil {
			t.Errorf("%+v accepted:\n%s", r, text)
		}
	}
}

// A table the new rules no longer mention is removed (pf would keep it):
// the guard once the kill switch's profiles stopped, the DNS table once the
// redirect went.
func TestPFRemovesUnusedTables(t *testing.T) {
	f := &fakePfctl{}
	p := &PF{Run: f.run}
	withGuard := dnsRules()
	withGuard.KillSwitch = &platform.KillSwitch{TunIface: "utun10", Prefixes: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}}
	kills := func() []string {
		var out []string
		for _, c := range f.calls {
			if strings.HasSuffix(c, "-T kill") {
				out = append(out, c)
			}
		}
		f.calls = nil
		return out
	}
	for i, tc := range []struct {
		r    platform.Rules
		want []string
	}{
		{withGuard, nil},
		{withGuard, nil},
		{dnsRules(), []string{"-a com.apple/subtun -t subtun_guard -T kill"}},
		{dnsRules(), nil},
		{platform.Rules{BlockIPv6: true}, []string{"-a com.apple/subtun -t subtun_dns -T kill"}},
	} {
		if err := p.Apply(tc.r); err != nil {
			t.Fatal(err)
		}
		if got := kills(); !slices.Equal(got, tc.want) {
			t.Errorf("apply %d: %q, want %q", i, got, tc.want)
		}
	}
}
