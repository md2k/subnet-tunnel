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
	calls []string
	stdin []string
	lo0   string
	rules string
	ours  string // our anchor's current NAT rules
	fail  string // fail calls starting with this
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
		return altq + f.ours, nil
	case "-s Anchors":
		return altq + "  com.apple\n  com.example.vpn\n", nil
	case "-E":
		return altq + "pf enabled\nToken : 10168373383532413219\n", nil
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
		"-s rules", "-s nat", "-a com.apple/subtun -s nat", "-s Interfaces -i lo0 -v", "-s Anchors",
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
		"already has rules":   {ours: "rdr pass on lo0 inet proto udp from any to <subtun_dns> port = 53 -> 127.0.0.1 port 61000\n"},
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
