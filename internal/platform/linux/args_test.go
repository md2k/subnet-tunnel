package linux

import (
	"net/netip"
	"slices"
	"strings"
	"testing"
)

func TestRouteArgs(t *testing.T) {
	got, err := routeArgs("add", netip.MustParsePrefix("10.96.0.0/12"), "subtun0")
	want := []string{"-4", "route", "add", "10.96.0.0/12", "dev", "subtun0", "table", "32761"}
	if err != nil || !slices.Equal(got, want) {
		t.Errorf("got %q %v, want %q", got, err, want)
	}
	for _, c := range []struct {
		p, iface, err string
	}{
		{"0.0.0.0/0", "subtun0", "default route"},
		{"10.96.1.0/12", "subtun0", "host bits"},
		{"fd00::/8", "subtun0", "IPv4"},
		{"10.0.0.0/8", "eth0", "not a subtun interface"},
		{"10.0.0.0/8", "subtun0 table main", "not a subtun interface"},
	} {
		p := netip.MustParsePrefix(c.p) // keeps host bits
		if _, err := routeArgs("add", p, c.iface); err == nil || !strings.Contains(err.Error(), c.err) {
			t.Errorf("%s %s: %v, want an error with %q", c.p, c.iface, err, c.err)
		}
	}
}

// Two rules for this machine's own traffic (iif lo), right before main:
// main's specific routes, then subtun's table.
func TestRuleArgs(t *testing.T) {
	want := [][]string{
		{"-4", "rule", "add", "pref", "32760", "iif", "lo", "lookup", "main", "suppress_prefixlength", "0"},
		{"-4", "rule", "add", "pref", "32761", "iif", "lo", "lookup", "32761"},
	}
	got := ruleArgs("add")
	if len(got) != len(want) {
		t.Fatalf("got %q", got)
	}
	for i := range want {
		if !slices.Equal(got[i], want[i]) {
			t.Errorf("rule %d: got %q, want %q", i, got[i], want[i])
		}
	}
}

func TestCountJSON(t *testing.T) {
	for out, want := range map[string]int{
		"":     0,
		"[]":   0,
		"[]\n": 0,
		`[{"priority":32760,"src":"all","iif":"lo","table":"main","suppress_prefixlen":0}]`: 1,
		`[{"dst":"10.0.0.0/8","dev":"subtun0"},{"dst":"10.96.0.0/12","dev":"subtun0"}]`:     2,
	} {
		if got, err := countJSON([]byte(out)); err != nil || got != want {
			t.Errorf("%q: got %d %v, want %d", out, got, err, want)
		}
	}
	if _, err := countJSON([]byte("Error: something")); err == nil {
		t.Error("not JSON: no error")
	}
}
