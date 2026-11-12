//go:build darwin

package darwin

import (
	"net/netip"
	"strings"
	"testing"
)

func TestRouteArgs(t *testing.T) {
	cases := map[string]string{
		"10.244.0.0/16": "-n add -net 10.244.0.0/16 -interface utun7",
		"10.96.0.10/32": "-n add -host 10.96.0.10 -interface utun7",
	}
	for cidr, want := range cases {
		args, err := routeArgs("add", netip.MustParsePrefix(cidr), "utun7")
		if err != nil {
			t.Fatal(err)
		}
		if got := strings.Join(args, " "); got != want {
			t.Errorf("%s: got %q, want %q", cidr, got, want)
		}
	}
}

func TestRouteArgsRefusesBadInput(t *testing.T) {
	bad := []struct {
		prefix netip.Prefix
		iface  string
	}{
		{netip.Prefix{}, "utun7"},
		{netip.MustParsePrefix("0.0.0.0/0"), "utun7"},
		{netip.MustParsePrefix("10.244.1.0/16"), "utun7"}, // host bits
		{netip.MustParsePrefix("fd00::/8"), "utun7"},
		{netip.MustParsePrefix("10.244.0.0/16"), "en0"},
		{netip.MustParsePrefix("10.244.0.0/16"), "utun7 -ifscope en0"},
		{netip.MustParsePrefix("10.244.0.0/16"), ""},
	}
	for _, c := range bad {
		if args, err := routeArgs("add", c.prefix, c.iface); err == nil {
			t.Errorf("%v on %q accepted: %q", c.prefix, c.iface, args)
		}
	}
}
