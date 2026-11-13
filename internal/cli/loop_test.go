package cli

import (
	"net/netip"
	"strings"
	"testing"
)

func TestRoutesInternet(t *testing.T) {
	cases := map[string]bool{
		"0.0.0.0/1,128.0.0.0/1": true, // full tunnel
		"1.1.1.1/32":            true,
		"10.96.0.0/12":          false, // Docker Desktop's services
		"10.0.0.0/8,172.16.0.0/12,192.168.0.0/16": false,
		"192.0.2.0/24":    false, // documentation
		"100.64.0.0/10":   false, // CGNAT
		"172.16.0.0/11":   true,  // reaches past 172.16/12
		"198.18.249.1/32": false,
	}
	for in, want := range cases {
		var ps []netip.Prefix
		for _, s := range strings.Split(in, ",") {
			ps = append(ps, netip.MustParsePrefix(s))
		}
		if got := routesInternet(ps); got != want {
			t.Errorf("routesInternet(%s) = %v, want %v", in, got, want)
		}
	}
}

func TestCovered(t *testing.T) {
	set := []netip.Prefix{netip.MustParsePrefix("192.0.2.0/25"), netip.MustParsePrefix("192.0.2.128/25")}
	if !covered(netip.MustParsePrefix("192.0.2.0/24"), set) {
		t.Error("/24 made of two /25s not covered")
	}
	if covered(netip.MustParsePrefix("192.0.2.0/23"), set) {
		t.Error("/23 covered by a /24's worth")
	}
}
