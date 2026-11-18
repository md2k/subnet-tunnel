package netinfo

import (
	"net/netip"
	"testing"
)

func TestParseIPRouteDefault(t *testing.T) {
	for out, want := range map[string]string{
		`[{"dst":"default","gateway":"192.168.112.1","dev":"end0","protocol":"dhcp","prefsrc":"192.168.112.8","metric":100,"flags":[]}]`:        "192.168.112.1",
		`[{"dst":"default","dev":"wg0","scope":"link","flags":[]},{"dst":"default","gateway":"10.0.0.1","dev":"eth0","metric":600,"flags":[]}]`: "10.0.0.1", // an interface route first
		`[]`:              "",
		``:                "",
		`Error: no route`: "",
	} {
		got, ok := parseIPRouteDefault([]byte(out))
		if want == "" {
			if ok {
				t.Errorf("%q: got %s, want none", out, got)
			}
			continue
		}
		if !ok || got != netip.MustParseAddr(want) {
			t.Errorf("%q: got %s %v, want %s", out, got, ok, want)
		}
	}
}
