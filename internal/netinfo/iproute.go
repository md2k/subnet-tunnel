package netinfo

import (
	"encoding/json"
	"net/netip"
)

// parseIPRouteDefault reads the gateway of `ip -4 -j route show default`
// (Linux): the first default route with an IPv4 gateway, lowest metric
// first as ip lists them.
func parseIPRouteDefault(out []byte) (netip.Addr, bool) {
	var routes []struct {
		Gateway string `json:"gateway"`
	}
	if err := json.Unmarshal(out, &routes); err != nil {
		return netip.Addr{}, false
	}
	for _, r := range routes {
		if a, err := netip.ParseAddr(r.Gateway); err == nil && a.Is4() {
			return a, true
		}
	}
	return netip.Addr{}, false
}
