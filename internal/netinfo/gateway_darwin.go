package netinfo

import (
	"context"
	"net/netip"
	"os/exec"
	"strings"
	"time"
)

// DefaultGateway returns the IPv4 default gateway, if it is an address
// (not an interface route).
func DefaultGateway() (netip.Addr, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "/sbin/route", "-n", "get", "default").Output()
	if err != nil {
		return netip.Addr{}, false
	}
	return parseRouteGet(string(out))
}

func parseRouteGet(out string) (netip.Addr, bool) {
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok || strings.TrimSpace(k) != "gateway" {
			continue
		}
		a, err := netip.ParseAddr(strings.TrimSpace(v))
		if err != nil || !a.Is4() {
			return netip.Addr{}, false
		}
		return a, true
	}
	return netip.Addr{}, false
}
