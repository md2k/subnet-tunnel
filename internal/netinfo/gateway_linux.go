package netinfo

import (
	"context"
	"net/netip"
	"os/exec"
	"time"

	"github.com/md2k/subnet-tunnel/internal/syscmd"
)

// DefaultGateway returns the IPv4 default gateway of the main table, if it
// is an address (not an interface route).
func DefaultGateway() (netip.Addr, bool) {
	ip, err := syscmd.Find("ip")
	if err != nil {
		return netip.Addr{}, false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, ip, "-4", "-j", "route", "show", "default").Output()
	if err != nil {
		return netip.Addr{}, false
	}
	return parseIPRouteDefault(out)
}
