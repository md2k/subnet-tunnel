// Package netinfo reads this machine's network state for route safety
// checks: interface networks and the default gateway. Read-only, no root.
package netinfo

import (
	"net"
	"net/netip"

	"github.com/md2k/subnet-tunnel/internal/routes"
)

// LocalNetworks returns the IPv4 networks of interfaces that are up,
// except loopback.
func LocalNetworks() []routes.Local {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []routes.Local
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			addr, ok := netip.AddrFromSlice(ipn.IP)
			if !ok {
				continue
			}
			addr = addr.Unmap()
			if !addr.Is4() || addr.IsLinkLocalUnicast() {
				continue
			}
			ones, _ := ipn.Mask.Size()
			out = append(out, routes.Local{Iface: ifc.Name, Network: netip.PrefixFrom(addr, ones).Masked()})
		}
	}
	return out
}
