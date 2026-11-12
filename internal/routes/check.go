package routes

import (
	"fmt"
	"net/netip"
)

// Reserved is an address that must stay out of the tunnel's routes.
type Reserved struct {
	Addr netip.Addr
	What string // e.g. "subtun's utun address", "default gateway"
	// ViaLocal: the address is fine inside a route that is broader than the
	// local network holding it, because that network's own route is more
	// specific and wins (the default gateway on a LAN). Without it, any
	// route containing the address is refused (subtun's own address).
	ViaLocal bool
}

// Local is a network attached to one of this machine's interfaces.
type Local struct {
	Iface   string
	Network netip.Prefix // interface address with its netmask
}

// Check reports routes that would break things (errors) and routes that
// overlap local networks (warnings: the most specific route still wins, so
// the overlapping part follows whichever route is more specific).
func Check(plan Plan, reserved []Reserved, locals []Local) (errs, warns []string) {
	for _, r := range reserved {
		if !r.Addr.IsValid() {
			continue
		}
		p, ok := plan.Routed(r.Addr)
		if !ok {
			continue
		}
		if r.ViaLocal {
			if l, found := mostSpecificLocal(locals, r.Addr); found && p.Bits() < l.Network.Bits() {
				continue // the local network's route is more specific: the address stays reachable
			}
		}
		errs = append(errs, fmt.Sprintf("route %s contains %s %s; exclude it or use narrower routes", p, r.What, r.Addr))
	}
	for _, l := range locals {
		for _, p := range plan.Routes {
			if !p.Overlaps(l.Network) {
				continue
			}
			if p.Bits() >= l.Network.Bits() {
				warns = append(warns, fmt.Sprintf("route %s takes over part of %s on %s: those addresses go through the tunnel", p, l.Network, l.Iface))
			} else {
				warns = append(warns, fmt.Sprintf("route %s contains %s on %s: that network stays on %s (more specific)", p, l.Network, l.Iface, l.Iface))
			}
		}
	}
	return errs, warns
}

func mostSpecificLocal(locals []Local, a netip.Addr) (Local, bool) {
	var best Local
	found := false
	for _, l := range locals {
		if l.Network.Contains(a) && (!found || l.Network.Bits() > best.Network.Bits()) {
			best, found = l, true
		}
	}
	return best, found
}

// HostPrefixes turns addresses into /32 prefixes, skipping invalid and
// non-IPv4 ones (used to auto-exclude the carrier's own endpoints).
func HostPrefixes(addrs []netip.Addr) []netip.Prefix {
	var out []netip.Prefix
	for _, a := range addrs {
		a = a.Unmap()
		if a.IsValid() && a.Is4() && !a.IsLoopback() {
			out = append(out, netip.PrefixFrom(a, 32))
		}
	}
	return out
}
