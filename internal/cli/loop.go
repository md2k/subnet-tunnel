package cli

import (
	"net/netip"

	"github.com/md2k/subnet-tunnel/internal/dns"
)

// notInternet are the IPv4 ranges that aren't on the public internet:
// private, shared (CGNAT), loopback, link-local, benchmarking (subtun's
// own utun address), documentation, multicast and reserved.
var notInternet = func() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
		"192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
		"203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
	} {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

// routesInternet reports whether the routes send any public internet
// address into the tunnel. Through a target on this machine those loop:
// the target reaches them through this machine, back into the tunnel.
func routesInternet(final []netip.Prefix) bool {
	for _, r := range final {
		if !covered(r.Masked(), notInternet) {
			return true
		}
	}
	return false
}

// covered reports whether every address of r is in one of set's prefixes.
func covered(r netip.Prefix, set []netip.Prefix) bool {
	if !r.Addr().Is4() {
		return false // routes are IPv4; anything else counts as uncovered
	}
	overlaps := false
	for _, n := range set {
		if n.Bits() <= r.Bits() && n.Contains(r.Addr()) {
			return true
		}
		overlaps = overlaps || n.Overlaps(r)
	}
	if !overlaps || r.Bits() >= r.Addr().BitLen() {
		return false
	}
	lo := netip.PrefixFrom(r.Addr(), r.Bits()+1)
	b := r.Addr().As4()
	v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	v |= 1 << (31 - r.Bits())
	hi := netip.PrefixFrom(netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}), r.Bits()+1)
	return covered(lo, set) && covered(hi, set)
}

const localLoopWarning = "the target seems to run on this machine (subtun connects to a local socket or loopback): " +
	"its connections to the routed internet addresses leave through this machine and loop back into the tunnel. " +
	"subtun cuts such loops, so those addresses won't work through this target; use one outside this machine for them"

// unreachable reports addresses a DNS answer from the tunnel can't usefully
// point at: private ones no route covers (they mean something only inside
// the target's network, which only the routes reach).
func unreachable(routes []netip.Prefix) func(netip.Addr) bool {
	return func(a netip.Addr) bool {
		if !dns.Private(a) {
			return false
		}
		for _, r := range routes {
			if r.Contains(a) {
				return false
			}
		}
		return true
	}
}
