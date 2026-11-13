package cli

import (
	"fmt"
	"net/netip"

	"github.com/md2k/subnet-tunnel/internal/netinfo"
	"github.com/md2k/subnet-tunnel/internal/routes"
)

// The machine's networks and default gateway; replaced in tests.
var (
	localNetworks  = netinfo.LocalNetworks
	defaultGateway = netinfo.DefaultGateway
)

// autoExclude is a range subtun keeps out of the routes by itself.
type autoExclude struct {
	prefix netip.Prefix
	reason string
}

// neverRouted are ranges that don't belong in the tunnel. They also keep
// the route pieces valid: the root helper refuses a route that starts at a
// loopback or multicast address (224.0.0.0/3 is a piece of 128.0.0.0/1).
var neverRouted = []autoExclude{
	{netip.MustParsePrefix("0.0.0.0/8"), `"this network"`},
	{netip.MustParsePrefix("127.0.0.0/8"), "loopback"},
	{netip.MustParsePrefix("169.254.0.0/16"), "link-local"},
	{netip.MustParsePrefix("224.0.0.0/3"), "multicast, reserved and broadcast"},
}

// localExcludes makes each local network an automatic exclude: the LAN stays
// on its interface even where excludes inside it (the API server's address)
// split the routes into pieces more specific than the LAN's own route.
func localExcludes(locals []routes.Local) []autoExclude {
	seen := map[netip.Prefix]bool{}
	var out []autoExclude
	for _, l := range locals {
		p := l.Network.Masked()
		if seen[p] || !p.Addr().Is4() {
			continue
		}
		seen[p] = true
		out = append(out, autoExclude{p, "local network on " + l.Iface})
	}
	return out
}

// autoExcludes returns the candidates some route contains and is less
// specific than; a route at least as specific as a candidate is an
// explicit choice and wins. The notes explain them in the plan.
func autoExcludes(includes []netip.Prefix, cands []autoExclude) ([]netip.Prefix, []routes.Note) {
	var out []netip.Prefix
	var notes []routes.Note
	for _, c := range cands {
		for _, inc := range includes {
			if inc.Bits() < c.prefix.Bits() && inc.Contains(c.prefix.Addr()) {
				out = append(out, c.prefix)
				notes = append(notes, routes.Note{Prefix: c.prefix, Exclude: true,
					Reason: fmt.Sprintf("%s, stays out of the tunnel (excluded automatically)", c.reason)})
				break
			}
		}
	}
	return out, notes
}
