package routes

import (
	"errors"
	"fmt"
	"net/netip"
)

// ParsePrefix accepts "10.244.0.0/16" or a bare address (a /32). It must be
// IPv4 and written with its host bits zero.
func ParsePrefix(s string) (netip.Prefix, error) {
	var p netip.Prefix
	if a, err := netip.ParseAddr(s); err == nil {
		p = netip.PrefixFrom(a, a.BitLen())
	} else if p, err = netip.ParsePrefix(s); err != nil {
		return netip.Prefix{}, fmt.Errorf("%q is not an IP address or CIDR", s)
	}
	if err := check(p); err != nil {
		return netip.Prefix{}, err
	}
	return p, nil
}

// ParseRoute is ParsePrefix plus what makes sense to send through the
// tunnel: not the default route, loopback or multicast.
func ParseRoute(s string) (netip.Prefix, error) {
	p, err := ParsePrefix(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	if p.Bits() == 0 {
		return netip.Prefix{}, errors.New("capturing the default route (0.0.0.0/0) is not supported; for a full tunnel give 0.0.0.0/1 128.0.0.0/1")
	}
	if p.Addr().IsLoopback() || p.Addr().IsMulticast() {
		return netip.Prefix{}, fmt.Errorf("%s: loopback and multicast ranges can't be routed through the tunnel", p)
	}
	return p, nil
}

// ParseAll parses a list with fn, naming the first bad entry.
func ParseAll(ss []string, fn func(string) (netip.Prefix, error)) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(ss))
	for _, s := range ss {
		p, err := fn(s)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}
