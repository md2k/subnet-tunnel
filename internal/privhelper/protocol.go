// Package privhelper is the small piece of subtun that runs as root.
//
// subtun itself runs as the user. For utun capture it starts
// `sudo subtun helper` once; the helper creates the utun interface, sets its
// address, adds routes and hands the interface's file descriptor back over a
// private unix socket. Packets are only ever handled by the user process.
//
// One-shot mode (the default and the only mode so far): after setup the
// helper exits. Routes on the utun disappear with the interface when subtun
// exits, crashes or is killed, so nothing is left behind. If the user
// process goes away before setup is complete, the helper removes what it
// added. A session mode that stays up for runtime changes would reuse the
// same command loop.
//
// The helper only accepts a fixed set of validated commands and carries
// them out through the platform drivers (internal/platform), which use fixed
// argument lists and never a shell.
package privhelper

import (
	"errors"
	"fmt"
	"net/netip"
	"time"
)

// Ops.
const (
	OpCreateTun = "create_tun"
	OpAddRoute  = "add_route"
	OpDone      = "done"
)

// Request is one command from subtun to the helper.
type Request struct {
	Op   string `json:"op"`
	MTU  int    `json:"mtu,omitempty"`
	Addr string `json:"addr,omitempty"` // utun address (IPv4, point-to-point to itself)
	CIDR string `json:"cidr,omitempty"`
}

// Response answers one Request. create_tun also carries the utun file
// descriptor as SCM_RIGHTS ancillary data.
type Response struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
	Name  string `json:"name,omitempty"` // utun interface name
}

// Limits.
const (
	MinMTU      = 1280
	MaxMTU      = 65535
	maxLine     = 4096
	tokenLen    = 64 // hex characters
	ioTimeout   = 30 * time.Second
	connTimeout = 3 * time.Minute // includes typing the sudo password
)

// ValidateMTU checks an MTU for the utun.
func ValidateMTU(mtu int) error {
	if mtu < MinMTU || mtu > MaxMTU {
		return fmt.Errorf("MTU %d out of range %d-%d", mtu, MinMTU, MaxMTU)
	}
	return nil
}

// ValidateTunAddr checks the utun's own address.
func ValidateTunAddr(s string) (netip.Addr, error) {
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("utun address: %w", err)
	}
	if !a.Is4() || a.IsLoopback() || a.IsMulticast() || a.IsUnspecified() || a.IsLinkLocalUnicast() {
		return netip.Addr{}, fmt.Errorf("utun address %s: need a unicast IPv4 address", a)
	}
	return a, nil
}

// ParseCIDR accepts "10.244.0.0/16" or a bare address (a /32). The prefix
// must be IPv4, written with its host bits zero, and not the default route.
func ParseCIDR(s string) (netip.Prefix, error) {
	var p netip.Prefix
	if a, err := netip.ParseAddr(s); err == nil {
		p = netip.PrefixFrom(a, a.BitLen())
	} else if p, err = netip.ParsePrefix(s); err != nil {
		return netip.Prefix{}, fmt.Errorf("%q is not an IP address or CIDR", s)
	}
	if !p.Addr().Is4() {
		return netip.Prefix{}, fmt.Errorf("%s: only IPv4 is supported so far", p)
	}
	if p.Masked() != p {
		return netip.Prefix{}, fmt.Errorf("%s has host bits set; did you mean %s?", p, p.Masked())
	}
	if p.Bits() == 0 {
		return netip.Prefix{}, errors.New("capturing the default route (0.0.0.0/0) is not supported")
	}
	if p.Addr().IsLoopback() || p.Addr().IsMulticast() {
		return netip.Prefix{}, fmt.Errorf("%s: loopback and multicast ranges can't be routed through the tunnel", p)
	}
	return p, nil
}
