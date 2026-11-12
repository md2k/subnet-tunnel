// Package privhelper is the small piece of subtun that runs as root.
//
// subtun itself runs as the user. For utun capture it starts
// `sudo subtun helper` once; the helper creates the utun interface, sets its
// address, adds routes and hands the interface's file descriptor back over a
// private unix socket. Packets are only ever handled by the user process.
//
// One-shot mode (the default): after setup the helper exits. Routes on the
// utun disappear with the interface when subtun exits, crashes or is killed,
// so nothing is left behind. If the user process goes away before setup is
// complete, the helper removes what it added.
//
// Session mode (done with Session set; needed once firewall rules are
// applied, e.g. for DNS capture): the helper stays connected, accepts
// firewall updates, and removes its firewall rules when subtun disconnects,
// crashes or is killed, or when the helper itself is interrupted.
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

	"github.com/md2k/subnet-tunnel/internal/platform"
)

// Ops.
const (
	OpCreateTun     = "create_tun"
	OpAddRoute      = "add_route"
	OpApplyFirewall = "apply_firewall"
	OpDone          = "done"
)

// Request is one command from subtun to the helper.
type Request struct {
	Op      string          `json:"op"`
	MTU     int             `json:"mtu,omitempty"`
	Addr    string          `json:"addr,omitempty"` // utun address (IPv4, point-to-point to itself)
	CIDR    string          `json:"cidr,omitempty"`
	Rules   *platform.Rules `json:"rules,omitempty"`   // apply_firewall
	Session bool            `json:"session,omitempty"` // done: stay up for the session
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
	maxServers  = 16
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

// ValidateRules checks firewall rules sent by subtun.
func ValidateRules(r *platform.Rules) error {
	if r == nil {
		return errors.New("no rules")
	}
	if d := r.DNS; d != nil {
		if len(d.Servers) == 0 || len(d.Servers) > maxServers {
			return fmt.Errorf("DNS redirect: %d servers, want 1-%d", len(d.Servers), maxServers)
		}
		for _, a := range d.Servers {
			if !a.Is4() || a.IsLoopback() || a.IsUnspecified() || a.IsMulticast() {
				return fmt.Errorf("DNS redirect: server %s is not a unicast IPv4 address", a)
			}
		}
		if d.ListenPort < 1024 || d.BypassPort < 1024 || d.ListenPort == d.BypassPort {
			return fmt.Errorf("DNS redirect: ports %d and %d must be different and at least 1024", d.ListenPort, d.BypassPort)
		}
	}
	return nil
}
