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
	"regexp"
	"time"

	"github.com/md2k/subnet-tunnel/internal/platform"
)

// Ops.
const (
	OpCreateTun     = "create_tun"
	OpAddRoute      = "add_route"       // also during a session
	OpDeleteRoute   = "delete_route"    // a route this helper added; also during a session
	OpFlushDNS      = "flush_dns_cache" // during a session: answers cached while a tunnel was down go
	OpApplyFirewall = "apply_firewall"
	OpClearFirewall = "clear_firewall" // during a session: none of its rules is needed any more (kill switch profiles stopped)
	OpDone          = "done"
	OpEnd           = "end"     // session: end it, keeping the persist rules or not
	OpAdopt         = "adopt"   // first: take over rules an earlier session left, DNS relaxed
	OpCleanup       = "cleanup" // first: remove rules an earlier session left
)

// Request is one command from subtun to the helper.
type Request struct {
	Op      string          `json:"op"`
	MTU     int             `json:"mtu,omitempty"`
	Addr    string          `json:"addr,omitempty"` // utun address (IPv4, point-to-point to itself)
	CIDR    string          `json:"cidr,omitempty"`
	Rules   *platform.Rules `json:"rules,omitempty"`   // apply_firewall
	Persist *platform.Rules `json:"persist,omitempty"` // apply_firewall: what stays if the tunnel goes away
	Session bool            `json:"session,omitempty"` // done: stay up for the session
	Keep    bool            `json:"keep,omitempty"`    // end: leave the persist rules in place
}

// Response answers one Request. create_tun also carries the utun file
// descriptor as SCM_RIGHTS ancillary data.
type Response struct {
	OK      bool   `json:"ok"`
	Error   string `json:"error,omitempty"`
	Name    string `json:"name,omitempty"`    // utun interface name
	Message string `json:"message,omitempty"` // adopt, cleanup: what was done
	Kept    bool   `json:"kept,omitempty"`    // adopt: an earlier session's blocking rules are in place
	Running bool   `json:"running,omitempty"` // adopt: the rules belong to a session that is running
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
	maxGuarded  = 8192 // kill switch prefixes
	maxRoutes   = 8192
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
	if r.Empty() {
		return errors.New("empty rules")
	}
	if r.DNS != nil && len(r.DNSBlock) > 0 {
		return errors.New("DNS redirect and DNS block are exclusive")
	}
	if d := r.DNS; d != nil {
		if err := validateServers("DNS redirect", d.Servers); err != nil {
			return err
		}
		if d.ListenPort < 1024 || d.BypassPort < 1024 || d.ListenPort == d.BypassPort {
			return fmt.Errorf("DNS redirect: ports %d and %d must be different and at least 1024", d.ListenPort, d.BypassPort)
		}
	}
	if len(r.DNSBlock) > 0 {
		if err := validateServers("DNS block", r.DNSBlock); err != nil {
			return err
		}
	}
	if k := r.KillSwitch; k != nil {
		if len(k.Prefixes) == 0 || len(k.Prefixes) > maxGuarded {
			return fmt.Errorf("kill switch: %d prefixes, want 1-%d", len(k.Prefixes), maxGuarded)
		}
		for _, p := range k.Prefixes {
			if !p.IsValid() || !p.Addr().Is4() || p.Masked() != p || p.Bits() == 0 || p.Addr().IsLoopback() {
				return fmt.Errorf("kill switch: %s is not an IPv4 prefix with host bits zero (and not the default route)", p)
			}
		}
		if k.TunIface != "" && !utunName.MatchString(k.TunIface) {
			return fmt.Errorf("kill switch: interface %q is not a utun", k.TunIface)
		}
	}
	return nil
}

// ValidatePersist checks the rules meant to stay when the tunnel is gone:
// they may only block.
func ValidatePersist(r *platform.Rules) error {
	if err := ValidateRules(r); err != nil {
		return err
	}
	if r.DNS != nil || r.KillSwitch != nil && r.KillSwitch.TunIface != "" {
		return errors.New("rules left behind can only block")
	}
	return nil
}

var utunName = regexp.MustCompile(`^utun[0-9]{1,5}$`)

func validateServers(what string, servers []netip.Addr) error {
	if len(servers) == 0 || len(servers) > maxServers {
		return fmt.Errorf("%s: %d servers, want 1-%d", what, len(servers), maxServers)
	}
	for _, a := range servers {
		if !a.Is4() || a.IsLoopback() || a.IsUnspecified() || a.IsMulticast() {
			return fmt.Errorf("%s: server %s is not a unicast IPv4 address", what, a)
		}
	}
	return nil
}
