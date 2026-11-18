// Package linux implements the platform drivers for Linux (Debian and
// Ubuntu first): a TUN interface, routes in a table of subtun's own with
// `ip`, and (for now) no firewall features.
//
// Routing: subtun's routes live in table 32761. Two rules send this
// machine's own traffic (iif lo) there, after any other policy rules and
// right before main: first main without its default route (the LAN,
// container and pod networks, other VPNs' routes keep working), then
// subtun's table, then main's default route. Traffic the machine forwards
// for containers, pods or VMs never uses subtun's routes, so a target on
// this machine (a local cluster, a container) doesn't loop back into the
// tunnel.
//
// The argument builders here have no OS dependencies and are tested on any
// OS; the drivers that run them are Linux only.
package linux

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

// Routing table and rule priorities (main is 32766).
const (
	Table     = 32761
	PrefMain  = 32760 // iif lo lookup main suppress_prefixlength 0
	PrefTable = 32761 // iif lo lookup Table
)

// ifName is the shape of subtun's interface names (the kernel picks N).
var ifName = regexp.MustCompile(`^subtun[0-9]{1,5}$`)

// routeArgs builds the `ip` arguments for a route in subtun's table. The
// helper validates its input already; these checks keep the driver safe on
// its own.
func routeArgs(verb string, p netip.Prefix, iface string) ([]string, error) {
	if !p.IsValid() || !p.Addr().Is4() {
		return nil, fmt.Errorf("route %s: IPv4 only so far", p)
	}
	if p.Bits() == 0 {
		return nil, fmt.Errorf("route %s: not the default route", p)
	}
	if p.Masked() != p {
		return nil, fmt.Errorf("route %s: host bits set", p)
	}
	if !ifName.MatchString(iface) {
		return nil, fmt.Errorf("route %s: interface %q is not a subtun interface", p, iface)
	}
	return []string{"-4", "route", verb, p.String(), "dev", iface, "table", strconv.Itoa(Table)}, nil
}

// ruleArgs builds the `ip` arguments for the two rules, in order.
func ruleArgs(verb string) [][]string {
	return [][]string{
		{"-4", "rule", verb, "pref", strconv.Itoa(PrefMain), "iif", "lo", "lookup", "main", "suppress_prefixlength", "0"},
		{"-4", "rule", verb, "pref", strconv.Itoa(PrefTable), "iif", "lo", "lookup", strconv.Itoa(Table)},
	}
}

// countJSON counts the entries of `ip -j ... show` output (empty output: 0).
func countJSON(out []byte) (int, error) {
	s := strings.TrimSpace(string(out))
	if s == "" {
		return 0, nil
	}
	var entries []json.RawMessage
	if err := json.Unmarshal([]byte(s), &entries); err != nil {
		return 0, fmt.Errorf("unexpected ip output %q: %w", s, err)
	}
	return len(entries), nil
}
