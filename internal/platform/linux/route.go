//go:build linux

package linux

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// Route keeps subtun's routes in table Table, with `ip`. It implements
// platform.RouteTable: Setup adds the two rules that steer this machine's
// own traffic to the table, Teardown removes them.
type Route struct{}

// Add routes p into iface (in subtun's table).
func (Route) Add(p netip.Prefix, iface string) error {
	args, err := routeArgs("add", p, iface)
	if err != nil {
		return err
	}
	return run("ip", args...)
}

// Delete removes the route for p on iface.
func (Route) Delete(p netip.Prefix, iface string) error {
	args, err := routeArgs("del", p, iface)
	if err != nil {
		return err
	}
	return run("ip", args...)
}

// Setup adds the rules for iface, after removing any an earlier session
// left. It refuses while another subtun interface exists, or when another
// program uses the rule priorities.
func (r Route) Setup(iface string) error {
	if !ifName.MatchString(iface) {
		return fmt.Errorf("%q is not a subtun interface", iface)
	}
	if other := subtunInterface(iface); other != "" {
		return fmt.Errorf("another subtun is running (interface %s exists); stop it first", other)
	}
	if _, err := r.Teardown(); err != nil {
		return err
	}
	for _, pref := range []int{PrefMain, PrefTable} {
		out, err := output("ip", "-4", "-j", "rule", "show", "pref", strconv.Itoa(pref))
		if err != nil {
			return err
		}
		if n, err := countJSON(out); err != nil {
			return err
		} else if n > 0 {
			return fmt.Errorf("routing rule priority %d is used by another program (ip rule show pref %d); subtun needs it", pref, pref)
		}
	}
	for _, args := range ruleArgs("add") {
		if err := run("ip", args...); err != nil {
			_, _ = r.Teardown()
			return err
		}
	}
	return nil
}

// Teardown removes subtun's rules (only rules exactly like its own) and any
// routes left in its table.
func (Route) Teardown() (bool, error) {
	removed := false
	for _, args := range ruleArgs("del") {
		for range 16 { // an earlier version or crash may have left several
			err := run("ip", args...)
			if err == nil {
				removed = true
				continue
			}
			if strings.Contains(err.Error(), "No such file or directory") {
				break
			}
			return removed, err
		}
	}
	out, err := output("ip", "-4", "-j", "route", "show", "table", strconv.Itoa(Table))
	if err != nil {
		return removed, err
	}
	if n, err := countJSON(out); err != nil {
		return removed, err
	} else if n > 0 {
		if err := run("ip", "-4", "route", "flush", "table", strconv.Itoa(Table)); err != nil {
			return removed, err
		}
		removed = true
	}
	return removed, nil
}

// InUse names a subtun interface that exists now ("" if none).
func (Route) InUse() (string, error) { return subtunInterface(""), nil }

// subtunInterface returns the first subtun interface other than except.
func subtunInterface(except string) string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, ifc := range ifaces {
		if ifc.Name != except && ifName.MatchString(ifc.Name) {
			return ifc.Name
		}
	}
	return ""
}
