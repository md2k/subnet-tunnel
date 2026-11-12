//go:build darwin

package darwin

import (
	"context"
	"fmt"
	"net/netip"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// Route adds and removes routes with /sbin/route, fixed argument lists and
// no shell. Routes point at an interface, so macOS removes them together
// with it.
type Route struct{}

// Add routes p into iface.
func (Route) Add(p netip.Prefix, iface string) error {
	args, err := routeArgs("add", p, iface)
	if err != nil {
		return err
	}
	return run("/sbin/route", args...)
}

// Delete removes the route for p on iface.
func (Route) Delete(p netip.Prefix, iface string) error {
	args, err := routeArgs("delete", p, iface)
	if err != nil {
		return err
	}
	return run("/sbin/route", args...)
}

var utunName = regexp.MustCompile(`^utun[0-9]{1,5}$`)

// routeArgs builds the /sbin/route arguments. The helper validates its
// input already; these checks keep the driver safe on its own.
func routeArgs(verb string, p netip.Prefix, iface string) ([]string, error) {
	if !p.IsValid() || !p.Addr().Is4() || p.Masked() != p || p.Bits() == 0 {
		return nil, fmt.Errorf("route %s: need an IPv4 prefix with host bits zero, not the default route", p)
	}
	if !utunName.MatchString(iface) {
		return nil, fmt.Errorf("route %s: interface %q is not a utun", p, iface)
	}
	kind, dst := "-net", p.String()
	if p.IsSingleIP() {
		kind, dst = "-host", p.Addr().String()
	}
	return []string{"-n", verb, kind, dst, "-interface", iface}, nil
}

func run(name string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}
