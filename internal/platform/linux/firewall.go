//go:build linux

package linux

import (
	"errors"

	"github.com/md2k/subnet-tunnel/internal/platform"
)

// Firewall stands in until the nftables driver: it accepts no rules, so DNS
// capture, the kill switch and the IPv6 block are refused, and it never has
// anything to remove.
type Firewall struct{}

var errNoFirewall = errors.New("DNS capture, the kill switch and the IPv6 block aren't implemented on Linux yet (routes and SOCKS are)")

// Apply refuses everything but empty rules.
func (Firewall) Apply(r platform.Rules) error {
	if r.Empty() {
		return nil
	}
	return errNoFirewall
}

// Flush has nothing to remove.
func (Firewall) Flush() error { return nil }

// Busy: no rules are ever loaded.
func (Firewall) Busy() (bool, error) { return false, nil }

// Token: nothing keeps a firewall enabled for subtun.
func (Firewall) Token() string { return "" }

// Adopt has nothing to take over.
func (Firewall) Adopt(string) {}
