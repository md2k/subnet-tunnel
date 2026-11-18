//go:build linux

package linux

import (
	"fmt"
	"strings"

	"github.com/md2k/subnet-tunnel/internal/platform"
	"github.com/md2k/subnet-tunnel/internal/syscmd"
)

// Firewall is the nftables driver: subtun's own table, inet subtun, replaced
// in one transaction (nftScript) and deleted on Flush. Nothing keeps
// nftables "enabled", so there is no token to hold.
type Firewall struct{}

// Apply replaces subtun's table with r.
func (f Firewall) Apply(r platform.Rules) error {
	if r.Empty() {
		return f.Flush()
	}
	script, err := nftScript(r)
	if err != nil {
		return err
	}
	if _, err := syscmd.Find("nft"); err != nil {
		return fmt.Errorf("DNS capture, the kill switch and the IPv6 block need nftables (install the nftables package): %w", err)
	}
	return runInput(script, "nft", "-f", "-")
}

// Flush deletes subtun's table (gone already is fine).
func (Firewall) Flush() error {
	if _, err := syscmd.Find("nft"); err != nil {
		return nil // without nft nothing was ever loaded
	}
	if err := run("nft", "delete", "table", "inet", "subtun"); err != nil && !noSuchTable(err) {
		return err
	}
	return nil
}

// Busy reports whether subtun's table exists.
func (Firewall) Busy() (bool, error) {
	if _, err := syscmd.Find("nft"); err != nil {
		return false, nil
	}
	if err := run("nft", "list", "table", "inet", "subtun"); err != nil {
		if noSuchTable(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// Token: nothing to hold.
func (Firewall) Token() string { return "" }

// Adopt: nothing to take over.
func (Firewall) Adopt(string) {}

func noSuchTable(err error) bool {
	return strings.Contains(err.Error(), "No such file or directory")
}

// DNSCache flushes systemd-resolved's cache (no resolvectl: nothing to do).
type DNSCache struct{}

// Flush implements platform.DNSCache.
func (DNSCache) Flush() error {
	if _, err := syscmd.Find("resolvectl"); err != nil {
		return nil
	}
	return run("resolvectl", "flush-caches")
}
