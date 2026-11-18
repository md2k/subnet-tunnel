package dns

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net/netip"
	"os"
	"runtime"
	"slices"
	"strings"
	"time"
)

// ResolvConf is where the system's DNS servers are read from. On macOS it
// is generated from the primary network service's resolver.
const ResolvConf = "/etc/resolv.conf"

// LocalServers reports whether a local resolver (a loopback address:
// systemd-resolved's 127.0.0.53, a local dnsmasq) can be captured on this
// OS: on Linux the firewall redirects in the output hook, and the resolver
// asks upstream from its own process, which isn't redirected; macOS's pf
// redirect works through lo0 and can't.
var LocalServers = runtime.GOOS == "linux"

// SystemServers returns the IPv4 DNS servers listed in a resolv.conf, and a
// note for each server that can't be captured (IPv6; loopback, unless
// LocalServers).
func SystemServers(path string) ([]netip.Addr, []string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	servers, notes := parseResolvConf(data, LocalServers)
	return servers, notes, nil
}

func parseResolvConf(data []byte, local bool) ([]netip.Addr, []string) {
	var servers []netip.Addr
	var notes []string
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 2 || f[0] != "nameserver" {
			continue
		}
		a, err := netip.ParseAddr(f[1])
		if err != nil {
			continue
		}
		a = a.Unmap()
		switch {
		case !a.Is4():
			notes = append(notes, fmt.Sprintf("IPv6 DNS server %s is not captured (IPv4 only so far)", a))
		case a.IsUnspecified() || a.IsLoopback() && !local:
			notes = append(notes, fmt.Sprintf("local DNS server %s is not captured", a))
		case !slices.Contains(servers, a):
			servers = append(servers, a)
		}
	}
	return servers, notes
}

// SearchDomains returns the search domains in a resolv.conf ("search" and
// "domain" lines).
func SearchDomains(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseSearch(data), nil
}

func parseSearch(data []byte) []string {
	var out []string
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) >= 2 && (f[0] == "search" || f[0] == "domain") {
			for _, d := range f[1:] {
				if !slices.Contains(out, d) {
					out = append(out, d)
				}
			}
		}
	}
	return out
}

// WatchServers calls fn with the system's DNS servers whenever they change
// (network switch, VPN up or down), reading them with read every interval.
// It doesn't call fn for the servers already in effect at the start
// (initial) and skips empty lists, which show up briefly while the network
// changes.
func WatchServers(ctx context.Context, interval time.Duration, initial []netip.Addr, read func() ([]netip.Addr, []string, error), fn func([]netip.Addr, []string)) {
	current := initial
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		servers, notes, err := read()
		if err != nil || len(servers) == 0 || slices.Equal(servers, current) {
			continue
		}
		current = servers
		fn(servers, notes)
	}
}
