package dns

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net/netip"
	"os"
	"slices"
	"strings"
	"time"
)

// ResolvConf is where the system's DNS servers are read from. On macOS it
// is generated from the primary network service's resolver.
const ResolvConf = "/etc/resolv.conf"

// SystemServers returns the IPv4 DNS servers listed in a resolv.conf, and a
// note for each server that can't be captured (IPv6, loopback).
func SystemServers(path string) ([]netip.Addr, []string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	servers, notes := parseResolvConf(data)
	return servers, notes, nil
}

func parseResolvConf(data []byte) ([]netip.Addr, []string) {
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
		case a.IsLoopback() || a.IsUnspecified():
			notes = append(notes, fmt.Sprintf("local DNS server %s is not captured", a))
		case !slices.Contains(servers, a):
			servers = append(servers, a)
		}
	}
	return servers, notes
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
