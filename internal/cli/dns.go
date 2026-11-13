package cli

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strings"

	"github.com/md2k/subnet-tunnel/internal/capture"
	"github.com/md2k/subnet-tunnel/internal/dns"
)

// The system's DNS servers and search domains; replaced in tests.
var (
	systemDNS    = func() ([]netip.Addr, []string, error) { return dns.SystemServers(dns.ResolvConf) }
	systemSearch = func() ([]string, error) { return dns.SearchDomains(dns.ResolvConf) }
)

// planDNS validates the DNS settings before anything connects or asks for
// sudo. It returns nil options when DNS capture is off (no domains or
// patterns, or capture: off), and notes worth a warning.
func planDNS(s settings, rp *routePlan) (*capture.DNSOptions, []string, error) {
	unrouted, err := dns.ParseUnrouted(s.dnsUnrouted)
	if err != nil {
		return nil, nil, err
	}
	if len(s.dnsDomains) == 0 && len(s.dnsPatterns) == 0 {
		return nil, nil, nil
	}
	switch s.dnsCapture {
	case "", "firewall":
	case "off":
		return nil, nil, nil
	default:
		return nil, nil, fmt.Errorf("DNS capture %q: use firewall or off", s.dnsCapture)
	}
	if rp == nil && s.dnsListen == "" {
		// A profile without routes may inherit DNS settings from defaults.
		return nil, []string{"DNS settings ignored: DNS capture works together with the utun capture, and there are no routes (CIDRs)"}, nil
	}
	m, err := dns.NewMatcher(s.dnsDomains, s.dnsPatterns)
	if err != nil {
		return nil, nil, err
	}
	var tunAddr netip.Addr
	if rp != nil {
		tunAddr = rp.opts.TunAddr
	}
	if m.CatchAll() {
		search, _ := systemSearch()
		m.SetLocal(search, dnsLocals(tunAddr)())
	}
	// Locals too without ".": one may be added while running.
	opts := &capture.DNSOptions{Match: m, Tunnels: []capture.DNSTunnel{{Unrouted: unrouted}}, Locals: dnsLocals(tunAddr)}
	var notes []string

	if len(s.dnsServers) == 0 || len(s.dnsServers) == 1 && s.dnsServers[0] == "auto" {
		servers, n, err := systemDNS()
		if err != nil {
			return nil, nil, fmt.Errorf("reading the system's DNS servers: %w", err)
		}
		if len(servers) == 0 {
			return nil, n, fmt.Errorf("no IPv4 DNS server in %s to capture; set the servers explicitly", dns.ResolvConf)
		}
		opts.Servers, opts.Auto, notes = servers, true, n
	} else if opts.Servers, err = parseServers(s.dnsServers); err != nil {
		return nil, nil, err
	}

	switch s.dnsFallback {
	case "", "system":
	default:
		ap, err := parseResolver(s.dnsFallback)
		if err != nil {
			return nil, nil, err
		}
		opts.Fallback = []netip.AddrPort{ap}
	}

	// Unmatched names leave over UDP; inside a routed CIDR that UDP would go
	// into the utun, which only carries TCP so far.
	fallback := opts.Fallback
	if fallback == nil {
		for _, a := range opts.Servers {
			fallback = append(fallback, netip.AddrPortFrom(a, 53))
		}
	}
	for _, ap := range fallback {
		if rp == nil {
			break
		}
		if p, ok := rp.plan.Routed(ap.Addr()); ok {
			notes = append(notes, fmt.Sprintf("fallback DNS server %s is inside the routed %s: names not matched will fail (UDP isn't carried through the tunnel yet); exclude it (-x %s) or match all names (--dns-domain .)",
				ap.Addr(), p, ap.Addr()))
		}
	}
	return opts, notes, nil
}

// dnsLocals reads the machine's networks for the names "." leaves local,
// without subtun's own utun: it appears once the utun exists (with a
// network around the address, not just the address, as the root test
// showed), and its reverse zone is no local network.
func dnsLocals(tunAddr netip.Addr) func() []netip.Prefix {
	return func() []netip.Prefix {
		return slices.DeleteFunc(localPrefixes(), func(p netip.Prefix) bool {
			return tunAddr.IsValid() && p.Contains(tunAddr)
		})
	}
}

// parseServers checks a list of DNS servers to capture.
func parseServers(list []string) ([]netip.Addr, error) {
	var out []netip.Addr
	for _, v := range list {
		a, err := netip.ParseAddr(v)
		if err != nil || !a.Is4() || a.IsLoopback() || a.IsUnspecified() || a.IsMulticast() {
			return nil, fmt.Errorf("DNS server %q: need a unicast IPv4 address (or auto)", v)
		}
		out = append(out, a)
	}
	return out, nil
}

// parseResolver accepts IP or IP:port (IPv4; port 53 by default).
func parseResolver(v string) (netip.AddrPort, error) {
	ap, err := netip.ParseAddrPort(v)
	if err != nil {
		a, aerr := netip.ParseAddr(v)
		if aerr != nil {
			return netip.AddrPort{}, fmt.Errorf("DNS fallback %q: want system, IP or IP:port", v)
		}
		ap = netip.AddrPortFrom(a, 53)
	}
	if !ap.Addr().Is4() || ap.Addr().IsUnspecified() || ap.Port() == 0 {
		return netip.AddrPort{}, fmt.Errorf("DNS fallback %q: need an IPv4 address", v)
	}
	return ap, nil
}

func printDNSPlan(w io.Writer, d *capture.DNSOptions, domains, patterns []string) {
	servers := make([]string, len(d.Servers))
	for i, a := range d.Servers {
		servers[i] = a.String()
	}
	fmt.Fprintf(w, "DNS capture (firewall): queries to %s are answered by subtun\n", strings.Join(servers, ", "))
	what := strings.Join(domains, ", ")
	if len(patterns) > 0 {
		if what != "" {
			what += ", "
		}
		what += fmt.Sprintf("%d pattern(s)", len(patterns))
	}
	fmt.Fprintf(w, "  through the tunnel: %s\n", what)
	if d.Match.CatchAll() {
		fmt.Fprintf(w, "  except names under %s (local network; list one to send it through the tunnel)\n", strings.Join(d.Match.Local(), ", "))
	}
	fmt.Fprintf(w, "  answers through the tunnel at private addresses no route covers: %s\n", d.Tunnels[0].Unrouted)
	if d.Fallback != nil {
		fmt.Fprintf(w, "  other names: %s\n", d.Fallback[0])
	} else {
		fmt.Fprintf(w, "  other names: the captured servers\n")
	}
	if d.Auto {
		fmt.Fprintln(w, "  servers follow the system's when the network changes")
	}
}

// serveDNSDev answers DNS on addr (UDP and TCP) with the engine, without
// capturing anything: for testing the DNS path with dig and no root.
func serveDNSDev(ctx context.Context, addr string, d *capture.DNSOptions, log *slog.Logger) (func(), error) {
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("DNS listener: %w", err)
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		_ = pc.Close()
		return nil, fmt.Errorf("DNS listener: %w", err)
	}
	bpc, _, dial, err := dns.ListenBypass()
	if err != nil {
		_ = pc.Close()
		_ = ln.Close()
		return nil, err
	}
	fallback := d.Fallback
	if fallback == nil {
		for _, a := range d.Servers {
			fallback = append(fallback, netip.AddrPortFrom(a, 53))
		}
	}
	fwd := dns.NewForwarder(bpc, dial, func() []netip.AddrPort { return fallback })
	eng := d.Engine(fwd, log)
	go func() { _ = eng.ServeUDP(ctx, pc) }()
	go func() { _ = eng.ServeTCP(ctx, ln) }()
	log.Info("DNS listener ready (development, nothing captured)", "addr", addr, "fallback", fallback)
	return func() {
		_ = pc.Close()
		_ = ln.Close()
		_ = fwd.Close()
	}, nil
}
