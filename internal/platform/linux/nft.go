package linux

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/md2k/subnet-tunnel/internal/platform"
)

// nftScript renders r as a script for `nft -f -` that replaces subtun's
// table (inet subtun) in one transaction: create it if missing, delete it,
// define it again. Only this machine's own traffic is touched (output
// hooks); other tables (Docker's, Cilium's) are never looked at.
//
// DNS is redirected in the nat hook, before the filter hook sees the
// packet, so a DNS server inside the guarded prefixes is still captured
// (pf: the DNS rules come before the kill switch). Rejections answer at
// once (TCP reset, ICMP unreachable), like pf's "block return".
func nftScript(r platform.Rules) (string, error) {
	if r.DNS != nil && len(r.DNSBlock) > 0 {
		return "", errors.New("DNS redirect and DNS block are exclusive")
	}
	var sets, nat, filter []string
	if d := r.DNS; d != nil {
		if d.ListenPort == 0 || d.BypassPort == 0 || d.ListenPort == d.BypassPort {
			return "", errors.New("DNS redirect needs two different ports")
		}
		list, err := nftServers(d.Servers)
		if err != nil {
			return "", err
		}
		sets = append(sets, "set dns {\n\t\ttype ipv4_addr\n\t\telements = { "+list+" }\n\t}")
		nat = append(nat,
			fmt.Sprintf("meta l4proto { tcp, udp } th sport %d return", d.BypassPort),
			fmt.Sprintf("ip daddr @dns meta l4proto { tcp, udp } th dport 53 dnat ip to 127.0.0.1:%d", d.ListenPort))
	}
	if len(r.DNSBlock) > 0 {
		list, err := nftServers(r.DNSBlock)
		if err != nil {
			return "", err
		}
		sets = append(sets, "set dns {\n\t\ttype ipv4_addr\n\t\telements = { "+list+" }\n\t}")
		filter = append(filter, "ip daddr @dns tcp dport 53 reject with tcp reset", "ip daddr @dns udp dport 53 reject")
	}
	if k := r.KillSwitch; k != nil {
		if len(k.Prefixes) == 0 {
			return "", errors.New("kill switch without prefixes")
		}
		list := make([]string, len(k.Prefixes))
		for i, p := range k.Prefixes {
			switch {
			case !p.IsValid() || !p.Addr().Is4():
				return "", fmt.Errorf("kill switch prefix %s: IPv4 only", p)
			case p.Bits() == 0:
				return "", fmt.Errorf("kill switch prefix %s: not the default route", p)
			case p.Masked() != p:
				return "", fmt.Errorf("kill switch prefix %s: host bits set", p)
			}
			list[i] = p.String()
		}
		if k.TunIface != "" && !ifName.MatchString(k.TunIface) {
			return "", fmt.Errorf("kill switch interface %q is not a subtun interface", k.TunIface)
		}
		sets = append(sets, "set guard {\n\t\ttype ipv4_addr\n\t\tflags interval\n\t\tauto-merge\n\t\telements = { "+strings.Join(list, ", ")+" }\n\t}")
		if k.TunIface != "" {
			filter = append(filter, fmt.Sprintf("oifname %q ip daddr @guard accept", k.TunIface))
		}
		filter = append(filter, "ip daddr @guard meta l4proto tcp reject with tcp reset", "ip daddr @guard reject")
	}
	if r.BlockIPv6 {
		filter = append(filter,
			`meta nfproto ipv6 oifname "lo" accept`,
			"ip6 daddr { fe80::/10, ff00::/8 } accept",
			"meta nfproto ipv6 meta l4proto tcp reject with tcp reset",
			"meta nfproto ipv6 reject")
	}

	var b strings.Builder
	b.WriteString("table inet subtun\ndelete table inet subtun\ntable inet subtun {\n")
	for _, s := range sets {
		b.WriteString("\t" + s + "\n")
	}
	chain := func(name, typ string, prio int, rules []string) {
		if len(rules) == 0 {
			return
		}
		fmt.Fprintf(&b, "\tchain %s {\n\t\ttype %s hook output priority %d; policy accept;\n", name, typ, prio)
		for _, r := range rules {
			b.WriteString("\t\t" + r + "\n")
		}
		b.WriteString("\t}\n")
	}
	chain("nat_out", "nat", -100, nat)
	chain("filter_out", "filter", 0, filter)
	b.WriteString("}\n")
	return b.String(), nil
}

// nftServers lists DNS servers for a set. Loopback servers are fine on
// Linux (systemd-resolved's 127.0.0.53, a local dnsmasq): the redirect
// happens in the output hook, and they ask upstream from their own
// process, which isn't redirected.
func nftServers(servers []netip.Addr) (string, error) {
	if len(servers) == 0 {
		return "", errors.New("DNS rules need servers")
	}
	list := make([]string, len(servers))
	for i, a := range servers {
		if !a.Is4() || a.IsUnspecified() || a.IsMulticast() {
			return "", fmt.Errorf("DNS server %s: need an IPv4 address", a)
		}
		list[i] = a.String()
	}
	return strings.Join(list, ", "), nil
}
