package linux

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/md2k/subnet-tunnel/internal/platform"
)

func addrs(s ...string) []netip.Addr {
	out := make([]netip.Addr, len(s))
	for i, a := range s {
		out[i] = netip.MustParseAddr(a)
	}
	return out
}

func prefixes(s ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(s))
	for i, p := range s {
		out[i] = netip.MustParsePrefix(p)
	}
	return out
}

// Everything at once: the script replaces subtun's table in one
// transaction; DNS is redirected in the nat hook (before the filter, so a
// DNS server inside the guarded prefixes is still captured); the kill
// switch lets the tunnel interface through and rejects the rest; IPv6 goes
// except loopback, link-local and multicast.
func TestNftScript(t *testing.T) {
	got, err := nftScript(platform.Rules{
		DNS:        &platform.DNSRedirect{Servers: addrs("127.0.0.53", "192.168.112.1"), ListenPort: 53530, BypassPort: 53531},
		KillSwitch: &platform.KillSwitch{TunIface: "subtun0", Prefixes: prefixes("10.0.0.0/8", "172.16.0.0/12")},
		BlockIPv6:  true,
	})
	if err != nil {
		t.Fatal(err)
	}
	want := `table inet subtun
delete table inet subtun
table inet subtun {
	set dns {
		type ipv4_addr
		elements = { 127.0.0.53, 192.168.112.1 }
	}
	set guard {
		type ipv4_addr
		flags interval
		auto-merge
		elements = { 10.0.0.0/8, 172.16.0.0/12 }
	}
	chain nat_out {
		type nat hook output priority -100; policy accept;
		meta l4proto { tcp, udp } th sport 53531 return
		ip daddr @dns meta l4proto { tcp, udp } th dport 53 dnat ip to 127.0.0.1:53530
	}
	chain filter_out {
		type filter hook output priority 0; policy accept;
		oifname "subtun0" ip daddr @guard accept
		ip daddr @guard meta l4proto tcp reject with tcp reset
		ip daddr @guard reject
		meta nfproto ipv6 oifname "lo" accept
		ip6 daddr { fe80::/10, ff00::/8 } accept
		meta nfproto ipv6 meta l4proto tcp reject with tcp reset
		meta nfproto ipv6 reject
	}
}
`
	if got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
}

// What stays when the tunnel is gone: DNS held (rejected), everything to
// the prefixes rejected whatever the interface.
func TestNftScriptHolding(t *testing.T) {
	got, err := nftScript(platform.Rules{
		DNSBlock:   addrs("127.0.0.53"),
		KillSwitch: &platform.KillSwitch{Prefixes: prefixes("0.0.0.0/1", "128.0.0.0/1")},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"ip daddr @dns tcp dport 53 reject with tcp reset\n",
		"ip daddr @dns udp dport 53 reject\n",
		"elements = { 0.0.0.0/1, 128.0.0.0/1 }",
		"ip daddr @guard reject\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	for _, not := range []string{"oifname", "nat_out", "dnat"} {
		if strings.Contains(got, not) {
			t.Errorf("unexpected %q in:\n%s", not, got)
		}
	}
}

func TestNftScriptRefuses(t *testing.T) {
	dns := func(servers ...string) *platform.DNSRedirect {
		return &platform.DNSRedirect{Servers: addrs(servers...), ListenPort: 53530, BypassPort: 53531}
	}
	for name, c := range map[string]struct {
		r   platform.Rules
		err string
	}{
		"both DNS":       {platform.Rules{DNS: dns("127.0.0.53"), DNSBlock: addrs("127.0.0.53")}, "exclusive"},
		"no servers":     {platform.Rules{DNS: dns()}, "servers"},
		"IPv6 server":    {platform.Rules{DNS: dns("fd00::53")}, "IPv4"},
		"same ports":     {platform.Rules{DNS: &platform.DNSRedirect{Servers: addrs("127.0.0.53"), ListenPort: 53530, BypassPort: 53530}}, "ports"},
		"no prefixes":    {platform.Rules{KillSwitch: &platform.KillSwitch{TunIface: "subtun0"}}, "prefixes"},
		"default route":  {platform.Rules{KillSwitch: &platform.KillSwitch{Prefixes: prefixes("0.0.0.0/0")}}, "default route"},
		"host bits":      {platform.Rules{KillSwitch: &platform.KillSwitch{Prefixes: []netip.Prefix{netip.MustParsePrefix("10.1.0.0/8")}}}, "host bits"},
		"other iface":    {platform.Rules{KillSwitch: &platform.KillSwitch{TunIface: "eth0", Prefixes: prefixes("10.0.0.0/8")}}, "not a subtun interface"},
		"injected iface": {platform.Rules{KillSwitch: &platform.KillSwitch{TunIface: `subtun0" accept`, Prefixes: prefixes("10.0.0.0/8")}}, "not a subtun interface"},
	} {
		if _, err := nftScript(c.r); err == nil || !strings.Contains(err.Error(), c.err) {
			t.Errorf("%s: %v, want an error with %q", name, err, c.err)
		}
	}
}
