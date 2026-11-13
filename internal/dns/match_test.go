package dns

import (
	"net/netip"
	"slices"
	"strings"
	"testing"
)

func TestMatcherDomains(t *testing.T) {
	m, err := NewMatcher([]string{"Company.com", "*.privatelink.blob.core.windows.net", ".*.azurecr.io", ".internal."}, nil)
	if err != nil {
		t.Fatal(err)
	}
	match := []string{"company.com", "db.eu.COMPANY.com.", "x.privatelink.blob.core.windows.net", "privatelink.blob.core.windows.net", "reg.azurecr.io", "a.b.internal"}
	nomatch := []string{"badcompany.com", "company.com.evil.org", "blob.core.windows.net", "azurecr.io.x", "example.org"}
	for _, n := range match {
		if !m.Match(n) {
			t.Errorf("%s: not matched", n)
		}
	}
	for _, n := range nomatch {
		if m.Match(n) {
			t.Errorf("%s: matched", n)
		}
	}
}

func TestMatcherAllAndPatterns(t *testing.T) {
	all, _ := NewMatcher([]string{"."}, nil)
	if !all.Match("anything.example") {
		t.Error(`"." should match every name`)
	}
	m, err := NewMatcher(nil, []string{`^db-[0-9]+\.prod\.`})
	if err != nil {
		t.Fatal(err)
	}
	if !m.Match("db-12.prod.company.com") || m.Match("web.prod.company.com") || m.Match("xdb-1.prod.x") {
		t.Error("pattern matching")
	}
	if none, _ := NewMatcher(nil, nil); !none.Empty() || none.Match("company.com") {
		t.Error("empty matcher")
	}
}

func TestMatcherRejects(t *testing.T) {
	for d, want := range map[string]string{
		".*\\.company\\.com": "regular expression",
		"comp(any).com":      "regular expression",
		"":                   "not a domain",
		"a..b":               "not a domain",
		"bad name.com":       "not a domain",
	} {
		if _, err := NewMatcher([]string{d}, nil); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: got %v, want %q", d, err, want)
		}
	}
	if _, err := NewMatcher(nil, []string{"(unclosed"}); err == nil {
		t.Error("bad pattern accepted")
	}
}

func TestParseResolvConf(t *testing.T) {
	servers, notes := parseResolvConf([]byte(`# macOS
domain lan
nameserver 192.168.1.1
nameserver 192.168.1.1
nameserver fd00::1
nameserver 127.0.0.1
nameserver bogus
nameserver 1.1.1.1
`))
	if want := []netip.Addr{netip.MustParseAddr("192.168.1.1"), netip.MustParseAddr("1.1.1.1")}; !slices.Equal(servers, want) {
		t.Fatalf("servers %v", servers)
	}
	if len(notes) != 2 || !strings.Contains(notes[0], "IPv6") || !strings.Contains(notes[1], "127.0.0.1") {
		t.Fatalf("notes %q", notes)
	}
}

// "." leaves local names alone: multicast DNS (.local) and the system's
// search domains. Listed domains and patterns still win.
func TestMatcherCatchAllLeavesLocal(t *testing.T) {
	m, err := NewMatcher([]string{".", "cluster.local"}, []string{`^db\.lan$`})
	if err != nil {
		t.Fatal(err)
	}
	if !m.CatchAll() {
		t.Fatal("not a catch-all")
	}
	if !m.SetLocal([]string{"lan", "Home.Arpa.", "lan", "."}, nil) || m.SetLocal([]string{"lan", "home.arpa"}, nil) {
		t.Fatal("SetLocal change reporting wrong")
	}
	if got := m.Local(); !slices.Equal(got, []string{"local", "lan", "home.arpa", "254.169.in-addr.arpa", "e.f.ip6.arpa"}) {
		t.Fatalf("local %v", got)
	}
	for name, want := range map[string]bool{
		"example.com":                          true,
		"printer.local":                        false,
		"local":                                false,
		"kubernetes.default.svc.cluster.local": true, // listed
		"nas.lan":                              false,
		"NAS.LAN.":                             false,
		"db.lan":                               true, // pattern
		"router.home.arpa":                     false,
		"planet.com":                           true, // "lan" is a label suffix, not a string suffix
	} {
		if got := m.Match(name); got != want {
			t.Errorf("Match(%q) = %v, want %v", name, got, want)
		}
	}
	// Without ".", local names only go through the tunnel if listed.
	split, _ := NewMatcher([]string{"corp.example"}, nil)
	split.SetLocal([]string{"corp.example"}, nil)
	if !split.Match("git.corp.example") || split.Match("printer.local") {
		t.Fatal("split matcher")
	}
}

func TestParseSearch(t *testing.T) {
	got := parseSearch([]byte("# generated\ndomain lan\nsearch lan home.arpa\nnameserver 192.168.1.1\n"))
	if !slices.Equal(got, []string{"lan", "home.arpa"}) {
		t.Fatalf("got %v", got)
	}
}

func TestReverseZones(t *testing.T) {
	mp := netip.MustParsePrefix
	cases := []struct {
		nets []string
		want []string
	}{
		{[]string{"192.168.1.0/24"}, []string{"1.168.192.in-addr.arpa"}},
		{[]string{"172.20.10.0/28"}, []string{"10.20.172.in-addr.arpa"}}, // a phone hotspot
		{[]string{"192.168.0.0/22"}, []string{"0.168.192.in-addr.arpa", "1.168.192.in-addr.arpa", "2.168.192.in-addr.arpa", "3.168.192.in-addr.arpa"}},
		{[]string{"10.0.0.0/17"}, []string{"0.10.in-addr.arpa"}},
		{[]string{"100.64.0.0/16", "10.0.0.0/8"}, []string{"64.100.in-addr.arpa", "10.in-addr.arpa"}},
		{[]string{"198.18.249.1/32", "192.168.1.0/24", "192.168.1.0/24"}, []string{"249.18.198.in-addr.arpa", "1.168.192.in-addr.arpa"}},
		{[]string{"0.0.0.0/4"}, nil}, // too wide to mean a network
	}
	for _, c := range cases {
		var nets []netip.Prefix
		for _, n := range c.nets {
			nets = append(nets, mp(n))
		}
		want := append(c.want, "254.169.in-addr.arpa", "e.f.ip6.arpa")
		if got := ReverseZones(nets); !slices.Equal(got, want) {
			t.Errorf("%v: got %v, want %v", c.nets, got, want)
		}
	}
	if got := ReverseZones([]netip.Prefix{mp("172.16.0.0/12")}); len(got) != 16+2 || got[0] != "16.172.in-addr.arpa" || got[15] != "31.172.in-addr.arpa" {
		t.Errorf("172.16.0.0/12: %v", got)
	}
}

// "." leaves reverse lookups for the LAN and link-local alone (PTR, DNS-SD
// browsing); other reverse lookups, like a cluster's own addresses, still
// go through the tunnel.
func TestMatcherCatchAllLeavesLocalReverseZones(t *testing.T) {
	m, err := NewMatcher([]string{"."}, nil)
	if err != nil {
		t.Fatal(err)
	}
	m.SetLocal(nil, []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")})
	for name, want := range map[string]bool{
		"5.1.168.192.in-addr.arpa":                                                 false,
		"b._dns-sd._udp.0.1.168.192.in-addr.arpa":                                  false,
		"lb._dns-sd._udp.0.1.168.192.in-addr.arpa":                                 false,
		"7.3.254.169.in-addr.arpa":                                                 false,
		"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f.ip6.arpa": false,
		"10.0.96.10.in-addr.arpa":                                                  true, // a cluster address
		"8.8.8.8.in-addr.arpa":                                                     true,
		"5.2.168.192.in-addr.arpa":                                                 true, // not this LAN
	} {
		if got := m.Match(name); got != want {
			t.Errorf("Match(%q) = %v, want %v", name, got, want)
		}
	}
	// Explicitly listed, a LAN zone goes through the tunnel after all.
	m2, _ := NewMatcher([]string{".", "1.168.192.in-addr.arpa"}, nil)
	m2.SetLocal(nil, []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")})
	if !m2.Match("5.1.168.192.in-addr.arpa") {
		t.Error("listed reverse zone not sent through the tunnel")
	}
}

// Several tunnels: the longest matching domain wins, then patterns in
// order, then ".", and a tunnel switched off gives its names to the next
// match.
func TestMultiMatcherPick(t *testing.T) {
	m, err := NewMultiMatcher([]Names{
		{Domains: []string{".", "example"}},                          // 0: work, full tunnel
		{Domains: []string{"corp.example", "cluster.local"}},         // 1: dev
		{Patterns: []string{`^db-[0-9]+\.`}, Domains: []string{"x"}}, // 2: db
	})
	if err != nil {
		t.Fatal(err)
	}
	m.SetLocal([]string{"lan"}, nil)
	want := map[string]int{
		"web.corp.example.": 1, // longer than "example"
		"corp.example":      1,
		"other.example":     0,
		"svc.cluster.local": 1, // listed, though under "local"
		"db-1.corp.example": 1, // a domain beats a pattern
		"db-1.github.com":   2,
		"github.com":        0, // "."
		"printer.local":     -1,
		"nas.lan":           -1,
		"a.x":               2,
	}
	pick := func(name string) int {
		if t, ok := m.Pick(name); ok {
			return t
		}
		return -1
	}
	for name, w := range want {
		if got := pick(name); got != w {
			t.Errorf("%s: target %d, want %d", name, got, w)
		}
	}
	// dev gave up: its names go to work's "example" and ".".
	m.SetOn(1, false)
	for name, w := range map[string]int{"web.corp.example": 0, "svc.cluster.local": -1, "db-1.corp.example": 0} {
		if got := pick(name); got != w {
			t.Errorf("dev off, %s: target %d, want %d", name, got, w)
		}
	}
	m.SetOn(0, false)
	if got := pick("github.com"); got != -1 {
		t.Errorf("work off, github.com: target %d", got)
	}
	m.SetOn(1, true)
	if got := pick("web.corp.example"); got != 1 {
		t.Errorf("dev back on: target %d", got)
	}
}

func TestMultiMatcherConflicts(t *testing.T) {
	for want, sets := range map[string][]Names{
		"listed for two tunnels": {{Domains: []string{"corp.example"}}, {Domains: []string{"*.Corp.Example."}}},
		"only one tunnel":        {{Domains: []string{"."}}, {Domains: []string{"."}}},
		"looks like a regular":   {{Domains: []string{"a"}}, {Domains: []string{"^b$"}}},
	} {
		if _, err := NewMultiMatcher(sets); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%v: %v, want %q", sets, err, want)
		}
	}
	// The same domain twice for one tunnel is fine.
	if _, err := NewMultiMatcher([]Names{{Domains: []string{"a.example", "A.example."}}}); err != nil {
		t.Error(err)
	}
}

// subtun's own endpoints never go through a tunnel, whatever matches them,
// so a tunnel that is down can still reach its API server.
func TestSetOwn(t *testing.T) {
	m, err := NewMultiMatcher([]Names{{Domains: []string{"."}}, {Domains: []string{"eks.example.com"}}})
	if err != nil {
		t.Fatal(err)
	}
	m.SetOwn([]string{"ABC.eks.example.com.", "api.dev.example.org", "192.0.2.1", ""})
	if got := m.Own(); !slices.Equal(got, []string{"abc.eks.example.com", "api.dev.example.org"}) {
		t.Fatalf("own: %q", got)
	}
	for name, want := range map[string]int{
		"abc.eks.example.com": -1, "api.dev.example.org.": -1,
		"xyz.eks.example.com": 1, "github.com": 0,
	} {
		got := -1
		if tg, ok := m.Pick(name); ok {
			got = tg
		}
		if got != want {
			t.Errorf("%s: %d, want %d", name, got, want)
		}
	}
}

// Names change while running: the new set replaces the old one whole, a
// conflict changes nothing, and a target switched off stays off.
func TestSetNames(t *testing.T) {
	m, err := NewMultiMatcher([]Names{{Domains: []string{"a.example"}}, {Domains: []string{"b.example"}}})
	if err != nil {
		t.Fatal(err)
	}
	pick := func(name string) int {
		if tg, ok := m.Pick(name); ok {
			return tg
		}
		return -1
	}
	m.SetOn(1, false)
	if err := m.SetNames([]Names{{Domains: []string{"a.example", "c.example"}}, {Domains: []string{"."}, Patterns: []string{`^db\.`}}}); err != nil {
		t.Fatal(err)
	}
	if pick("x.c.example") != 0 || pick("db.z.example") != -1 || !m.CatchAll() {
		t.Errorf("after SetNames: c=%d db=%d all=%v", pick("x.c.example"), pick("db.z.example"), m.CatchAll())
	}
	m.SetOn(1, true)
	if pick("db.z.example") != 1 || pick("github.com") != 1 || pick("b.example") != 1 {
		t.Errorf("target 1 back on: db=%d github=%d b=%d", pick("db.z.example"), pick("github.com"), pick("b.example"))
	}
	for _, bad := range [][]Names{
		{{Domains: []string{"a.example"}}, {Domains: []string{"a.example"}}}, // the same domain twice
		{{Domains: []string{"."}}, {Domains: []string{"."}}},                 // "." twice
		{{Patterns: []string{"("}}, {}},                                      // not an expression
		{{Domains: []string{"a.example"}}},                                   // a tunnel missing
	} {
		if err := m.SetNames(bad); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
	if pick("x.c.example") != 0 || !m.CatchAll() {
		t.Error("a refused change changed the names")
	}
}

// A tunnel added while running: a new target, off until switched on.
func TestSetNamesGrows(t *testing.T) {
	m, err := NewMultiMatcher([]Names{{Domains: []string{"a.example"}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.SetNames([]Names{{Domains: []string{"a.example"}}, {Domains: []string{"b.example"}}}); err != nil {
		t.Fatal(err)
	}
	if _, ok := m.Pick("x.b.example"); ok {
		t.Error("a new target is on before SetOn")
	}
	m.SetOn(1, true)
	if tg, ok := m.Pick("x.b.example"); !ok || tg != 1 {
		t.Errorf("after SetOn: %d %v", tg, ok)
	}
	if tg, _ := m.Pick("x.a.example"); tg != 0 {
		t.Errorf("target 0: %d", tg)
	}
}
