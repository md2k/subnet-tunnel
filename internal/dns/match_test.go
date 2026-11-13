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
	if !m.SetLocal([]string{"lan", "Home.Arpa.", "lan", "."}) || m.SetLocal([]string{"lan", "home.arpa"}) {
		t.Fatal("SetLocal change reporting wrong")
	}
	if got := m.Local(); !slices.Equal(got, []string{"local", "lan", "home.arpa"}) {
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
	split.SetLocal([]string{"corp.example"})
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
