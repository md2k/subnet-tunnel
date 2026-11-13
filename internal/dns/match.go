package dns

import (
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"sync/atomic"
)

// Matcher decides which names are resolved through the tunnel.
type Matcher struct {
	all      bool
	domains  []string
	patterns []*regexp.Regexp
	local    atomic.Pointer[[]string] // suffixes "." leaves alone; see SetLocal
}

// NewMatcher builds a matcher from domain suffixes and regular expressions.
//
// A domain matches itself and every name below it: "company.com" matches
// "company.com" and "db.eu.company.com", not "badcompany.com". "." matches
// every name except local ones (see SetLocal). A leading "*.", "." or ".*."
// (sshuttle's pattern form) is accepted and ignored.
//
// Patterns are Go regular expressions (RE2), matched against the lowercase
// name without the trailing dot, unanchored: write ^ and $ where needed.
func NewMatcher(domains, patterns []string) (*Matcher, error) {
	m := &Matcher{}
	seen := map[string]bool{}
	for _, d := range domains {
		n, err := NormalizeDomain(d)
		if err != nil {
			return nil, err
		}
		if n == "." {
			m.all = true
			continue
		}
		if !seen[n] {
			seen[n] = true
			m.domains = append(m.domains, n)
		}
	}
	for _, p := range patterns {
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("DNS pattern %q: %w", p, err)
		}
		m.patterns = append(m.patterns, re)
	}
	m.SetLocal(nil, nil)
	return m, nil
}

// CatchAll reports whether "." is among the domains.
func (m *Matcher) CatchAll() bool { return m.all }

// SetLocal sets the system's search domains and the machine's networks.
// With ".", names under "local" (multicast DNS), under the search domains
// (a router's "lan" or "home.arpa", short names completed with them) and
// under the reverse zones of the networks and of link-local addresses
// (PTR lookups and DNS-SD browsing for the LAN) stay with the fallback
// resolver: they belong to the local network, and the target's resolver
// can't answer them. A listed domain or pattern still sends such a name
// through the tunnel ("cluster.local"). It reports whether the list
// changed.
func (m *Matcher) SetLocal(search []string, networks []netip.Prefix) bool {
	list := []string{"local"}
	for _, d := range append(search, ReverseZones(networks)...) {
		n, err := NormalizeDomain(d)
		if err != nil || n == "." || slices.Contains(list, n) {
			continue
		}
		list = append(list, n)
	}
	if old := m.local.Load(); old != nil && slices.Equal(*old, list) {
		return false
	}
	m.local.Store(&list)
	return true
}

// Local returns the suffixes "." leaves alone.
func (m *Matcher) Local() []string { return *m.local.Load() }

// Empty reports whether the matcher matches nothing.
func (m *Matcher) Empty() bool { return !m.all && len(m.domains) == 0 && len(m.patterns) == 0 }

// Match reports whether name (any case, trailing dot optional) goes through
// the tunnel.
func (m *Matcher) Match(name string) bool {
	name = normalize(name)
	for _, d := range m.domains {
		if under(name, d) {
			return true
		}
	}
	for _, re := range m.patterns {
		if re.MatchString(name) {
			return true
		}
	}
	if !m.all {
		return false
	}
	for _, d := range *m.local.Load() {
		if under(name, d) {
			return false
		}
	}
	return true
}

// under reports whether name is d or below it.
func under(name, d string) bool { return name == d || strings.HasSuffix(name, "."+d) }

// NormalizeDomain checks a domain suffix and returns it lowercase without
// leading ".*." / "*." / "." or trailing dot; "." stays ".".
func NormalizeDomain(d string) (string, error) {
	s := strings.ToLower(strings.TrimSpace(d))
	if s == "." {
		return ".", nil
	}
	for _, prefix := range []string{".*.", "*.", "."} {
		if strings.HasPrefix(s, prefix) {
			s = s[len(prefix):]
			break
		}
	}
	s = strings.TrimSuffix(s, ".")
	if strings.ContainsAny(s, "*()[]\\^$+?|{}") {
		return "", fmt.Errorf("DNS domain %q looks like a regular expression: domains are plain suffixes (company.com); put expressions in patterns", d)
	}
	if s == "" || len(s) > 253 {
		return "", fmt.Errorf("DNS domain %q: not a domain name", d)
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 {
			return "", fmt.Errorf("DNS domain %q: not a domain name", d)
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return "", fmt.Errorf("DNS domain %q: not a domain name", d)
			}
		}
	}
	return s, nil
}

// linkLocalZones are the reverse zones of link-local addresses: IPv4
// 169.254.0.0/16, and fe00::/8 for IPv6 (fe80::/10 and the rest of the
// non-global block).
var linkLocalZones = []string{"254.169.in-addr.arpa", "e.f.ip6.arpa"}

// ReverseZones returns the in-addr.arpa zones covering the IPv4 networks,
// plus the link-local zones. Zones follow octet boundaries: a /24 or longer
// is its /24's zone, a /8 or /16 its own; a network between two boundaries
// is the zones of the next longer one when that's at most 16 of them, else
// the zone of the shorter one (192.168.0.0/22: four /24 zones; 10.0.0.0/17:
// 0.10.in-addr.arpa).
func ReverseZones(networks []netip.Prefix) []string {
	var out []string
	add := func(z string) {
		if !slices.Contains(out, z) {
			out = append(out, z)
		}
	}
	for _, p := range networks {
		p = p.Masked()
		if !p.Addr().Is4() || p.Bits() < 8 {
			continue
		}
		bits := p.Bits()
		below := min(bits/8*8, 24)
		if bits >= 24 || bits%8 == 0 {
			add(zone(p.Addr(), below))
			continue
		}
		next := below + 8
		if next-bits > 4 {
			add(zone(p.Addr(), below))
			continue
		}
		b := p.Addr().As4()
		v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
		for i := 0; i < 1<<(next-bits); i++ {
			w := v + uint32(i)<<(32-next)
			add(zone(netip.AddrFrom4([4]byte{byte(w >> 24), byte(w >> 16), byte(w >> 8), byte(w)}), next))
		}
	}
	return append(out, linkLocalZones...)
}

// zone is the in-addr.arpa zone of a's first bits (8, 16 or 24).
func zone(a netip.Addr, bits int) string {
	b := a.As4()
	labels := make([]string, 0, 4)
	for i := bits/8 - 1; i >= 0; i-- {
		labels = append(labels, fmt.Sprint(b[i]))
	}
	return strings.Join(append(labels, "in-addr.arpa"), ".")
}
