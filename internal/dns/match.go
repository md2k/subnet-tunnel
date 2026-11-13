package dns

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"sync/atomic"
)

// Matcher decides which names are resolved through a tunnel, and with
// several tunnels, through which one: each domain and pattern belongs to a
// target (the tunnel's index).
type Matcher struct {
	all      int // target of ".", -1: none
	domains  []domain
	patterns []pattern
	off      []atomic.Bool            // per target: switched off (its tunnel gave up)
	local    atomic.Pointer[[]string] // suffixes "." leaves alone; see SetLocal
}

type domain struct {
	name   string
	target int
}

type pattern struct {
	re     *regexp.Regexp
	target int
}

// Names is one target's domains and patterns.
type Names struct {
	Domains  []string
	Patterns []string
}

// NewMatcher builds a matcher from domain suffixes and regular expressions,
// all for one tunnel (target 0).
//
// A domain matches itself and every name below it: "company.com" matches
// "company.com" and "db.eu.company.com", not "badcompany.com". "." matches
// every name except local ones (see SetLocal). A leading "*.", "." or ".*."
// (sshuttle's pattern form) is accepted and ignored.
//
// Patterns are Go regular expressions (RE2), matched against the lowercase
// name without the trailing dot, unanchored: write ^ and $ where needed.
func NewMatcher(domains, patterns []string) (*Matcher, error) {
	return NewMultiMatcher([]Names{{Domains: domains, Patterns: patterns}})
}

// NewMultiMatcher builds a matcher for several tunnels, target i being
// sets[i]. A name goes to the target with the longest matching domain, else
// to the first target (in order) with a matching pattern, else to the
// target with "." (local names excepted). The same domain for two targets,
// or "." for more than one, is an error.
func NewMultiMatcher(sets []Names) (*Matcher, error) {
	m := &Matcher{all: -1, off: make([]atomic.Bool, len(sets))}
	owner := map[string]int{}
	for t, set := range sets {
		for _, d := range set.Domains {
			n, err := NormalizeDomain(d)
			if err != nil {
				return nil, err
			}
			if n == "." {
				if m.all >= 0 && m.all != t {
					return nil, errors.New(`DNS domain ".": only one tunnel can resolve all names`)
				}
				m.all = t
				continue
			}
			if o, ok := owner[n]; ok {
				if o != t {
					return nil, fmt.Errorf("DNS domain %q is listed for two tunnels", n)
				}
				continue
			}
			owner[n] = t
			m.domains = append(m.domains, domain{n, t})
		}
		for _, p := range set.Patterns {
			re, err := regexp.Compile(p)
			if err != nil {
				return nil, fmt.Errorf("DNS pattern %q: %w", p, err)
			}
			m.patterns = append(m.patterns, pattern{re, t})
		}
	}
	m.SetLocal(nil, nil)
	return m, nil
}

// CatchAll reports whether "." is among the domains.
func (m *Matcher) CatchAll() bool { return m.all >= 0 }

// SetOn switches a target on or off. A target that is off matches nothing:
// its names go to the next match, or the fallback.
func (m *Matcher) SetOn(target int, on bool) { m.off[target].Store(!on) }

func (m *Matcher) on(target int) bool { return !m.off[target].Load() }

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
func (m *Matcher) Empty() bool { return m.all < 0 && len(m.domains) == 0 && len(m.patterns) == 0 }

// Match reports whether name (any case, trailing dot optional) goes through
// a tunnel.
func (m *Matcher) Match(name string) bool {
	_, ok := m.Pick(name)
	return ok
}

// Pick returns the target name goes to, if any.
func (m *Matcher) Pick(name string) (target int, ok bool) {
	name = normalize(name)
	best, bestLen := -1, -1
	for _, d := range m.domains {
		if len(d.name) > bestLen && m.on(d.target) && under(name, d.name) {
			best, bestLen = d.target, len(d.name)
		}
	}
	if best >= 0 {
		return best, true
	}
	for _, p := range m.patterns {
		if m.on(p.target) && p.re.MatchString(name) {
			return p.target, true
		}
	}
	if m.all < 0 || !m.on(m.all) {
		return -1, false
	}
	for _, d := range *m.local.Load() {
		if under(name, d) {
			return -1, false
		}
	}
	return m.all, true
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
