package dns

import (
	"fmt"
	"regexp"
	"strings"
)

// Matcher decides which names are resolved through the tunnel.
type Matcher struct {
	all      bool
	domains  []string
	patterns []*regexp.Regexp
}

// NewMatcher builds a matcher from domain suffixes and regular expressions.
//
// A domain matches itself and every name below it: "company.com" matches
// "company.com" and "db.eu.company.com", not "badcompany.com". "." matches
// every name. A leading "*.", "." or ".*." (sshuttle's pattern form) is
// accepted and ignored.
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
	return m, nil
}

// Empty reports whether the matcher matches nothing.
func (m *Matcher) Empty() bool { return !m.all && len(m.domains) == 0 && len(m.patterns) == 0 }

// Match reports whether name (any case, trailing dot optional) goes through
// the tunnel.
func (m *Matcher) Match(name string) bool {
	if m.all {
		return true
	}
	name = normalize(name)
	for _, d := range m.domains {
		if name == d || strings.HasSuffix(name, "."+d) {
			return true
		}
	}
	for _, re := range m.patterns {
		if re.MatchString(name) {
			return true
		}
	}
	return false
}

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
