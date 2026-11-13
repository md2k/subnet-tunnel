package logx

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"regexp"
	"strings"
)

// Attribute keys masking applies to: DNS names asked through subtun, the
// destinations of connections and DNS answers, and errors (which may repeat
// a destination: "dial 10.1.2.3:443: ...", "lookup db.corp.example: ...").
const (
	KeyName  = "name"  // a DNS name
	KeyDst   = "dst"   // a destination, address:port or name:port (SOCKS)
	KeyAddrs = "addrs" // addresses a DNS answer points at
	KeyErr   = "err"
)

var (
	ipv4Re = regexp.MustCompile(`\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b`)
	nameRe = regexp.MustCompile(`(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]\b`)
)

// Masker replaces DNS names and destinations in log records by short keyed
// hashes: the same value gives the same hash within a run, nothing links
// runs. A masked name keeps the configured domain it falls under
// ("h3fa9c1.corp.example"), so the log still says which domain was asked.
type Masker struct {
	DNS, Dest bool
	// Domains returns the configured DNS domains; nil: none.
	Domains func() []string
	key     []byte
}

// NewMasker returns a masker with a fresh key.
func NewMasker(dns, dest bool, domains func() []string) *Masker {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	return &Masker{DNS: dns, Dest: dest, Domains: domains, key: key}
}

// Active reports whether it masks anything.
func (m *Masker) Active() bool { return m != nil && (m.DNS || m.Dest) }

func (m *Masker) hash(s string) string {
	h := hmac.New(sha256.New, m.key)
	h.Write([]byte(s))
	return hex.EncodeToString(h.Sum(nil))[:6]
}

// Name masks a DNS name.
func (m *Masker) Name(name string) string {
	n := strings.TrimSuffix(strings.ToLower(name), ".")
	suffix := ""
	if m.Domains != nil {
		for _, d := range m.Domains() {
			d = strings.TrimSuffix(strings.ToLower(d), ".")
			if d == "" || d == "." || len(d) <= len(suffix) {
				continue
			}
			if n == d || strings.HasSuffix(n, "."+d) {
				suffix = d
			}
		}
	}
	if suffix == "" { // the last two labels
		labels := strings.Split(n, ".")
		if len(labels) <= 2 {
			return "h" + m.hash(n)
		}
		suffix = strings.Join(labels[len(labels)-2:], ".")
	}
	if n == suffix {
		return n
	}
	return "h" + m.hash(n) + "." + suffix
}

// Addr masks an address, or address:port (the port stays). A host name
// (a SOCKS destination) is masked as a name.
func (m *Masker) Addr(s string) string {
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		host, port = s, ""
	}
	masked := "ip-" + m.hash(host)
	if _, err := netip.ParseAddr(host); err != nil {
		masked = m.Name(host)
	}
	if port == "" {
		return masked
	}
	return net.JoinHostPort(masked, port)
}

// scrub masks what an error text repeats: addresses (destinations) and
// names (DNS).
func (m *Masker) scrub(s string) string {
	if m.Dest {
		s = ipv4Re.ReplaceAllStringFunc(s, func(a string) string { return "ip-" + m.hash(a) })
	}
	if m.DNS {
		s = nameRe.ReplaceAllStringFunc(s, m.Name)
	}
	return s
}

// Replace is a slog ReplaceAttr: it masks the attributes masking applies
// to.
func (m *Masker) Replace(_ []string, a slog.Attr) slog.Attr {
	if !m.Active() {
		return a
	}
	switch a.Key {
	case KeyName:
		if m.DNS {
			return slog.String(a.Key, m.Name(a.Value.String()))
		}
	case KeyDst:
		// An address is a destination; a host name (SOCKS) a name too.
		host, _, err := net.SplitHostPort(a.Value.String())
		if err != nil {
			host = a.Value.String()
		}
		if _, err := netip.ParseAddr(host); err == nil && m.Dest || err != nil && (m.DNS || m.Dest) {
			return slog.String(a.Key, m.Addr(a.Value.String()))
		}
	case KeyAddrs:
		if m.Dest {
			return slog.Any(a.Key, m.addrs(a.Value))
		}
	case KeyErr:
		return slog.String(a.Key, m.scrub(a.Value.String()))
	}
	return a
}

func (m *Masker) addrs(v slog.Value) any {
	switch x := v.Any().(type) {
	case []netip.Addr:
		out := make([]string, len(x))
		for i, a := range x {
			out[i] = m.Addr(a.String())
		}
		return out
	case []string:
		out := make([]string, len(x))
		for i, a := range x {
			out[i] = m.Addr(a)
		}
		return out
	case netip.Addr, netip.AddrPort, string:
		return m.Addr(fmt.Sprint(x))
	}
	return m.Addr(v.String())
}
