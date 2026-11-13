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
	"strings"
)

// Attribute keys masking applies to: DNS names asked through subtun, and
// the destinations of connections and DNS answers.
const (
	KeyName  = "name"  // a DNS name
	KeyDst   = "dst"   // a destination, address:port
	KeyAddrs = "addrs" // addresses a DNS answer points at
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

// Addr masks an address, or address:port (the port stays).
func (m *Masker) Addr(s string) string {
	if host, port, err := net.SplitHostPort(s); err == nil {
		return net.JoinHostPort("ip-"+m.hash(host), port)
	}
	return "ip-" + m.hash(s)
}

// Replace is a slog ReplaceAttr: it masks the attributes masking applies
// to.
func (m *Masker) Replace(_ []string, a slog.Attr) slog.Attr {
	if !m.Active() {
		return a
	}
	switch {
	case a.Key == KeyName && m.DNS:
		return slog.String(a.Key, m.Name(a.Value.String()))
	case (a.Key == KeyDst || a.Key == KeyAddrs) && m.Dest:
		return slog.Any(a.Key, m.addrs(a.Value))
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
