package dns

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// What to do with a name resolved through the tunnel to a private address
// no route covers (dns.unrouted).
const (
	UnroutedWarn     = "warn"     // keep the answer, log it (default)
	UnroutedFallback = "fallback" // answer from the fallback resolver instead
	UnroutedBlock    = "block"    // drop those addresses from the answer
)

// ParseUnrouted checks a dns.unrouted value; "" is the default.
func ParseUnrouted(s string) (string, error) {
	switch s {
	case "":
		return UnroutedWarn, nil
	case UnroutedWarn, UnroutedFallback, UnroutedBlock:
		return s, nil
	}
	return "", fmt.Errorf("dns.unrouted %q: use warn, fallback or block", s)
}

// privateRanges are addresses that only mean something inside one network:
// an answer in them from the target's resolver points into the target's
// network (or a VPN's address space there, like 100.64.0.0/10), so only the
// tunnel can reach it. 0/8 and loopback aren't here: resolvers that block
// names answer with them on purpose.
var privateRanges = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"),
}

// Private reports whether a is in a private range (see privateRanges).
func Private(a netip.Addr) bool {
	a = a.Unmap()
	for _, p := range privateRanges {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

const unroutedLogEvery = 10 * time.Minute

// Unrouted applies dns.unrouted to answers from the tunnel.
type Unrouted struct {
	Mode string
	// Unreachable reports whether an address answered through the tunnel
	// can't be reached through it: private, and no route covers it.
	Unreachable func(netip.Addr) bool
	Log         *slog.Logger

	mu     sync.Mutex
	logged map[string]time.Time // name -> last log line
}

// check applies the policy to a tunnel answer to msg (the query). It
// returns the answer to send and a word for the log ("" if unchanged).
func (u *Unrouted) check(ctx context.Context, fallback Upstream, q query, msg, answer []byte) ([]byte, string) {
	bad := unreachableA(answer, u.Unreachable)
	if len(bad) == 0 {
		return answer, ""
	}
	switch u.Mode {
	case UnroutedFallback:
		alt, err := fallback.Exchange(ctx, msg)
		if err != nil || !answers(alt, q.header.ID) {
			u.note(q.name, slog.LevelWarn, "DNS answer through the tunnel points at an address no route covers, and the fallback resolver failed; keeping the tunnel's answer",
				"name", q.name, "addrs", bad, "err", err)
			return answer, ""
		}
		u.note(q.name, slog.LevelInfo, "DNS answer through the tunnel points at an address no route covers; answering from the fallback resolver instead",
			"name", q.name, "addrs", bad)
		return alt, "fallback (unrouted)"
	case UnroutedBlock:
		out, err := dropA(answer, u.Unreachable)
		if err != nil {
			return answer, ""
		}
		u.note(q.name, slog.LevelInfo, "DNS answer through the tunnel points at an address no route covers; dropped it from the answer",
			"name", q.name, "addrs", bad)
		return out, "blocked (unrouted)"
	default:
		u.note(q.name, slog.LevelWarn, "DNS answer through the tunnel points at an address no route covers: it won't be reached through the tunnel. Route it, or set dns.unrouted (fallback, block)",
			"name", q.name, "addrs", bad)
		return answer, ""
	}
}

// note logs at most once per name every unroutedLogEvery.
func (u *Unrouted) note(name string, level slog.Level, msg string, args ...any) {
	u.mu.Lock()
	now := time.Now()
	if u.logged == nil {
		u.logged = map[string]time.Time{}
	}
	if last, ok := u.logged[name]; ok && now.Sub(last) < unroutedLogEvery {
		u.mu.Unlock()
		return
	}
	if len(u.logged) > 1024 {
		for n, t := range u.logged {
			if now.Sub(t) >= unroutedLogEvery {
				delete(u.logged, n)
			}
		}
	}
	u.logged[name] = now
	u.mu.Unlock()
	u.Log.Log(context.Background(), level, msg, args...)
}

// unreachableA returns the A records' addresses in answer for which bad
// is true.
func unreachableA(answer []byte, bad func(netip.Addr) bool) []netip.Addr {
	var p dnsmessage.Parser
	if _, err := p.Start(answer); err != nil {
		return nil
	}
	if err := p.SkipAllQuestions(); err != nil {
		return nil
	}
	var out []netip.Addr
	for {
		h, err := p.AnswerHeader()
		if err != nil {
			return out
		}
		if h.Type != dnsmessage.TypeA {
			if err := p.SkipAnswer(); err != nil {
				return out
			}
			continue
		}
		r, err := p.AResource()
		if err != nil {
			return out
		}
		if a := netip.AddrFrom4(r.A); bad(a) {
			out = append(out, a)
		}
	}
}

// dropA rebuilds answer without the A records for which bad is true.
func dropA(answer []byte, bad func(netip.Addr) bool) ([]byte, error) {
	var p dnsmessage.Parser
	h, err := p.Start(answer)
	if err != nil {
		return nil, err
	}
	qs, err := p.AllQuestions()
	if err != nil {
		return nil, err
	}
	ans, err := p.AllAnswers()
	if err != nil {
		return nil, err
	}
	auth, err := p.AllAuthorities()
	if err != nil {
		return nil, err
	}
	add, err := p.AllAdditionals()
	if err != nil {
		return nil, err
	}
	b := dnsmessage.NewBuilder(nil, h)
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	for _, q := range qs {
		if err := b.Question(q); err != nil {
			return nil, err
		}
	}
	sections := []struct {
		start func() error
		rs    []dnsmessage.Resource
	}{{b.StartAnswers, ans}, {b.StartAuthorities, auth}, {b.StartAdditionals, add}}
	for i, sec := range sections {
		if err := sec.start(); err != nil {
			return nil, err
		}
		for _, r := range sec.rs {
			if a, ok := r.Body.(*dnsmessage.AResource); ok && i == 0 && bad(netip.AddrFrom4(a.A)) {
				continue
			}
			if err := addResource(&b, r); err != nil {
				return nil, err
			}
		}
	}
	return b.Finish()
}

func addResource(b *dnsmessage.Builder, r dnsmessage.Resource) error {
	switch body := r.Body.(type) {
	case *dnsmessage.AResource:
		return b.AResource(r.Header, *body)
	case *dnsmessage.AAAAResource:
		return b.AAAAResource(r.Header, *body)
	case *dnsmessage.CNAMEResource:
		return b.CNAMEResource(r.Header, *body)
	case *dnsmessage.MXResource:
		return b.MXResource(r.Header, *body)
	case *dnsmessage.NSResource:
		return b.NSResource(r.Header, *body)
	case *dnsmessage.PTRResource:
		return b.PTRResource(r.Header, *body)
	case *dnsmessage.SOAResource:
		return b.SOAResource(r.Header, *body)
	case *dnsmessage.SRVResource:
		return b.SRVResource(r.Header, *body)
	case *dnsmessage.TXTResource:
		return b.TXTResource(r.Header, *body)
	case *dnsmessage.OPTResource:
		return b.OPTResource(r.Header, *body)
	case *dnsmessage.UnknownResource:
		return b.UnknownResource(r.Header, *body)
	}
	return fmt.Errorf("DNS record type %v not supported for rewriting", r.Header.Type)
}
