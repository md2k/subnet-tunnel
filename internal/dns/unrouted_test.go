package dns

import (
	"bytes"
	"context"
	"log/slog"
	"net/netip"
	"slices"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func TestParseUnrouted(t *testing.T) {
	for in, want := range map[string]string{"": "warn", "warn": "warn", "fallback": "fallback", "block": "block"} {
		if got, err := ParseUnrouted(in); err != nil || got != want {
			t.Errorf("ParseUnrouted(%q) = %q, %v", in, got, err)
		}
	}
	for _, bad := range []string{"tunnel", "auto", "Warn"} {
		if _, err := ParseUnrouted(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestPrivate(t *testing.T) {
	for s, want := range map[string]bool{
		"100.64.1.1": true, "10.1.2.3": true, "172.20.0.1": true, "192.168.1.5": true, "198.18.0.9": true,
		"140.82.112.3": false, "127.0.0.1": false, "0.0.0.0": false, "8.8.8.8": false,
	} {
		if got := Private(netip.MustParseAddr(s)); got != want {
			t.Errorf("Private(%s) = %v", s, got)
		}
	}
}

func aRecords(t *testing.T, msg []byte) []netip.Addr {
	t.Helper()
	var p dnsmessage.Parser
	if _, err := p.Start(msg); err != nil {
		t.Fatal(err)
	}
	_ = p.SkipAllQuestions()
	ans, err := p.AllAnswers()
	if err != nil {
		t.Fatal(err)
	}
	var out []netip.Addr
	for _, r := range ans {
		if a, ok := r.Body.(*dnsmessage.AResource); ok {
			out = append(out, netip.AddrFrom4(a.A))
		}
	}
	return out
}

// The tunnel answers 10.96.0.0 and 10.96.0.1 (the fakes); only the second
// is unreachable here.
func TestUnroutedModes(t *testing.T) {
	second := netip.MustParseAddr("10.96.0.1")
	q := buildQuery(7, "web.company.com.", 0)
	for _, mode := range []string{UnroutedWarn, UnroutedFallback, UnroutedBlock} {
		tun, fb := &fakeUpstream{records: 2}, &fakeUpstream{records: 1}
		e := newEngine(t, tun, fb)
		e.Tunnels[0].Unrouted = &Unrouted{Mode: mode, Unreachable: func(a netip.Addr) bool { return a == second }, Log: slog.New(slog.DiscardHandler)}
		got := e.Answer(context.Background(), q, true)
		switch mode {
		case UnroutedWarn:
			if !bytes.Equal(got, buildAnswer(q, 2)) || len(fb.names()) != 0 {
				t.Errorf("warn changed the answer or asked the fallback")
			}
		case UnroutedFallback:
			if !bytes.Equal(got, buildAnswer(q, 1)) || !slices.Equal(fb.names(), []string{"web.company.com"}) {
				t.Errorf("fallback: not the fallback's answer (asked %q)", fb.names())
			}
		case UnroutedBlock:
			if a := aRecords(t, got); !slices.Equal(a, []netip.Addr{netip.MustParseAddr("10.96.0.0")}) || header(t, got).ID != 7 {
				t.Errorf("block: records %v", a)
			}
		}
	}

	// Nothing unreachable, or a name that didn't go through the tunnel: the
	// answer passes unchanged in every mode.
	for _, mode := range []string{UnroutedFallback, UnroutedBlock} {
		tun, fb := &fakeUpstream{records: 2}, &fakeUpstream{records: 2}
		e := newEngine(t, tun, fb)
		e.Tunnels[0].Unrouted = &Unrouted{Mode: mode, Unreachable: func(netip.Addr) bool { return false }, Log: slog.New(slog.DiscardHandler)}
		if got := e.Answer(context.Background(), q, true); !bytes.Equal(got, buildAnswer(q, 2)) {
			t.Errorf("%s: answer changed without unreachable addresses", mode)
		}
		e.Tunnels[0].Unrouted.Unreachable = func(netip.Addr) bool { return true }
		other := buildQuery(8, "example.org.", 0)
		if got := e.Answer(context.Background(), other, true); !bytes.Equal(got, buildAnswer(other, 2)) {
			t.Errorf("%s: a fallback answer was checked", mode)
		}
	}
}

// block keeps everything but the dropped A records (a CNAME chain, other
// sections).
func TestDropAKeepsTheRest(t *testing.T) {
	name, target := dnsmessage.MustNewName("github.com."), dnsmessage.MustNewName("lb.github.com.")
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 9, Response: true})
	_ = b.StartQuestions()
	_ = b.Question(dnsmessage.Question{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET})
	_ = b.StartAnswers()
	rh := func(n dnsmessage.Name) dnsmessage.ResourceHeader {
		return dnsmessage.ResourceHeader{Name: n, Class: dnsmessage.ClassINET, TTL: 60}
	}
	_ = b.CNAMEResource(rh(name), dnsmessage.CNAMEResource{CNAME: target})
	_ = b.AResource(rh(target), dnsmessage.AResource{A: [4]byte{100, 64, 1, 1}})
	_ = b.AResource(rh(target), dnsmessage.AResource{A: [4]byte{140, 82, 112, 3}})
	msg, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	bad := func(a netip.Addr) bool { return Private(a) }
	if got := unreachableA(msg, bad); !slices.Equal(got, []netip.Addr{netip.MustParseAddr("100.64.1.1")}) {
		t.Fatalf("unreachable %v", got)
	}
	out, err := dropA(msg, bad)
	if err != nil {
		t.Fatal(err)
	}
	var p dnsmessage.Parser
	if _, err := p.Start(out); err != nil {
		t.Fatal(err)
	}
	_ = p.SkipAllQuestions()
	ans, _ := p.AllAnswers()
	if len(ans) != 2 || ans[0].Header.Type != dnsmessage.TypeCNAME || aRecords(t, out)[0] != netip.MustParseAddr("140.82.112.3") {
		t.Fatalf("after drop: %+v", ans)
	}
}
