package capture

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"
)

func mps(ss ...string) []netip.Prefix {
	var out []netip.Prefix
	for _, s := range ss {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}

// seq hands out lists in turn, then the last one forever.
type seq struct {
	mu    sync.Mutex
	lists [][]netip.Prefix
}

func (s *seq) read() []netip.Prefix {
	s.mu.Lock()
	defer s.mu.Unlock()
	l := s.lists[0]
	if len(s.lists) > 1 {
		s.lists = s.lists[1:]
	}
	return l
}

func TestWatchLocalsReportsChangesOnly(t *testing.T) {
	s := &seq{lists: [][]netip.Prefix{
		mps("192.168.1.0/24", "198.18.249.1/32"),
		mps("198.18.249.1/32", "192.168.1.0/24"), // same, other order
		mps("10.20.0.0/16", "198.18.249.1/32"),   // another Wi-Fi
	}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	got := make(chan []netip.Prefix, 4)
	go watchLocals(ctx, time.Millisecond, s.read, func(p []netip.Prefix) { got <- p })
	select {
	case p := <-got:
		if !slices.Equal(p, mps("10.20.0.0/16", "198.18.249.1/32")) {
			t.Fatalf("changed to %v", p)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("change not reported")
	}
	select {
	case p := <-got:
		t.Fatalf("reported again: %v", p)
	case <-time.After(50 * time.Millisecond):
	}
}

// A full tunnel with a kill switch: joining another network makes the guard
// leave the new LAN out (and take the old one back in).
func TestFollowLocalsUpdatesTheGuard(t *testing.T) {
	final := mps("0.0.0.0/1", "128.0.0.0/1")
	home, office := mps("192.168.1.0/24"), mps("10.20.0.0/16")
	g, err := newGuardState(Guard{Base: final}, home)
	if err != nil {
		t.Fatal(err)
	}
	s := &seq{lists: [][]netip.Prefix{home, office}}
	applied := make(chan []netip.Prefix, 4)
	apply := func() error { applied <- g.get(); return nil }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go followLocals(ctx, time.Millisecond, s.read, g, apply, slog.New(slog.DiscardHandler))

	var now []netip.Prefix
	select {
	case now = <-applied:
	case <-time.After(3 * time.Second):
		t.Fatal("guard not re-applied")
	}
	covers := func(ps []netip.Prefix, a string) bool {
		return slices.ContainsFunc(ps, func(p netip.Prefix) bool { return p.Contains(netip.MustParseAddr(a)) })
	}
	if covers(now, "10.20.5.1") || !covers(now, "192.168.1.5") || !covers(now, "8.8.8.8") {
		t.Fatalf("guard after the change: %v", now)
	}
}

// A failing apply or a guard that would be empty leaves things as they were.
func TestFollowLocalsKeepsGuardOnEmpty(t *testing.T) {
	final := mps("10.20.0.0/16")
	g, err := newGuardState(Guard{Base: final}, nil)
	if err != nil {
		t.Fatal(err)
	}
	s := &seq{lists: [][]netip.Prefix{nil, mps("10.0.0.0/8")}} // a local network now covers every route
	var calls int
	var mu sync.Mutex
	apply := func() error { mu.Lock(); calls++; mu.Unlock(); return errors.New("unexpected") }
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	followLocals(ctx, time.Millisecond, s.read, g, apply, slog.New(slog.DiscardHandler))
	mu.Lock()
	defer mu.Unlock()
	if calls != 0 || !slices.Equal(g.get(), final) {
		t.Fatalf("calls %d, guard %v", calls, g.get())
	}
}

// Several tunnels: the base changes as profiles come and go, the local
// networks stay out of it, and the lockdown part is tracked alongside.
func TestGuardStateBaseAndLockdown(t *testing.T) {
	lan := mps("10.1.0.0/24")
	g, err := newGuardState(Guard{Base: mps("10.0.0.0/8"), Lockdown: mps("10.0.0.0/8")}, lan)
	if err != nil {
		t.Fatal(err)
	}
	covers := func(ps []netip.Prefix, a string) bool {
		return slices.ContainsFunc(ps, func(p netip.Prefix) bool { return p.Contains(netip.MustParseAddr(a)) })
	}
	if !covers(g.get(), "10.9.9.9") || covers(g.get(), "10.1.0.5") || !slices.Equal(g.get(), g.getLockdown()) {
		t.Fatalf("start: %v / %v", g.get(), g.getLockdown())
	}
	// Another profile now owns 10.50.0.0/16 and isn't in lockdown.
	changed, err := g.setBase(Guard{Base: mps("10.0.0.0/8", "172.16.0.0/12"), Lockdown: mps("10.0.0.0/8")})
	if err != nil || !changed {
		t.Fatalf("setBase: %v %v", changed, err)
	}
	if !covers(g.get(), "172.16.1.1") || covers(g.getLockdown(), "172.16.1.1") || covers(g.getLockdown(), "10.1.0.5") {
		t.Fatalf("after setBase: %v / %v", g.get(), g.getLockdown())
	}
	if changed, _ := g.setBase(Guard{Base: mps("10.0.0.0/8", "172.16.0.0/12"), Lockdown: mps("10.0.0.0/8")}); changed {
		t.Fatal("the same base reported as a change")
	}
	// Local networks change: the new base is kept.
	if changed, err := g.setLocals(mps("172.16.5.0/24")); err != nil || !changed {
		t.Fatalf("setLocals: %v %v", changed, err)
	}
	if covers(g.get(), "172.16.5.1") || !covers(g.get(), "10.1.0.5") || !covers(g.get(), "172.16.1.1") {
		t.Fatalf("after setLocals: %v", g.get())
	}
	// A guard that would be empty is kept.
	if _, err := g.setLocals(mps("10.0.0.0/8", "172.16.0.0/12")); !errors.Is(err, errEmptyGuard) || len(g.get()) == 0 {
		t.Fatalf("empty guard: %v, %v", err, g.get())
	}
}
