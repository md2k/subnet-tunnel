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
	start, err := guardFor(final, home)
	if err != nil {
		t.Fatal(err)
	}
	g := &guardState{prefixes: start}
	s := &seq{lists: [][]netip.Prefix{home, office}}
	applied := make(chan []netip.Prefix, 4)
	apply := func() error { applied <- g.get(); return nil }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go followLocals(ctx, time.Millisecond, final, s.read, g, apply, slog.New(slog.DiscardHandler))

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
	g := &guardState{prefixes: final}
	s := &seq{lists: [][]netip.Prefix{nil, mps("10.0.0.0/8")}} // a local network now covers every route
	var calls int
	var mu sync.Mutex
	apply := func() error { mu.Lock(); calls++; mu.Unlock(); return errors.New("unexpected") }
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	followLocals(ctx, time.Millisecond, final, s.read, g, apply, slog.New(slog.DiscardHandler))
	mu.Lock()
	defer mu.Unlock()
	if calls != 0 || !slices.Equal(g.get(), final) {
		t.Fatalf("calls %d, guard %v", calls, g.get())
	}
}
