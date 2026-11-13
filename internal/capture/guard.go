package capture

import (
	"context"
	"log/slog"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/md2k/subnet-tunnel/internal/routes"
)

// guardState is the kill switch's current guarded prefixes. They follow the
// machine's networks: routes minus the local networks more specific than
// them (as in the routing table), so a network joined later (another Wi-Fi,
// with another subnet) isn't blocked, router and DHCP included.
type guardState struct {
	mu       sync.Mutex
	prefixes []netip.Prefix
}

func (g *guardState) get() []netip.Prefix {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.prefixes
}

func (g *guardState) set(p []netip.Prefix) {
	g.mu.Lock()
	g.prefixes = p
	g.mu.Unlock()
}

// guardFor computes the guarded prefixes for the routes and local networks.
func guardFor(final, locals []netip.Prefix) ([]netip.Prefix, error) {
	p, err := routes.Compute(final, locals)
	if err != nil {
		return nil, err
	}
	return p.Routes, nil
}

// watchLocals calls fn with the machine's networks whenever they change,
// reading them with read every interval. The list at the start is the
// baseline (fn isn't called for it).
func watchLocals(ctx context.Context, interval time.Duration, read func() []netip.Prefix, fn func([]netip.Prefix)) {
	norm := func(ps []netip.Prefix) []netip.Prefix {
		out := slices.Clone(ps)
		slices.SortFunc(out, func(a, b netip.Prefix) int {
			if c := a.Addr().Compare(b.Addr()); c != 0 {
				return c
			}
			return a.Bits() - b.Bits()
		})
		return slices.Compact(out)
	}
	current := norm(read())
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		next := norm(read())
		if slices.Equal(next, current) {
			continue
		}
		current = next
		fn(next)
	}
}

// followLocals keeps the guard in step with the machine's networks: on a
// change it recomputes the guard and re-applies the firewall rules (the
// running ones and those that stay) through apply. A guard that would be
// empty (every route a local network) is kept as it was.
func followLocals(ctx context.Context, interval time.Duration, final []netip.Prefix, read func() []netip.Prefix,
	g *guardState, apply func() error, log *slog.Logger) {
	watchLocals(ctx, interval, read, func(locals []netip.Prefix) {
		next, err := guardFor(final, locals)
		if err != nil || len(next) == 0 {
			log.Warn("local networks changed, but the kill switch keeps its guard", "err", err, "guarded_prefixes", len(next))
			return
		}
		if slices.Equal(next, g.get()) {
			return
		}
		g.set(next)
		if err := apply(); err != nil {
			if ctx.Err() == nil {
				log.Warn("local networks changed, but updating the kill switch failed", "err", err)
			}
			return
		}
		log.Info("local networks changed; kill switch follows", "guarded_prefixes", len(next))
	})
}
