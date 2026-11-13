package capture

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/md2k/subnet-tunnel/internal/routes"
)

// Guard is what the kill switch guards, before the local networks are
// taken out.
type Guard struct {
	// Base is guarded while subtun runs and stays blocked when the tunnel
	// goes away: the routes of the profiles with a kill switch.
	Base []netip.Prefix
	// Lockdown is the part that also stays blocked after a deliberate stop
	// (the profiles in lockdown mode); a subset of Base.
	Lockdown []netip.Prefix
}

// guardState is the kill switch's current guard. It follows the machine's
// networks: the base minus the local networks more specific than it (as in
// the routing table), so a network joined later (another Wi-Fi, with
// another subnet) isn't blocked, router and DHCP included. With several
// tunnels the base changes as profiles come and go.
type guardState struct {
	mu       sync.Mutex
	base     Guard
	locals   []netip.Prefix
	prefixes []netip.Prefix // base.Base minus locals: guarded now
	lockdown []netip.Prefix // base.Lockdown minus locals
}

func newGuardState(g Guard, locals []netip.Prefix) (*guardState, error) {
	s := &guardState{locals: locals}
	if _, err := s.setBase(g); err != nil {
		return nil, err
	}
	return s, nil
}

func (g *guardState) get() []netip.Prefix {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.prefixes
}

func (g *guardState) getLockdown() []netip.Prefix {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.lockdown
}

// setBase recomputes the guard for a new base (several tunnels: profiles
// came or went) and reports whether what is guarded changed.
func (g *guardState) setBase(base Guard) (changed bool, err error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.recompute(base, g.locals, false)
}

// setLocals recomputes the guard for new local networks. A guard that
// would be empty while the base isn't (every route a local network) is
// kept as it was, with errEmptyGuard.
func (g *guardState) setLocals(locals []netip.Prefix) (changed bool, err error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.recompute(g.base, locals, true)
}

var errEmptyGuard = errors.New("every guarded route is a local network")

func (g *guardState) recompute(base Guard, locals []netip.Prefix, keepIfEmpty bool) (bool, error) {
	prefixes, err := guardFor(base.Base, locals)
	if err != nil {
		return false, err
	}
	if keepIfEmpty && len(prefixes) == 0 && len(base.Base) > 0 {
		return false, errEmptyGuard
	}
	lockdown, err := guardFor(base.Lockdown, locals)
	if err != nil {
		return false, err
	}
	changed := !slices.Equal(prefixes, g.prefixes) || !slices.Equal(lockdown, g.lockdown)
	g.base, g.locals, g.prefixes, g.lockdown = base, locals, prefixes, lockdown
	return changed, nil
}

// guardFor computes the guarded prefixes for the routes and local networks.
func guardFor(final, locals []netip.Prefix) ([]netip.Prefix, error) {
	if len(final) == 0 {
		return nil, nil
	}
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
func followLocals(ctx context.Context, interval time.Duration, read func() []netip.Prefix,
	g *guardState, apply func() error, log *slog.Logger) {
	watchLocals(ctx, interval, read, func(locals []netip.Prefix) {
		changed, err := g.setLocals(locals)
		if err != nil {
			log.Warn("local networks changed, but the kill switch keeps its guard", "err", err)
			return
		}
		if !changed {
			return
		}
		if err := apply(); err != nil {
			if ctx.Err() == nil {
				log.Warn("local networks changed, but updating the kill switch failed", "err", err)
			}
			return
		}
		log.Info("local networks changed; kill switch follows", "guarded_prefixes", len(g.get()))
	})
}
