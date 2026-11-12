package netstack

import (
	"sync"
	"time"
)

// Loop guard defaults.
const (
	// DefaultMaxOpening is how many connections to one destination (address
	// and port) may be opening at once.
	DefaultMaxOpening = 64
	// DefaultMaxOpen is how many may be open or opening at once.
	DefaultMaxOpen = 256
	// DefaultLoopHold is how long a destination that hit a cap is refused.
	DefaultLoopHold = 10 * time.Second

	loopWarnEvery = time.Minute // refusals: one warning per destination
	failInfoEvery = time.Minute // connect failures at info level, the rest at debug
	maxTracked    = 4096        // per-destination log state kept before pruning
)

// loopGuard limits connections per destination to cut routing loops.
//
// A routing loop opens connections to one destination without end: the
// target reaches the address through this machine (Docker Desktop, kind,
// minikube send their traffic out through the host), the routes send that
// back into the tunnel, to the target again, and so on. Each new connection
// waits on the next while it's being dialed (a proxy that connects onward
// before accepting, like Docker Desktop's) or stays open (one that accepts
// first). So there are two caps: connections still opening, and all open
// ones. When either is hit the destination is refused for a while, so the
// chain unwinds and retries don't build a new one each time. Normal clients
// stay far below both.
type loopGuard struct {
	maxOpening, maxOpen int
	hold                time.Duration
	now                 func() time.Time

	mu      sync.Mutex
	opening map[string]int
	open    map[string]int
	held    map[string]time.Time // refused until
	warned  map[string]warnState
	failed  map[string]time.Time // last info-level connect failure
}

type warnState struct {
	at      time.Time // last warning
	refused int       // refusals since then
}

func newLoopGuard(maxOpening, maxOpen int, hold time.Duration) *loopGuard {
	return &loopGuard{
		maxOpening: maxOpening, maxOpen: maxOpen, hold: hold, now: time.Now,
		opening: map[string]int{}, open: map[string]int{}, held: map[string]time.Time{},
		warned: map[string]warnState{}, failed: map[string]time.Time{},
	}
}

// acquire counts a new connection to dst, or refuses it: while dst is held,
// or when it hits a cap, which starts a hold. For a refusal, warn says
// whether to log one now, and refused how many connections were refused
// since the last warning (this one included).
func (g *loopGuard) acquire(dst string) (ok, warn bool, refused int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	if until, held := g.held[dst]; held && now.Before(until) {
		return g.refuse(dst, now)
	} else if held {
		delete(g.held, dst)
	}
	if g.opening[dst] >= g.maxOpening || g.open[dst] >= g.maxOpen {
		g.held[dst] = now.Add(g.hold)
		return g.refuse(dst, now)
	}
	g.opening[dst]++
	g.open[dst]++
	return true, false, 0
}

func (g *loopGuard) refuse(dst string, now time.Time) (ok, warn bool, refused int) {
	w := g.warned[dst]
	w.refused++
	if !w.at.IsZero() && now.Sub(w.at) < loopWarnEvery {
		g.warned[dst] = w
		return false, false, 0
	}
	g.warned[dst] = warnState{at: now}
	for d, s := range g.warned { // forget old ones, so the maps stay small
		if now.Sub(s.at) >= loopWarnEvery {
			delete(g.warned, d)
		}
	}
	for d, until := range g.held {
		if !now.Before(until) {
			delete(g.held, d)
		}
	}
	return false, true, w.refused
}

// dialed ends the opening phase of a connection acquire counted, whether
// the dial worked or not.
func (g *loopGuard) dialed(dst string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	dec(g.opening, dst)
}

// release ends a connection acquire counted.
func (g *loopGuard) release(dst string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	dec(g.open, dst)
}

func dec(m map[string]int, k string) {
	if m[k] <= 1 {
		delete(m, k)
	} else {
		m[k]--
	}
}

// looping reports whether dst hit a cap within the last loopWarnEvery, so
// failures to reach it are part of a loop unwinding, not news.
func (g *loopGuard) looping(dst string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	w, ok := g.warned[dst]
	return ok && g.now().Sub(w.at) < loopWarnEvery
}

// reportFailure says whether a failed connect to dst should be logged at
// info level: once per failInfoEvery per destination. A loop or a dead
// destination can fail thousands of times a minute.
func (g *loopGuard) reportFailure(dst string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	if last, ok := g.failed[dst]; ok && now.Sub(last) < failInfoEvery {
		return false
	}
	if len(g.failed) >= maxTracked {
		for d, last := range g.failed {
			if now.Sub(last) >= failInfoEvery {
				delete(g.failed, d)
			}
		}
	}
	g.failed[dst] = now
	return true
}
