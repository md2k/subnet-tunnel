package netstack

import (
	"sync"
	"time"
)

// DefaultMaxPerDestination is how many connections may be open or opening
// to one destination (address and port) at once.
const DefaultMaxPerDestination = 256

// loopWarnEvery is how often refusals for one destination are logged.
const loopWarnEvery = time.Minute

// loopGuard caps the connections open or opening to each destination.
//
// A routing loop opens connections to one destination without end: the
// target reaches the address through this machine (Docker Desktop, kind,
// minikube all send their traffic out through the host), the routes send
// that back into the tunnel, to the target again, and so on, each
// connection waiting on the next. At the cap the next one is refused and
// the chain unwinds within moments. Normal clients stay far below the cap,
// and ones that open and close many connections in a row don't add up,
// since only open connections count.
type loopGuard struct {
	max int
	now func() time.Time

	mu     sync.Mutex
	open   map[string]int
	warned map[string]warnState
}

type warnState struct {
	at      time.Time // last warning
	refused int       // refusals since then
}

func newLoopGuard(max int) *loopGuard {
	return &loopGuard{max: max, now: time.Now, open: map[string]int{}, warned: map[string]warnState{}}
}

// acquire counts a new connection to dst, or refuses it at the cap. For a
// refusal, warn says whether to log one now, and refused how many
// connections were refused since the last warning (this one included).
func (g *loopGuard) acquire(dst string) (ok, warn bool, refused int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.open[dst] < g.max {
		g.open[dst]++
		return true, false, 0
	}
	now := g.now()
	w := g.warned[dst]
	w.refused++
	if !w.at.IsZero() && now.Sub(w.at) < loopWarnEvery {
		g.warned[dst] = w
		return false, false, 0
	}
	g.warned[dst] = warnState{at: now}
	for d, s := range g.warned { // forget old ones, so the map stays small
		if now.Sub(s.at) >= loopWarnEvery {
			delete(g.warned, d)
		}
	}
	return false, true, w.refused
}

// release ends a connection acquire counted.
func (g *loopGuard) release(dst string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.open[dst] <= 1 {
		delete(g.open, dst)
	} else {
		g.open[dst]--
	}
}

// looping reports whether dst hit the cap within the last loopWarnEvery,
// so failures to reach it are part of a loop unwinding, not news.
func (g *loopGuard) looping(dst string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	w, ok := g.warned[dst]
	return ok && g.now().Sub(w.at) < loopWarnEvery
}
