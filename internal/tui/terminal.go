package tui

import (
	"sync"
	"sync/atomic"
)

// Terminal lends the terminal of a TUI running inside subtun (subtun up
// --tui) to what needs it for a while: sudo asking for the password.
type Terminal struct {
	mu sync.Mutex
	a  *app
}

func (t *Terminal) set(a *app) {
	t.mu.Lock()
	t.a = a
	t.mu.Unlock()
}

// Lend runs f with the TUI stepped aside (the terminal as it was before
// the TUI started), then brings the TUI back. With no TUI running, it just
// runs f.
func (t *Terminal) Lend(f func()) {
	t.mu.Lock()
	a := t.a
	t.mu.Unlock()
	if a == nil {
		f()
		return
	}
	// f runs once: on the UI goroutine with the screen suspended, or here
	// when the TUI ends before it got to it.
	var claimed atomic.Bool
	done := make(chan struct{})
	a.update(func() {
		if !claimed.CompareAndSwap(false, true) {
			return
		}
		defer close(done)
		if !a.tv.Suspend(f) {
			f()
		}
	})
	select {
	case <-done:
	case <-a.ctx.Done():
	case <-a.ended:
	}
	if claimed.CompareAndSwap(false, true) {
		f()
		return
	}
	<-done
}
