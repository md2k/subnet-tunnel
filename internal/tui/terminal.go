package tui

import (
	"sync"
	"sync/atomic"
)

// Terminal lends the terminal of a TUI running inside subtun (subtun up
// --tui) to what needs it for a while: sudo asking for the password.
type Terminal struct {
	mu   sync.Mutex
	a    *app
	wait chan struct{} // a TUI is starting: closed once it runs, or has ended
}

// Starting says a TUI is about to run on this terminal (call it before
// Run's goroutine): Lend waits until it runs, or has ended, so sudo never
// asks while the TUI takes the terminal over.
func (t *Terminal) Starting() {
	t.mu.Lock()
	if t.wait == nil {
		t.wait = make(chan struct{})
	}
	t.mu.Unlock()
}

// Ended says the TUI is gone (Run did: a caller whose Run never got to
// run calls it); Lend then just runs f.
func (t *Terminal) Ended() { t.set(nil) }

func (t *Terminal) set(a *app) {
	t.mu.Lock()
	t.a = a
	if t.wait != nil {
		close(t.wait)
		t.wait = nil
	}
	t.mu.Unlock()
}

// Lend runs f with the TUI stepped aside (the terminal as it was before
// the TUI started), then brings the TUI back. With no TUI running, it just
// runs f.
func (t *Terminal) Lend(f func()) {
	t.mu.Lock()
	wait := t.wait
	t.mu.Unlock()
	if wait != nil {
		<-wait
	}
	t.mu.Lock()
	a := t.a
	t.mu.Unlock()
	if a == nil {
		f()
		return
	}
	// f runs once: on the UI goroutine with the screen suspended, or here
	// once the TUI has ended (and given the terminal back) before it got to
	// it.
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
	case <-a.ended: // the event loop stops after its context ends, so this comes
	}
	if claimed.CompareAndSwap(false, true) {
		f()
		return
	}
	<-done
}
