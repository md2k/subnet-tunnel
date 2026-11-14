package tui

import (
	"strings"
	"testing"
	"time"

	"github.com/gdamore/tcell/v2"
)

func waitStop(t *testing.T, stops <-chan struct{}) {
	t.Helper()
	select {
	case <-stops:
	case <-time.After(5 * time.Second):
		t.Fatal("subtun wasn't stopped")
	}
}

// Inside subtun (up --tui): changes work under control: status; q asks
// before stopping subtun, worded by the kill switches; the TUI then shows
// the stop until subtun ends it.
func TestInside(t *testing.T) {
	f := newFake("status")
	stops := make(chan struct{}, 4)
	u := start(t, f, Options{Stop: func() { stops <- struct{}{} }})
	u.wait("control status", "? help · q stop")
	if strings.Contains(u.text(), "read only") {
		t.Error("read only, inside subtun")
	}
	u.press("s") // a change: asks, with its dry run
	u.wait("Stop work?", "Dry run")
	u.key(tcell.KeyEscape)
	u.gone("Stop work?")

	u.press("q")
	u.wait("Stop subtun?", "vault: kill switch lockdown: blocking rules stay", "work: kill switch on: its blocks are lifted")
	u.key(tcell.KeyEscape)
	u.gone("Stop subtun?")
	select {
	case <-stops:
		t.Fatal("stopped on esc")
	default:
	}

	u.press("q")
	u.wait("Stop subtun?")
	u.key(tcell.KeyEnter) // the focused button: Stop subtun
	waitStop(t, stops)
	u.gone("Stop subtun?")
	u.wait("stopping…")
	u.press("s")
	u.wait("subtun is stopping")
	u.press("?") // the key list says what q does here
	u.wait("q (or Ctrl-C) stops subtun, after asking")
}

// Ctrl-C asks too, over any dialog; a second one stops at once. A stop
// from elsewhere (a signal) closes the question and shows the stop.
// (One TUI at a time: each sets tview's styles; subtests end theirs.)
func TestInsideCtrlC(t *testing.T) {
	t.Run("ctrl-c", func(t *testing.T) {
		stops := make(chan struct{}, 4)
		u := start(t, newFake("full"), Options{Stop: func() { stops <- struct{}{} }})
		u.wait("control full")
		u.press("a") // the add-profile dialog
		u.wait("Add a profile")
		u.key(tcell.KeyCtrlC)
		u.gone("Add a profile")
		u.wait("Stop subtun?", "Ctrl-C again stops at once")
		u.key(tcell.KeyCtrlC)
		waitStop(t, stops)
		u.wait("stopping…")
	})
	t.Run("signal", func(t *testing.T) {
		stopping := make(chan struct{})
		u := start(t, newFake("full"), Options{Stop: func() {}, Stopping: stopping})
		u.press("q")
		u.wait("Stop subtun?")
		close(stopping)
		u.gone("Stop subtun?")
		u.wait("stopping…")
	})
}

// Lend runs f with the TUI stepped aside, and the TUI comes back; with no
// TUI running it just runs f.
func TestTerminalLend(t *testing.T) {
	term := &Terminal{}
	ran := false
	term.Lend(func() { ran = true })
	if !ran {
		t.Fatal("not run without a TUI")
	}

	t.Run("running", func(t *testing.T) {
		u := start(t, newFake("full"), Options{Stop: func() {}, Terminal: term})
		lent := make(chan struct{})
		go term.Lend(func() { close(lent) })
		select {
		case <-lent:
		case <-time.After(5 * time.Second):
			t.Fatal("not run with the TUI")
		}
		u.press("l") // the TUI takes keys again
		u.wait("subtun › logs")
	})
	// Ended (the subtest's TUI), the TUI no longer has the terminal.
	ran = false
	term.Lend(func() { ran = true })
	if !ran {
		t.Fatal("not run after the TUI ended")
	}
}
