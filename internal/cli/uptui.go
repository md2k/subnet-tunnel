package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/term"

	"github.com/md2k/subnet-tunnel/internal/control"
	"github.com/md2k/subnet-tunnel/internal/logring"
	"github.com/md2k/subnet-tunnel/internal/privhelper"
	"github.com/md2k/subnet-tunnel/internal/tui"
)

// tuiTail is how many log lines are printed when the TUI closes after
// subtun stopped by itself (a stop asked for prints the lines from it).
const tuiTail = 20

// The terminal the TUI runs in; replaced in tests.
var (
	isTerminal           = func() bool { return term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd())) }
	tuiOut     io.Writer = os.Stderr
	runTUI               = tui.Run
)

func checkTUI(dryRun bool) error {
	if dryRun {
		return errors.New("--tui and --dry-run don't go together: a dry run only prints the plan")
	}
	if !isTerminal() {
		return errors.New("--tui needs a terminal")
	}
	return nil
}

// upTUI is the terminal UI of subtun up --tui: the same as subtun tui's,
// on the run's API in memory, with changes allowed whatever control says.
type upTUI struct {
	cancel  context.CancelFunc
	done    chan error
	ring    *logring.Ring
	term    *tui.Terminal
	stopped chan uint64 // the last log line's number before the stop
}

// startUpTUI shows the TUI until end. stop stops subtun (q, after asking);
// stopping is closed once subtun stops for whatever reason.
func startUpTUI(srv *control.Server, ring *logring.Ring, configFile string, stop func(), stopping <-chan struct{}) *upTUI {
	ctx, cancel := context.WithCancel(context.Background())
	u := &upTUI{cancel: cancel, done: make(chan error, 1), ring: ring, term: &tui.Terminal{}, stopped: make(chan uint64, 1)}
	o := tuiOptions(tuiFromConfig(configFile, io.Discard), "", "", "")
	o.Source, o.Stop, o.Stopping, o.Terminal = tui.API(srv.InMemory(ctx)), stop, stopping, u.term
	go func() {
		err := runTUI(ctx, o)
		if err != nil && ctx.Err() == nil {
			stop() // no TUI: no way to see or stop the run
		}
		u.done <- err
	}()
	return u
}

// lend has the terminal while sudo may ask for the password.
func (u *upTUI) lend() privhelper.Lend {
	return func(f func()) {
		u.term.Lend(func() {
			fmt.Fprintln(tuiOut, "subtun: the terminal UI steps aside for sudo; it comes back once the root helper runs")
			f()
		})
	}
}

// stopping marks where the stop's log lines begin (before "shutting
// down"); only the first mark counts.
func (u *upTUI) stopping() {
	select {
	case u.stopped <- lastSeq(u.ring):
	default:
	}
}

// end closes the TUI once subtun has stopped, and prints the log lines of
// the stop (the last ones when subtun stopped by itself): what it shows
// goes with it.
func (u *upTUI) end() {
	u.cancel()
	err := <-u.done
	var from uint64
	marked := false
	select {
	case from = <-u.stopped:
		marked = true
	default:
	}
	lines := u.ring.Lines()
	start := max(len(lines)-tuiTail, 0)
	if marked {
		start = len(lines)
		for start > 0 && lines[start-1].Seq > from {
			start--
		}
	}
	for _, l := range lines[start:] {
		fmt.Fprintln(tuiOut, l.Text)
	}
	if err != nil {
		fmt.Fprintf(tuiOut, "subtun: terminal UI: %v\n", err)
	}
}

func lastSeq(r *logring.Ring) uint64 {
	lines := r.Lines()
	if len(lines) == 0 {
		return 0
	}
	return lines[len(lines)-1].Seq
}
