package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"
	"time"

	"golang.org/x/term"

	"github.com/md2k/subnet-tunnel/internal/control"
	"github.com/md2k/subnet-tunnel/internal/logring"
	"github.com/md2k/subnet-tunnel/internal/privhelper"
	"github.com/md2k/subnet-tunnel/internal/transport/k8s"
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
	// captureStderr points the process's standard error (fd 2) at the log
	// while the TUI has the terminal, so what else writes there (a
	// kubeconfig login plugin, a library) doesn't scribble over it. It
	// returns the terminal's own standard error, to write to meanwhile, and
	// restore, which puts fd 2 back.
	captureStderr = captureFd2
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

// switchWriter is the terminal's share of the log: off while the TUI has
// the terminal.
type switchWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (s *switchWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.w.Write(p)
}

func (s *switchWriter) set(w io.Writer) {
	s.mu.Lock()
	s.w = w
	s.mu.Unlock()
}

// upTUI is the terminal UI of subtun up --tui: the same as subtun tui's,
// on the run's API in memory, with changes allowed whatever control says.
type upTUI struct {
	cancel  context.CancelFunc
	done    chan error
	ring    *logring.Ring
	term    *tui.Terminal
	termLog *switchWriter
	out     io.Writer // the terminal while fd 2 goes to the log
	restore func()
	stopped chan uint64 // the last log line's number before the stop

	once sync.Once
	err  error
}

// startUpTUI shows the TUI until end. stop stops subtun (q, after asking);
// stopping is closed once subtun stops. termLog is the log's terminal
// output, off meanwhile.
func startUpTUI(srv *control.Server, ring *logring.Ring, configFile string, stop func(), stopping <-chan struct{}, termLog *switchWriter, log *slog.Logger) *upTUI {
	ctx, cancel := context.WithCancel(context.Background())
	u := &upTUI{cancel: cancel, done: make(chan error, 1), ring: ring, term: &tui.Terminal{}, termLog: termLog,
		out: tuiOut, restore: func() {}, stopped: make(chan uint64, 1)}
	termLog.set(io.Discard)
	if out, restore, err := captureStderr(log); err != nil {
		log.Debug("standard error stays the terminal's", "err", err)
	} else {
		u.out, u.restore = out, restore
	}
	k8s.StdinBusy("subtun's terminal UI has the terminal: log in first (kubectl get pods, say), then start subtun")
	hook := func() { _ = u.close(2 * time.Second) }
	beforeHardExit.Store(&hook)

	o := tuiOptions(tuiFromConfig(configFile, io.Discard), "", "", "")
	o.Source, o.Stop, o.Stopping, o.Terminal = tui.API(srv.InMemory(ctx)), stop, stopping, u.term
	u.term.Starting()
	go func() {
		err := runTUI(ctx, o)
		u.term.Ended()
		if ctx.Err() == nil {
			stop() // no TUI: nothing shows the run, or stops it
		}
		u.done <- err
	}()
	return u
}

// lend has the terminal while sudo may ask for the password.
func (u *upTUI) lend() privhelper.Lend {
	return u.lendFor("for sudo; it comes back once the root helper runs")
}

// askLend has the terminal while a connect asks a question (an SSH host
// key, a key's passphrase).
func (u *upTUI) askLend() func(func()) {
	return u.lendFor("for a question; it comes back once it's answered")
}

func (u *upTUI) lendFor(why string) func(func()) {
	return func(f func()) {
		u.term.Lend(func() {
			fmt.Fprintln(u.out, "subtun: the terminal UI steps aside "+why)
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

// end closes the TUI once subtun has stopped, gives the terminal back and
// prints the log lines of the stop (the last ones when subtun stopped by
// itself): what the TUI showed goes with it. The error is the TUI's own.
func (u *upTUI) end() error { return u.close(0) }

// close is end, waiting at most timeout for the TUI (0: as long as it
// takes): the --max-duration watchdog's way out.
func (u *upTUI) close(timeout time.Duration) error {
	u.once.Do(func() {
		u.cancel()
		if timeout > 0 {
			select {
			case u.err = <-u.done:
			case <-time.After(timeout):
			}
		} else {
			u.err = <-u.done
		}
		beforeHardExit.Store(nil)
		k8s.StdinBusy("")
		u.restore()
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
		u.termLog.set(tuiOut)
	})
	return u.err
}

func lastSeq(r *logring.Ring) uint64 {
	lines := r.Lines()
	if len(lines) == 0 {
		return 0
	}
	return lines[len(lines)-1].Seq
}
