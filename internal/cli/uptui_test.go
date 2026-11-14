package cli

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/md2k/subnet-tunnel/internal/agentbin"
	"github.com/md2k/subnet-tunnel/internal/capture"
	"github.com/md2k/subnet-tunnel/internal/control"
	"github.com/md2k/subnet-tunnel/internal/logring"
	"github.com/md2k/subnet-tunnel/internal/meter"
	"github.com/md2k/subnet-tunnel/internal/privhelper"
	"github.com/md2k/subnet-tunnel/internal/transport"
	"github.com/md2k/subnet-tunnel/internal/tui"
)

// syncBuffer is a bytes.Buffer safe to read while written.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// The TUI inside subtun talks to the run through its API in memory, makes
// changes under control: status, and q stops subtun as a signal would;
// when it closes, the stop's log lines are printed.
func TestUpTUI(t *testing.T) {
	origCtl, origCap, origLeft := startControl, startCapture, leftoversMarked
	origTerm, origOut, origRun := isTerminal, tuiOut, runTUI
	t.Cleanup(func() {
		startControl, startCapture, leftoversMarked = origCtl, origCap, origLeft
		isTerminal, tuiOut, runTUI = origTerm, origOut, origRun
	})
	sockets := make(chan *engineStatus, 1)
	startControl = func(_ context.Context, es *engineStatus, _ *logring.Ring, _ *slog.Logger) { sockets <- es }
	leftoversMarked = func() bool { return false }
	startCapture = func(context.Context, *multiPlan, []bool, []*liveTunnel, []meter.Dialer, *router, *privhelper.Client, *leftovers, bool, func(string), *slog.Logger) (*capture.Capture, error) {
		return nil, errors.New("no capture in tests")
	}
	isTerminal = func() bool { return true }
	out := &syncBuffer{}
	tuiOut = out
	opened := make(chan tui.Options, 1)
	closed := make(chan struct{})
	runTUI = func(ctx context.Context, o tui.Options) error {
		opened <- o
		<-ctx.Done()
		close(closed)
		return nil
	}

	mp := multiPlanFor(t, "work", "dev")
	connects := make(chan string, 16)
	for _, sp := range mp.specs {
		sp.s.socks = ""
		name := sp.name
		sp.connect = func(ctx context.Context, _ []agentbin.Binary, _ *slog.Logger) (*transport.Carrier, error) {
			connects <- name
			<-ctx.Done()
			return nil, ctx.Err()
		}
	}
	done := make(chan error, 1)
	go func() {
		done <- runEngine(context.Background(), &globalOpts{}, mp, engineOpts{control: controlStatus, tui: true})
	}()
	es := <-sockets
	o := <-opened
	for range 2 {
		<-connects
	}
	if o.Stop == nil || o.Stopping == nil || o.Terminal == nil || mp.lend == nil {
		t.Fatalf("not inside: %+v, lend %v", o, mp.lend != nil)
	}
	// The socket stays read only (control: status); the TUI changes things.
	if srv := es.server(logring.New(0, 0), slog.Default(), es.control == controlFull); srv.Change != nil {
		t.Error("the socket takes changes under control: status")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	st, err := o.Source.Status(ctx)
	if err != nil || st.Control != controlStatus || len(st.Tunnels) != 2 {
		t.Fatalf("status through the TUI's source: %+v %v", st, err)
	}
	res, err := o.Source.Change(ctx, control.Change{Kind: control.KindRoute, Op: "add", Profile: "dev", CIDRs: []string{"10.70.0.0/16"}})
	if err != nil || !res.Changed {
		t.Fatalf("change through the TUI: %+v %v", res, err)
	}

	var held []string
	lctx, lcancel := context.WithTimeout(ctx, 300*time.Millisecond)
	_ = o.Source.Logs(lctx, func(l logring.Line) { held = append(held, l.Text) })
	lcancel()
	if !strings.Contains(strings.Join(held, "\n"), "10.70.0.0/16") {
		t.Fatalf("the change isn't in the TUI's log lines: %q", held)
	}

	o.Stop() // q, confirmed
	select {
	case <-o.Stopping:
	case <-time.After(5 * time.Second):
		t.Fatal("stopping not said")
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("a stop asked for ended with %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("subtun didn't stop")
	}
	select {
	case <-closed:
	default:
		t.Error("the TUI is still open")
	}
	printed := out.String()
	first, _, _ := strings.Cut(printed, "\n")
	if !strings.Contains(first, "shutting down") || strings.Contains(printed, "10.70.0.0/16") {
		t.Errorf("printed when the TUI closed: the stop's lines only, from shutting down:\n%s", printed)
	}
}

// A TUI that can't start stops the run: nothing would show it, or stop it.
func TestUpTUIFails(t *testing.T) {
	origCtl, origCap, origLeft := startControl, startCapture, leftoversMarked
	origTerm, origOut, origRun := isTerminal, tuiOut, runTUI
	t.Cleanup(func() {
		startControl, startCapture, leftoversMarked = origCtl, origCap, origLeft
		isTerminal, tuiOut, runTUI = origTerm, origOut, origRun
	})
	startControl = func(context.Context, *engineStatus, *logring.Ring, *slog.Logger) {}
	leftoversMarked = func() bool { return false }
	isTerminal = func() bool { return true }
	out := &syncBuffer{}
	tuiOut = out
	runTUI = func(context.Context, tui.Options) error { return errors.New("no tty") }
	mp := multiPlanFor(t, "work")
	mp.specs[0].s.socks = ""
	mp.specs[0].connect = func(ctx context.Context, _ []agentbin.Binary, _ *slog.Logger) (*transport.Carrier, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	done := make(chan error, 1)
	go func() { done <- runEngine(context.Background(), &globalOpts{}, mp, engineOpts{tui: true}) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("subtun went on without its TUI")
	}
	if !strings.Contains(out.String(), "subtun: terminal UI: no tty") {
		t.Errorf("printed: %s", out.String())
	}
}

func TestTUIFlagRefused(t *testing.T) {
	origTerm := isTerminal
	t.Cleanup(func() { isTerminal = origTerm })
	isTerminal = func() bool { return false }
	for name, tc := range map[string]struct {
		args []string
		want string
	}{
		"dry run":            {[]string{"--config", "testdata/multi.yaml", "up", "work", "--tui", "--dry-run"}, "--tui and --dry-run don't go together"},
		"dry run, several":   {[]string{"--config", "testdata/multi.yaml", "up", "--profile", "work,dev", "--tui", "--dry-run"}, "--tui and --dry-run don't go together"},
		"no terminal":        {[]string{"--config", "testdata/multi.yaml", "up", "work", "--tui"}, "--tui needs a terminal"},
		"no terminal, k8s":   {[]string{"k8s", "toolbox", "--socks", "127.0.0.1:0", "--tui"}, "--tui needs a terminal"},
		"no terminal, multi": {[]string{"--config", "testdata/multi.yaml", "up", "--profile", "work,dev", "--tui"}, "--tui needs a terminal"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := runCLI(t, tc.args...); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("%v, want %q", err, tc.want)
			}
		})
	}
}
