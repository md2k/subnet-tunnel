package tui

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gdamore/tcell/v2"

	"github.com/md2k/subnet-tunnel/internal/config"
	"github.com/md2k/subnet-tunnel/internal/control"
	"github.com/md2k/subnet-tunnel/internal/logring"
	"github.com/md2k/subnet-tunnel/internal/meter"
)

// fake is a running subtun for the TUI: no sockets.
type fake struct {
	mu      sync.Mutex
	st      control.Status
	fail    error
	cfg     control.ConfigProfiles
	lines   []logring.Line
	changes []control.Change // the ones made (not dry runs)
	dry     []control.Change
	more    chan logring.Line // lines that come later
}

func newFake(controlMode string) *fake {
	now := time.Now()
	return &fake{st: control.Status{
		PID: 4242, Started: now.Add(-time.Hour), Control: controlMode, Utun: "utun10", TunAddr: "198.18.249.1", Helper: "session",
		Tunnels: []control.Tunnel{
			{Name: "work", State: "up", Since: now.Add(-72 * time.Minute), Target: "pod ops/toolbox, container c, linux/arm64, binary agent",
				Include: []string{"10.0.0.0/8", "10.70.0.0/16"}, Routes: []string{"10.0.0.0/8"}, RoutesOn: true,
				Domains: []string{".", "corp.example"}, KillSwitch: "on", Changes: []string{"+route 10.70.0.0/16"}, Agent: "0.4.1",
				ChangedAt:  map[string]time.Time{"+route 10.70.0.0/16": time.Date(2026, 11, 14, 15, 2, 0, 0, time.Local)},
				RouteNotes: map[string]string{"10.0.0.0/8": "parts carried by dev (more specific)"}, Unrouted: "warn",
				Counts: meter.Counts{Open: 3, Total: 120, UpRate: 120_000, DownRate: 3_100_000}},
			{Name: "dev", State: "reconnecting", Attempt: 2, Attempts: 10, Include: []string{"10.50.0.0/16"}, Domains: []string{"cluster.local"},
				LastError: "pod dev/debug: not found"},
			{Name: "vault", State: "up", Since: now.Add(-time.Minute), Include: []string{"10.60.0.0/16"}, KillSwitch: "lockdown"},
		},
	}, cfg: control.ConfigProfiles{Path: "/home/u/.config/subtun/config.yaml", Profiles: []control.ConfigProfile{
		{Name: "work", InRun: true},
		{Name: "staging", Target: "pod stg/toolbox", Routes: []string{"10.80.0.0/16"}},
		{Name: "prod", Target: "pod prd/toolbox", Routes: []string{"10.0.0.0/8"}},
	}}, lines: []logring.Line{
		{Seq: 1, Time: now.Add(-3 * time.Second), Text: `time=15:01:02.114 level=INFO msg=reconnected tunnel=work via="pod ops/toolbox"`, Level: "INFO", Tunnel: "work"},
		{Seq: 2, Time: now.Add(-2 * time.Second), Text: `time=15:01:05.551 level=WARN msg="connection to the agent lost; reconnecting" tunnel=dev`, Level: "WARN", Tunnel: "dev"},
		{Seq: 3, Time: now.Add(-time.Second), Text: `time=15:01:06.000 level=DEBUG msg="dns query" tunnel=dev name=api.dev.example`, Level: "DEBUG", Tunnel: "dev"},
		{Seq: 4, Time: now.Add(-time.Second), Text: `time=15:01:07.000 level=INFO msg="helper: level=INFO msg=\"route removed\" cidr=10.60.0.0/16"`, Level: "INFO", Component: "helper"},
	}, more: make(chan logring.Line, 8)}
}

func (f *fake) Status(context.Context) (control.Status, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.st, f.fail
}

func (f *fake) Samples(context.Context) ([]control.TunnelSamples, error) {
	now := time.Now()
	var ss []meter.Sample
	for i := range 30 {
		ss = append(ss, meter.Sample{Time: now.Add(time.Duration(i-30) * time.Second), Up: uint64(i * 1000), Down: uint64(i * 100_000)})
	}
	return []control.TunnelSamples{{Name: "work", Samples: ss}}, nil
}

func (f *fake) Conns(context.Context) ([]control.TunnelConns, error) {
	return []control.TunnelConns{{Name: "work", Conns: []meter.ConnInfo{{Dst: "10.0.4.17:5432", Via: "utun", Opened: time.Now().Add(-12 * time.Minute), Up: 1_100_000, Down: 30_000_000}}}}, nil
}

func (f *fake) Config(context.Context) (control.ConfigProfiles, error) { return f.cfg, nil }

func (f *fake) Logs(ctx context.Context, fn func(logring.Line)) error {
	f.mu.Lock()
	lines := append([]logring.Line(nil), f.lines...)
	f.mu.Unlock()
	for _, l := range lines {
		fn(l)
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case l := <-f.more:
			fn(l)
		}
	}
}

func (f *fake) Change(_ context.Context, c control.Change) (control.Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if c.Profile == "prod" {
		return control.Result{}, errors.New("route 10.0.0.0/8 is work's")
	}
	what := strings.TrimSpace(fmt.Sprint(c.Op, " ", strings.Join(append(append(c.CIDRs, c.Domains...), c.Patterns...), " ")))
	if c.DryRun {
		f.dry = append(f.dry, c)
		return control.Result{Profile: c.Profile, DryRun: true, Message: "would " + what}, nil
	}
	f.changes = append(f.changes, c)
	return control.Result{Profile: c.Profile, Changed: true, Message: "did " + what}, nil
}

func (f *fake) made() []control.Change {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]control.Change(nil), f.changes...)
}

// sized is a simulation screen of a usable size (Init sets 80x25). It
// keeps a copy of the screen's text after each draw, made on the drawing
// goroutine: the simulation's cells may only be read there.
type sized struct {
	tcell.SimulationScreen
	w, h  int
	ready chan struct{} // closed once Init is done
	mu    *sync.Mutex
	shown *string
}

func (s sized) Init() error {
	err := s.SimulationScreen.Init()
	s.SetSize(s.w, s.h)
	close(s.ready)
	return err
}

func (s sized) Show() {
	s.SimulationScreen.Show()
	s.keep()
}

func (s sized) Sync() {
	s.SimulationScreen.Sync()
	s.keep()
}

func (s sized) keep() {
	cells, w, h := s.GetContents()
	var b strings.Builder
	for y := range h {
		for x := range w {
			if c := cells[y*w+x]; len(c.Runes) > 0 {
				b.WriteString(string(c.Runes))
			} else {
				b.WriteByte(' ')
			}
		}
		b.WriteByte('\n')
	}
	s.mu.Lock()
	*s.shown = b.String()
	s.mu.Unlock()
}

type ui struct {
	t   *testing.T
	sim tcell.SimulationScreen
	scr sized
}

// start runs the TUI on a 120x40 simulation screen until the test ends.
func start(t *testing.T, f *fake, o Options) *ui {
	t.Helper()
	return startSized(t, f, o, 120, 40)
}

func startSized(t *testing.T, f *fake, o Options, w, h int) *ui {
	t.Helper()
	sim := tcell.NewSimulationScreen("UTF-8")
	scr := sized{SimulationScreen: sim, w: w, h: h, ready: make(chan struct{}), mu: &sync.Mutex{}, shown: new(string)}
	o.Source, o.Screen, o.Interval = f, scr, 50*time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, o) }()
	select {
	case <-scr.ready:
	case <-time.After(5 * time.Second):
		t.Fatal("the screen wasn't set up")
	}
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("the TUI didn't stop")
		}
	})
	u := &ui{t: t, sim: sim, scr: scr}
	u.wait("subtun · pid 4242")
	return u
}

func (u *ui) text() string {
	u.scr.mu.Lock()
	defer u.scr.mu.Unlock()
	return *u.scr.shown
}

// wait waits until every text is on the screen.
func (u *ui) wait(texts ...string) {
	u.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		s := u.text()
		missing := ""
		for _, want := range texts {
			if !strings.Contains(s, want) {
				missing = want
				break
			}
		}
		if missing == "" {
			return
		}
		if time.Now().After(deadline) {
			u.t.Fatalf("%q not on the screen:\n%s", missing, s)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// gone waits until text is off the screen.
func (u *ui) gone(text string) {
	u.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for strings.Contains(u.text(), text) {
		if time.Now().After(deadline) {
			u.t.Fatalf("%q still on the screen:\n%s", text, u.text())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (u *ui) key(k tcell.Key) { u.sim.InjectKey(k, 0, tcell.ModNone) }
func (u *ui) press(keys string) {
	for _, r := range keys {
		u.sim.InjectKey(tcell.KeyRune, r, tcell.ModNone)
	}
}

// waitChange waits for the n-th change made.
func waitChange(t *testing.T, f *fake, n int) control.Change {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if m := f.made(); len(m) >= n {
			return m[n-1]
		}
		if time.Now().After(deadline) {
			t.Fatalf("change %d not made: %+v", n, f.made())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// The dashboard shows every profile and the logs; v switches the layout
// and says so, to be remembered.
func TestDashboard(t *testing.T) {
	f := newFake("full")
	layouts := make(chan string, 4)
	u := start(t, f, Options{OnLayout: func(l string) { layouts <- l }})
	u.wait("─ Profiles (3)", "▶ ● work", "up 1h12m", "reconnecting 2/10", "pod ops/toolbox", "10.0.0.0/8 +1", "lockdown",
		"120.0 kB", "3.1 MB", "reconnected", "connection to the agent lost; reconnecting", "control full", "? help · q quit",
		"helper  INFO  route removed cidr=10.60.0.0/16") // a relayed line: its source, its own message
	if strings.Contains(u.text(), "dns query") {
		t.Error("a debug line at the default level info")
	}
	u.key(tcell.KeyDown)
	u.wait("▶ ◐ dev")
	u.key(tcell.KeyUp)
	// The traffic gauge takes the table's spare width: work fills part of it.
	for _, l := range strings.Split(u.text(), "\n") {
		if strings.Contains(l, "● work") && (!strings.Contains(l, "·") || !strings.ContainsAny(l, "▏▎▍▌▋▊▉█")) {
			t.Errorf("no gauge: %q", l)
		}
	}
	// u: rates in bits a second, and back.
	u.press("u")
	u.wait("24.8 Mb", "960.0 kb")
	u.press("u")
	u.wait("3.1 MB")
	next := func() string {
		select {
		case l := <-layouts:
			return l
		case <-time.After(5 * time.Second):
			return "nothing"
		}
	}
	u.press("v")
	u.wait("routes", "+10.70.0.0/16", "kill switch on", "conns 3 open", "pod ops/toolbox · binary agent 0.4.1 · up 1h12m", "add from config")
	if l := next(); l != config.LayoutDetail {
		t.Errorf("remembered %q", l)
	}
	// The list moves the detail, and the logs, with it.
	u.key(tcell.KeyDown)
	u.wait("last error: pod dev/debug: not found", "Logs · profile: dev")
	u.gone("reconnected via")
	u.press("v")
	u.wait("Profiles (3)")
	if l := next(); l != config.LayoutTable {
		t.Errorf("remembered %q", l)
	}
}

// A read-only run shows everything and refuses the action keys, saying why.
func TestReadOnly(t *testing.T) {
	f := newFake("status")
	u := start(t, f, Options{Layout: config.LayoutDetail})
	u.wait("control status (read only)", "read only: this subtun runs with control: status")
	u.press("s")
	u.press("a")
	u.press("l") // keys are handled in order: s and a are done once the logs show
	u.wait("subtun › logs")
	f.mu.Lock()
	n := len(f.changes) + len(f.dry)
	f.mu.Unlock()
	if n != 0 {
		t.Fatalf("a read-only run was asked for %d changes", n)
	}
}

// Stopping asks first, worded by the profile's kill switch, with the dry
// run; the change is made on confirm.
func TestStop(t *testing.T) {
	f := newFake("full")
	u := start(t, f, Options{})
	u.wait("Profiles (3)")
	u.key(tcell.KeyDown)
	u.key(tcell.KeyDown)
	u.press("s")
	u.wait("Stop vault?", "kill switch lockdown: its routes stay and its traffic is refused", "work, dev go on.", "Dry run: would stop")
	u.key(tcell.KeyEnter)
	if c := waitChange(t, f, 1); c.Kind != control.KindProfile || c.Op != "stop" || c.Profile != "vault" || c.DryRun {
		t.Fatalf("change: %+v", c)
	}
	u.gone("Stop vault?")
	u.wait("profile vault: did stop")
	// Esc cancels.
	u.press("s")
	u.wait("Stop vault?")
	u.key(tcell.KeyEscape)
	u.gone("Stop vault?")
	if n := len(f.made()); n != 1 {
		t.Fatalf("%d changes", n)
	}
}

// The profile screen lists what the profile asks for and its connections;
// a adds a route after the dry run, d deletes the selected one.
func TestProfileScreen(t *testing.T) {
	f := newFake("full")
	u := start(t, f, Options{})
	u.wait("Profiles (3)")
	u.key(tcell.KeyEnter)
	u.wait("subtun › work", "work · up 1h12m · pod ops/toolbox (binary agent 0.4.1)", "Routes on the utun",
		"[a] add  [d] delete  [x] exclude", "10.0.0.0/8", "parts carried by dev (more specific)", "added 15:02", "configured",
		"DNS names through this tunnel", "(all, except local names)", "unrouted answers: warn", "corp.example",
		"Open connections (1)", "10.0.4.17:5432", "(on the utun)", "Traffic · 5 min", "· peak ", "· scale ", "esc back · ? help",
		"Logs · work", "reconnected via")
	if strings.Contains(u.text(), "connection to the agent lost") {
		t.Fatal("the profile's log pane shows another profile's lines")
	}
	// c and l hide and show its connections and logs.
	u.press("c")
	u.gone("Open connections (1)")
	u.press("l")
	u.gone("Logs · work")
	u.press("cl")
	u.wait("Open connections (1)", "Logs · work")
	u.press("a")
	u.wait("Add a route to work", "CIDRs or IPs")
	u.press("10.80.0.0/16")
	u.wait("Dry run: would add 10.80.0.0/16")
	u.key(tcell.KeyEnter)
	if c := waitChange(t, f, 1); c.Kind != control.KindRoute || c.Op != "add" || c.Profile != "work" || len(c.CIDRs) != 1 || c.CIDRs[0] != "10.80.0.0/16" || c.Exclude {
		t.Fatalf("change: %+v", c)
	}
	u.gone("Add a route to work")
	u.wait("profile work: did add 10.80.0.0/16")
	// The first route is selected: 10.0.0.0/8.
	u.press("d")
	u.wait("Delete route 10.0.0.0/8?", "Dry run: would del 10.0.0.0/8")
	u.key(tcell.KeyEnter)
	if c := waitChange(t, f, 2); c.Kind != control.KindRoute || c.Op != "del" || c.CIDRs[0] != "10.0.0.0/8" {
		t.Fatalf("change: %+v", c)
	}
	u.gone("Delete route 10.0.0.0/8?")
	// DNS names: domains and patterns.
	u.press("A")
	u.wait("Add DNS names to work")
	u.press("db.example")
	u.wait("Dry run: would add db.example")
	u.key(tcell.KeyEnter)
	if c := waitChange(t, f, 3); c.Kind != control.KindDNS || c.Domains[0] != "db.example" {
		t.Fatalf("change: %+v", c)
	}
	u.gone("Add DNS names to work")
	u.key(tcell.KeyEscape)
	u.wait("Profiles (3)")
}

// The logs screen filters by profile, level and search.
func TestLogs(t *testing.T) {
	f := newFake("full")
	u := start(t, f, Options{})
	u.wait("reconnected")
	u.press("l")
	u.wait("subtun › logs · profile: all · level: info", "reconnected")
	u.press("vvv") // warn, error, debug
	u.wait("level: debug", "dns query")
	u.press("p") // work
	u.wait("profile: work")
	u.gone("dns query")
	u.press("pp") // dev, vault
	u.press("p")  // all
	u.wait("profile: all", "dns query")
	u.press("v") // info and up
	u.wait("level: info")
	u.gone("dns query")
	u.press("/")
	u.press("lost")
	u.key(tcell.KeyEnter)
	u.wait("search: lost", "connection to the agent lost")
	u.gone("msg=reconnected")
	u.key(tcell.KeyEscape)
	u.wait("Profiles (3)")
}

// Adding a profile lists the config file's profiles not in the run, says
// which can't join and why, and starts the chosen one.
func TestAddProfile(t *testing.T) {
	f := newFake("full")
	u := start(t, f, Options{})
	u.wait("Profiles (3)")
	u.press("a")
	u.wait("Add a profile from /home/u/.config/subtun/config.yaml", "staging", "can join", "can't join: route 10.0.0.0/8 is work's",
		"Dry run: would start")
	u.key(tcell.KeyEnter)
	if c := waitChange(t, f, 1); c.Op != "start" || c.Profile != "staging" || c.DryRun {
		t.Fatalf("change: %+v", c)
	}
	u.gone("Add a profile from")
}

// A subtun that stops answering says so; its last state stays.
func TestNoAnswer(t *testing.T) {
	f := newFake("full")
	u := start(t, f, Options{})
	u.wait("Profiles (3)")
	f.mu.Lock()
	f.fail = errors.New("connection refused")
	f.mu.Unlock()
	u.wait("no answer: subtun stopped?", "Profiles (3)")
	u.press("s")
	u.wait("subtun doesn't answer")
}

// f pauses the logs: new lines are counted, not shown, until f again.
func TestPause(t *testing.T) {
	f := newFake("full")
	u := start(t, f, Options{})
	u.wait("reconnected", "following")
	u.press("f")
	u.wait("paused")
	f.more <- logring.Line{Seq: 5, Time: time.Now(), Text: "time=1 level=INFO msg=later tunnel=work", Level: "INFO", Tunnel: "work"}
	u.wait("paused (1 new)")
	if strings.Contains(u.text(), "later") {
		t.Fatal("a paused view got a new line")
	}
	u.press("f")
	u.wait("later", "following")
	// A repeat (a stream that reconnected) isn't shown twice.
	f.more <- logring.Line{Seq: 5, Time: time.Now(), Text: "time=1 level=INFO msg=later tunnel=work", Level: "INFO", Tunnel: "work"}
	f.more <- logring.Line{Seq: 6, Time: time.Now(), Text: "time=1 level=INFO msg=latest tunnel=work", Level: "INFO", Tunnel: "work"}
	u.wait("latest")
	if n := strings.Count(u.text(), "later"); n != 1 {
		t.Fatalf("the repeat shown: %d times", n)
	}
}

// The key list returns to the screen it was opened from.
func TestHelpReturns(t *testing.T) {
	f := newFake("full")
	u := start(t, f, Options{})
	u.wait("Profiles (3)")
	u.key(tcell.KeyEnter)
	u.wait("subtun › work")
	u.press("L")
	u.wait("subtun › logs")
	u.press("?")
	u.wait("subtun › keys")
	u.key(tcell.KeyEscape)
	u.wait("subtun › logs")
	u.key(tcell.KeyEscape)
	u.wait("subtun › work")
}

// On 80x24 the table drops columns rather than lose the rates, the keys to
// get help and out come first, and dialogs fit.
func TestNarrow(t *testing.T) {
	f := newFake("full")
	u := startSized(t, f, Options{}, 80, 24)
	u.wait("Profiles (3)", "120.0 kB", "3.1 MB", "reconnecting 2/10", "? help · q quit")
	u.press("a")
	u.wait("staging", "can't join")
	for _, l := range strings.Split(u.text(), "\n") {
		if strings.Contains(l, "staging") && !strings.Contains(l, "│ staging") && !strings.Contains(l, "║ staging") {
			t.Fatalf("the dialog's first column is cut: %q", l)
		}
	}
	u.key(tcell.KeyEscape)
	u.gone("staging")
	u.key(tcell.KeyDown)
	u.key(tcell.KeyDown)
	u.press("s")
	u.wait("Stop vault?", "Dry run: would stop")
	u.key(tcell.KeyEscape)
}

// The TUI follows the terminal's size: the table and an open dialog fit
// again at once.
func TestResize(t *testing.T) {
	f := newFake("full")
	u := start(t, f, Options{})
	u.wait("Profiles (3)", "TARGET", "pod ops/toolbox")
	u.press("a")
	u.wait("Add a profile from", "can join")
	u.sim.SetSize(80, 24)
	u.sim.PostEvent(tcell.NewEventResize(80, 24))
	u.wait("? help · q quit")
	u.gone("pod ops/toolbox") // the table's TARGET column went; the dialog has its own
	for _, l := range strings.Split(u.text(), "\n") {
		if strings.Contains(l, "staging") && !strings.Contains(l, "│ staging") && !strings.Contains(l, "║ staging") {
			t.Fatalf("the dialog's first column is cut after the resize: %q", l)
		}
	}
	u.key(tcell.KeyEscape)
	u.sim.SetSize(120, 40)
	u.sim.PostEvent(tcell.NewEventResize(120, 40))
	u.wait("TARGET", "pod ops/toolbox")
}
