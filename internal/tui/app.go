// Package tui is subtun's terminal UI: it attaches to a running subtun's
// control socket, shows its profiles, traffic and logs, and with control:
// full changes it (stop, start, reconnect, routes, DNS names, profiles
// added from the config file). Every change shows its dry run first.
package tui

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"github.com/md2k/subnet-tunnel/internal/config"
	"github.com/md2k/subnet-tunnel/internal/control"
	"github.com/md2k/subnet-tunnel/internal/logring"
	"github.com/md2k/subnet-tunnel/internal/meter"
)

// Options configure the TUI.
type Options struct {
	Source Source
	// Layout is the dashboard's layout: config.LayoutTable (default) or
	// config.LayoutDetail.
	Layout string
	// OnLayout is called when v switches the layout (to remember it).
	OnLayout func(string)
	// Units are the rates' units: config.UnitsBytes (default) or
	// config.UnitsBits; OnUnits is called when u switches them.
	Units   string
	OnUnits func(string)
	// Screen is the terminal; nil: this one. Tests pass a simulation.
	Screen tcell.Screen
	// Interval between status polls; 0: a second.
	Interval time.Duration
}

const (
	queryTimeout  = 3 * time.Second
	changeTimeout = 15 * time.Second // a reload looks the target's endpoint up
	flashFor      = 8 * time.Second
	dryRunDelay   = 300 * time.Millisecond // after the last key typed
)

// The screens.
const (
	scrDash    = "dash"
	scrProfile = "profile"
	scrLogs    = "logs"
	scrHelp    = "help"
)

const readOnlyText = "read only: this subtun runs with control: status; start it with --control full (or control: full in the config file) to change it here"

type app struct {
	o     Options
	ctx   context.Context
	quit  context.CancelFunc
	tv    *tview.Application
	pages *tview.Pages

	header, msg, keys *tview.TextView

	// The dashboard.
	body     *tview.Flex
	top      tview.Primitive // the profiles part of body
	topH     int
	table    *tview.Table // layout table
	list     *tview.Table // layout detail
	detail   *tview.TextView
	dashLogs *tview.TextView

	// The profile screen.
	profInfo  *tview.TextView
	profItems *tview.Table
	profConns *tview.Table
	profGraph *tview.TextView
	profCard  *tview.Flex
	profFlex  *tview.Flex
	itemRows  []item

	// The logs screen.
	logsFlex *tview.Flex
	fullLogs *tview.TextView
	search   *tview.InputField

	helpView *tview.TextView

	// State: touched on the UI goroutine only.
	st         control.Status
	have       bool  // a status arrived
	gone       error // the last poll failed
	samples    map[string][]meter.Sample
	conns      map[string][]meter.ConnInfo
	logs       logBuf
	logText    bool // the log view on screen holds text
	filter     logFilter
	following  bool
	unseen     int // lines that came while paused
	layout     string
	bits       bool // rates in bits a second (u), not bytes
	sel        int  // the selected profile (index in st.Tunnels: a run never drops one)
	open       int  // the profile screen's profile; -1: none
	screen     string
	logsBack   string          // the screen esc on the logs returns to
	helpBack   string          // the screen the key list returns to
	dialog     tview.Primitive // the open dialog; nil: none
	focusWas   tview.Primitive
	flashText  string
	flashUntil time.Time
	searching  bool

	// The terminal's size at the last draw; layouts fit it.
	scrW, scrH int
	// The open dialog's wanted size and its place, to fit it again.
	dlgW, dlgH      int
	dlgCol, dlgCell *tview.Flex
	dlgBox          tview.Primitive

	// Handing work to the UI goroutine (see pump).
	ui        chan func()
	started   chan struct{} // closed at the first draw
	startOnce sync.Once

	wantConns atomic.Bool
	pollNow   chan struct{}

	pendMu  sync.Mutex
	pending []logring.Line
}

// Run shows the TUI until q, Ctrl-C or ctx ends.
func Run(ctx context.Context, o Options) error {
	if o.Interval <= 0 {
		o.Interval = time.Second
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	a := newApp(ctx, cancel, o)
	if o.Screen != nil {
		a.tv.SetScreen(o.Screen)
	}
	a.tv.SetBeforeDrawFunc(a.resized)
	a.tv.SetAfterDrawFunc(func(tcell.Screen) { a.startOnce.Do(func() { close(a.started) }) })
	ended := make(chan struct{})
	go a.pump(ended)
	go a.poll()
	go a.streamLogs()
	go a.flushLogs()
	err := a.tv.Run()
	close(ended)
	return err
}

// pump hands the background goroutines' work to the UI goroutine. It is the
// only caller of QueueUpdate, which waits until the update has run, and it
// is the one that stops the event loop once ctx ends (q, Ctrl-C, the
// caller): so nothing ever waits on an event loop that has stopped.
func (a *app) pump(ended <-chan struct{}) {
	select {
	case <-a.started:
	case <-ended:
		return
	}
	for {
		if a.ctx.Err() != nil {
			a.tv.Stop()
			return
		}
		select {
		case <-a.ctx.Done():
		case <-ended:
			return
		case f := <-a.ui:
			a.tv.QueueUpdateDraw(f)
		}
	}
}

// resized fits everything to the terminal again when its size changed
// (before tview lays out the draw).
func (a *app) resized(scr tcell.Screen) bool {
	if w, h := scr.Size(); w != a.scrW || h != a.scrH {
		a.scrW, a.scrH = w, h
		a.refitDialog()
		a.refresh()
	}
	return false
}

// update runs f on the UI goroutine, then redraws; dropped once the TUI is
// stopping.
func (a *app) update(f func()) {
	select {
	case a.ui <- f:
	case <-a.ctx.Done():
	}
}

func newApp(ctx context.Context, quit context.CancelFunc, o Options) *app {
	// The terminal's own colours, not tview's black.
	tview.Styles.PrimitiveBackgroundColor = tcell.ColorDefault
	tview.Styles.PrimaryTextColor = tcell.ColorDefault
	tview.Styles.BorderColor = tcell.ColorGray
	tview.Styles.TitleColor = tcell.ColorDefault
	tview.Styles.GraphicsColor = tcell.ColorGray

	a := &app{o: o, ctx: ctx, quit: quit, tv: tview.NewApplication(), pages: tview.NewPages(), samples: map[string][]meter.Sample{},
		conns: map[string][]meter.ConnInfo{}, following: true, screen: scrDash, open: -1, pollNow: make(chan struct{}, 1),
		ui: make(chan func(), 64), started: make(chan struct{})}
	a.filter.level = levels[0]
	a.bits = o.Units == config.UnitsBits

	a.header = tview.NewTextView().SetDynamicColors(true).SetWrap(false)
	a.header.SetBackgroundColor(tcell.ColorNavy)
	a.header.SetTextColor(tcell.ColorWhite)
	a.msg = tview.NewTextView().SetDynamicColors(true).SetWrap(false)
	a.keys = tview.NewTextView().SetDynamicColors(true).SetWrap(false)

	a.buildDash()
	a.buildProfile()
	a.buildLogs()
	a.helpView = tview.NewTextView().SetDynamicColors(true).SetText(helpText)
	a.helpView.SetBorder(true).SetTitle(" Keys ")

	a.pages.AddPage(scrDash, a.body, true, true)
	a.pages.AddPage(scrProfile, a.profilePage(), true, false)
	a.pages.AddPage(scrLogs, a.logsFlex, true, false)
	a.pages.AddPage(scrHelp, a.helpView, true, false)
	root := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(a.header, 1, 0, false).
		AddItem(a.pages, 0, 1, true).
		AddItem(a.msg, 1, 0, false).
		AddItem(a.keys, 1, 0, false)
	a.tv.SetRoot(root, true).SetInputCapture(a.onKey)

	layout := o.Layout
	if layout != config.LayoutDetail {
		layout = config.LayoutTable
	}
	a.setLayout(layout)
	a.refresh()
	return a
}

// poll asks for the status, the samples, and the connections while the
// profile screen is open, every interval or at once after a change.
func (a *app) poll() {
	t := time.NewTicker(a.o.Interval)
	defer t.Stop()
	for {
		ctx, cancel := context.WithTimeout(a.ctx, queryTimeout)
		st, err := a.o.Source.Status(ctx)
		var ts []control.TunnelSamples
		var conns []control.TunnelConns
		if err == nil {
			// All 5 minutes each time: no cursor to lose when the clock steps.
			ts, _ = a.o.Source.Samples(ctx)
			if a.wantConns.Load() {
				conns, _ = a.o.Source.Conns(ctx)
			}
		}
		cancel()
		a.update(func() { a.apply(st, ts, conns, err) })
		select {
		case <-a.ctx.Done():
			return
		case <-t.C:
		case <-a.pollNow:
		}
	}
}

func (a *app) pollSoon() {
	select {
	case a.pollNow <- struct{}{}:
	default:
	}
}

func (a *app) apply(st control.Status, ts []control.TunnelSamples, conns []control.TunnelConns, err error) {
	if err != nil {
		a.gone = err
		a.refresh()
		return
	}
	renew := !a.have || len(st.Tunnels) != len(a.st.Tunnels)
	a.st, a.have, a.gone = st, true, nil
	if ts != nil {
		a.samples = map[string][]meter.Sample{}
		for _, t := range ts {
			a.samples[t.Name] = t.Samples
		}
	}
	if conns != nil {
		a.conns = map[string][]meter.ConnInfo{}
		for _, c := range conns {
			a.conns[c.Name] = c.Conns
		}
	}
	if renew { // names and colours for the log lines
		a.rebuildLogs()
	}
	a.refresh()
}

// streamLogs follows the run's log lines, again after the stream breaks.
func (a *app) streamLogs() {
	for a.ctx.Err() == nil {
		_ = a.o.Source.Logs(a.ctx, func(l logring.Line) {
			a.pendMu.Lock()
			a.pending = append(a.pending, l)
			if n := len(a.pending); n > maxLines {
				a.pending = a.pending[n-maxLines:]
			}
			a.pendMu.Unlock()
		})
		select {
		case <-a.ctx.Done():
		case <-time.After(time.Second):
		}
	}
}

// flushLogs hands the lines that came to the UI a few times a second.
func (a *app) flushLogs() {
	t := time.NewTicker(150 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-a.ctx.Done():
			return
		case <-t.C:
		}
		a.pendMu.Lock()
		batch := a.pending
		a.pending = nil
		a.pendMu.Unlock()
		if len(batch) > 0 {
			a.update(func() { a.addLines(batch) })
		}
	}
}

// goTo shows screen s.
func (a *app) goTo(s string) {
	a.screen = s
	a.wantConns.Store(s == scrProfile)
	a.pages.SwitchToPage(s)
	switch s {
	case scrDash:
		a.tv.SetFocus(a.top)
	case scrProfile:
		a.tv.SetFocus(a.profItems)
	case scrLogs:
		a.tv.SetFocus(a.fullLogs)
	}
	if s == scrDash || s == scrLogs {
		a.follow() // a log view comes on screen: fresh, following
	}
	a.refresh()
}

// refresh redraws everything from the state.
func (a *app) refresh() {
	now := time.Now()
	a.renderHeader()
	if a.have {
		a.renderDash(now)
		if a.screen == scrProfile {
			a.renderProfile(now)
		}
	}
	a.renderKeys()
	a.renderMsg(now)
}

func (a *app) renderHeader() {
	var s string
	switch {
	case a.gone != nil && !a.have:
		s = " subtun · [red]no answer:[-] " + tview.Escape(a.gone.Error())
	case !a.have:
		s = " subtun · connecting to the control socket…"
	case a.screen == scrProfile && a.open >= 0 && a.open < len(a.st.Tunnels):
		s = " subtun › " + tview.Escape(nameOf(a.st.Tunnels[a.open]))
	case a.screen == scrLogs:
		s = " subtun › logs · " + tview.Escape(a.filter.describe()) + " · " + a.followText()
	case a.screen == scrHelp:
		s = " subtun › keys"
	default:
		st := a.st
		s = fmt.Sprintf(" subtun · pid %d · up %s", st.PID, short(time.Since(st.Started)))
		if st.Utun != "" {
			s += fmt.Sprintf(" · %s %s · %s helper", st.Utun, st.TunAddr, st.Helper)
		} else if slices.ContainsFunc(st.Tunnels, func(t control.Tunnel) bool { return len(t.Include) > 0 }) {
			s += " · capture not started yet"
		}
		if st.Control == "full" {
			s += " · control full"
		} else {
			s += " · control " + st.Control + " (read only)"
		}
	}
	if a.gone != nil && a.have {
		s += " · [red]no answer: subtun stopped?[-]"
	}
	a.header.SetText(s)
}

func (a *app) followText() string {
	if a.following {
		return "following"
	}
	if a.unseen > 0 {
		return fmt.Sprintf("paused (%d new)", a.unseen)
	}
	return "paused"
}

// key is a key for the key bar; an action greyed out in a read-only run.
func (a *app) key(k, what string, action bool) string {
	if action && (a.st.Control != "full" || a.gone != nil) {
		return "[gray]" + k + " " + what + "[-]"
	}
	return "[yellow]" + k + "[-] " + what
}

// renderKeys shows the screen's keys, the ones to get help, out and back
// first (a narrow terminal cuts the end).
func (a *app) renderKeys() {
	var ks []string
	switch a.screen {
	case scrDash:
		ks = []string{a.key("?", "help", false), a.key("q", "quit", false), a.key("↑↓", "select", false), a.key("enter", "open", false),
			a.key("v", "layout", false), a.key("s", "stop", true), a.key("S", "start", true), a.key("r", "reconnect", true),
			a.key("a", "add profile", true), a.key("l", "logs", false), a.key("u", "units", false), a.key("tab", "focus", false), a.key("f", "follow", false)}
	case scrProfile:
		ks = []string{a.key("esc", "back", false), a.key("?", "help", false), a.key("s", "stop", true), a.key("S", "start", true),
			a.key("r", "reconnect", true), a.key("R", "reload", true), a.key("a/x", "add route/exclude", true), a.key("A", "add DNS", true),
			a.key("d", "delete", true), a.key("l", "logs", false), a.key("u", "units", false), a.key("tab", "focus", false)}
	case scrLogs:
		ks = []string{a.key("esc", "back", false), a.key("f", "follow", false), a.key("p", "profile", false), a.key("v", "level", false),
			a.key("/", "search", false), a.key("g/G", "top/bottom", false)}
	case scrHelp:
		ks = []string{a.key("esc", "back", false), a.key("q", "quit", false)}
	}
	a.keys.SetText(" " + strings.Join(ks, "  "))
}

// flash shows a message for a while; color is a tview colour name.
func (a *app) flash(color, text string) {
	a.flashText = "[" + color + "]" + tview.Escape(text) + "[-]"
	a.flashUntil = time.Now().Add(flashFor)
	a.renderMsg(time.Now())
}

func (a *app) renderMsg(now time.Time) {
	switch {
	case a.flashText != "" && now.Before(a.flashUntil):
		a.msg.SetText(" " + a.flashText)
	case a.have && a.st.Control != "full":
		a.msg.SetText(" [yellow]" + readOnlyText + "[-]")
	default:
		a.msg.SetText("")
	}
}

// onKey routes a key: dialogs and the search field take their own keys.
func (a *app) onKey(ev *tcell.EventKey) *tcell.EventKey {
	if ev.Key() == tcell.KeyCtrlC { // tview's own Ctrl-C would skip pump
		a.quit()
		return nil
	}
	if a.dialog != nil || a.searching {
		return ev
	}
	switch ev.Rune() {
	case 'q':
		a.quit()
		return nil
	case '?':
		if a.screen != scrHelp {
			a.helpBack = a.screen
			a.goTo(scrHelp)
		}
		return nil
	case 'u':
		a.bits = !a.bits
		units := config.UnitsBytes
		if a.bits {
			units = config.UnitsBits
		}
		if a.o.OnUnits != nil {
			a.o.OnUnits(units)
		}
		a.refresh()
		return nil
	}
	switch a.screen {
	case scrHelp:
		if ev.Key() == tcell.KeyEscape {
			a.goTo(a.helpBack)
			return nil
		}
		return ev
	case scrDash:
		return a.dashKey(ev)
	case scrProfile:
		return a.profileKey(ev)
	case scrLogs:
		return a.logsKey(ev)
	}
	return ev
}

// act runs an action that changes the run, if the run takes changes.
func (a *app) act(f func()) {
	switch {
	case !a.have:
	case a.gone != nil:
		a.flash("red", "subtun doesn't answer")
	case a.st.Control != "full":
		a.flash("yellow", readOnlyText)
	default:
		f()
	}
}

// send makes a change in the background; done gets the answer on the UI
// goroutine.
func (a *app) send(ch control.Change, done func(control.Result, error)) {
	go func() {
		ctx, cancel := context.WithTimeout(a.ctx, changeTimeout)
		defer cancel()
		res, err := a.o.Source.Change(ctx, ch)
		a.update(func() {
			done(res, err)
			if !ch.DryRun {
				a.pollSoon()
			}
		})
	}()
}

// do makes a change now and says what it did.
func (a *app) do(ch control.Change) {
	a.send(ch, a.flashAnswer)
}

// flashAnswer says what a change did, or why it was refused.
func (a *app) flashAnswer(res control.Result, err error) {
	if err != nil {
		a.flash("red", err.Error())
		return
	}
	text := res.Message
	if res.Profile != "" {
		text = "profile " + res.Profile + ": " + text
	}
	color := "green"
	if len(res.Warnings) > 0 {
		text += " (warning: " + strings.Join(res.Warnings, "; ") + ")"
		color = "yellow"
	}
	a.flash(color, text)
}

// profileColor is the colour of a profile's name in the logs.
func (a *app) profileColor(name string) string {
	for i, t := range a.st.Tunnels {
		if t.Name == name {
			return profileColors[i%len(profileColors)]
		}
	}
	return "white"
}

func (a *app) nameWidth() int {
	w := 0
	for _, t := range a.st.Tunnels {
		w = max(w, len(t.Name))
	}
	return w
}

const helpText = `
 [yellow]Dashboard[-]
   ↑ ↓ j k     select a profile
   enter       open the profile screen
   v           switch the layout: table, or list and detail
   s S r       stop, start, reconnect the selected profile
   a           add a profile from the config file
   l           the logs, full screen; / searches them
   tab         move between the profiles and the logs
   f           follow the logs, or pause them
   u           rates in bytes or bits a second (MB/s, Mb/s)

 [yellow]Profile screen[-]
   a x         add a route, an exclude
   A           add DNS domains or patterns
   d           delete the selected route, exclude, domain or pattern
   s S r       stop, start, reconnect
   R           read the profile from the config file again
   l           its logs
   tab         move between its routes and its connections
   esc         back

 [yellow]Logs[-]
   f           follow, or pause (scrolling back pauses too)
   p           the profile shown: all, or one
   v           the lowest level shown
   /           search (enter applies, esc cancels; empty: none)
   g G         top, bottom
   esc         back

 Changes need control: full. Each one shows its dry run before it is made,
 and lasts until subtun stops. q quits the TUI; subtun goes on.
`
