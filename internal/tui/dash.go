package tui

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"github.com/md2k/subnet-tunnel/internal/config"
	"github.com/md2k/subnet-tunnel/internal/control"
	"github.com/md2k/subnet-tunnel/internal/meter"
)

const (
	listWidth  = 34 // layout detail's profile list
	detailRows = 11 // layout detail's profile part: the detail's lines and borders
	sparkCells = 10 // the table's sparkline
)

func (a *app) buildDash() {
	sel := tcell.StyleDefault.Reverse(true)
	a.table = tview.NewTable().SetSelectable(true, false).SetFixed(1, 0).SetSelectedStyle(sel)
	a.table.SetBorder(true)
	a.table.SetSelectionChangedFunc(func(row, _ int) {
		if row >= 1 {
			a.sel = row - 1
		}
	})
	a.list = tview.NewTable().SetSelectable(true, false).SetSelectedStyle(sel)
	a.list.SetBorder(true).SetTitle(" Profiles ")
	a.list.SetSelectionChangedFunc(func(row, _ int) {
		a.sel = row
		if a.have {
			a.renderDetail(time.Now())
		}
	})
	a.detail = tview.NewTextView().SetDynamicColors(true).SetWrap(false)
	a.detail.SetBorder(true)
	a.dashLogs = newLogView()
	a.body = tview.NewFlex().SetDirection(tview.FlexRow)
}

func newLogView() *tview.TextView {
	tv := tview.NewTextView().SetDynamicColors(true).SetWrap(false).SetMaxLines(maxLines)
	tv.SetBorder(true)
	return tv
}

// setLayout puts the dashboard together in layout l.
func (a *app) setLayout(l string) {
	a.layout = l
	a.body.Clear()
	if l == config.LayoutDetail {
		a.top = tview.NewFlex().AddItem(a.list, listWidth, 0, true).AddItem(a.detail, 0, 1, false)
	} else {
		a.top = a.table
	}
	a.topH = a.topHeight()
	a.body.AddItem(a.top, a.topH, 0, true).AddItem(a.dashLogs, 0, 1, false)
	if a.screen == scrDash && a.dialog == nil {
		a.tv.SetFocus(a.top)
	}
}

// topHeight is the profiles part's height for the profiles there are.
func (a *app) topHeight() int {
	n := max(len(a.st.Tunnels), 1)
	if a.layout == config.LayoutDetail {
		return max(n+2, detailRows)
	}
	return min(n+3, 15)
}

func (a *app) renderDash(now time.Time) {
	if a.sel >= len(a.st.Tunnels) {
		a.sel = max(len(a.st.Tunnels)-1, 0)
	}
	if h := a.topHeight(); h != a.topH {
		a.topH = h
		a.body.ResizeItem(a.top, h, 0)
	}
	if a.layout == config.LayoutDetail {
		a.renderList(now)
		a.renderDetail(now)
	} else {
		a.renderTable(now)
	}
	a.renderLogTitles()
}

var tableHeads = []string{"", "NAME", "STATE", "TARGET", "ROUTES", "DNS", "KS", "↑/s", "↓/s", "5 MIN"}

func (a *app) renderTable(now time.Time) {
	t := a.table
	t.Clear()
	t.SetTitle(fmt.Sprintf(" Profiles (%d) ", len(a.st.Tunnels)))
	for c, h := range tableHeads {
		cell := tview.NewTableCell(h).SetTextColor(tcell.ColorGray).SetSelectable(false)
		if c == 7 || c == 8 {
			cell.SetAlign(tview.AlignRight)
		}
		t.SetCell(0, c, cell)
	}
	for i, tn := range a.st.Tunnels {
		r := i + 1
		set := func(c int, text string) *tview.TableCell {
			cell := tview.NewTableCell(text)
			t.SetCell(r, c, cell)
			return cell
		}
		set(0, glyph(tn.State))
		set(1, tview.Escape(nameOf(tn)))
		state := stateText(tn, now)
		if tn.State != "up" {
			state = "[" + stateColor(tn.State) + "]" + state + "[-]"
		}
		set(2, state)
		set(3, tview.Escape(cut(targetShort(tn.Target), 24)))
		set(4, tview.Escape(cut(routesShort(tn), 22)))
		set(5, tview.Escape(cut(dnsShort(tn), 22)))
		set(6, ksText(tn.KillSwitch))
		up, down := "-", "-"
		if tn.State == "up" {
			up, down = rate(tn.Counts.UpRate), rate(tn.Counts.DownRate)
		}
		set(7, up).SetAlign(tview.AlignRight)
		set(8, down).SetAlign(tview.AlignRight)
		set(9, a.sparkFor(tn, totalOf, sparkCells))
	}
	t.Select(a.sel+1, 0)
}

// ksText is a kill switch mode, coloured; "-" for none.
func ksText(mode string) string {
	switch mode {
	case "lockdown":
		return "[red]lockdown[-]"
	case "on":
		return "[yellow]on[-]"
	}
	return "-"
}

// sparkFor is a tunnel's traffic sparkline, coloured by its state.
func (a *app) sparkFor(t control.Tunnel, f func(meter.Sample) uint64, width int) string {
	if t.State == "stopped" {
		return "[gray]" + strings.Repeat("·", width) + "[-]"
	}
	color := "green"
	if t.State != "up" {
		color = "gray"
	}
	return "[" + color + "]" + spark(sampleValues(a.samples[t.Name], f), width) + "[-]"
}

func (a *app) renderList(now time.Time) {
	l := a.list
	l.Clear()
	for i, tn := range a.st.Tunnels {
		state := stateText(tn, now)
		if tn.State != "up" {
			state = "[" + stateColor(tn.State) + "]" + state + "[-]"
		}
		l.SetCell(i, 0, tview.NewTableCell(glyph(tn.State)))
		l.SetCell(i, 1, tview.NewTableCell(tview.Escape(cut(nameOf(tn), 12))))
		l.SetCell(i, 2, tview.NewTableCell(state).SetExpansion(1))
	}
	l.Select(a.sel, 0)
}

func (a *app) renderDetail(now time.Time) {
	if a.sel >= len(a.st.Tunnels) {
		a.detail.SetTitle("")
		a.detail.SetText("")
		return
	}
	t := a.st.Tunnels[a.sel]
	a.detail.SetTitle(" " + tview.Escape(nameOf(t)) + " ")
	_, _, w, _ := a.detail.GetInnerRect()
	a.detail.SetText(a.detailText(t, now, max(w-12, 10)))
}

// detailText is the selected profile's detail in layout detail.
func (a *app) detailText(t control.Tunnel, now time.Time, sparkW int) string {
	var b strings.Builder
	line := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }
	head := []string{"[" + stateColor(t.State) + "]" + stateText(t, now) + "[-]"}
	if t.Target != "" {
		head = append(head, tview.Escape(t.Target))
	}
	line("%s", strings.Join(head, " · "))
	its := items(t)
	if s := listOf(its, "route"); s != "" {
		line("[gray]routes [-]  %s", s)
	} else if t.SOCKS != "" {
		line("[gray]routes [-]  none: SOCKS only")
	}
	if s := listOf(its, "exclude"); s != "" {
		line("[gray]exclude[-]  %s", s)
	}
	if s := listOf(its, "dns", "pattern"); s != "" {
		line("[gray]DNS    [-]  %s", s)
	}
	var extra []string
	if t.KillSwitch != "" {
		extra = append(extra, "kill switch "+ksText(t.KillSwitch))
	}
	if t.SOCKS != "" {
		extra = append(extra, "SOCKS "+tview.Escape(t.SOCKS))
	}
	if len(extra) > 0 {
		line("%s", strings.Join(extra, " · "))
	}
	c := t.Counts
	line("[gray]↑[-] %-10s %s", rate(c.UpRate), a.sparkFor(t, upOf, sparkW))
	line("[gray]↓[-] %-10s %s", rate(c.DownRate), a.sparkFor(t, downOf, sparkW))
	line("conns %d open · %d total · %d failed · DNS %d ok / %d failed", c.Open, c.Total, c.Failed, t.DNSCounts.Answered, t.DNSCounts.Failed)
	if t.LastError != "" && t.State != "up" {
		line("[red]last error:[-] %s", tview.Escape(t.LastError))
	}
	return strings.TrimSuffix(b.String(), "\n")
}

// current is the profile the keys act on: the profile screen's, or the
// selected one.
func (a *app) current() (control.Tunnel, bool) {
	i := a.sel
	if a.screen == scrProfile {
		i = a.open
	}
	if !a.have || i < 0 || i >= len(a.st.Tunnels) {
		return control.Tunnel{}, false
	}
	return a.st.Tunnels[i], true
}

func (a *app) dashKey(ev *tcell.EventKey) *tcell.EventKey {
	switch ev.Key() {
	case tcell.KeyEnter:
		if a.tv.GetFocus() != a.dashLogs {
			a.openProfile(a.sel)
			return nil
		}
	case tcell.KeyTab, tcell.KeyBacktab:
		if a.tv.GetFocus() == a.dashLogs {
			a.tv.SetFocus(a.top)
		} else {
			a.tv.SetFocus(a.dashLogs)
		}
		return nil
	}
	if a.tv.GetFocus() == a.dashLogs && scrollsBack(ev) {
		a.following = false
		a.renderLogTitles()
		return ev
	}
	switch ev.Rune() {
	case 'v':
		l := config.LayoutDetail
		if a.layout == config.LayoutDetail {
			l = config.LayoutTable
		}
		a.setLayout(l)
		a.refresh()
		if a.o.OnLayout != nil {
			a.o.OnLayout(l)
		}
		return nil
	case 's':
		a.act(a.confirmStop)
		return nil
	case 'S':
		a.act(func() { a.profileOp("start") })
		return nil
	case 'r':
		a.act(func() { a.profileOp("reconnect") })
		return nil
	case 'a':
		a.act(a.addProfileDialog)
		return nil
	case 'l':
		a.openLogs()
		return nil
	case '/':
		a.openLogs()
		a.startSearch()
		return nil
	case 'f':
		a.toggleFollow()
		return nil
	}
	return ev
}

// profileOp starts or reconnects the current profile.
func (a *app) profileOp(op string) {
	t, ok := a.current()
	if !ok {
		return
	}
	a.do(control.Change{Kind: control.KindProfile, Op: op, Profile: t.Name})
}

// running lists the other profiles that are up or connecting.
func (a *app) running(except int) []string {
	var out []string
	for i, t := range a.st.Tunnels {
		if i != except && slices.Contains([]string{"up", "connecting", "reconnecting"}, t.State) {
			out = append(out, nameOf(t))
		}
	}
	return out
}
