package tui

import (
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"github.com/md2k/subnet-tunnel/internal/config"
	"github.com/md2k/subnet-tunnel/internal/control"
	"github.com/md2k/subnet-tunnel/internal/meter"
)

const (
	listWidth  = 34 // layout detail's profile list
	maxTopRows = 16 // the profiles part at most (more on a tall screen); more profiles scroll
	gaugeCells = 10 // the table's traffic gauge, at least
)

func (a *app) buildDash() {
	sel := tcell.StyleDefault.Reverse(true)
	a.table = tview.NewTable().SetSelectable(true, false).SetFixed(1, 0).SetSelectedStyle(sel)
	boxed(a.table.Box, "Profiles")
	a.table.SetSelectionChangedFunc(func(row, _ int) {
		if row >= 1 {
			a.sel = row - 1
			a.markSelected(a.table, 1)
		}
	})
	a.list = tview.NewTable().SetSelectable(true, false).SetSelectedStyle(sel)
	boxed(a.list.Box, "Profiles")
	a.list.SetSelectionChangedFunc(func(row, _ int) {
		if row >= len(a.st.Tunnels) || row == a.sel {
			return // a render selecting the same row again
		}
		a.sel = row
		a.markSelected(a.list, 0)
		if a.have {
			a.renderDetail(time.Now())
			if a.screen == scrDash {
				a.rebuildLogs() // the logs follow the selected profile
			}
		}
	})
	a.detail = tview.NewTextView().SetDynamicColors(true).SetWrap(false)
	boxed(a.detail.Box, "")
	a.dashLogs = newLogView()
	a.body = tview.NewFlex().SetDirection(tview.FlexRow)
}

// markSelected puts ▶ before the selected profile's row (the first row
// after skip is the first profile's).
func (a *app) markSelected(t *tview.Table, skip int) {
	for i := range a.st.Tunnels {
		if c := t.GetCell(i+skip, 0); c != nil {
			c.SetText(map[bool]string{true: "▶", false: " "}[i == a.sel])
		}
	}
}

func newLogView() *tview.TextView {
	tv := tview.NewTextView().SetDynamicColors(true).SetWrap(false).SetMaxLines(maxLines)
	boxed(tv.Box, "Logs")
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

// topHeight is the profiles part's height for the profiles there are (and
// in layout detail, for the detail's lines with its graphs).
func (a *app) topHeight() int {
	n := max(len(a.st.Tunnels), 1)
	limit := max(maxTopRows, a.scrH*3/5)
	if a.layout == config.LayoutDetail {
		// state, routes, exclude, DNS, kill switch, two graphs with their
		// headers, connections, last error; and the borders
		return min(max(n+4, 8+2*a.graphRows()+2+2), limit)
	}
	return min(n+3, limit)
}

// graphRows is how high a traffic graph is: higher on a taller screen.
func (a *app) graphRows() int {
	if a.scrH == 0 {
		return 3
	}
	return min(max((a.scrH-16)/6, 2), 5)
}

// rate is a rate in the units chosen (u); rateCell without the "/s" (the
// table's heading says it).
func (a *app) rate(n uint64) string     { return rateText(n, a.bits) }
func (a *app) rateCell(n uint64) string { return strings.TrimSuffix(a.rate(n), "/s") }

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

// The table's columns, in order; the flexible ones shrink to flexMin when
// the terminal is narrow, then columns go in dropOrder.
var (
	tableHeads = []string{"▶", "●", "NAME", "STATE", "TARGET", "ROUTES", "DNS", "KS", "↑/s", "↓/s", "TRAFFIC"}
	flexCols   = []string{"TARGET", "ROUTES", "DNS"}
	flexCap    = map[string]int{"TARGET": 40, "ROUTES": 32, "DNS": 32}
	dropOrder  = []string{"TARGET", "DNS", "TRAFFIC", "KS"}
)

const flexMin = 8

// fitColumns fits columns of the widths wanted into width (one space
// between columns): the flexible ones shrink first, then columns are
// dropped, then what is left over goes back to the flexible ones.
func fitColumns(width int, want map[string]int) map[string]int {
	w := maps.Clone(want)
	total := func() int {
		n := -1
		for _, v := range w {
			n += v + 1
		}
		return n
	}
	for total() > width {
		widest := ""
		for _, c := range flexCols {
			if v, ok := w[c]; ok && v > flexMin && (widest == "" || v > w[widest]) {
				widest = c
			}
		}
		if widest != "" {
			w[widest]--
			continue
		}
		i := slices.IndexFunc(dropOrder, func(c string) bool { _, ok := w[c]; return ok })
		if i < 0 {
			break
		}
		delete(w, dropOrder[i])
	}
	for spare := width - total(); spare > 0; {
		grown := false
		for _, c := range flexCols {
			if v, ok := w[c]; ok && v < want[c] && spare > 0 {
				w[c]++
				spare--
				grown = true
			}
		}
		if !grown {
			break
		}
	}
	return w
}

func (a *app) renderTable(now time.Time) {
	t := a.table
	t.Clear()
	t.SetTitle(boxTitle(fmt.Sprintf("Profiles (%d)", len(a.st.Tunnels))))
	// The plain texts, to measure; colours come after cutting.
	rows := make([]map[string]string, len(a.st.Tunnels))
	want := map[string]int{}
	for _, h := range tableHeads {
		want[h] = utf8.RuneCountInString(h)
	}
	for i, tn := range a.st.Tunnels {
		up, down := "-", "-"
		if tn.State == "up" {
			up, down = a.rateCell(tn.Counts.UpRate), a.rateCell(tn.Counts.DownRate)
		}
		ks := tn.KillSwitch
		if ks == "" {
			ks = "-"
		}
		rows[i] = map[string]string{"NAME": nameOf(tn), "STATE": stateText(tn, now), "TARGET": targetShort(tn.Target),
			"ROUTES": routesShort(tn), "DNS": dnsShort(tn), "KS": ks, "↑/s": up, "↓/s": down, "TRAFFIC": strings.Repeat(" ", gaugeCells)}
		for c, v := range rows[i] {
			n := utf8.RuneCountInString(v)
			if limit, ok := flexCap[c]; ok {
				n = min(n, limit)
			}
			want[c] = max(want[c], n)
		}
	}
	width := 118 // before the first draw
	if a.scrW > 0 {
		width = a.scrW - 2 // the table spans the screen, less its borders
	}
	widths := fitColumns(width, want)
	if w, ok := widths["TRAFFIC"]; ok { // the gauge takes the rest
		used := -1
		for _, v := range widths {
			used += v + 1
		}
		widths["TRAFFIC"] = w + max(width-used, 0)
	}
	col := 0
	for _, h := range tableHeads {
		cw, ok := widths[h]
		if !ok {
			continue
		}
		right := h == "↑/s" || h == "↓/s"
		title := h
		if h == "▶" || h == "●" {
			title = ""
		}
		head := tview.NewTableCell(title).SetTextColor(tcell.ColorGray).SetSelectable(false)
		if right {
			head.SetAlign(tview.AlignRight)
		}
		t.SetCell(0, col, head)
		for i, tn := range a.st.Tunnels {
			var text string
			switch h {
			case "▶":
				text = map[bool]string{true: "▶", false: " "}[i == a.sel]
			case "●":
				text = glyph(tn.State)
			case "STATE":
				text = tview.Escape(cut(rows[i][h], cw))
				if tn.State != "up" {
					text = "[" + stateColor(tn.State) + "]" + text + "[-]"
				}
			case "KS":
				text = ksText(tn.KillSwitch)
			case "TRAFFIC":
				text = a.gaugeFor(tn, cw)
			default:
				text = tview.Escape(cut(rows[i][h], cw))
			}
			cell := tview.NewTableCell(text).SetMaxWidth(cw)
			if right {
				cell.SetAlign(tview.AlignRight)
			}
			if h == "TRAFFIC" { // selected, keep its colours: a reversed gauge reads wrong
				cell.SetSelectedStyle(tcell.StyleDefault.Foreground(tcell.ColorGreen))
			}
			t.SetCell(i+1, col, cell)
		}
		col++
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

// gaugeFor is a tunnel's traffic now (both ways) as a bar filling from the
// left, against the scale of its last 5 minutes.
func (a *app) gaugeFor(t control.Tunnel, width int) string {
	if t.State != "up" {
		return "[gray]" + strings.Repeat("·", width) + "[-]"
	}
	top := niceTop(slices.Max(append(sampleValues(a.samples[t.Name], totalOf), 0)))
	return gauge(t.Counts.UpRate+t.Counts.DownRate, top, width)
}

// chartFor is a tunnel's traffic as a braille chart height rows high; a
// stopped one's is dots.
func (a *app) chartFor(t control.Tunnel, f func(meter.Sample) uint64, width, height int) []string {
	if t.State == "stopped" {
		rows := make([]string, height)
		rows[height-1] = "[gray]" + strings.Repeat("·", width) + "[-]"
		return rows
	}
	vals := sampleValues(a.samples[t.Name], f)
	return braille(vals, width, height, niceTop(slices.Max(append(vals, 0))))
}

// trafficGraph is a tunnel's traffic as btop draws a network: upload rising
// above a zero line, download hanging below it, each against its own scale,
// with a line for each above and below. half is each side's height.
func (a *app) trafficGraph(t control.Tunnel, width, half int) []string {
	ss := a.samples[t.Name]
	up, down := sampleValues(ss, upOf), sampleValues(ss, downOf)
	head := func(arrow string, now uint64, vals []uint64) string {
		s := "[gray]" + arrow + "[-] " + a.rate(now)
		if peak := slices.Max(append(vals, 0)); t.State != "stopped" && peak > 0 {
			s += " [gray]· peak " + a.rate(peak) + " · scale " + a.rate(niceTop(peak)) + "[-]"
		}
		return s
	}
	out := []string{head("↑", t.Counts.UpRate, up)}
	if t.State == "stopped" {
		rows := make([]string, 2*half)
		rows[half-1] = "[gray]" + strings.Repeat("·", width) + "[-]"
		out = append(out, rows...)
	} else {
		out = append(out, area(up, width, half, niceTop(slices.Max(append(up, 0))), false)...)
		out = append(out, area(down, width, half, niceTop(slices.Max(append(down, 0))), true)...)
	}
	return append(out, head("↓", t.Counts.DownRate, down))
}

func (a *app) renderList(now time.Time) {
	l := a.list
	l.Clear()
	for i, tn := range a.st.Tunnels {
		state := stateText(tn, now)
		if tn.State == "reconnecting" && tn.Attempts > 0 {
			state = fmt.Sprintf("reconn %d/%d", tn.Attempt, tn.Attempts)
		}
		if tn.State != "up" {
			state = "[" + stateColor(tn.State) + "]" + state + "[-]"
		}
		l.SetCell(i, 0, tview.NewTableCell(map[bool]string{true: "▶", false: " "}[i == a.sel]))
		l.SetCell(i, 1, tview.NewTableCell(glyph(tn.State)))
		l.SetCell(i, 2, tview.NewTableCell(tview.Escape(cut(nameOf(tn), 12))))
		l.SetCell(i, 3, tview.NewTableCell(state).SetExpansion(1))
	}
	n := len(a.st.Tunnels)
	l.SetCell(n, 0, tview.NewTableCell("").SetSelectable(false))
	l.SetCell(n+1, 1, tview.NewTableCell("[gray]a[-]").SetSelectable(false))
	l.SetCell(n+1, 2, tview.NewTableCell("[gray]add from config[-]").SetSelectable(false))
	l.Select(a.sel, 0)
}

func (a *app) renderDetail(now time.Time) {
	if a.sel >= len(a.st.Tunnels) {
		a.detail.SetTitle("")
		a.detail.SetText("")
		return
	}
	t := a.st.Tunnels[a.sel]
	a.detail.SetTitle(boxTitle(tview.Escape(nameOf(t))))
	w := 84 // before the first draw
	if a.scrW > 0 {
		w = a.scrW - listWidth - 2 // next to the list, less its borders
	}
	a.detail.SetText(a.detailText(t, now, max(w, 10)))
}

// detailText is the selected profile's detail in layout detail.
func (a *app) detailText(t control.Tunnel, now time.Time, sparkW int) string {
	var b strings.Builder
	line := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }
	var head []string
	if t.Target != "" {
		head = append(head, tview.Escape(targetShort(t.Target)))
		if ag := agentText(t); ag != "" {
			head = append(head, tview.Escape(ag))
		}
	}
	head = append(head, "["+stateColor(t.State)+"]"+stateText(t, now)+"[-]")
	line("%s", strings.Join(head, " · "))
	its := items(t)
	if s := listOf(its, "route"); s != "" {
		line("[gray]routes [-]  %s", s)
	} else if t.SOCKS != "" {
		line("[gray]routes [-]  none: SOCKS only (%s)", tview.Escape(t.SOCKS))
	}
	if s := listOf(its, "exclude"); s != "" {
		line("[gray]exclude[-]  %s", s)
	}
	ks := ""
	if t.KillSwitch != "" {
		ks = "kill switch " + ksText(t.KillSwitch)
	}
	if s := listOf(its, "dns", "pattern"); s != "" {
		if ks != "" {
			s += "        " + ks
		}
		line("[gray]DNS    [-]  %s", s)
	} else if ks != "" {
		line("%s", ks)
	}
	line("")
	c := t.Counts
	for _, l := range a.trafficGraph(t, sparkW, a.graphRows()) {
		line("%s", l)
	}
	line("conns %d open · %d total · %d failed · DNS %d ok / %d failed", c.Open, c.Total, c.Failed, t.DNSCounts.Answered, t.DNSCounts.Failed)
	if t.LastError != "" && t.State != "up" {
		line("[red]last error:[-] %s", tview.Escape(t.LastError))
	}
	return strings.TrimSuffix(b.String(), "\n")
}

// current is the profile the keys act on: the profile screen's, or the
// selected one; i is its index.
func (a *app) current() (t control.Tunnel, i int, ok bool) {
	i = a.sel
	if a.screen == scrProfile {
		i = a.open
	}
	if !a.have || i < 0 || i >= len(a.st.Tunnels) {
		return control.Tunnel{}, -1, false
	}
	return a.st.Tunnels[i], i, true
}

func (a *app) dashKey(ev *tcell.EventKey) *tcell.EventKey {
	logsFocused := a.tv.GetFocus() == a.dashLogs
	switch ev.Key() {
	case tcell.KeyEnter:
		if !logsFocused {
			a.openProfile(a.sel)
			return nil
		}
	case tcell.KeyTab, tcell.KeyBacktab:
		if logsFocused {
			a.tv.SetFocus(a.top)
		} else {
			a.tv.SetFocus(a.dashLogs)
		}
		return nil
	}
	if logsFocused && a.logScrollKey(ev) || !logsFocused && ev.Rune() == 'f' && a.logScrollKey(ev) {
		return nil
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
	}
	return ev
}

// profileOp starts or reconnects the current profile.
func (a *app) profileOp(op string) {
	if t, _, ok := a.current(); ok {
		a.do(control.Change{Kind: control.KindProfile, Op: op, Profile: t.Name})
	}
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
