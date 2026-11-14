package tui

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"github.com/md2k/subnet-tunnel/internal/control"
	"github.com/md2k/subnet-tunnel/internal/dns"
	"github.com/md2k/subnet-tunnel/internal/meter"
	"github.com/md2k/subnet-tunnel/internal/routes"
)

// The profile screen, in panes (btop style), each shown or hidden with
// its number key:
//
//	2 traffic      its counts next to its traffic graph       (top)
//	1 config       what it asks for, on two tabs (t): routes  (middle, left)
//	               and excludes, DNS names
//	3 connections  its open connections                       (middle, right)
//	4 logs         its log lines                              (bottom)
//
// Which panes show, and the config tab, are remembered between runs.
const (
	paneConfig = iota
	paneTraffic
	paneConns
	paneLogs
)

// paneKeys name the panes in the saved state; paneNames for people.
var (
	paneKeys  = []string{"config", "traffic", "connections", "logs"}
	paneNames = []string{"routes and DNS names", "traffic", "connections", "logs"}
)

// The config pane's tabs.
const (
	tabRoutes = "routes"
	tabDNS    = "dns"
)

func (a *app) buildProfile() {
	sel := tcell.StyleDefault.Reverse(true)
	a.profItems = tview.NewTable().SetSelectable(true, false).SetSelectedStyle(sel)
	a.profHint = tview.NewTextView().SetDynamicColors(true).SetWrap(false)
	a.profCfg = tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(a.profHint, 1, 0, false).
		AddItem(a.profItems, 0, 1, true)
	boxed(a.profCfg.Box, "")
	a.profStats = tview.NewTextView().SetDynamicColors(true).SetWrap(false)
	boxed(a.profStats.Box, "Counts")
	a.profGraph = tview.NewTextView().SetDynamicColors(true).SetWrap(false)
	boxed(a.profGraph.Box, "Traffic · 5 min")
	a.profConns = tview.NewTable()
	boxed(a.profConns.Box, "")
	a.profLogs = a.newLogView()
	a.profTop, a.profMid = tview.NewFlex(), tview.NewFlex()
	a.panes = [4]bool{true, true, true, true}
	for _, h := range a.o.HiddenPanes {
		if i := slices.Index(paneKeys, h); i >= 0 {
			a.panes[i] = false
		}
	}
	a.cfgTab = tabRoutes
	if a.o.ConfigTab == tabDNS {
		a.cfgTab = tabDNS
	}
}

// boxed gives a box a border and a title at the top left, as "─ title ─".
func boxed(b *tview.Box, title string) {
	b.SetBorder(true).SetTitleAlign(tview.AlignLeft).SetTitle(boxTitle(title))
}

func boxTitle(title string) string {
	if title == "" {
		return ""
	}
	return "─ " + title + " "
}

func (a *app) profilePage() tview.Primitive {
	a.profFlex = tview.NewFlex().SetDirection(tview.FlexRow)
	a.layoutProfile()
	return a.profFlex
}

// layoutProfile puts the profile screen together from the panes shown.
func (a *app) layoutProfile() {
	a.profFlex.Clear()
	a.profTop.Clear()
	a.profMid.Clear()
	wide := a.scrW == 0 || a.scrW >= 120
	if wide {
		a.profTop.SetDirection(tview.FlexColumn)
		a.profMid.SetDirection(tview.FlexColumn)
	} else { // narrow: one above the other
		a.profTop.SetDirection(tview.FlexRow)
		a.profMid.SetDirection(tview.FlexRow)
	}
	if a.panes[paneTraffic] {
		if wide {
			a.profTop.AddItem(a.profStats, 0, 2, false).AddItem(a.profGraph, 0, 3, false)
		} else {
			a.profTop.AddItem(a.profStats, a.statsRows(), 0, false).AddItem(a.profGraph, 0, 1, false)
		}
		a.profFlex.AddItem(a.profTop, a.topRows(), 0, false)
	}
	if a.panes[paneConfig] {
		a.profMid.AddItem(a.profCfg, 0, 3, true)
	}
	if a.panes[paneConns] {
		a.profMid.AddItem(a.profConns, 0, 2, false)
	}
	if a.panes[paneConfig] || a.panes[paneConns] {
		a.profFlex.AddItem(a.profMid, 0, 3, true)
	}
	if a.panes[paneLogs] {
		a.profFlex.AddItem(a.profLogs, 0, 2, false)
	}
	if a.panes[paneTraffic] && !a.panes[paneConfig] && !a.panes[paneConns] && !a.panes[paneLogs] {
		a.profFlex.ResizeItem(a.profTop, 0, 1) // alone: all the room
	}
	if a.screen == scrProfile && a.dialog == nil {
		a.tv.SetFocus(a.profFocusable()[0])
	}
}

// statsRows is the traffic stats' height (lines and borders); topRows the
// traffic pane's: stats next to the graph, or above it when narrow.
func (a *app) statsRows() int { return max(a.statLines, 1) + 2 }

func (a *app) topRows() int {
	graph := 2*a.graphRows() + 2 + 2
	if a.scrW == 0 || a.scrW >= 120 {
		return max(a.statsRows(), graph)
	}
	return a.statsRows() + graph
}

// profFocusable are the profile screen's panes tab moves through, the
// first the one that takes the focus.
func (a *app) profFocusable() []tview.Primitive {
	var out []tview.Primitive
	if a.panes[paneConfig] {
		out = append(out, a.profItems)
	}
	if a.panes[paneConns] {
		out = append(out, a.profConns)
	}
	if a.panes[paneLogs] {
		out = append(out, a.profLogs)
	}
	if len(out) == 0 {
		out = append(out, a.profFlex)
	}
	return out
}

// togglePane shows or hides one of the profile screen's panes.
func (a *app) togglePane(p int) {
	a.panes[p] = !a.panes[p]
	a.layoutProfile()
	if p == paneLogs && a.panes[p] {
		a.follow()
	}
	state := "hidden"
	if a.panes[p] {
		state = "shown"
	}
	a.flash("green", fmt.Sprintf("%s %s (%d)", paneNames[p], state, p+1))
	a.saveView()
	a.refresh()
}

// switchTab shows the config pane's other tab (or the one given).
func (a *app) switchTab(tab string) {
	if tab == "" {
		tab = map[string]string{tabRoutes: tabDNS, tabDNS: tabRoutes}[a.cfgTab]
	}
	if tab != a.cfgTab {
		a.cfgTab = tab
		a.profItems.Select(0, 0)
		a.saveView()
	}
	a.refresh()
}

// saveView hands the panes hidden, the config tab and the log levels
// hidden to be remembered.
func (a *app) saveView() {
	if a.o.OnView == nil {
		return
	}
	v := View{ConfigTab: a.cfgTab}
	for i, on := range a.panes {
		if !on {
			v.HiddenPanes = append(v.HiddenPanes, paneKeys[i])
		}
	}
	for i, hide := range a.filter.hide {
		if hide {
			v.HiddenLevels = append(v.HiddenLevels, levelNames[i])
		}
	}
	a.o.OnView(v)
}

func (a *app) openProfile(i int) {
	if !a.have || i < 0 || i >= len(a.st.Tunnels) {
		return
	}
	a.open = i
	a.profItems.Select(0, 0)
	a.goTo(scrProfile)
	a.pollSoon()
}

// cardLine is a row of the config pane: a heading, an item, or a line of
// text; item rows can be selected (d deletes one).
type cardLine struct {
	cells []string // tview-tagged
	item  *item
}

func (a *app) renderProfile(now time.Time) {
	if a.open < 0 || a.open >= len(a.st.Tunnels) {
		return
	}
	t := a.st.Tunnels[a.open]

	// Traffic: the stats next to the graph.
	stats := a.statsText(t)
	if n := strings.Count(stats, "\n") + 1; n != a.statLines {
		a.statLines = n
		a.layoutProfile()
	}
	a.profStats.SetText(stats)
	w := 120 // before the first draw
	if a.scrW > 0 {
		w = a.scrW
	}
	gw := w - 2 // the graph's width, less its borders
	if a.scrW == 0 || a.scrW >= 120 {
		gw = w - w*2/5 - 2
	}
	a.profGraph.SetText(strings.Join(a.trafficGraph(t, max(gw, 10), a.graphRows()), "\n"))

	// Config: the tab's rows.
	a.cardLines = a.configLines(t)
	a.profCfg.SetTitle(boxTitle(a.tabsTitle(t)))
	a.profHint.SetText(a.tabHint(t))
	row, _ := a.profItems.GetSelection()
	a.profItems.Clear()
	for r, l := range a.cardLines {
		for c, text := range l.cells {
			cell := tview.NewTableCell(text).SetSelectable(l.item != nil)
			if c == len(l.cells)-1 {
				cell.SetExpansion(1)
			}
			a.profItems.SetCell(r, c, cell)
		}
	}
	// tview's Table spins forever on an arrow key when rows are selectable
	// but none is: select rows only when there is an item to select.
	hasItem := slices.ContainsFunc(a.cardLines, func(l cardLine) bool { return l.item != nil })
	a.profItems.SetSelectable(hasItem, false)
	if hasItem {
		a.profItems.Select(a.selectableRow(row), 0)
	}

	conns := a.conns[t.Name]
	a.profConns.Clear()
	a.profConns.SetTitle(boxTitle(fmt.Sprintf("Open connections (%d)", len(conns))))
	for c, h := range []string{"DESTINATION", "VIA", "AGE", "UP", "DOWN"} {
		a.profConns.SetCell(0, c, tview.NewTableCell(h+"   ").SetTextColor(tcell.ColorGray))
	}
	for i, c := range conns {
		for col, text := range []string{tview.Escape(c.Dst), c.Via, short(now.Sub(c.Opened)), meter.Bytes(c.Up), meter.Bytes(c.Down)} {
			a.profConns.SetCell(i+1, col, tview.NewTableCell(text+"   "))
		}
	}
	a.profLogs.SetTitle(boxTitle("Logs · " + tview.Escape(nameOf(t)) + " · levels: " + a.filter.levels() + " · " + a.followText()))
}

// selectableRow is row if it can be selected, else the nearest item row
// after it (or before); 0 when there is none.
func (a *app) selectableRow(row int) int {
	for r := max(row, 0); r < len(a.cardLines); r++ {
		if a.cardLines[r].item != nil {
			return r
		}
	}
	for r := min(row, len(a.cardLines)-1); r >= 0; r-- {
		if a.cardLines[r].item != nil {
			return r
		}
	}
	return 0
}

// cardTitle is "work · up 1h12m · pod ops/toolbox (binary agent 0.4.1) ·
// kill switch on".
func (a *app) cardTitle(t control.Tunnel, now time.Time) string {
	parts := []string{tview.Escape(nameOf(t)), stateText(t, now)}
	if t.Target != "" {
		target := targetShort(t.Target)
		if ag := agentText(t); ag != "" {
			target += " (" + ag + ")"
		}
		parts = append(parts, tview.Escape(target))
	}
	if t.KillSwitch != "" {
		parts = append(parts, "kill switch "+t.KillSwitch)
	}
	if t.SOCKS != "" {
		parts = append(parts, "SOCKS "+tview.Escape(t.SOCKS))
	}
	return strings.Join(parts, " · ")
}

// tabsTitle is the config pane's title: its tabs, the one shown bright.
func (a *app) tabsTitle(t control.Tunnel) string {
	its := items(t)
	count := func(kinds ...string) int {
		n := 0
		for _, it := range its {
			if slices.Contains(kinds, it.kind) && !it.removed {
				n++
			}
		}
		return n
	}
	tab := func(name string, n int, on bool) string {
		if on {
			return fmt.Sprintf("[yellow::b]%s (%d)[-::-]", name, n)
		}
		return fmt.Sprintf("[gray]%s (%d)[-]", name, n)
	}
	return tab("Routes", count("route", "exclude"), a.cfgTab == tabRoutes) + " · " + tab("DNS names", count("dns", "pattern"), a.cfgTab == tabDNS)
}

// tabHint is the line of keys for the tab shown; grey where they don't
// work (a read-only run, a profile without routes, a run without DNS
// capture).
func (a *app) tabHint(t control.Tunnel) string {
	works := a.writable() && !a.stopping
	other := "DNS names"
	keys := []string{"a add", "x exclude", "d delete"}
	if a.cfgTab == tabRoutes {
		works = works && len(t.Include) > 0
	} else {
		works = works && a.st.DNS != nil && !a.st.DNS.Development
		other, keys = "routes", []string{"a add", "d delete"}
	}
	color := "[yellow]"
	if !works {
		color = "[darkgray]"
	}
	var parts []string
	for _, k := range keys {
		key, what, _ := strings.Cut(k, " ")
		parts = append(parts, color+key+"[-] "+what)
	}
	return " " + strings.Join(parts, "  ") + "    [yellow]t[-] " + other
}

// configLines are the rows of the config tab shown: the routes and
// excludes, or the DNS names, each with when it was added and a note.
func (a *app) configLines(t control.Tunnel) []cardLine {
	var out []cardLine
	text := func(cells ...string) { out = append(out, cardLine{cells: cells}) }
	its := items(t)
	when := func(it item) string {
		sign := "+"
		if it.removed {
			sign = "-"
		}
		at := t.ChangedAt[sign+it.kind+" "+normalizedValue(it)] // the change texts carry normalized values
		switch {
		case it.added && !at.IsZero():
			return "[green]added " + at.Local().Format("15:04") + "[-]"
		case it.added:
			return "[green]added[-]"
		case it.removed && !at.IsZero():
			return "[gray]removed " + at.Local().Format("15:04") + "[-]"
		case it.removed:
			return "[gray]removed[-]"
		}
		return "configured"
	}
	row := func(it item, label, after, note string) {
		value := tview.Escape(it.value)
		switch {
		case it.added:
			value = "[green]" + value + "[-]"
		case it.removed:
			value = "[gray]" + value + "[-]"
		}
		out = append(out, cardLine{cells: []string{" " + label + value + after, when(it), "[gray]" + tview.Escape(note) + "[-]"}, item: &it})
	}
	if a.cfgTab == tabRoutes {
		n := 0
		for _, it := range its {
			if it.kind == "route" {
				row(it, "", "", t.RouteNotes[it.value])
				n++
			}
		}
		if n == 0 {
			text(" [gray]none: SOCKS only (routes can't be added to a profile that started without)[-]", "", "")
		}
		if slices.ContainsFunc(its, func(it item) bool { return it.kind == "exclude" }) {
			text("", "", "")
			text(" [gray]Excludes[-]", "", "")
			for _, it := range its {
				if it.kind == "exclude" {
					row(it, "", "", "")
				}
			}
		}
		return out
	}
	first := true
	for _, it := range its {
		if it.kind != "dns" && it.kind != "pattern" {
			continue
		}
		note := ""
		if first && t.Unrouted != "" {
			note = "unrouted answers: " + t.Unrouted
		}
		first = false
		switch {
		case it.kind == "pattern":
			row(it, "pattern ", "", note)
		case it.value == ".":
			row(it, "", "  [gray](all, except local names)[-]", note)
		default:
			row(it, "", "", note)
		}
	}
	switch {
	case first && (a.st.DNS == nil || a.st.DNS.Development):
		text(" [gray]none (this run doesn't capture DNS, so names can't be added)[-]", "", "")
	case first:
		text(" [gray]none[-]", "", "")
	}
	return out
}

// statsText is the traffic pane's counts.
func (a *app) statsText(t control.Tunnel) string {
	c := t.Counts
	via := ""
	if c.ViaSOCKS > 0 {
		via = fmt.Sprintf(" (%d via SOCKS)", c.ViaSOCKS)
	}
	var lines []string
	if v := viaText(t); v != "" {
		lines = append(lines, "[gray]via    [-]  "+tview.Escape(v))
	}
	lines = append(lines,
		fmt.Sprintf("[gray]conns  [-]  %d open / %d total / %d failed%s", c.Open, c.Total, c.Failed, via),
		fmt.Sprintf("[gray]bytes  [-]  ↑ %s (%s)  ↓ %s (%s)", meter.Bytes(c.Up), a.rate(c.UpRate), meter.Bytes(c.Down), a.rate(c.DownRate)),
		fmt.Sprintf("[gray]DNS    [-]  %d answered, %d failed", t.DNSCounts.Answered, t.DNSCounts.Failed),
	)
	if c.Refused > 0 {
		lines = append(lines, fmt.Sprintf("[gray]guard  [-]  [yellow]loop guard refused %d[-]", c.Refused))
	}
	if len(t.Routes) > 0 {
		on := "not on the utun"
		if t.RoutesOn {
			on = "on the utun"
		}
		lines = append(lines, fmt.Sprintf("[gray]carries[-]  %s [gray](%s)[-]", tview.Escape(summary(t.Routes, 4)), on))
	}
	if t.LastError != "" && t.State != "up" {
		lines = append(lines, "[red]error  [-]  "+tview.Escape(t.LastError))
	}
	return strings.Join(lines, "\n")
}

// normalizedValue is an item's value as the runtime changes write it.
func normalizedValue(it item) string {
	switch it.kind {
	case "route":
		return normalized(routes.ParseRoute)(it.value)
	case "exclude":
		return normalized(routes.ParsePrefix)(it.value)
	case "dns":
		if n, err := dns.NormalizeDomain(it.value); err == nil {
			return n
		}
	}
	return it.value
}

// agentText is the agent from a target's description: "binary agent 0.4.1".
func agentText(t control.Tunnel) string {
	i := strings.LastIndex(t.Target, ", ")
	if i < 0 {
		return ""
	}
	kind := t.Target[i+2:]
	if t.Agent != "" && strings.HasSuffix(kind, "agent") {
		kind += " " + t.Agent
	}
	return kind
}

// summary lists up to n items, then how many more.
func summary(list []string, n int) string {
	if len(list) <= n {
		return strings.Join(list, ", ")
	}
	return fmt.Sprintf("%s and %d more", strings.Join(list[:n], ", "), len(list)-n)
}

// selectedItem is the item selected on the profile screen.
func (a *app) selectedItem() (item, bool) {
	row, _ := a.profItems.GetSelection()
	if row < 0 || row >= len(a.cardLines) || a.cardLines[row].item == nil {
		return item{}, false
	}
	return *a.cardLines[row].item, true
}

func (a *app) profileKey(ev *tcell.EventKey) *tcell.EventKey {
	switch ev.Key() {
	case tcell.KeyEscape:
		a.open = -1
		a.goTo(scrDash)
		return nil
	case tcell.KeyTab, tcell.KeyBacktab: // the panes shown
		order := a.profFocusable()
		i := slices.Index(order, a.tv.GetFocus())
		a.tv.SetFocus(order[(i+1)%len(order)])
		return nil
	}
	if a.tv.GetFocus() == a.profLogs && a.logScrollKey(ev) {
		return nil
	}
	t, _, ok := a.current()
	if !ok {
		return ev
	}
	switch ev.Rune() {
	case 's':
		a.act(a.confirmStop)
	case 'S':
		a.act(func() { a.profileOp("start") })
	case 'r':
		a.act(func() { a.profileOp("reconnect") })
	case 'R':
		a.act(func() { a.confirmReload(t) })
	case 't':
		a.switchTab("")
	case 'a':
		if a.cfgTab == tabDNS {
			a.act(func() { a.dnsDialog(t) })
		} else {
			a.act(func() { a.routeDialog(t, false) })
		}
	case 'x':
		a.switchTab(tabRoutes)
		a.act(func() { a.routeDialog(t, true) })
	case 'A':
		a.switchTab(tabDNS)
		a.act(func() { a.dnsDialog(t) })
	case 'd', 'D':
		a.act(func() {
			it, ok := a.selectedItem()
			switch {
			case !a.panes[paneConfig]:
				a.flash("yellow", "show the routes and DNS names first (1)")
			case !ok && a.cfgTab == tabDNS:
				a.flash("yellow", "select a domain or pattern to delete")
			case !ok:
				a.flash("yellow", "select a route or exclude to delete")
			case it.removed:
				a.flash("yellow", it.kind+" "+it.value+" is removed already")
			default:
				a.confirmDelete(t, it)
			}
		})
	case '1', '2', '3', '4':
		a.togglePane(int(ev.Rune() - '1'))
	case 'c':
		a.togglePane(paneConns)
	case 'l':
		a.togglePane(paneLogs)
	case 'L':
		a.filter.profile = t.Name
		a.openLogs()
	default:
		return ev
	}
	return nil
}
