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

// The profile screen: a card (what the profile asks for, in sections, and
// its traffic graph next to it), then its open connections and its log
// lines, each shown or hidden (c, l).

func (a *app) buildProfile() {
	sel := tcell.StyleDefault.Reverse(true)
	a.profItems = tview.NewTable().SetSelectable(true, false).SetSelectedStyle(sel)
	a.profTraffic = tview.NewTextView().SetDynamicColors(true).SetWrap(false)
	a.profLeft = tview.NewFlex().SetDirection(tview.FlexRow)
	boxed(a.profLeft.Box, "")
	a.profGraph = tview.NewTextView().SetDynamicColors(true).SetWrap(false)
	boxed(a.profGraph.Box, "Traffic · 5 min")
	a.profConns = tview.NewTable()
	boxed(a.profConns.Box, "")
	a.profLogs = a.newLogView()
	a.panes = [4]bool{true, true, true, true}
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
	a.profLeft.AddItem(a.profItems, 0, 1, true).AddItem(a.profTraffic, 4, 0, false)
	a.profCard = tview.NewFlex()
	a.profFlex = tview.NewFlex().SetDirection(tview.FlexRow)
	a.layoutProfile()
	return a.profFlex
}

// The profile screen's panes, each shown or hidden with its number key
// (btop style): what it asks for, its traffic graph, its connections, its
// logs. On a wide terminal the first two sit side by side.
const (
	paneConfig = iota
	paneGraph
	paneConns
	paneLogs
)

var paneNames = []string{"routes and DNS", "traffic graph", "connections", "logs"}

// layoutProfile puts the profile screen together from the panes shown:
// the card (sections, graph), then the connections and the logs, which
// share what is left.
func (a *app) layoutProfile() {
	a.profFlex.Clear()
	a.profCard.Clear()
	if a.panes[paneConfig] {
		a.profCard.AddItem(a.profLeft, 0, 3, true)
	}
	if a.panes[paneGraph] {
		a.profCard.AddItem(a.profGraph, 0, 2, false)
	}
	a.arrangeCard()
	card := a.panes[paneConfig] || a.panes[paneGraph]
	rest := a.panes[paneConns] || a.panes[paneLogs]
	switch {
	case card && rest:
		a.profFlex.AddItem(a.profCard, a.cardRows(), 0, true)
	case card:
		a.profFlex.AddItem(a.profCard, 0, 1, true)
	}
	if a.panes[paneConns] {
		a.profFlex.AddItem(a.profConns, 0, 1, false)
	}
	if a.panes[paneLogs] {
		a.profFlex.AddItem(a.profLogs, 0, 2, false)
	}
	if a.screen == scrProfile && a.dialog == nil {
		a.tv.SetFocus(a.profFocusable()[0])
	}
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

// sideBySide reports whether the card's graph goes next to its sections
// (wide screens) or below them.
func (a *app) sideBySide() bool { return a.scrW == 0 || a.scrW >= 140 }

// cardRows is the card's height: the sections and traffic lines next to
// the graph (both sides and their lines), or the two stacked, as shown;
// borders included.
func (a *app) cardRows() int {
	left, graph := 0, 0
	if a.panes[paneConfig] {
		left = len(a.cardLines) + a.trafficRows + 2
	}
	if a.panes[paneGraph] {
		graph = 2*a.graphRows() + 2 + 2
	}
	if a.sideBySide() {
		return max(left, graph)
	}
	return left + graph
}

// arrangeCard puts the graph next to the sections or below them.
func (a *app) arrangeCard() {
	if a.sideBySide() {
		a.profCard.SetDirection(tview.FlexColumn)
		a.profCard.ResizeItem(a.profLeft, 0, 3)
		a.profCard.ResizeItem(a.profGraph, 0, 2)
		return
	}
	a.profCard.SetDirection(tview.FlexRow)
	a.profCard.ResizeItem(a.profLeft, len(a.cardLines)+a.trafficRows+2, 0)
	a.profCard.ResizeItem(a.profGraph, 2*a.graphRows()+2+2, 0)
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
	a.refresh()
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

// cardLine is a row of the card: a section's heading, an item, or a line of
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
	a.cardLines = a.card(t)
	traffic := a.trafficText(t)
	a.trafficRows = strings.Count(traffic, "\n") + 1
	a.profLeft.ResizeItem(a.profTraffic, a.trafficRows, 0)
	a.profTraffic.SetText(traffic)
	a.arrangeCard()
	if a.panes[paneConns] || a.panes[paneLogs] {
		a.profFlex.ResizeItem(a.profCard, a.cardRows(), 0)
	}
	a.profLeft.SetTitle(boxTitle(a.cardTitle(t, now)))
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

	w := 120 // before the first draw
	if a.scrW > 0 {
		w = a.scrW
	}
	gw := w - 2 // the graph's part, less its borders
	if a.sideBySide() {
		gw = w - w*3/5 - 2
	}
	a.profGraph.SetText(strings.Join(a.trafficGraph(t, max(gw, 10), a.graphRows()), "\n"))

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
	a.profLogs.SetTitle(boxTitle("Logs · " + tview.Escape(nameOf(t)) + " · level: " + strings.ToLower(a.filter.level.String()) + " · " + a.followText()))
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

// card is the profile card's rows: routes, excludes, DNS names, each with
// its keys and notes.
func (a *app) card(t control.Tunnel) []cardLine {
	var out []cardLine
	text := func(cells ...string) { out = append(out, cardLine{cells: cells}) }
	// heading starts a section, with its keys: yellow when they work here.
	heading := func(title, keys string, works bool) {
		color := "[yellow]"
		if !works || a.st.Control != "full" {
			color = "[darkgray]"
		}
		text("[gray]"+title+"[-]", "", color+tview.Escape(keys)+"[-]")
	}
	routed := len(t.Include) > 0
	dnsCaptured := a.st.DNS != nil && !a.st.DNS.Development
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
	// row adds an item: label before its value, note after.
	row := func(it item, label, after, note string) {
		value := tview.Escape(it.value)
		switch {
		case it.added:
			value = "[green]" + value + "[-]"
		case it.removed:
			value = "[gray]" + value + "[-]"
		}
		out = append(out, cardLine{cells: []string{"  " + label + value + after, when(it), "[gray]" + tview.Escape(note) + "[-]"}, item: &it})
	}

	heading("Routes on the utun", "[a] add  [d] delete  [x] exclude", routed)
	n := 0
	for _, it := range its {
		if it.kind == "route" {
			row(it, "", "", t.RouteNotes[it.value])
			n++
		}
	}
	if n == 0 {
		text("  [gray]none: SOCKS only (routes can't be added to a profile that started without)[-]", "", "")
	}
	if slices.ContainsFunc(its, func(it item) bool { return it.kind == "exclude" }) {
		heading("Excludes", "", true)
		for _, it := range its {
			if it.kind == "exclude" {
				row(it, "", "", "")
			}
		}
	}
	text("", "", "")
	heading("DNS names through this tunnel", "[A] add  [D] delete", dnsCaptured)
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
	case first && !dnsCaptured:
		text("  [gray]none (this run doesn't capture DNS, so names can't be added)[-]", "", "")
	case first:
		text("  [gray]none[-]", "", "")
	}
	text("", "", "")
	return out
}

// trafficText is the card's traffic lines.
func (a *app) trafficText(t control.Tunnel) string {
	c := t.Counts
	via := ""
	if c.ViaSOCKS > 0 {
		via = fmt.Sprintf(" (%d through SOCKS)", c.ViaSOCKS)
	}
	lines := []string{
		fmt.Sprintf("[gray]Traffic[-]  conns %d open / %d total / %d failed%s · loop guard refused %d", c.Open, c.Total, c.Failed, via, c.Refused),
		fmt.Sprintf("         ↑ %s (%s)  ↓ %s (%s) · DNS %d answered, %d failed", meter.Bytes(c.Up), a.rate(c.UpRate), meter.Bytes(c.Down), a.rate(c.DownRate),
			t.DNSCounts.Answered, t.DNSCounts.Failed),
	}
	if len(t.Routes) > 0 {
		on := "not on the utun"
		if t.RoutesOn {
			on = "on the utun"
		}
		lines = append(lines, fmt.Sprintf("         carries %s [gray](%s)[-]", tview.Escape(summary(t.Routes, 4)), on))
	}
	if t.LastError != "" && t.State != "up" {
		lines = append(lines, "[red]Error[-]    "+tview.Escape(t.LastError))
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
	case 'a':
		a.act(func() { a.routeDialog(t, false) })
	case 'x':
		a.act(func() { a.routeDialog(t, true) })
	case 'A':
		a.act(func() { a.dnsDialog(t) })
	case 'd', 'D':
		a.act(func() {
			it, ok := a.selectedItem()
			switch {
			case !a.panes[paneConfig]:
				a.flash("yellow", "show the routes and DNS names first (1)")
			case !ok:
				a.flash("yellow", "select a route, exclude, domain or pattern to delete")
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
