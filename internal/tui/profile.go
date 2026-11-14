package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"github.com/md2k/subnet-tunnel/internal/control"
	"github.com/md2k/subnet-tunnel/internal/meter"
)

const profInfoRows = 11

func (a *app) buildProfile() {
	a.profInfo = tview.NewTextView().SetDynamicColors(true).SetWrap(false)
	a.profInfo.SetBorder(true)
	sel := tcell.StyleDefault.Reverse(true)
	a.profItems = tview.NewTable().SetSelectable(true, false).SetFixed(1, 0).SetSelectedStyle(sel)
	a.profItems.SetBorder(true).SetTitle(" Routes and DNS names ")
	a.profConns = tview.NewTable().SetFixed(1, 0)
	a.profConns.SetBorder(true)
}

func (a *app) profilePage() tview.Primitive {
	return tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(a.profInfo, profInfoRows, 0, false).
		AddItem(a.profItems, 0, 1, true).
		AddItem(a.profConns, 0, 1, false)
}

func (a *app) openProfile(i int) {
	if !a.have || i < 0 || i >= len(a.st.Tunnels) {
		return
	}
	a.open = i
	a.profItems.Select(1, 0)
	a.goTo(scrProfile)
	a.pollSoon()
}

func (a *app) renderProfile(now time.Time) {
	if a.open < 0 || a.open >= len(a.st.Tunnels) {
		return
	}
	t := a.st.Tunnels[a.open]
	a.profInfo.SetTitle(" " + tview.Escape(nameOf(t)) + " ")
	w := 118 // before the first draw
	if a.scrW > 0 {
		w = a.scrW - 2
	}
	a.profInfo.SetText(a.profileText(t, now, max(w-graphLabel, 10)))

	// What it asks for, as rows to act on.
	row, col := a.profItems.GetSelection()
	a.profItems.Clear()
	for c, h := range []string{"KIND", "VALUE", "NOTE"} {
		a.profItems.SetCell(0, c, tview.NewTableCell(h).SetTextColor(tcell.ColorGray).SetSelectable(false))
	}
	a.itemRows = items(t)
	for i, it := range a.itemRows {
		note := "configured"
		switch {
		case it.added:
			note = "[green]added while running[-]"
		case it.removed:
			note = "[gray]removed while running[-]"
		}
		a.profItems.SetCell(i+1, 0, tview.NewTableCell(it.kind))
		a.profItems.SetCell(i+1, 1, tview.NewTableCell(itemText(it)))
		a.profItems.SetCell(i+1, 2, tview.NewTableCell(note).SetExpansion(1))
	}
	if len(a.itemRows) == 0 {
		a.profItems.SetCell(1, 1, tview.NewTableCell("[gray]no routes or DNS names: SOCKS only[-]").SetSelectable(false))
	}
	a.profItems.Select(min(max(row, 1), max(len(a.itemRows), 1)), col)

	conns := a.conns[t.Name]
	a.profConns.Clear()
	a.profConns.SetTitle(fmt.Sprintf(" Open connections (%d) ", len(conns)))
	for c, h := range []string{"DESTINATION", "VIA", "AGE", "UP", "DOWN"} {
		cell := tview.NewTableCell(h).SetTextColor(tcell.ColorGray)
		if c >= 2 {
			cell.SetAlign(tview.AlignRight)
		}
		a.profConns.SetCell(0, c, cell)
	}
	for i, c := range conns {
		a.profConns.SetCell(i+1, 0, tview.NewTableCell(tview.Escape(c.Dst)).SetExpansion(1))
		a.profConns.SetCell(i+1, 1, tview.NewTableCell(c.Via))
		a.profConns.SetCell(i+1, 2, tview.NewTableCell(short(now.Sub(c.Opened))).SetAlign(tview.AlignRight))
		a.profConns.SetCell(i+1, 3, tview.NewTableCell(meter.Bytes(c.Up)).SetAlign(tview.AlignRight))
		a.profConns.SetCell(i+1, 4, tview.NewTableCell(meter.Bytes(c.Down)).SetAlign(tview.AlignRight))
	}
}

// profileText is the top of the profile screen.
func (a *app) profileText(t control.Tunnel, now time.Time, sparkW int) string {
	var b strings.Builder
	line := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }
	head := []string{"[" + stateColor(t.State) + "]" + stateText(t, now) + "[-]"}
	if t.Target != "" {
		head = append(head, tview.Escape(t.Target))
	}
	if t.KillSwitch != "" {
		head = append(head, "kill switch "+ksText(t.KillSwitch))
	}
	if t.SOCKS != "" {
		head = append(head, "SOCKS "+tview.Escape(t.SOCKS))
	}
	line("%s", strings.Join(head, " · "))
	if len(t.Routes) > 0 {
		on := "[gray](not on the utun)[-]"
		if t.RoutesOn {
			on = "[gray](on the utun)[-]"
		}
		line("[gray]carries[-]   %s %s", tview.Escape(summary(t.Routes, 6)), on)
	}
	c := t.Counts
	via := ""
	if c.ViaSOCKS > 0 {
		via = fmt.Sprintf(" (%d through SOCKS)", c.ViaSOCKS)
	}
	line("[gray]traffic[-]   conns %d open / %d total / %d failed%s · loop guard refused %d", c.Open, c.Total, c.Failed, via, c.Refused)
	line("          ↑ %s (%s)  ↓ %s (%s) · DNS %d answered, %d failed", meter.Bytes(c.Up), rate(c.UpRate), meter.Bytes(c.Down), rate(c.DownRate),
		t.DNSCounts.Answered, t.DNSCounts.Failed)
	line("%s", a.graphText(t, "↑", c.UpRate, upOf, sparkW))
	line("%s", a.graphText(t, "↓", c.DownRate, downOf, sparkW))
	if t.LastError != "" && t.State != "up" {
		line("[red]last error:[-] %s", tview.Escape(t.LastError))
	}
	return strings.TrimSuffix(b.String(), "\n")
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
	if row < 1 || row > len(a.itemRows) {
		return item{}, false
	}
	return a.itemRows[row-1], true
}

func (a *app) profileKey(ev *tcell.EventKey) *tcell.EventKey {
	switch ev.Key() {
	case tcell.KeyEscape:
		a.open = -1
		a.goTo(scrDash)
		return nil
	case tcell.KeyTab, tcell.KeyBacktab:
		if a.tv.GetFocus() == a.profConns {
			a.tv.SetFocus(a.profItems)
		} else {
			a.tv.SetFocus(a.profConns)
		}
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
			case !ok:
				a.flash("yellow", "select a route, exclude, domain or pattern to delete")
			case it.removed:
				a.flash("yellow", it.kind+" "+it.value+" is removed already")
			default:
				a.confirmDelete(t, it)
			}
		})
	case 'l':
		a.filter.profile = t.Name
		a.openLogs()
	default:
		return ev
	}
	return nil
}
