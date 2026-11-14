package tui

import (
	"fmt"
	"slices"
	"strings"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"github.com/md2k/subnet-tunnel/internal/logring"
)

func (a *app) buildLogs() {
	a.fullLogs = newLogView()
	a.search = tview.NewInputField().SetLabel(" / ")
	a.search.SetDoneFunc(func(key tcell.Key) {
		switch key {
		case tcell.KeyEnter:
			a.filter.search = strings.TrimSpace(a.search.GetText())
			a.rebuildLogs()
		case tcell.KeyEscape:
		default:
			return
		}
		a.endSearch()
	})
	a.logsFlex = tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(a.fullLogs, 0, 1, true).
		AddItem(a.search, 0, 0, false) // shown while searching
}

func (a *app) openLogs() {
	if a.screen != scrLogs {
		a.back = a.screen
	}
	a.screen = scrLogs
	a.pages.SwitchToPage(scrLogs)
	a.tv.SetFocus(a.fullLogs)
	if a.following {
		a.fullLogs.ScrollToEnd()
	}
	a.refresh()
}

func (a *app) startSearch() {
	a.searching = true
	a.search.SetText(a.filter.search)
	a.logsFlex.ResizeItem(a.search, 1, 0)
	a.tv.SetFocus(a.search)
}

func (a *app) endSearch() {
	a.searching = false
	a.logsFlex.ResizeItem(a.search, 0, 0)
	a.tv.SetFocus(a.fullLogs)
	a.refresh()
}

// scrollsBack reports whether a key scrolls a log view away from its end.
func scrollsBack(ev *tcell.EventKey) bool {
	switch ev.Key() {
	case tcell.KeyUp, tcell.KeyPgUp, tcell.KeyHome, tcell.KeyCtrlB:
		return true
	}
	return ev.Rune() == 'k' || ev.Rune() == 'g'
}

func (a *app) logsKey(ev *tcell.EventKey) *tcell.EventKey {
	if ev.Key() == tcell.KeyEscape {
		a.leave()
		return nil
	}
	if ev.Key() == tcell.KeyEnd || ev.Rune() == 'G' {
		a.following = true
		a.unseen = 0
		a.fullLogs.ScrollToEnd()
		a.refresh()
		return nil
	}
	if scrollsBack(ev) {
		a.following = false
		a.refresh()
		return ev
	}
	switch ev.Rune() {
	case 'f':
		a.toggleFollow()
		return nil
	case 'p':
		names := []string{""}
		for _, t := range a.st.Tunnels {
			if t.Name != "" {
				names = append(names, t.Name)
			}
		}
		i := slices.Index(names, a.filter.profile)
		a.filter.profile = names[(i+1)%len(names)]
		a.rebuildLogs()
		a.refresh()
		return nil
	case 'v':
		i := slices.Index(levels, a.filter.level)
		a.filter.level = levels[(i+1)%len(levels)]
		a.rebuildLogs()
		a.refresh()
		return nil
	case '/':
		a.startSearch()
		return nil
	}
	return ev
}

func (a *app) toggleFollow() {
	a.following = !a.following
	if a.following {
		a.unseen = 0
		a.dashLogs.ScrollToEnd()
		a.fullLogs.ScrollToEnd()
	}
	a.refresh()
}

func (a *app) formatLine(l logring.Line) string {
	return formatLine(l, a.filter, a.nameWidth(), a.profileColor)
}

// addLines adds new log lines to the views.
func (a *app) addLines(batch []logring.Line) {
	var shown []string
	for _, l := range batch {
		if a.logs.add(l) && a.filter.match(l) {
			shown = append(shown, a.formatLine(l))
		}
	}
	if len(shown) == 0 {
		return
	}
	text := strings.Join(shown, "\n")
	if a.logText {
		text = "\n" + text
	}
	a.logText = true
	for _, tv := range []*tview.TextView{a.dashLogs, a.fullLogs} {
		fmt.Fprint(tv, text)
		if a.following {
			tv.ScrollToEnd()
		}
	}
	if !a.following {
		a.unseen += len(shown)
	}
	a.renderLogTitles()
	if a.screen == scrLogs {
		a.renderHeader()
	}
}

// rebuildLogs shows the lines kept again, as the filter picks them.
func (a *app) rebuildLogs() {
	var shown []string
	for _, l := range a.logs.lines {
		if a.filter.match(l) {
			shown = append(shown, a.formatLine(l))
		}
	}
	text := strings.Join(shown, "\n")
	a.logText = len(shown) > 0
	a.unseen = 0
	for _, tv := range []*tview.TextView{a.dashLogs, a.fullLogs} {
		tv.SetText(text)
		if a.following {
			tv.ScrollToEnd()
		}
	}
	a.renderLogTitles()
}

func (a *app) renderLogTitles() {
	a.dashLogs.SetTitle(" Logs · " + tview.Escape(a.filter.describe()) + " · " + a.followText() + " ")
}
