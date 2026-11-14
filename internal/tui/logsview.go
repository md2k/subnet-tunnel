package tui

import (
	"fmt"
	"slices"
	"strings"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"github.com/md2k/subnet-tunnel/internal/logring"
)

// Two views show the log lines: the dashboard's and the full screen's.
// Only the one on screen gets new lines (tview trims a view to its maximum
// only when drawing it); a view coming on screen is filled again from the
// lines kept. Paused, it gets none: what it shows stays put, and the lines
// that came are counted.

func (a *app) buildLogs() {
	a.fullLogs = a.newLogView()
	a.search = tview.NewInputField().SetLabel(" / ")
	a.search.SetDoneFunc(func(key tcell.Key) {
		switch key {
		case tcell.KeyEnter:
			a.filter.search = strings.TrimSpace(a.search.GetText())
		case tcell.KeyEscape:
		default:
			return
		}
		a.searching = false
		a.logsFlex.ResizeItem(a.search, 0, 0)
		a.tv.SetFocus(a.fullLogs)
		a.rebuildLogs()
		a.refresh()
	})
	a.logsFlex = tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(a.fullLogs, 0, 1, true).
		AddItem(a.search, 0, 0, false) // shown while searching
}

// openLogs shows the logs full screen; esc returns to where it came from.
func (a *app) openLogs() {
	if a.screen != scrLogs {
		a.logsBack = a.screen
	}
	a.goTo(scrLogs)
}

func (a *app) startSearch() {
	a.searching = true
	a.search.SetText(a.filter.search)
	a.logsFlex.ResizeItem(a.search, 1, 0)
	a.tv.SetFocus(a.search)
}

// logView is the log view on screen; nil: none.
func (a *app) logView() *tview.TextView {
	switch {
	case a.screen == scrDash:
		return a.dashLogs
	case a.screen == scrLogs:
		return a.fullLogs
	case a.screen == scrProfile && a.panes[paneLogs]:
		return a.profLogs
	}
	return nil
}

// viewFilter is the filter of the log view on screen: the profile screen's
// shows its profile's lines; the dashboard's every profile's.
func (a *app) viewFilter() logFilter {
	f := a.filter
	if a.screen == scrProfile && a.open >= 0 && a.open < len(a.st.Tunnels) {
		f.profile = a.st.Tunnels[a.open].Name
	}
	return f
}

// scrollsBack reports whether a key scrolls a log view away from its end.
func scrollsBack(ev *tcell.EventKey) bool {
	switch ev.Key() {
	case tcell.KeyUp, tcell.KeyPgUp, tcell.KeyHome, tcell.KeyCtrlB:
		return true
	}
	return ev.Rune() == 'k' || ev.Rune() == 'g'
}

// toEnd reports whether a key goes to a log view's end.
func toEnd(ev *tcell.EventKey) bool { return ev.Key() == tcell.KeyEnd || ev.Rune() == 'G' }

// logScrollKey handles the keys of the log view on screen: following or
// pausing it, and d, i, w, e (the levels it shows); false: not one of them.
func (a *app) logScrollKey(ev *tcell.EventKey) bool {
	if i := strings.IndexRune("diwe", ev.Rune()); i >= 0 && ev.Modifiers()&tcell.ModAlt == 0 {
		a.filter.hide[i] = !a.filter.hide[i]
		a.rebuildLogs()
		a.flash("green", "levels shown: "+a.filter.levels())
		a.refresh()
		return true
	}
	switch {
	case toEnd(ev):
		a.follow()
	case scrollsBack(ev):
		a.pause()
		return false // the view scrolls
	case ev.Rune() == 'f':
		if a.following {
			a.pause()
		} else {
			a.follow()
		}
	default:
		return false
	}
	return true
}

func (a *app) logsKey(ev *tcell.EventKey) *tcell.EventKey {
	if ev.Key() == tcell.KeyEscape {
		if a.logsBack == scrProfile && a.open >= 0 {
			a.goTo(scrProfile)
		} else {
			a.goTo(scrDash)
		}
		return nil
	}
	if a.logScrollKey(ev) {
		return nil
	}
	switch ev.Rune() {
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
	case '/':
		a.startSearch()
		return nil
	}
	return ev
}

// follow fills the log view on screen with the lines kept and follows new
// ones.
func (a *app) follow() {
	a.following = true
	a.rebuildLogs()
	a.refresh()
}

// pause keeps the log view on screen as it is.
func (a *app) pause() {
	if a.following {
		a.following, a.unseen = false, 0
		a.refresh()
	}
}

func (a *app) formatLine(l logring.Line, f logFilter) string {
	return formatLine(l, f, max(a.nameWidth(), 7), a.profileColor)
}

// addLines keeps new log lines, and shows them if following.
func (a *app) addLines(batch []logring.Line) {
	var shown []string
	f := a.viewFilter()
	for _, l := range batch {
		if a.logs.add(l) && f.match(l) {
			shown = append(shown, a.formatLine(l, f))
		}
	}
	if len(shown) == 0 {
		return
	}
	if !a.following {
		a.unseen += len(shown)
	} else if tv := a.logView(); tv != nil {
		text := strings.Join(shown, "\n")
		if a.logText {
			text = "\n" + text
		}
		a.logText = true
		fmt.Fprint(tv, text)
		tv.ScrollToEnd()
	}
	a.renderLogTitles()
	if a.screen == scrLogs {
		a.renderHeader()
	}
}

// rebuildLogs fills the log view on screen with the lines kept, as the
// filter picks them, and goes to its end.
func (a *app) rebuildLogs() {
	a.unseen = 0
	a.renderLogTitles()
	tv := a.logView()
	if tv == nil {
		return
	}
	var shown []string
	f := a.viewFilter()
	for _, l := range a.logs.lines {
		if f.match(l) {
			shown = append(shown, a.formatLine(l, f))
		}
	}
	a.logText = len(shown) > 0
	tv.SetText(strings.Join(shown, "\n"))
	tv.ScrollToEnd()
}

func (a *app) renderLogTitles() {
	a.dashLogs.SetTitle(boxTitle("Logs · " + tview.Escape(a.filter.describe()) + " · " + a.followText()))
}
