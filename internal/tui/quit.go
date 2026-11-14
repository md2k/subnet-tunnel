package tui

import (
	"strings"

	"github.com/rivo/tview"

	"github.com/md2k/subnet-tunnel/internal/control"
)

// quitKey handles q and Ctrl-C. Attached (subtun tui), they quit the TUI.
// Inside subtun they ask before stopping it, and Ctrl-C at the question
// stops it at once.
func (a *app) quitKey(ctrlC bool) {
	if !a.inside() {
		a.quit()
		return
	}
	switch {
	case a.stopping:
		a.flash("yellow", "subtun is stopping")
	case a.quitDlg != nil && a.dialog == a.quitDlg.flex:
		if ctrlC {
			a.stopNow()
		}
	default:
		if a.dialog != nil { // Ctrl-C over another dialog
			a.closeDialog(a.dialog)
		}
		if a.searching {
			a.searching = false
			a.logsFlex.ResizeItem(a.search, 0, 0)
			a.tv.SetFocus(a.fullLogs)
		}
		a.confirmQuit()
	}
}

func (a *app) confirmQuit() {
	d := a.newDlg("Stop subtun?", quitText(a.st.Tunnels))
	d.form.AddButton("Stop subtun", a.stopNow).AddButton("Cancel", func() { a.closeDlg(d) })
	d.result.SetText("[gray]Ctrl-C again stops at once; esc cancels.[-]")
	a.quitDlg = d
	a.showDlg(d, 3)
}

// quitText says what stopping subtun does, by the profiles' kill switches.
func quitText(ts []control.Tunnel) string {
	s := "Its routes, DNS capture and SOCKS proxies go, and traffic goes the normal way (as after Ctrl-C without the TUI)."
	var lockdown, on []string
	for _, t := range ts {
		switch t.KillSwitch {
		case "lockdown":
			lockdown = append(lockdown, nameOf(t))
		case "on":
			on = append(on, nameOf(t))
		}
	}
	if len(lockdown) > 0 {
		s += "\n" + tview.Escape(strings.Join(lockdown, ", ")) + ": kill switch [red]lockdown[-]: blocking rules stay after subtun stops, so this traffic is [red]refused[-] until the next run takes them over, or subtun cleanup removes them."
	}
	if len(on) > 0 {
		s += "\n" + tview.Escape(strings.Join(on, ", ")) + ": kill switch [yellow]on[-]: its blocks are lifted too."
	}
	return s
}

// stopNow stops subtun; the TUI shows the stop until subtun ends it.
func (a *app) stopNow() {
	a.stopped()
	a.o.Stop()
}

// stopped shows that subtun is stopping.
func (a *app) stopped() {
	if a.quitDlg != nil {
		a.closeDlg(a.quitDlg)
		a.quitDlg = nil
	}
	if !a.stopping {
		a.stopping = true
		a.refresh()
	}
}
