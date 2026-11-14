package tui

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"github.com/md2k/subnet-tunnel/internal/control"
)

// dlg is a dialog: an explanation, a form, and the dry run or the answer.
type dlg struct {
	flex   *tview.Flex
	text   *tview.TextView
	form   *tview.Form
	result *tview.TextView
	gen    int  // the dry run asked last; older answers are dropped
	shown  int  // the dry run on show
	busy   bool // the change is on its way
}

const (
	dialogWidth = 84
	resultRows  = 4
)

func (a *app) newDlg(title, text string) *dlg {
	d := &dlg{
		flex:   tview.NewFlex().SetDirection(tview.FlexRow),
		text:   tview.NewTextView().SetDynamicColors(true).SetWordWrap(true).SetText(text),
		form:   tview.NewForm().SetButtonsAlign(tview.AlignCenter),
		result: tview.NewTextView().SetDynamicColors(true).SetWordWrap(true),
	}
	d.flex.SetBorder(true).SetTitle(" " + tview.Escape(title) + " ")
	d.form.SetCancelFunc(func() { a.closeDlg(d) })
	return d
}

// fit is a dialog's size on this screen: the pages part (the screen less
// the header, message and key lines).
func (a *app) fit(w, h int) (int, int) {
	if a.scrW > 0 {
		return max(min(w, a.scrW), 1), max(min(h, a.scrH-3), 1)
	}
	return w, h
}

// showDlg opens the dialog; formRows is the form's height.
func (a *app) showDlg(d *dlg, formRows int) {
	w, _ := a.fit(dialogWidth, 0)
	textRows := 0
	if d.text.GetText(false) != "" {
		textRows = textHeight(d.text.GetText(false), w-4)
		d.flex.AddItem(d.text, textRows, 0, false)
	}
	d.flex.AddItem(d.form, formRows, 0, true)
	d.flex.AddItem(d.result, resultRows, 0, false)
	d.flex.SetBorderPadding(0, 0, 1, 1)
	a.openDialog(d.flex, dialogWidth, textRows+formRows+resultRows+2, d.form) // the size wanted: fitted again on a resize
}

// textHeight is how many rows text takes wrapped to width.
func textHeight(text string, width int) int {
	n := 0
	for _, l := range strings.Split(text, "\n") {
		n += max(1, (tview.TaggedStringWidth(l)+width-1)/max(width, 1))
	}
	return n + 1 // a blank row before what follows
}

func (a *app) openDialog(p tview.Primitive, w, h int, focus tview.Primitive) {
	a.dlgW, a.dlgH = w, h
	w, h = a.fit(w, h)
	a.focusWas = a.tv.GetFocus()
	a.dialog = p
	// A Flex leaves what is behind it; the frame clears the dialog's area.
	a.dlgBox = tview.NewFrame(p).SetBorders(0, 0, 0, 0, 0, 0)
	a.dlgCell = tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(nil, 0, 1, false).
		AddItem(a.dlgBox, h, 0, true).
		AddItem(nil, 0, 1, false)
	a.dlgCol = tview.NewFlex().
		AddItem(nil, 0, 1, false).
		AddItem(a.dlgCell, w, 0, true).
		AddItem(nil, 0, 1, false)
	a.pages.AddPage("dialog", a.dlgCol, true, true)
	a.tv.SetFocus(focus)
}

// refitDialog fits the open dialog to the screen again.
func (a *app) refitDialog() {
	if a.dialog == nil {
		return
	}
	w, h := a.fit(a.dlgW, a.dlgH)
	a.dlgCol.ResizeItem(a.dlgCell, w, 0)
	a.dlgCell.ResizeItem(a.dlgBox, h, 0)
}

// closeDialog closes p if it is still the open dialog.
func (a *app) closeDialog(p tview.Primitive) {
	if a.dialog != p {
		return
	}
	a.pages.RemovePage("dialog")
	a.dialog = nil
	if a.focusWas != nil {
		a.tv.SetFocus(a.focusWas)
	}
}

// closeDlg closes d; dry runs still on their way are dropped.
func (a *app) closeDlg(d *dlg) {
	d.gen++
	a.closeDialog(d.flex)
}

// resultText is a change's answer for a dialog.
func resultText(res control.Result, err error) string {
	if err != nil {
		return "[red]refused:[-] " + tview.Escape(err.Error())
	}
	s := tview.Escape(res.Message)
	if res.DryRun {
		s = "[gray]Dry run:[-] [green]" + s + "[-]"
	}
	for _, w := range res.Warnings {
		s += "\n[yellow]warning:[-] " + tview.Escape(w)
	}
	return s
}

// dryRun asks for build's change as a dry run, once the typing pauses
// (now when delay is 0); ok false clears the answer.
func (a *app) dryRun(d *dlg, delay time.Duration, build func() (control.Change, bool)) {
	d.gen++
	gen := d.gen
	ch, ok := build()
	if !ok {
		d.result.SetText("")
		return
	}
	ch.DryRun = true
	ask := func() {
		if gen != d.gen || a.dialog != d.flex {
			return
		}
		a.send(ch, func(res control.Result, err error) {
			if gen == d.gen {
				d.result.SetText(resultText(res, err))
				d.shown = gen
			}
		})
	}
	if delay == 0 {
		ask()
		return
	}
	time.AfterFunc(delay, func() { a.update(ask) })
}

// submit makes build's change once its dry run is on show (asked for
// earlier, it asks for the dry run now instead). The dialog closes when the
// change is made, and says why when it is refused; an answer that comes
// after the dialog was closed is said below.
func (a *app) submit(d *dlg, build func() (control.Change, bool)) {
	ch, ok := build()
	if !ok || d.busy {
		return
	}
	if d.shown != d.gen {
		a.dryRun(d, 0, build)
		return
	}
	d.busy = true
	d.gen++ // a dry run still on its way is old now
	d.result.SetText("[gray]working…[-]")
	a.send(ch, func(res control.Result, err error) {
		d.busy = false
		if a.dialog != d.flex {
			a.flashAnswer(res, err)
			return
		}
		if err != nil {
			d.result.SetText(resultText(res, err))
			return
		}
		a.closeDlg(d)
		a.flashAnswer(res, nil)
	})
}

// confirm asks before a change, showing its dry run.
func (a *app) confirm(title, text, button string, ch control.Change) {
	d := a.newDlg(title, text)
	build := func() (control.Change, bool) { return ch, true }
	d.form.AddButton(button, func() { a.submit(d, build) }).AddButton("Cancel", func() { a.closeDlg(d) })
	a.showDlg(d, 3)
	a.dryRun(d, 0, build)
}

func (a *app) confirmStop() {
	t, i, ok := a.current()
	if !ok {
		return
	}
	a.confirm("Stop "+nameOf(t)+"?", stopText(t, a.running(i)), "Stop",
		control.Change{Kind: control.KindProfile, Op: "stop", Profile: t.Name})
}

// stopText says what stopping a profile does, by its kill switch.
func stopText(t control.Tunnel, others []string) string {
	name := tview.Escape(nameOf(t))
	var s string
	switch t.KillSwitch {
	case "lockdown":
		s = name + " has kill switch [red]lockdown[-]: its routes stay and its traffic is [red]refused[-] until you start it again (as after Ctrl-C)."
	case "on":
		s = name + " has kill switch [yellow]on[-]: its blocks are lifted and its traffic goes the normal way (as after Ctrl-C)."
	default:
		s = "Its routes and DNS names are removed; its traffic goes the normal way (as after Ctrl-C)."
	}
	if len(others) > 0 {
		s += "\n" + tview.Escape(strings.Join(others, ", ")) + " go on."
	} else {
		s += "\nNo other profile is running; subtun goes on, and S starts this one again."
	}
	return s
}

func (a *app) confirmReload(t control.Tunnel) {
	a.confirm("Reload "+nameOf(t)+"?",
		"Read "+tview.Escape(nameOf(t))+" from the config file again and restart it: the changes made while running are dropped.",
		"Reload", control.Change{Kind: control.KindProfile, Op: "start", Profile: t.Name, Reload: true})
}

func (a *app) confirmDelete(t control.Tunnel, it item) {
	ch := control.Change{Op: "del", Profile: t.Name}
	switch it.kind {
	case "route", "exclude":
		ch.Kind, ch.CIDRs, ch.Exclude = control.KindRoute, []string{it.value}, it.kind == "exclude"
	case "dns":
		ch.Kind, ch.Domains = control.KindDNS, []string{it.value}
	case "pattern":
		ch.Kind, ch.Patterns = control.KindDNS, []string{it.value}
	}
	a.confirm(fmt.Sprintf("Delete %s %s?", it.kind, it.value), "", "Delete", ch)
}

// routeDialog adds routes (or excludes) to a profile.
func (a *app) routeDialog(t control.Tunnel, exclude bool) {
	title := "Add a route to " + nameOf(t)
	if exclude {
		title = "Add an exclude to " + nameOf(t)
	}
	d := a.newDlg(title, "")
	var cidrs string
	build := func() (control.Change, bool) {
		f := strings.Fields(strings.ReplaceAll(cidrs, ",", " "))
		return control.Change{Kind: control.KindRoute, Op: "add", Profile: t.Name, CIDRs: f, Exclude: exclude}, len(f) > 0
	}
	d.form.AddInputField("CIDRs or IPs", "", 50, nil, func(s string) {
		cidrs = s
		a.dryRun(d, dryRunDelay, build)
	})
	d.form.AddCheckbox("exclude (never route them)", exclude, func(on bool) {
		exclude = on
		a.dryRun(d, 0, build)
	})
	d.form.AddButton("Add", func() { a.submit(d, build) }).AddButton("Cancel", func() { a.closeDlg(d) })
	enterSubmits(d.form, func() { a.submit(d, build) })
	a.showDlg(d, 7)
}

// dnsDialog adds DNS domains or patterns to a profile.
func (a *app) dnsDialog(t control.Tunnel) {
	d := a.newDlg("Add DNS names to "+nameOf(t), "Domains match themselves and every name below them; patterns are regular expressions. Separate several with spaces.")
	var domains, patterns string
	build := func() (control.Change, bool) {
		ch := control.Change{Kind: control.KindDNS, Op: "add", Profile: t.Name, Domains: strings.Fields(domains), Patterns: strings.Fields(patterns)}
		return ch, len(ch.Domains)+len(ch.Patterns) > 0
	}
	d.form.AddInputField("Domains", "", 50, nil, func(s string) {
		domains = s
		a.dryRun(d, dryRunDelay, build)
	})
	d.form.AddInputField("Patterns", "", 50, nil, func(s string) {
		patterns = s
		a.dryRun(d, dryRunDelay, build)
	})
	d.form.AddButton("Add", func() { a.submit(d, build) }).AddButton("Cancel", func() { a.closeDlg(d) })
	enterSubmits(d.form, func() { a.submit(d, build) })
	a.showDlg(d, 7)
}

// enterSubmits makes enter in the form's input fields submit it.
func enterSubmits(f *tview.Form, submit func()) {
	for i := range f.GetFormItemCount() {
		if in, ok := f.GetFormItem(i).(*tview.InputField); ok {
			in.SetDoneFunc(func(k tcell.Key) {
				if k == tcell.KeyEnter {
					submit()
				}
			})
		}
	}
}

// addProfileDialog lists the config file's profiles not in the run, each
// checked by a dry run, and adds the one chosen.
func (a *app) addProfileDialog() {
	if slices.ContainsFunc(a.st.Tunnels, func(t control.Tunnel) bool { return t.Name == "" }) {
		a.flash("yellow", "this run's tunnel comes from the command line (subtun k8s or docker): profiles can't be added to it")
		return
	}
	table := tview.NewTable().SetSelectable(true, false).SetFixed(1, 0).SetSelectedStyle(tcell.StyleDefault.Reverse(true))
	result := tview.NewTextView().SetDynamicColors(true).SetWordWrap(true).SetText("[gray]reading the config file…[-]")
	hint := tview.NewTextView().SetDynamicColors(true).SetTextAlign(tview.AlignCenter).
		SetText("[yellow]enter[-] add and start · [yellow]esc[-] cancel")
	flex := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(table, 0, 1, true).
		AddItem(result, 3, 0, false).
		AddItem(hint, 1, 0, false)
	flex.SetBorder(true).SetBorderPadding(0, 0, 1, 1).SetTitle(" Add a profile from the config file ")

	var cands []control.ConfigProfile
	answers := map[string]string{} // dry run answers by name
	refused := map[string]bool{}
	busy := false
	showRow := func(row int) {
		if row < 1 || row > len(cands) {
			return
		}
		if s, ok := answers[cands[row-1].Name]; ok {
			result.SetText(s)
		} else {
			result.SetText("[gray]checking…[-]")
		}
	}
	table.SetSelectionChangedFunc(func(row, _ int) { showRow(row) })
	table.SetDoneFunc(func(k tcell.Key) {
		if k == tcell.KeyEscape {
			a.closeDialog(flex)
		}
	})
	table.SetSelectedFunc(func(row, _ int) {
		if busy || row < 1 || row > len(cands) {
			return
		}
		name := cands[row-1].Name
		if _, checked := answers[name]; !checked || refused[name] {
			return // its dry run first; a profile that can't join isn't added
		}
		busy = true
		result.SetText("[gray]working…[-]")
		a.send(control.Change{Kind: control.KindProfile, Op: "start", Profile: name}, func(res control.Result, err error) {
			busy = false
			if a.dialog != flex {
				a.flashAnswer(res, err)
				return
			}
			if err != nil {
				result.SetText(resultText(res, err))
				return
			}
			a.closeDialog(flex)
			a.flashAnswer(res, nil)
		})
	})
	a.openDialog(flex, 110, 16, table)

	go func() {
		ctx, cancel := context.WithTimeout(a.ctx, queryTimeout)
		cp, err := a.o.Source.Config(ctx)
		cancel()
		a.update(func() {
			switch {
			case a.dialog != flex: // closed meanwhile
				return
			case err != nil:
				result.SetText(resultText(control.Result{}, err))
				return
			case cp.Error != "":
				result.SetText("[red]" + tview.Escape(cp.Error) + "[-]")
				return
			}
			for _, p := range cp.Profiles {
				if !p.InRun {
					cands = append(cands, p)
				}
			}
			if len(cands) == 0 {
				result.SetText("every profile of " + tview.Escape(cp.Path) + " is in this run already")
				return
			}
			flex.SetTitle(" Add a profile from " + tview.Escape(cp.Path) + " ")
			for c, h := range []string{"NAME", "TARGET", "ROUTES", "NOTES"} {
				table.SetCell(0, c, tview.NewTableCell(h).SetTextColor(tcell.ColorGray).SetSelectable(false))
			}
			for i, p := range cands {
				r := i + 1
				routes := summary(p.Routes, 2)
				if routes == "" && p.SOCKS != "" {
					routes = "SOCKS " + p.SOCKS
				}
				table.SetCell(r, 0, tview.NewTableCell(tview.Escape(p.Name)))
				table.SetCell(r, 1, tview.NewTableCell(tview.Escape(cut(p.Target, 26))))
				table.SetCell(r, 2, tview.NewTableCell(tview.Escape(cut(routes, 30))))
				table.SetCell(r, 3, tview.NewTableCell("[gray]checking…[-]").SetExpansion(1))
				name := p.Name
				a.send(control.Change{Kind: control.KindProfile, Op: "start", Profile: name, DryRun: true}, func(res control.Result, err error) {
					answers[name] = resultText(res, err)
					note := "[green]can join[-]"
					if err != nil {
						refused[name] = true
						note = "[gray]can't join: " + tview.Escape(err.Error()) + "[-]"
						table.GetCell(r, 0).SetTextColor(tcell.ColorGray)
					}
					table.GetCell(r, 3).SetText(note)
					if sel, _ := table.GetSelection(); sel == r {
						showRow(r)
					}
				})
			}
			table.Select(1, 0)
			showRow(1)
		})
	}()
}
