package tui

import (
	"fmt"
	"math"
	"slices"
	"strings"
	"time"

	"github.com/rivo/tview"

	"github.com/md2k/subnet-tunnel/internal/control"
	"github.com/md2k/subnet-tunnel/internal/dns"
	"github.com/md2k/subnet-tunnel/internal/meter"
	"github.com/md2k/subnet-tunnel/internal/routes"
)

var blocks = []rune("▁▂▃▄▅▆▇█")

// spark draws values as a sparkline width cells wide, the newest on the
// right. More values than cells are grouped (the largest of each group);
// fewer leave the left blank. The scale is the largest value shown.
func spark(vals []uint64, width int) string {
	if width <= 0 {
		return ""
	}
	groups := vals
	if len(vals) > width {
		size := (len(vals) + width - 1) / width
		groups = nil
		for end := len(vals); end > 0; end -= size {
			groups = append(groups, slices.Max(vals[max(0, end-size):end]))
		}
		slices.Reverse(groups)
	}
	var top uint64
	for _, v := range groups {
		top = max(top, v)
	}
	var b strings.Builder
	b.WriteString(strings.Repeat(" ", width-len(groups)))
	for _, v := range groups {
		i := 0
		if top > 0 && v > 0 {
			i = int(math.Ceil(float64(v) / float64(top) * float64(len(blocks)-1)))
		}
		b.WriteRune(blocks[i])
	}
	return b.String()
}

// sampleValues picks one value from each sample.
func sampleValues(ss []meter.Sample, f func(meter.Sample) uint64) []uint64 {
	out := make([]uint64, len(ss))
	for i, s := range ss {
		out[i] = f(s)
	}
	return out
}

func upOf(s meter.Sample) uint64    { return s.Up }
func downOf(s meter.Sample) uint64  { return s.Down }
func totalOf(s meter.Sample) uint64 { return s.Up + s.Down }

// short is a duration for people, to two units at most: 42s, 4m, 1h12m,
// 2d3h.
func short(d time.Duration) string {
	d = max(d, 0).Round(time.Second)
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh%dm", int(d.Hours()), int(d.Minutes())%60)
	}
	return fmt.Sprintf("%dd%dh", int(d.Hours())/24, int(d.Hours())%24)
}

func rate(n uint64) string { return meter.Bytes(n) + "/s" }

// stateText is a tunnel's state with how long or which attempt.
func stateText(t control.Tunnel, now time.Time) string {
	switch t.State {
	case "up", "stopped", "gave up":
		return t.State + " " + short(now.Sub(t.Since))
	case "reconnecting", "connecting":
		if t.Attempts > 0 {
			return fmt.Sprintf("%s %d/%d", t.State, t.Attempt, t.Attempts)
		}
	}
	return t.State
}

// stateColor is the colour (a tview tag name) of a state.
func stateColor(state string) string {
	switch state {
	case "up":
		return "green"
	case "connecting", "reconnecting":
		return "yellow"
	case "gave up":
		return "red"
	}
	return "gray"
}

// glyph is a state's symbol, coloured.
func glyph(state string) string {
	g := map[string]string{"up": "●", "connecting": "◐", "reconnecting": "◐", "gave up": "✕"}[state]
	if g == "" {
		g = "○"
	}
	return "[" + stateColor(state) + "]" + g + "[-]"
}

// targetShort is the target without the agent details: "pod ops/toolbox".
func targetShort(t string) string {
	if i := strings.Index(t, ", "); i >= 0 {
		return t[:i]
	}
	return t
}

func nameOf(t control.Tunnel) string {
	if t.Name == "" {
		return "tunnel"
	}
	return t.Name
}

// item is one route, exclude, DNS domain or pattern a profile asks for, as
// the profile screen lists it.
type item struct {
	kind    string // route, exclude, dns, pattern (as in runtime changes)
	value   string
	added   bool // added while running
	removed bool // configured, removed while running
}

// items lists what a tunnel asks for, marking what changed while running
// (from its runtime changes: "+route 10.9.0.0/16", "-dns x.example").
func items(t control.Tunnel) []item {
	changed := map[string]bool{}
	for _, c := range t.Changes {
		changed[c] = true
	}
	var out []item
	add := func(kind string, vals []string, key func(string) string) {
		for _, v := range vals {
			out = append(out, item{kind: kind, value: v, added: changed["+"+kind+" "+key(v)]})
		}
		for _, c := range t.Changes {
			if v, ok := strings.CutPrefix(c, "-"+kind+" "); ok {
				out = append(out, item{kind: kind, value: v, removed: true})
			}
		}
	}
	add("route", t.Include, normalized(routes.ParseRoute))
	add("exclude", t.Exclude, normalized(routes.ParsePrefix))
	add("dns", t.Domains, func(d string) string {
		if n, err := dns.NormalizeDomain(d); err == nil {
			return n
		}
		return d
	})
	add("pattern", t.Patterns, func(p string) string { return p })
	return out
}

func normalized[T fmt.Stringer](parse func(string) (T, error)) func(string) string {
	return func(v string) string {
		if p, err := parse(v); err == nil {
			return p.String()
		}
		return v
	}
}

// itemText is an item for the detail views: added ones green with a +,
// removed ones grey with a -.
func itemText(it item) string {
	v := tview.Escape(it.value)
	switch {
	case it.added:
		return "[green]+" + v + "[-]"
	case it.removed:
		return "[gray]-" + v + "[-]"
	}
	return v
}

// listOf joins the texts of the items of one kind.
func listOf(its []item, kinds ...string) string {
	var parts []string
	for _, it := range its {
		if slices.Contains(kinds, it.kind) {
			s := itemText(it)
			if it.kind == "pattern" {
				s = "pattern " + s
			}
			parts = append(parts, s)
		}
	}
	return strings.Join(parts, "  ")
}

// routesShort is the routes column: the first route, and how many more.
func routesShort(t control.Tunnel) string {
	switch {
	case len(t.Include) == 0 && t.SOCKS != "":
		return "SOCKS " + t.SOCKS
	case len(t.Include) == 0:
		return "-"
	case len(t.Include) == 1:
		return t.Include[0]
	}
	return fmt.Sprintf("%s +%d", t.Include[0], len(t.Include)-1)
}

// dnsShort is the DNS column.
func dnsShort(t control.Tunnel) string {
	names := slices.Clone(t.Domains)
	if n := len(t.Patterns); n > 0 {
		names = append(names, fmt.Sprintf("%d pattern(s)", n))
	}
	if len(names) == 0 {
		return "-"
	}
	return strings.Join(names, ", ")
}

// cut shortens s to n characters (runes), with an ellipsis.
func cut(s string, n int) string {
	r := []rune(s)
	if len(r) <= n || n < 1 {
		return s
	}
	return string(r[:n-1]) + "…"
}
