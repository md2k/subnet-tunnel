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

// niceTop is a chart's scale for its largest value v: the next 1, 2 or 5
// times a power of ten at or above v plus a tenth, so steady traffic
// doesn't fill the chart; 0 for 0.
func niceTop(v uint64) uint64 {
	if v == 0 {
		return 0
	}
	x := float64(v) * 1.1
	p := math.Pow(10, math.Floor(math.Log10(x)))
	for _, m := range []float64{1, 2, 5} {
		if m*p >= x {
			return uint64(math.Ceil(m * p))
		}
	}
	return uint64(math.Ceil(10 * p))
}

// Braille dots of a cell's left and right column (on U+2800), none to all
// four: filled from the bottom (rising) and from the top (hanging).
var (
	riseLeft  = [5]rune{0, 0x40, 0x44, 0x46, 0x47}
	riseRight = [5]rune{0, 0x80, 0xA0, 0xB0, 0xB8}
	hangLeft  = [5]rune{0, 0x01, 0x03, 0x07, 0x47}
	hangRight = [5]rune{0, 0x08, 0x18, 0x38, 0xB8}
)

// gradient is the colour of a chart's dots at frac of its height (btop
// style): green low, then yellow, orange, red at the top.
func gradient(frac float64) string {
	switch {
	case frac <= 0.5:
		return "green"
	case frac <= 0.75:
		return "yellow"
	case frac <= 0.9:
		return "orange"
	}
	return "red"
}

// eighths are a cell filled from the left: none to whole.
var eighths = []rune(" ▏▎▍▌▋▊▉█")

// gauge draws v against top as a bar width cells wide filling from the
// left, each cell coloured by how far along it is (the gradient); the rest
// is a grey track.
func gauge(v, top uint64, width int) string {
	if width <= 0 {
		return ""
	}
	units := 0
	if top > 0 {
		units = min(int(math.Round(float64(v)/float64(top)*float64(width*8))), width*8)
	}
	if v > 0 && units == 0 {
		units = 1
	}
	var b strings.Builder
	cur := ""
	set := func(tag string) {
		if tag != cur {
			b.WriteString(tag)
			cur = tag
		}
	}
	for i := range width {
		switch fill := min(max(units-i*8, 0), 8); fill {
		case 0:
			set("[gray]")
			b.WriteRune('·')
		default:
			set("[" + gradient(float64(i+1)/float64(width)) + "]")
			b.WriteRune(eighths[fill])
		}
	}
	b.WriteString("[-]")
	return b.String()
}

// braille draws values as an area chart of braille dots rising from the
// bottom (see area).
func braille(vals []uint64, width, height int, top uint64) []string {
	return area(vals, width, height, top, false)
}

// area draws values as an area chart of braille dots, height rows high and
// width cells wide (two values a cell, four dots a row), the newest on the
// right, the rows top first, against the scale top: rising from the bottom,
// or hanging from the top. More values than dot columns are grouped evenly
// (the largest of each group). Each cell is coloured by how far its dots
// reach; zeros, and the time no value has reached yet, show a grey
// baseline on the row the chart grows from.
func area(vals []uint64, width, height int, top uint64, hang bool) []string {
	if width <= 0 || height <= 0 {
		return make([]string, max(height, 0))
	}
	cols := width * 2
	groups := vals
	if n := len(vals); n > cols {
		groups = make([]uint64, cols)
		for i := range groups {
			groups[i] = slices.Max(vals[i*n/cols : (i+1)*n/cols])
		}
	}
	dots := height * 4
	levels := make([]int, cols) // dots long; 0: zero or no value
	for i, v := range groups {
		if v > 0 && top > 0 {
			l := int(math.Ceil(float64(v) / float64(top) * float64(dots)))
			levels[cols-len(groups)+i] = min(max(l, 1), dots)
		}
	}
	left, right, base := riseLeft, riseRight, rune(0x2800+0x40+0x80) // ⣀
	if hang {
		left, right, base = hangLeft, hangRight, 0x2800+0x01+0x08 // ⠉
	}
	rows := make([]string, height)
	for r := range height { // r: from the top
		near := height - 1 - r // rows between this one and where the chart grows from
		if hang {
			near = r
		}
		floor := near * 4
		edge := near == 0
		var b strings.Builder
		cur := ""
		set := func(tag string) {
			if tag != cur {
				b.WriteString(tag)
				cur = tag
			}
		}
		for c := range width {
			l, rt := levels[2*c], levels[2*c+1]
			fl, fr := min(max(l-floor, 0), 4), min(max(rt-floor, 0), 4)
			switch {
			case fl > 0 || fr > 0:
				ch := 0x2800 + left[fl] + right[fr]
				if edge && fl == 0 {
					ch += left[1]
				}
				if edge && fr == 0 {
					ch += right[1]
				}
				set("[" + gradient(float64(max(min(l, floor+4), min(rt, floor+4)))/float64(dots)) + "]")
				b.WriteRune(ch)
			case edge:
				set("[gray]")
				b.WriteRune(base)
			default:
				b.WriteRune(' ')
			}
		}
		if cur != "" {
			b.WriteString("[-]")
		}
		rows[r] = b.String()
	}
	return rows
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

// rateText is a rate for people: bytes a second, or bits (decimal units).
func rateText(n uint64, bits bool) string {
	if !bits {
		return meter.Bytes(n) + "/s"
	}
	if n*8 < 1000 {
		return fmt.Sprintf("%d b/s", n*8)
	}
	v, units := float64(n)*8, []string{"kb/s", "Mb/s", "Gb/s", "Tb/s"}
	i := -1
	for v >= 1000 && i < len(units)-1 {
		v /= 1000
		i++
	}
	return fmt.Sprintf("%.1f %s", v, units[i])
}

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
