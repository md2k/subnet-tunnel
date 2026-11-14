package tui

import (
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/md2k/subnet-tunnel/internal/control"
	"github.com/md2k/subnet-tunnel/internal/logring"
)

func TestSpark(t *testing.T) {
	for _, c := range []struct {
		vals  []uint64
		width int
		want  string
	}{
		{nil, 4, "    "},
		{[]uint64{0, 0}, 3, " ▁▁"},
		{[]uint64{1, 8}, 2, "▂█"},
		{[]uint64{0, 4, 8}, 3, "▁▅█"},
		// Grouped from the newest end, the largest of each group.
		{[]uint64{8, 0, 0, 1, 2, 4}, 3, "█▂▅"},
		{[]uint64{1, 2, 3, 4, 5}, 2, "▄█"},
		{[]uint64{5}, 0, ""},
	} {
		if got := spark(c.vals, c.width); got != c.want {
			t.Errorf("spark(%v, %d) = %q, want %q", c.vals, c.width, got, c.want)
		}
	}
}

func TestShort(t *testing.T) {
	for d, want := range map[time.Duration]string{
		-time.Second: "0s", 42 * time.Second: "42s", 4*time.Minute + 59*time.Second: "4m",
		72 * time.Minute: "1h12m", 51 * time.Hour: "2d3h",
	} {
		if got := short(d); got != want {
			t.Errorf("short(%v) = %q, want %q", d, got, want)
		}
	}
}

func TestStateText(t *testing.T) {
	now := time.Now()
	for _, c := range []struct {
		t    control.Tunnel
		want string
	}{
		{control.Tunnel{State: "up", Since: now.Add(-72 * time.Minute)}, "up 1h12m"},
		{control.Tunnel{State: "reconnecting", Attempt: 2, Attempts: 10}, "reconnecting 2/10"},
		{control.Tunnel{State: "connecting"}, "connecting"},
		{control.Tunnel{State: "stopped", Since: now.Add(-4 * time.Minute)}, "stopped 4m"},
	} {
		if got := stateText(c.t, now); got != c.want {
			t.Errorf("%+v: %q, want %q", c.t, got, c.want)
		}
	}
}

// Items list what a profile asks for, with what changed while running
// marked (the change texts are normalized: an IP is a /32, a domain lower
// case without the dot).
func TestItems(t *testing.T) {
	tn := control.Tunnel{
		Include: []string{"10.0.0.0/8", "10.71.0.5"}, Exclude: []string{"10.1.0.0/16"},
		Domains: []string{"corp.example", "New.Example."}, Patterns: []string{`^db\.`},
		Changes: []string{"+route 10.71.0.5/32", "-route 203.0.113.0/24", "+dns new.example", "+pattern ^db\\."},
	}
	var got []string
	for _, it := range items(tn) {
		mark := " "
		if it.added {
			mark = "+"
		} else if it.removed {
			mark = "-"
		}
		got = append(got, mark+it.kind+" "+it.value)
	}
	want := []string{" route 10.0.0.0/8", "+route 10.71.0.5", "-route 203.0.113.0/24", " exclude 10.1.0.0/16",
		" dns corp.example", "+dns New.Example.", "+pattern ^db\\."}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("items:\n%v\nwant\n%v", got, want)
	}
	if s := listOf(items(tn), "route"); s != "10.0.0.0/8  [green]+10.71.0.5[-]  [gray]-203.0.113.0/24[-]" {
		t.Errorf("listOf: %q", s)
	}
}

func TestColumns(t *testing.T) {
	if got := routesShort(control.Tunnel{Include: []string{"10.0.0.0/8", "10.1.0.0/16", "10.2.0.0/16"}}); got != "10.0.0.0/8 +2" {
		t.Errorf("routes: %q", got)
	}
	if got := routesShort(control.Tunnel{SOCKS: "127.0.0.1:1080"}); got != "SOCKS 127.0.0.1:1080" {
		t.Errorf("SOCKS only: %q", got)
	}
	if got := dnsShort(control.Tunnel{Domains: []string{".", "corp.example"}, Patterns: []string{"a", "b"}}); got != "., corp.example, 2 pattern(s)" {
		t.Errorf("dns: %q", got)
	}
	if got := targetShort("pod ops/toolbox, container c, linux/arm64, binary agent"); got != "pod ops/toolbox" {
		t.Errorf("target: %q", got)
	}
	if got := cut("abcdef", 4); got != "abc…" {
		t.Errorf("cut: %q", got)
	}
}

// A log line loses what the views show in columns; quoting and a profile
// name inside a word stay.
func TestLogMessage(t *testing.T) {
	for _, c := range []struct {
		l    logring.Line
		want string
	}{
		{logring.Line{Text: `time=15:01:05.551 level=WARN msg="connection lost; reconnecting" tunnel=dev policy="up to 10"`, Tunnel: "dev"},
			`connection lost; reconnecting policy="up to 10"`},
		{logring.Line{Text: `time=15:01:02.114 level=INFO msg=reconnected tunnel=work`, Tunnel: "work"}, "reconnected"},
		{logring.Line{Text: `time=1 level=INFO msg=up tunnel=workshop`, Tunnel: "work"}, "up tunnel=workshop"},
		{logring.Line{Text: "plain"}, "plain"},
	} {
		if got := logMessage(c.l); got != c.want {
			t.Errorf("%q: %q, want %q", c.l.Text, got, c.want)
		}
	}
}

func TestLogFilter(t *testing.T) {
	dbg := logring.Line{Text: "msg=x", Level: "DEBUG", Tunnel: "dev"}
	warn := logring.Line{Text: "msg=Reconnecting", Level: "WARN", Tunnel: "work"}
	none := logring.Line{Text: "msg=helper"} // no level: as info
	f := logFilter{level: slog.LevelDebug}
	if !f.match(dbg) || !f.match(warn) || !f.match(none) {
		t.Error("everything shown by default")
	}
	f.level = slog.LevelInfo
	if f.match(dbg) || !f.match(none) {
		t.Error("level")
	}
	f = logFilter{level: slog.LevelDebug, profile: "work"}
	if f.match(dbg) || !f.match(warn) || f.match(none) {
		t.Error("profile")
	}
	f = logFilter{level: slog.LevelDebug, search: "reconn"}
	if !f.match(warn) || f.match(dbg) {
		t.Error("search")
	}
	if got := highlight("a [x] Reconnect", "reconnect"); got != "a [x[] [black:yellow]Reconnect[-:-]" {
		t.Errorf("highlight: %q", got)
	}
}

// The buffer drops repeats (a stream that reconnected sends the held lines
// again, with their numbers) and keeps the newest lines.
func TestLogBuf(t *testing.T) {
	var b logBuf
	t0 := time.Now()
	if !b.add(logring.Line{Seq: 1, Time: t0, Text: "a"}) || !b.add(logring.Line{Seq: 2, Time: t0, Text: "b"}) {
		t.Fatal("new lines refused (the same time is fine)")
	}
	if b.add(logring.Line{Seq: 1, Text: "a"}) || b.add(logring.Line{Seq: 2, Text: "b"}) {
		t.Fatal("repeats kept")
	}
	for i := range maxLines + 5 {
		b.add(logring.Line{Seq: uint64(i + 3)})
	}
	if len(b.lines) != maxLines || b.lines[len(b.lines)-1].Seq != maxLines+7 {
		t.Fatalf("kept %d", len(b.lines))
	}
}

func TestFitColumns(t *testing.T) {
	want := map[string]int{"": 1, "NAME": 5, "STATE": 17, "TARGET": 15, "ROUTES": 13, "DNS": 15, "KS": 8, "↑/s": 10, "↓/s": 8, "5 MIN": 10}
	if got := fitColumns(200, want); len(got) != len(want) || got["TARGET"] != 15 {
		t.Errorf("wide: %v", got)
	}
	got := fitColumns(78, want)
	total := -1
	for _, v := range got {
		total += v + 1
	}
	if total > 78 {
		t.Errorf("78: %d wide: %v", total, got)
	}
	for _, c := range []string{"NAME", "STATE", "ROUTES", "↑/s", "↓/s"} {
		if _, ok := got[c]; !ok {
			t.Errorf("78: %s dropped: %v", c, got)
		}
	}
	if _, ok := got["TARGET"]; ok {
		t.Errorf("78: TARGET kept before DNS went: %v", got)
	}
}
