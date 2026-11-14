package tui

import (
	"fmt"
	"log/slog"
	"strconv"
	"strings"

	"github.com/rivo/tview"

	"github.com/md2k/subnet-tunnel/internal/logring"
)

// maxLines is how many log lines the TUI keeps (as the run's ring).
const maxLines = logring.DefaultLines

// logBuf is the log lines the TUI got, oldest first.
type logBuf struct {
	lines []logring.Line
	last  uint64 // the newest line's Seq: a stream that reconnects repeats the held lines
}

// add keeps l unless it was kept already.
func (b *logBuf) add(l logring.Line) bool {
	if l.Seq <= b.last {
		return false
	}
	b.last = l.Seq
	b.lines = append(b.lines, l)
	if len(b.lines) > maxLines {
		b.lines = b.lines[len(b.lines)-maxLines:] // append copies only the lines kept when it grows
	}
	return true
}

// logFilter picks the lines shown.
type logFilter struct {
	profile string     // "": every profile
	level   slog.Level // the lowest level shown
	search  string     // case-insensitive text; "": none
}

// levels are the filter's level choices, in the order v cycles them.
var levels = []slog.Level{slog.LevelDebug, slog.LevelInfo, slog.LevelWarn, slog.LevelError}

func lineLevel(l logring.Line) slog.Level {
	var lv slog.Level
	if lv.UnmarshalText([]byte(l.Level)) != nil {
		return slog.LevelInfo
	}
	return lv
}

func (f logFilter) match(l logring.Line) bool {
	if f.profile != "" && l.Tunnel != f.profile {
		return false
	}
	if lineLevel(l) < f.level {
		return false
	}
	return f.search == "" || strings.Contains(strings.ToLower(logMessage(l)), strings.ToLower(f.search))
}

// describe is the filter for a title: "profile: all · level: debug".
func (f logFilter) describe() string {
	p := f.profile
	if p == "" {
		p = "all"
	}
	s := fmt.Sprintf("profile: %s · level: %s", p, strings.ToLower(f.level.String()))
	if f.search != "" {
		s += " · search: " + f.search
	}
	return s
}

// logMessage is a line's text without what the TUI shows in columns: the
// time, the level, the profile; the message unquoted. A relayed line
// ("helper: level=INFO msg=...") shows the relayed message.
func logMessage(l logring.Line) string {
	s := l.Text
	for range 2 { // the line, then a relayed line inside it
		for _, key := range []string{"time=", "level="} {
			if strings.HasPrefix(s, key) {
				_, rest, _ := strings.Cut(s, " ")
				s = rest
			}
		}
		if rest, ok := strings.CutPrefix(s, "msg="); ok {
			s = rest
			if q, err := strconv.QuotedPrefix(rest); err == nil {
				if m, err := strconv.Unquote(q); err == nil {
					s = m + rest[len(q):]
				}
			}
		}
		relayed := false
		for _, prefix := range []string{"helper: ", "agent: "} {
			if rest, ok := strings.CutPrefix(s, prefix); ok && (strings.HasPrefix(rest, "level=") || strings.HasPrefix(rest, "msg=")) {
				s, relayed = rest, true
			}
		}
		if !relayed {
			break
		}
	}
	if l.Tunnel != "" {
		tok := " tunnel=" + l.Tunnel
		if i := strings.Index(s, tok); i >= 0 && (i+len(tok) == len(s) || s[i+len(tok)] == ' ') {
			s = s[:i] + s[i+len(tok):]
		}
	}
	return s
}

// highlight escapes s for tview and marks every match of search.
func highlight(s, search string) string {
	if search == "" {
		return tview.Escape(s)
	}
	var b strings.Builder
	lower, find := strings.ToLower(s), strings.ToLower(search)
	if len(lower) != len(s) || len(find) != len(search) { // lower-casing changed byte offsets
		lower, find = s, search
	}
	for {
		i := strings.Index(lower, find)
		if i < 0 {
			b.WriteString(tview.Escape(s))
			return b.String()
		}
		b.WriteString(tview.Escape(s[:i]))
		b.WriteString("[black:yellow]" + tview.Escape(s[i:i+len(find)]) + "[-:-]")
		s, lower = s[i+len(find):], lower[i+len(find):]
	}
}

// levelText is a level, padded and coloured.
func levelText(lv slog.Level) string {
	s := fmt.Sprintf("%-5s", lv.String())
	switch {
	case lv >= slog.LevelError:
		return "[red]" + s + "[-]"
	case lv >= slog.LevelWarn:
		return "[yellow]" + s + "[-]"
	case lv < slog.LevelInfo:
		return "[gray]" + s + "[-]"
	}
	return s
}

// profileColors colour the profiles' names in the logs, in status order.
var profileColors = []string{"green", "aqua", "fuchsia", "yellow", "blue", "orange", "lime", "purple"}

// formatLine is one log line for a log view: time, profile (or, without
// one, the part of subtun that logged it, grey), level, text.
func formatLine(l logring.Line, f logFilter, width int, color func(string) string) string {
	var who string
	switch {
	case l.Tunnel != "":
		who = "[" + color(l.Tunnel) + "]" + tview.Escape(fmt.Sprintf("%-*s", width, l.Tunnel)) + "[-]"
	case l.Component != "" && l.Component != "tunnel":
		who = "[gray]" + tview.Escape(fmt.Sprintf("%-*s", width, cut(l.Component, width))) + "[-]"
	default:
		who = strings.Repeat(" ", width)
	}
	return fmt.Sprintf("[gray]%s[-] %s %s %s", l.Time.Local().Format("15:04:05.000"), who, levelText(lineLevel(l)), highlight(logMessage(l), f.search))
}
