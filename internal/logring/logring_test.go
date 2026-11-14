package logring

import (
	"bytes"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"
)

func TestCaps(t *testing.T) {
	r := New(3, 1000)
	for i := 0; i < 5; i++ {
		r.Add(Line{Text: fmt.Sprint("line ", i)})
	}
	got := r.Lines()
	if len(got) != 3 || got[0].Text != "line 2" || got[2].Text != "line 4" {
		t.Fatalf("lines cap: %v", got)
	}
	r = New(100, 10)
	r.Add(Line{Text: "12345"})
	r.Add(Line{Text: "67890"})
	r.Add(Line{Text: "abc"})
	if got := r.Lines(); len(got) != 2 || got[0].Text != "67890" {
		t.Fatalf("bytes cap: %v", got)
	}
	// A single line over the byte cap is still kept (the latest).
	r.Add(Line{Text: strings.Repeat("x", 50)})
	if got := r.Lines(); len(got) != 1 || len(got[0].Text) != 50 {
		t.Fatalf("one long line: %v", got)
	}
	// Lines are numbered in the order added, also past the caps.
	if got := r.Lines()[0].Seq; got != 4 {
		t.Fatalf("seq %d", got)
	}
}

// A follower gets new lines; one that doesn't read loses lines and the
// writer never blocks.
func TestSubscribe(t *testing.T) {
	r := New(0, 0)
	_, ch, stop := r.Follow(2)
	r.Add(Line{Text: "a"})
	r.Add(Line{Text: "b"})
	done := make(chan struct{})
	go func() {
		for i := 0; i < 100; i++ {
			r.Add(Line{Text: "more"})
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Add blocked on a slow follower")
	}
	if l := <-ch; l.Text != "a" {
		t.Fatalf("first: %v", l)
	}
	stop()
	stop() // twice is fine
	r.Add(Line{Text: "after"})
	if r.dropped == 0 {
		t.Error("no lines counted as lost")
	}
}

// The ring holds what the terminal prints, and Tee feeds both.
func TestHandlerAndTee(t *testing.T) {
	r := New(0, 0)
	var term bytes.Buffer
	opts := &slog.HandlerOptions{Level: slog.LevelInfo}
	log := slog.New(Tee(slog.NewTextHandler(&term, opts), r.Handler(opts))).With("tunnel", "work")
	log.Info("tunnel up", "took", "1s")
	log.Debug("hidden")
	lines := r.Lines()
	if len(lines) != 1 || !strings.Contains(lines[0].Text, `msg="tunnel up" tunnel=work took=1s`) || strings.HasSuffix(lines[0].Text, "\n") {
		t.Fatalf("ring: %+v", lines)
	}
	if !strings.Contains(term.String(), `msg="tunnel up" tunnel=work`) || strings.Contains(term.String(), "hidden") {
		t.Fatalf("terminal: %q", term.String())
	}
	if l := lines[0]; l.Level != "INFO" || l.Tunnel != "work" {
		t.Fatalf("level %q, tunnel %q", l.Level, l.Tunnel)
	}
}

// Each line carries its record's level and profile: from With, from the
// record, none, never from a group.
func TestLineMeta(t *testing.T) {
	r := New(0, 0)
	base := slog.New(r.Handler(&slog.HandlerOptions{Level: slog.LevelDebug}))
	base.Warn("no profile")
	base.With("tunnel", "dev").Debug("from With")
	base.Error("from the record", "tunnel", "vault")
	base.WithGroup("g").Info("grouped", "tunnel", "nope")
	base.With("component", "helper").Info("from the helper")
	var got []string
	for _, l := range r.Lines() {
		got = append(got, l.Level+"/"+l.Tunnel+"/"+l.Component)
	}
	if want := "WARN//,DEBUG/dev/,ERROR/vault/,INFO//,INFO//helper"; strings.Join(got, ",") != want {
		t.Fatalf("got %v, want %s", got, want)
	}
}

// Follow hands over the lines held and then new ones, none twice, also
// after the ring wrapped around.
func TestFollow(t *testing.T) {
	r := New(3, 0)
	for i := 0; i < 5; i++ {
		r.Add(Line{Text: fmt.Sprint(i)})
	}
	held, ch, stop := r.Follow(4)
	defer stop()
	r.Add(Line{Text: "5"})
	var got []string
	for _, l := range held {
		got = append(got, l.Text)
	}
	got = append(got, (<-ch).Text)
	if strings.Join(got, ",") != "2,3,4,5" {
		t.Fatalf("got %v", got)
	}
	if lines := r.Lines(); len(lines) != 3 || lines[0].Text != "3" || lines[2].Text != "5" {
		t.Fatalf("after wrapping: %v", lines)
	}
}
