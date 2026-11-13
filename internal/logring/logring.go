// Package logring keeps subtun's recent log lines in memory for `subtun
// logs` and the control API: capped by lines and by bytes, never written
// to disk. Followers get new lines as they come; one that can't keep up
// loses lines, the logger never waits for it.
package logring

import (
	"bytes"
	"context"
	"log/slog"
	"sync"
	"time"
)

// Default caps.
const (
	DefaultLines = 5000
	DefaultBytes = 4 << 20
)

// Line is one log line as the terminal shows it.
type Line struct {
	Time time.Time `json:"time"`
	Text string    `json:"text"`
}

// Ring is the buffer.
type Ring struct {
	mu       sync.Mutex
	maxLines int
	maxBytes int
	lines    []Line // oldest first
	bytes    int
	subs     map[chan Line]struct{}
	dropped  uint64 // lines followers lost
}

// New returns a ring holding at most maxLines lines and maxBytes bytes of
// text (0: the defaults).
func New(maxLines, maxBytes int) *Ring {
	if maxLines <= 0 {
		maxLines = DefaultLines
	}
	if maxBytes <= 0 {
		maxBytes = DefaultBytes
	}
	return &Ring{maxLines: maxLines, maxBytes: maxBytes, subs: map[chan Line]struct{}{}}
}

// Add appends a line, dropping the oldest ones over the caps, and hands it
// to the followers.
func (r *Ring) Add(l Line) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lines = append(r.lines, l)
	r.bytes += len(l.Text)
	drop := 0
	for len(r.lines)-drop > r.maxLines || r.bytes > r.maxBytes && len(r.lines)-drop > 1 {
		r.bytes -= len(r.lines[drop].Text)
		drop++
	}
	if drop > 0 {
		r.lines = append(r.lines[:0], r.lines[drop:]...)
	}
	for ch := range r.subs {
		select {
		case ch <- l:
		default:
			r.dropped++
		}
	}
}

// Lines returns the lines held, oldest first.
func (r *Ring) Lines() []Line {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Line(nil), r.lines...)
}

// Subscribe returns new lines as they are added, buffering up to buf; the
// returned function ends the subscription.
func (r *Ring) Subscribe(buf int) (<-chan Line, func()) {
	ch := make(chan Line, buf)
	r.mu.Lock()
	r.subs[ch] = struct{}{}
	r.mu.Unlock()
	var once sync.Once
	return ch, func() {
		once.Do(func() {
			r.mu.Lock()
			delete(r.subs, ch)
			r.mu.Unlock()
		})
	}
}

// Handler returns a log handler that writes into the ring the lines a
// text handler with these options would print.
func (r *Ring) Handler(opts *slog.HandlerOptions) slog.Handler {
	return slog.NewTextHandler(writer{r}, opts)
}

// writer takes the text handler's output: one Write per record.
type writer struct{ r *Ring }

func (w writer) Write(p []byte) (int, error) {
	w.r.Add(Line{Time: time.Now(), Text: string(bytes.TrimRight(p, "\n"))})
	return len(p), nil
}

// Tee sends every record to all handlers.
func Tee(hs ...slog.Handler) slog.Handler { return tee(hs) }

type tee []slog.Handler

func (t tee) Enabled(ctx context.Context, l slog.Level) bool {
	for _, h := range t {
		if h.Enabled(ctx, l) {
			return true
		}
	}
	return false
}

func (t tee) Handle(ctx context.Context, rec slog.Record) error {
	var first error
	for _, h := range t {
		if !h.Enabled(ctx, rec.Level) {
			continue
		}
		if err := h.Handle(ctx, rec.Clone()); err != nil && first == nil {
			first = err
		}
	}
	return first
}

func (t tee) WithAttrs(as []slog.Attr) slog.Handler {
	out := make(tee, len(t))
	for i, h := range t {
		out[i] = h.WithAttrs(as)
	}
	return out
}

func (t tee) WithGroup(name string) slog.Handler {
	out := make(tee, len(t))
	for i, h := range t {
		out[i] = h.WithGroup(name)
	}
	return out
}
