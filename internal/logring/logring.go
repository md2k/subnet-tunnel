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

// Ring is the buffer: a circular one, so adding a line costs the same
// however many are held.
type Ring struct {
	mu       sync.Mutex
	maxLines int
	maxBytes int
	buf      []Line // circular: n lines from head
	head, n  int
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
	return &Ring{maxLines: maxLines, maxBytes: maxBytes, buf: make([]Line, maxLines), subs: map[chan Line]struct{}{}}
}

// Add appends a line, dropping the oldest ones over the caps, and hands it
// to the followers.
func (r *Ring) Add(l Line) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.n == r.maxLines {
		r.dropOldest()
	}
	r.buf[(r.head+r.n)%r.maxLines] = l
	r.n++
	r.bytes += len(l.Text)
	for r.bytes > r.maxBytes && r.n > 1 {
		r.dropOldest()
	}
	for ch := range r.subs {
		select {
		case ch <- l:
		default:
			r.dropped++
		}
	}
}

func (r *Ring) dropOldest() {
	r.bytes -= len(r.buf[r.head].Text)
	r.buf[r.head] = Line{}
	r.head = (r.head + 1) % r.maxLines
	r.n--
}

// Lines returns the lines held, oldest first.
func (r *Ring) Lines() []Line {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.linesLocked()
}

func (r *Ring) linesLocked() []Line {
	out := make([]Line, r.n)
	for i := range r.n {
		out[i] = r.buf[(r.head+i)%r.maxLines]
	}
	return out
}

// Follow returns the lines held and, from the same moment, new ones (so
// none is missed or repeated), buffering up to buf; stop ends it.
func (r *Ring) Follow(buf int) (held []Line, lines <-chan Line, stop func()) {
	ch := make(chan Line, buf)
	r.mu.Lock()
	held = r.linesLocked()
	r.subs[ch] = struct{}{}
	r.mu.Unlock()
	return held, ch, r.unsubscribe(ch)
}

func (r *Ring) unsubscribe(ch chan Line) func() {
	var once sync.Once
	return func() {
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
