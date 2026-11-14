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

// Line is one log line as the terminal shows it, with its level and the
// profile it is about (for filtering in a UI).
type Line struct {
	Seq    uint64    `json:"seq"` // 1, 2, ... in the order added: says which lines a reader has seen
	Time   time.Time `json:"time"`
	Text   string    `json:"text"`
	Level  string    `json:"level,omitempty"`  // DEBUG, INFO, WARN, ERROR
	Tunnel string    `json:"tunnel,omitempty"` // the profile; "": none, or the only one
}

// TunnelKey is the log attribute naming the profile a record is about.
const TunnelKey = "tunnel"

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
	seq      uint64 // the last line's Seq
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

// Add appends a line (numbering it), dropping the oldest ones over the
// caps, and hands it to the followers.
func (r *Ring) Add(l Line) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seq++
	l.Seq = r.seq
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
// text handler with these options would print, with each record's level
// and profile (its top-level TunnelKey attribute).
func (r *Ring) Handler(opts *slog.HandlerOptions) slog.Handler {
	w := &writer{r: r}
	return &handler{h: slog.NewTextHandler(w, opts), w: w}
}

// writer takes the text handler's output: one Write per record, made while
// handler.Handle holds mu and has set meta.
type writer struct {
	r    *Ring
	mu   sync.Mutex
	meta Line
}

func (w *writer) Write(p []byte) (int, error) {
	l := w.meta
	l.Time, l.Text = time.Now(), string(bytes.TrimRight(p, "\n"))
	w.r.Add(l)
	return len(p), nil
}

type handler struct {
	h       slog.Handler
	w       *writer
	tunnel  string
	grouped bool // attributes from now on are in a group: not the profile
}

func (h *handler) Enabled(ctx context.Context, l slog.Level) bool { return h.h.Enabled(ctx, l) }

func (h *handler) Handle(ctx context.Context, rec slog.Record) error {
	meta := Line{Level: rec.Level.String(), Tunnel: h.tunnel}
	if !h.grouped {
		rec.Attrs(func(a slog.Attr) bool {
			if a.Key == TunnelKey {
				meta.Tunnel = a.Value.String()
			}
			return true
		})
	}
	h.w.mu.Lock()
	defer h.w.mu.Unlock()
	h.w.meta = meta
	return h.h.Handle(ctx, rec)
}

func (h *handler) WithAttrs(as []slog.Attr) slog.Handler {
	out := *h
	out.h = h.h.WithAttrs(as)
	if !h.grouped {
		for _, a := range as {
			if a.Key == TunnelKey {
				out.tunnel = a.Value.String()
			}
		}
	}
	return &out
}

func (h *handler) WithGroup(name string) slog.Handler {
	out := *h
	out.h = h.h.WithGroup(name)
	out.grouped = out.grouped || name != ""
	return &out
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
