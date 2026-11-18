// Package relay copies bytes between two connections in both directions.
package relay

import (
	"io"
	"sync"
	"time"
)

type closeWriter interface{ CloseWrite() error }

// Stats is what one direction of a Pipe did.
type Stats struct {
	Bytes     int64
	Writes    int           // writes into the destination
	WriteWait time.Duration // inside the destination's Write: the next hop held the copy back
	Dur       time.Duration // until this direction ended
}

// ReadWait is the rest of the direction's time: waiting for the source (it
// had nothing to send, or sent slowly).
func (s Stats) ReadWait() time.Duration { return s.Dur - s.WriteWait }

// Attrs are log attributes for s under name: name (bytes), name_writes and
// name_wait (the write wait).
func (s Stats) Attrs(name string) []any {
	return []any{name, s.Bytes, name + "_writes", s.Writes, name + "_wait", s.WriteWait.Round(time.Millisecond)}
}

// Pipe copies a→b and b→a until both directions are done, then closes both.
//
// When one side reaches EOF, the other side's write half is closed (if it
// supports CloseWrite) so the peer sees EOF while the reverse direction keeps
// flowing; request/response protocols that shut down their write side rely on
// this. If a copy fails, or the destination can't half-close, both
// connections are closed so the other direction stops too.
func Pipe(a, b io.ReadWriteCloser) (aToB, bToA Stats) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); aToB = half(b, a) }()
	go func() { defer wg.Done(); bToA = half(a, b) }()
	wg.Wait()
	_ = a.Close()
	_ = b.Close()
	return aToB, bToA
}

func half(dst, src io.ReadWriteCloser) Stats {
	start := time.Now()
	tw := &timedWriter{w: dst}
	n, err := io.Copy(tw, src) // a source's WriteTo (smux streams have one) still gets used
	st := Stats{Bytes: n, Writes: tw.writes, WriteWait: tw.wait}
	if err == nil {
		if cw, ok := dst.(closeWriter); ok && cw.CloseWrite() == nil {
			st.Dur = time.Since(start)
			return st
		}
	}
	_ = dst.Close()
	_ = src.Close()
	st.Dur = time.Since(start)
	return st
}

// timedWriter counts the writes into w and the time they take.
type timedWriter struct {
	w      io.Writer
	writes int
	wait   time.Duration
}

func (t *timedWriter) Write(p []byte) (int, error) {
	start := time.Now()
	n, err := t.w.Write(p)
	t.wait += time.Since(start)
	t.writes++
	return n, err
}
