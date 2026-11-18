package relay_test

import (
	"io"
	"slices"
	"testing"
	"time"

	"github.com/md2k/subnet-tunnel/internal/relay"
	"github.com/md2k/subnet-tunnel/internal/testutil"
)

// slowWriter is a connection whose writes take delay: a next hop that holds
// the copy back.
type slowWriter struct {
	*testutil.Conn
	delay time.Duration
}

func (s slowWriter) Write(p []byte) (int, error) {
	time.Sleep(s.delay)
	return s.Conn.Write(p)
}

// Each direction reports its bytes, its writes and the time spent waiting on
// the destination's Write; the rest of its time was spent waiting for data.
func TestPipeStats(t *testing.T) {
	app, a := testutil.Pair()
	b, far := testutil.Pair()
	type result struct{ aToB, bToA relay.Stats }
	done := make(chan result)
	go func() {
		x, y := relay.Pipe(a, slowWriter{b, 20 * time.Millisecond})
		done <- result{x, y}
	}()

	go func() {
		for range 3 {
			_, _ = app.Write(make([]byte, 1000))
		}
		_ = app.CloseWrite()
	}()
	got, err := io.ReadAll(far)
	if err != nil || len(got) != 3000 {
		t.Fatalf("read %d bytes, %v", len(got), err)
	}
	time.Sleep(30 * time.Millisecond) // the far end is idle for a while
	_, _ = far.Write([]byte("bye"))
	_ = far.CloseWrite()
	if back, _ := io.ReadAll(app); string(back) != "bye" {
		t.Fatalf("back: %q", back)
	}
	r := <-done

	if r.aToB.Bytes != 3000 || r.aToB.Writes != 3 {
		t.Errorf("a to b: %d bytes in %d writes, want 3000 in 3", r.aToB.Bytes, r.aToB.Writes)
	}
	if r.aToB.WriteWait < 60*time.Millisecond || r.aToB.Dur < r.aToB.WriteWait {
		t.Errorf("a to b: waited %v writing in %v, want at least 60ms", r.aToB.WriteWait, r.aToB.Dur)
	}
	if r.bToA.Bytes != 3 || r.bToA.WriteWait > 10*time.Millisecond || r.bToA.ReadWait() < 30*time.Millisecond {
		t.Errorf("b to a: %d bytes, waited %v writing and %v for data", r.bToA.Bytes, r.bToA.WriteWait, r.bToA.ReadWait())
	}
	attrs := r.aToB.Attrs("down")
	if len(attrs) != 6 || !slices.Contains(attrs, any("down")) || !slices.Contains(attrs, any("down_writes")) || !slices.Contains(attrs, any("down_wait")) {
		t.Errorf("attrs: %v", attrs)
	}
}
