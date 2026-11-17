package agent

import (
	"bytes"
	"testing"
	"time"
)

func TestDatagramQueue(t *testing.T) {
	d := func(b byte) []byte { return bytes.Repeat([]byte{b}, 100) }
	q := newDatagramQueue(3 * (100 + datagramOverhead))
	for i := range byte(4) {
		if got, want := q.Push(d(i)), i < 3; got != want {
			t.Fatalf("push %d: %v, want %v", i, got, want)
		}
	}
	if q.Dropped() != 1 {
		t.Fatalf("dropped %d, want 1", q.Dropped())
	}
	if got, ok := q.Pop(); !ok || got[0] != 0 {
		t.Fatalf("pop: %v %v, want the first datagram", got[:1], ok)
	}
	if !q.Push(d(9)) {
		t.Fatal("no room after a pop")
	}
	// Empty datagrams take room too, so the queue stays bounded.
	q2 := newDatagramQueue(2 * datagramOverhead)
	if !q2.Push(nil) || !q2.Push(nil) || q2.Push(nil) {
		t.Fatal("empty datagrams aren't counted")
	}

	q.Close()
	for _, want := range []byte{1, 2, 9} {
		if got, ok := q.Pop(); !ok || got[0] != want {
			t.Fatalf("pop after close: %v %v, want %d", got[:1], ok, want)
		}
	}
	if _, ok := q.Pop(); ok {
		t.Fatal("pop on a closed, empty queue")
	}
	if q.Push(d(1)) {
		t.Fatal("push on a closed queue")
	}

	// Pop waits for a push, or for the close.
	q3 := newDatagramQueue(1 << 10)
	go func() { time.Sleep(20 * time.Millisecond); q3.Push([]byte("x")) }()
	if got, ok := q3.Pop(); !ok || string(got) != "x" {
		t.Fatalf("pop: %q %v", got, ok)
	}
	go func() { time.Sleep(20 * time.Millisecond); q3.Close() }()
	if _, ok := q3.Pop(); ok {
		t.Fatal("pop returned a datagram after the close")
	}
}
