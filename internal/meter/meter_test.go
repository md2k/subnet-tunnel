package meter

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

// fakeConn is one end of an in-memory pipe that can half-close and has a
// WriteTo fast path, like a tunnel stream.
type fakeConn struct {
	net.Conn
	closedWrite bool
	usedWriteTo bool
}

func (f *fakeConn) CloseWrite() error { f.closedWrite = true; return nil }
func (f *fakeConn) WriteTo(w io.Writer) (int64, error) {
	f.usedWriteTo = true
	return io.Copy(w, f.Conn)
}

type fakeDialer struct {
	conn *fakeConn
	err  error
}

func (d fakeDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	if d.err != nil {
		return nil, d.err
	}
	return d.conn, nil
}

func TestCountsAndConns(t *testing.T) {
	m := New()
	a, b := net.Pipe()
	fc := &fakeConn{Conn: a}
	c, err := m.Dialer(ViaUtun, fakeDialer{conn: fc}).DialContext(context.Background(), "tcp", "10.0.0.1:443")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Dialer(ViaSOCKS, fakeDialer{err: errors.New("refused")}).DialContext(context.Background(), "tcp", "x:1"); err == nil {
		t.Fatal("dial error lost")
	}
	m.Refused()

	go func() { _, _ = b.Write([]byte("hello back")); _ = b.Close() }()
	go func() { buf := make([]byte, 5); _, _ = io.ReadFull(b, buf) }()
	if _, err := c.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	var got bytes.Buffer
	if _, err := io.Copy(&got, c); err != nil { // through WriteTo
		t.Fatal(err)
	}
	if got.String() != "hello back" || !fc.usedWriteTo {
		t.Fatalf("copy: %q, WriteTo used %v", got.String(), fc.usedWriteTo)
	}
	if conns := m.Conns(); len(conns) != 1 || conns[0].Dst != "10.0.0.1:443" || conns[0].Up != 5 || conns[0].Down != 10 || conns[0].Via != ViaUtun {
		t.Fatalf("conns: %+v", conns)
	}
	if cw, ok := c.(interface{ CloseWrite() error }); !ok || cw.CloseWrite() != nil || !fc.closedWrite {
		t.Fatal("CloseWrite not passed through")
	}
	_ = c.Close()
	_ = c.Close()
	got2 := m.Counts()
	want := Counts{Open: 0, Total: 2, Failed: 1, ViaUtun: 1, ViaSOCKS: 1, Refused: 1, Up: 5, Down: 10}
	if got2 != want {
		t.Fatalf("counts:\n got %+v\nwant %+v", got2, want)
	}
}

func TestSamples(t *testing.T) {
	m := New()
	t0 := time.Unix(1000, 0)
	m.Sample(t0) // the baseline
	m.up.Add(2000)
	m.down.Add(500)
	m.Sample(t0.Add(2 * time.Second))
	s := m.Samples()
	if len(s) != 2 || s[1].Up != 1000 || s[1].Down != 250 {
		t.Fatalf("samples: %+v", s)
	}
	if c := m.Counts(); c.UpRate != 1000 || c.DownRate != 250 {
		t.Fatalf("rates: %+v", c)
	}
	for i := 0; i < keepSamples+10; i++ {
		m.Sample(t0.Add(time.Duration(3+i) * time.Second))
	}
	if n := len(m.Samples()); n != keepSamples {
		t.Fatalf("kept %d samples", n)
	}
}
