// Package testutil has in-memory connections for tests, so tests never open
// real sockets.
package testutil

import (
	"io"
	"net"
	"time"
)

// Conn is one end of an in-memory, full-duplex connection that supports
// half-close (CloseWrite), unlike net.Pipe.
type Conn struct {
	r *io.PipeReader
	w *io.PipeWriter
}

// Pair returns two connected ends.
func Pair() (*Conn, *Conn) {
	ar, bw := io.Pipe()
	br, aw := io.Pipe()
	return &Conn{r: ar, w: aw}, &Conn{r: br, w: bw}
}

func (c *Conn) Read(p []byte) (int, error)  { return c.r.Read(p) }
func (c *Conn) Write(p []byte) (int, error) { return c.w.Write(p) }

// CloseWrite makes the peer's reads return io.EOF; this end can still read.
func (c *Conn) CloseWrite() error { return c.w.Close() }

// Close closes both directions.
func (c *Conn) Close() error {
	_ = c.w.Close()
	return c.r.Close()
}

func (c *Conn) LocalAddr() net.Addr              { return addr{} }
func (c *Conn) RemoteAddr() net.Addr             { return addr{} }
func (c *Conn) SetDeadline(time.Time) error      { return nil }
func (c *Conn) SetReadDeadline(time.Time) error  { return nil }
func (c *Conn) SetWriteDeadline(time.Time) error { return nil }
func (addr) Network() string                     { return "mem" }
func (addr) String() string                      { return "mem" }

type addr struct{}
