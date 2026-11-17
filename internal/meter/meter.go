// Package meter counts what goes through one tunnel for `subtun status`:
// connections (open, total, failed; through the utun or the SOCKS proxy),
// bytes each way, rates sampled every second, connections the loop guard
// refused, and the connections open now.
package meter

import (
	"context"
	"fmt"
	"io"
	"net"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// How the connection reached the tunnel.
const (
	ViaUtun  = "utun"
	ViaSOCKS = "socks"
)

// keepSamples is how many 1 s samples are kept (5 minutes).
const keepSamples = 300

// Dialer opens a connection through the tunnel.
type Dialer interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

// Meter counts one tunnel. The zero value is not usable; use New.
type Meter struct {
	total, failed, refused atomic.Uint64
	viaUtun, viaSOCKS      atomic.Uint64
	up, down               atomic.Uint64 // bytes to the destination, and back

	mu      sync.Mutex
	conns   map[uint64]*Conn
	next    uint64
	samples []Sample // oldest first
	last    Sample   // totals at the last sample
}

// New returns a meter.
func New() *Meter { return &Meter{conns: map[uint64]*Conn{}} }

// Sample is the traffic in one second.
type Sample struct {
	Time time.Time `json:"time"`
	Up   uint64    `json:"up"`   // bytes per second
	Down uint64    `json:"down"` // bytes per second
}

// Counts are a meter's totals now.
type Counts struct {
	Open     int    `json:"open"`
	Total    uint64 `json:"total"`
	Failed   uint64 `json:"failed"`
	ViaUtun  uint64 `json:"viaUtun"`
	ViaSOCKS uint64 `json:"viaSocks"`
	Refused  uint64 `json:"loopGuardRefused"`
	Up       uint64 `json:"bytesUp"`
	Down     uint64 `json:"bytesDown"`
	UpRate   uint64 `json:"upRate"`   // bytes per second, the last sample
	DownRate uint64 `json:"downRate"` // bytes per second, the last sample
}

// ConnInfo is one open connection.
type ConnInfo struct {
	Dst    string    `json:"dst"`
	Proto  string    `json:"proto,omitempty"` // "udp" for a UDP flow; "": TCP
	Via    string    `json:"via"`
	Opened time.Time `json:"opened"`
	Up     uint64    `json:"bytesUp"`
	Down   uint64    `json:"bytesDown"`
}

// Label is the destination for people: "udp ADDR:PORT" for a UDP flow.
func (c ConnInfo) Label() string {
	if c.Proto != "" {
		return c.Proto + " " + c.Dst
	}
	return c.Dst
}

// Counts returns the totals.
func (m *Meter) Counts() Counts {
	m.mu.Lock()
	open := len(m.conns)
	var last Sample
	if n := len(m.samples); n > 0 {
		last = m.samples[n-1]
	}
	m.mu.Unlock()
	return Counts{
		Open: open, Total: m.total.Load(), Failed: m.failed.Load(),
		ViaUtun: m.viaUtun.Load(), ViaSOCKS: m.viaSOCKS.Load(), Refused: m.refused.Load(),
		Up: m.up.Load(), Down: m.down.Load(), UpRate: last.Up, DownRate: last.Down,
	}
}

// Samples returns the kept 1 s samples, oldest first.
func (m *Meter) Samples() []Sample {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.samples)
}

// Conns returns the open connections, oldest first.
func (m *Meter) Conns() []ConnInfo {
	m.mu.Lock()
	out := make([]ConnInfo, 0, len(m.conns))
	for _, c := range m.conns {
		out = append(out, ConnInfo{Dst: c.dst, Proto: c.proto, Via: c.via, Opened: c.opened, Up: c.up.Load(), Down: c.down.Load()})
	}
	m.mu.Unlock()
	slices.SortFunc(out, func(a, b ConnInfo) int { return a.Opened.Compare(b.Opened) })
	return out
}

// Sample records the traffic since the last sample; call it every second.
func (m *Meter) Sample(now time.Time) {
	up, down := m.up.Load(), m.down.Load()
	m.mu.Lock()
	defer m.mu.Unlock()
	s := Sample{Time: now}
	if !m.last.Time.IsZero() {
		secs := now.Sub(m.last.Time).Seconds()
		if secs <= 0 {
			secs = 1
		}
		s.Up = uint64(float64(up-m.last.Up) / secs)
		s.Down = uint64(float64(down-m.last.Down) / secs)
	}
	m.last = Sample{Time: now, Up: up, Down: down}
	m.samples = append(m.samples, s)
	if len(m.samples) > keepSamples {
		m.samples = append(m.samples[:0], m.samples[len(m.samples)-keepSamples:]...)
	}
}

// Refused counts a connection the loop guard refused.
func (m *Meter) Refused() { m.refused.Add(1) }

// Dialer returns d counted as via (ViaUtun or ViaSOCKS).
func (m *Meter) Dialer(via string, d Dialer) Dialer { return dialer{m, via, d} }

type dialer struct {
	m   *Meter
	via string
	d   Dialer
}

func (d dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	c, err := d.d.DialContext(ctx, network, addr)
	d.m.total.Add(1)
	if d.via == ViaSOCKS {
		d.m.viaSOCKS.Add(1)
	} else {
		d.m.viaUtun.Add(1)
	}
	if err != nil {
		d.m.failed.Add(1)
		return nil, err
	}
	conn := &Conn{Conn: c, m: d.m, dst: addr, via: d.via, opened: time.Now()}
	if strings.HasPrefix(network, "udp") {
		conn.proto = "udp"
	}
	d.m.mu.Lock()
	d.m.next++
	conn.id = d.m.next
	d.m.conns[conn.id] = conn
	d.m.mu.Unlock()
	return conn, nil
}

// Conn counts the bytes of one connection. It keeps CloseWrite (half
// close) and the WriteTo fast path of the connection it wraps.
type Conn struct {
	net.Conn
	m        *Meter
	id       uint64
	dst, via string
	proto    string // "udp", or "" for TCP
	opened   time.Time
	up, down atomic.Uint64
	once     sync.Once
}

func (c *Conn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.addDown(n)
	return n, err
}

func (c *Conn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.addUp(n)
	return n, err
}

// WriteTo copies the connection's data to w, through the wrapped
// connection's WriteTo when it has one.
func (c *Conn) WriteTo(w io.Writer) (int64, error) {
	if wt, ok := c.Conn.(io.WriterTo); ok {
		return wt.WriteTo(countingWriter{w, c})
	}
	return io.Copy(w, readerOnly{c})
}

// CloseWrite half-closes the connection, if the wrapped one can.
func (c *Conn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.Close()
}

// Close closes the connection and forgets it.
func (c *Conn) Close() error {
	c.once.Do(func() {
		c.m.mu.Lock()
		delete(c.m.conns, c.id)
		c.m.mu.Unlock()
	})
	return c.Conn.Close()
}

func (c *Conn) addUp(n int) {
	if n > 0 {
		c.up.Add(uint64(n))
		c.m.up.Add(uint64(n))
	}
}

func (c *Conn) addDown(n int) {
	if n > 0 {
		c.down.Add(uint64(n))
		c.m.down.Add(uint64(n))
	}
}

// countingWriter counts what the wrapped connection's WriteTo delivers.
type countingWriter struct {
	w io.Writer
	c *Conn
}

func (cw countingWriter) Write(p []byte) (int, error) {
	n, err := cw.w.Write(p)
	cw.c.addDown(n)
	return n, err
}

// readerOnly hides Conn's WriteTo from io.Copy.
type readerOnly struct{ io.Reader }

// Bytes is a byte count for people (decimal units): "1.5 MB".
func Bytes(n uint64) string {
	const unit = 1000
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	v, suffix := float64(n), []string{"kB", "MB", "GB", "TB"}
	i := -1
	for v >= unit && i < len(suffix)-1 {
		v /= unit
		i++
	}
	return fmt.Sprintf("%.1f %s", v, suffix[i])
}
