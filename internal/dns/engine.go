// Package dns is subtun's DNS engine. It answers the queries the system
// sends to its DNS servers (redirected to subtun by the firewall driver):
// names matching the configured domains or patterns are resolved through the
// tunnel by the target's resolver, everything else by a fallback resolver.
//
// The engine runs as the user and is the same on every OS; only the way
// queries reach it is platform specific.
package dns

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/md2k/subnet-tunnel/internal/proto"
)

// Upstream resolves one query.
type Upstream interface {
	Exchange(ctx context.Context, query []byte) ([]byte, error)
}

// UpstreamFunc adapts a function, e.g. tunnel.Client.ExchangeDNS.
type UpstreamFunc func(ctx context.Context, query []byte) ([]byte, error)

// Exchange implements Upstream.
func (f UpstreamFunc) Exchange(ctx context.Context, q []byte) ([]byte, error) { return f(ctx, q) }

// TCPUpstream can also ask over TCP, for answers too large for UDP.
type TCPUpstream interface {
	Upstream
	ExchangeTCP(ctx context.Context, query []byte) ([]byte, error)
}

// Engine answers queries.
type Engine struct {
	Match          *Matcher
	Tunnels        []Tunnel    // by the matcher's targets; more come with AddTunnel
	Fallback       TCPUpstream // everything else
	FallbackCounts *Counts     // names the fallback answered; nil: not counted
	Log            *slog.Logger

	added atomic.Pointer[[]Tunnel] // Tunnels plus those added while running
}

// AddTunnel adds a tunnel while the engine runs (a profile added to a
// running subtun): the next target. Add it before the matcher's names point
// at it. One caller at a time.
func (e *Engine) AddTunnel(t Tunnel) {
	cur := e.Tunnels
	if p := e.added.Load(); p != nil {
		cur = *p
	}
	next := append(slices.Clone(cur), t)
	e.added.Store(&next)
}

// tunnel returns target t's tunnel.
func (e *Engine) tunnel(t int) *Tunnel {
	if p := e.added.Load(); p != nil {
		return &(*p)[t]
	}
	return &e.Tunnels[t]
}

// Counts are the queries an upstream answered or failed (for status).
type Counts struct {
	Answered, Failed atomic.Uint64
}

func (c *Counts) count(err error) {
	if c == nil {
		return
	}
	if err != nil {
		c.Failed.Add(1)
	} else {
		c.Answered.Add(1)
	}
}

// Tunnel resolves the names the matcher gives one tunnel.
type Tunnel struct {
	Name     string    // the profile, for the log ("" with one tunnel)
	Upstream Upstream  // resolves through the agent (returns complete answers)
	Unrouted *Unrouted // answers pointing at private addresses its routes don't cover; nil: no check
	Counts   *Counts   // nil: not counted
}

const (
	queryTimeout = 10 * time.Second
	tcpIdle      = 10 * time.Second
	maxInflight  = 256
)

// Answer resolves one query and returns the message to send back, or nil to
// drop it (not a query). Errors become SERVFAIL. For a UDP client (udp true)
// an answer larger than the client accepts is replaced by a truncated one.
func (e *Engine) Answer(ctx context.Context, msg []byte, udp bool) []byte {
	q, err := parseQuery(msg)
	if err != nil {
		e.Log.Debug("dns: dropped", "err", err)
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()
	start := time.Now()

	route := "fallback"
	var answer []byte
	var tun *Tunnel
	if t, ok := e.Match.Pick(q.name); ok {
		route, tun = "tunnel", e.tunnel(t)
		if tun.Name != "" {
			route = "tunnel:" + tun.Name
		}
		answer, err = tun.Upstream.Exchange(ctx, msg)
	} else {
		answer, err = e.Fallback.Exchange(ctx, msg)
		if err == nil && !udp && truncated(answer) {
			answer, err = e.Fallback.ExchangeTCP(ctx, msg)
		}
	}
	if err == nil && !answers(answer, q.header.ID) {
		err = errors.New("answer does not match the query")
	}
	if err == nil && tun != nil && tun.Unrouted != nil {
		if a, how := tun.Unrouted.check(ctx, e.Fallback, q, msg, answer); how != "" {
			answer, route = a, how
		}
	}
	if tun != nil {
		tun.Counts.count(err)
	} else {
		e.FallbackCounts.count(err)
	}
	if err != nil {
		e.Log.Debug("dns: failed", "name", q.name, "type", q.question.Type, "via", route, "err", err)
		return failure(q)
	}
	e.Log.Debug("dns", "name", q.name, "type", q.question.Type, "via", route, "bytes", len(answer), "dur", time.Since(start).Round(time.Millisecond))
	if udp && len(answer) > q.udpSize {
		return truncate(q, answer)
	}
	return answer
}

// ServeUDP answers datagrams on pc until ctx ends or pc is closed.
func (e *Engine) ServeUDP(ctx context.Context, pc net.PacketConn) error {
	stop := context.AfterFunc(ctx, func() { _ = pc.Close() })
	defer stop()
	sem := make(chan struct{}, maxInflight)
	buf := make([]byte, proto.MaxDNSLen)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		msg := append([]byte(nil), buf[:n]...)
		select {
		case sem <- struct{}{}:
		default:
			e.Log.Warn("dns: too many queries in flight, dropping one")
			continue
		}
		go func() {
			defer func() { <-sem }()
			if out := e.Answer(ctx, msg, true); out != nil {
				_, _ = pc.WriteTo(out, addr)
			}
		}()
	}
}

// ServeTCP answers DNS-over-TCP connections on ln until ctx ends or ln is
// closed. Queries on one connection are answered in order.
func (e *Engine) ServeTCP(ctx context.Context, ln net.Listener) error {
	stop := context.AfterFunc(ctx, func() { _ = ln.Close() })
	defer stop()
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			e.serveConn(ctx, c)
		}()
	}
}

func (e *Engine) serveConn(ctx context.Context, c net.Conn) {
	defer c.Close()
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	defer stop()
	for {
		_ = c.SetReadDeadline(time.Now().Add(tcpIdle))
		msg, err := proto.ReadDNS(c)
		if err != nil {
			if !errors.Is(err, io.EOF) && ctx.Err() == nil {
				e.Log.Debug("dns: tcp connection ended", "err", err)
			}
			return
		}
		out := e.Answer(ctx, msg, false)
		if out == nil {
			return
		}
		if err := proto.WriteDNS(c, out); err != nil {
			return
		}
	}
}
