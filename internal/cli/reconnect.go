package cli

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/md2k/subnet-tunnel/internal/netstack"
	"github.com/md2k/subnet-tunnel/internal/transport"
	"github.com/md2k/subnet-tunnel/internal/tunnel"
)

// Reconnect defaults (reconnect.attempts, .delay, .maxDelay).
const (
	defaultReconnectAttempts = 10
	defaultReconnectDelay    = time.Second
	defaultReconnectMaxDelay = time.Minute
)

// errReconnecting is what dials and DNS get while the tunnel is down.
var errReconnecting = fmt.Errorf("the tunnel is down, reconnecting (%w)", netstack.ErrNoTunnel)

// liveTunnel is the tunnel client in use, swapped when subtun reconnects.
// The capture, the SOCKS proxy and DNS all go through it. While
// reconnecting it has none, so new connections and DNS fail at once
// instead of hanging.
type liveTunnel struct {
	cur atomic.Pointer[tunnel.Client]
}

func (l *liveTunnel) set(c *tunnel.Client) { l.cur.Store(c) }

// DialContext implements netstack.Dialer and socks.Dialer.
func (l *liveTunnel) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	c := l.cur.Load()
	if c == nil {
		return nil, errReconnecting
	}
	return c.DialContext(ctx, network, addr)
}

// ExchangeDNS resolves a query through the tunnel.
func (l *liveTunnel) ExchangeDNS(ctx context.Context, query []byte) ([]byte, error) {
	c := l.cur.Load()
	if c == nil {
		return nil, errReconnecting
	}
	return c.ExchangeDNS(ctx, query)
}

// session is one connection to the agent: the carrier and the tunnel
// client over it.
type session struct {
	carrier *transport.Carrier
	client  *tunnel.Client
}

func (s *session) close() {
	_ = s.client.Close()
	_ = s.carrier.Close()
}

// reconnectPolicy is how subtun retries after losing the agent: up to
// attempts tries per outage (0: don't, exit), waiting delay before the
// first and twice as long before each next one, at most maxDelay, with
// ±20 % jitter so several clients don't retry in step.
type reconnectPolicy struct {
	attempts        int
	delay, maxDelay time.Duration
}

func (p reconnectPolicy) String() string {
	if p.attempts == 0 {
		return "off: subtun exits when the connection to the agent is lost"
	}
	return fmt.Sprintf("up to %d attempts, waiting %s, then twice as long each time, at most %s", p.attempts, p.delay, p.maxDelay)
}

func (p reconnectPolicy) validate() error {
	switch {
	case p.attempts < 0:
		return errors.New("reconnect attempts: 0 or more (0: no reconnect)")
	case p.delay <= 0:
		return errors.New("reconnect delay must be positive")
	case p.maxDelay < p.delay:
		return errors.New("reconnect max delay must be at least the delay")
	}
	return nil
}

// wait is the pause before attempt n (from 1); jitter returns [0, 1).
func (p reconnectPolicy) wait(n int, jitter func() float64) time.Duration {
	d := p.delay
	for i := 1; i < n && d < p.maxDelay; i++ {
		d *= 2
	}
	d = min(d, p.maxDelay)
	return time.Duration(float64(d) * (0.8 + 0.4*jitter()))
}

// errHelperGone ends reconnecting when the root helper of the session went
// away: its rules are gone or left, and capture can't go on.
var errHelperGone = errors.New("the root helper exited while reconnecting")

// reconnect retries connecting by p, giving up early when ctx ends or stop
// closes (the root helper went away).
func reconnect(ctx context.Context, p reconnectPolicy, stop <-chan struct{}, try func(context.Context) (*session, error), log *slog.Logger) (*session, error) {
	for n := 1; n <= p.attempts; n++ {
		w := p.wait(n, rand.Float64)
		log.Info("reconnecting", "attempt", n, "of", p.attempts, "in", w.Round(10*time.Millisecond))
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-stop:
			return nil, errHelperGone
		case <-time.After(w):
		}
		s, err := try(ctx)
		if err == nil {
			return s, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		log.Warn("reconnect attempt failed", "attempt", n, "err", err)
	}
	return nil, fmt.Errorf("connection to the agent was lost; gave up after %d reconnect attempts", p.attempts)
}

// routedEndpoints are the carrier's addresses that the routes cover: after
// a reconnect the API server or Docker daemon may resolve to an address
// that wasn't excluded at the start, and subtun's own connection would go
// into the tunnel (routes don't change while running).
func routedEndpoints(final []netip.Prefix, endpoints []netip.Addr) []netip.Addr {
	var out []netip.Addr
	for _, a := range endpoints {
		for _, p := range final {
			if p.Contains(a) {
				out = append(out, a)
				break
			}
		}
	}
	return out
}
