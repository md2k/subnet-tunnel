package dns

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/md2k/subnet-tunnel/internal/proto"
)

// Forwarder sends queries to the fallback resolvers.
//
// All UDP queries share one socket. Its port is the one the firewall driver
// lets through untouched, so queries to a server that is also being captured
// (usually the case: the fallback is the system's resolver) leave normally
// instead of being redirected back to subtun. Each query gets a fresh ID on
// the way out, so concurrent clients using the same ID can't mix up answers.
type Forwarder struct {
	conn    net.PacketConn
	dialTCP func(ctx context.Context, server netip.AddrPort) (net.Conn, error)
	servers func() []netip.AddrPort

	// Per-server timeouts; zero means the defaults.
	UDPTimeout, TCPTimeout time.Duration

	mu      sync.Mutex
	pending map[uint16]*pending
	tcpMu   map[netip.AddrPort]*sync.Mutex
}

type pending struct {
	server netip.AddrPort
	ch     chan []byte
}

// NewForwarder reads answers from conn until Close. servers returns the
// current fallback resolvers, in order of preference. dialTCP opens a TCP
// connection to a server from the bypass port.
func NewForwarder(conn net.PacketConn, dialTCP func(context.Context, netip.AddrPort) (net.Conn, error), servers func() []netip.AddrPort) *Forwarder {
	f := &Forwarder{
		conn:    conn,
		dialTCP: dialTCP,
		servers: servers,
		pending: map[uint16]*pending{},
		tcpMu:   map[netip.AddrPort]*sync.Mutex{},
	}
	go f.readLoop()
	return f
}

// Close stops the forwarder.
func (f *Forwarder) Close() error { return f.conn.Close() }

func (f *Forwarder) readLoop() {
	buf := make([]byte, proto.MaxDNSLen)
	for {
		n, addr, err := f.conn.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		if n < 12 {
			continue
		}
		from := addrPort(addr)
		id := uint16(buf[0])<<8 | uint16(buf[1])
		f.mu.Lock()
		p := f.pending[id]
		f.mu.Unlock()
		if p == nil || p.server != from {
			continue // late, unknown or spoofed
		}
		select {
		case p.ch <- append([]byte(nil), buf[:n]...):
		default:
		}
	}
}

func addrPort(a net.Addr) netip.AddrPort {
	if u, ok := a.(*net.UDPAddr); ok {
		ap := u.AddrPort()
		return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
	}
	ap, _ := netip.ParseAddrPort(a.String())
	return ap
}

// Exchange sends the query over UDP to each fallback server in turn and
// returns the first answer.
func (f *Forwarder) Exchange(ctx context.Context, query []byte) ([]byte, error) {
	if len(query) < 12 {
		return nil, errors.New("short query")
	}
	timeout := f.UDPTimeout
	if timeout == 0 {
		timeout = 2 * time.Second
	}
	origID := uint16(query[0])<<8 | uint16(query[1])
	var lastErr error = errors.New("no fallback DNS server")
	for _, s := range f.servers() {
		answer, err := f.exchangeUDP(ctx, s, query, timeout)
		if err == nil {
			setID(answer, origID)
			return answer, nil
		}
		lastErr = fmt.Errorf("%s: %w", s, err)
		if ctx.Err() != nil {
			break
		}
	}
	return nil, lastErr
}

func (f *Forwarder) exchangeUDP(ctx context.Context, server netip.AddrPort, query []byte, timeout time.Duration) ([]byte, error) {
	p := &pending{server: server, ch: make(chan []byte, 1)}
	f.mu.Lock()
	var id uint16
	for {
		id = uint16(rand.Uint32())
		if f.pending[id] == nil {
			break
		}
	}
	f.pending[id] = p
	f.mu.Unlock()
	defer func() {
		f.mu.Lock()
		delete(f.pending, id)
		f.mu.Unlock()
	}()

	out := append([]byte(nil), query...)
	setID(out, id)
	if _, err := f.conn.WriteTo(out, net.UDPAddrFromAddrPort(server)); err != nil {
		return nil, err
	}
	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case answer := <-p.ch:
		return answer, nil
	case <-t.C:
		return nil, errors.New("timeout")
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// ExchangeTCP asks each fallback server in turn over TCP.
func (f *Forwarder) ExchangeTCP(ctx context.Context, query []byte) ([]byte, error) {
	timeout := f.TCPTimeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	var lastErr error = errors.New("no fallback DNS server")
	for _, s := range f.servers() {
		answer, err := f.exchangeTCP(ctx, s, query, timeout)
		if err == nil {
			return answer, nil
		}
		lastErr = fmt.Errorf("%s (tcp): %w", s, err)
		if ctx.Err() != nil {
			break
		}
	}
	return nil, lastErr
}

func (f *Forwarder) exchangeTCP(ctx context.Context, server netip.AddrPort, query []byte, timeout time.Duration) ([]byte, error) {
	// Every TCP query leaves from the same bypass port, so only one
	// connection per server can exist at a time.
	f.mu.Lock()
	m := f.tcpMu[server]
	if m == nil {
		m = &sync.Mutex{}
		f.tcpMu[server] = m
	}
	f.mu.Unlock()
	m.Lock()
	defer m.Unlock()

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	c, err := f.dialTCP(ctx, server)
	if err != nil {
		return nil, err
	}
	defer func() {
		// Reset instead of FIN: no TIME_WAIT blocking the next connection
		// from the same port.
		if l, ok := c.(interface{ SetLinger(int) error }); ok {
			_ = l.SetLinger(0)
		}
		_ = c.Close()
	}()
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	defer stop()
	if err := proto.WriteDNS(c, query); err != nil {
		return nil, err
	}
	answer, err := proto.ReadDNS(c)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	return answer, nil
}
