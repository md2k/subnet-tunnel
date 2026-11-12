package dns

import (
	"context"
	"net"
	"slices"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// buildQuery makes a query for name/type A, optionally with an EDNS0 OPT
// record advertising udpSize.
func buildQuery(id uint16, name string, udpSize int) []byte {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id, RecursionDesired: true})
	_ = b.StartQuestions()
	_ = b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(name), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET})
	if udpSize > 0 {
		_ = b.StartAdditionals()
		var rh dnsmessage.ResourceHeader
		_ = rh.SetEDNS0(udpSize, dnsmessage.RCodeSuccess, false)
		_ = b.OPTResource(rh, dnsmessage.OPTResource{})
	}
	out, err := b.Finish()
	if err != nil {
		panic(err)
	}
	return out
}

// buildAnswer answers q with n A records.
func buildAnswer(q []byte, n int) []byte {
	var p dnsmessage.Parser
	h, err := p.Start(q)
	if err != nil {
		panic(err)
	}
	question, _ := p.Question()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: h.ID, Response: true, RecursionDesired: h.RecursionDesired, RecursionAvailable: true})
	_ = b.StartQuestions()
	_ = b.Question(question)
	_ = b.StartAnswers()
	for i := range n {
		_ = b.AResource(dnsmessage.ResourceHeader{Name: question.Name, Class: dnsmessage.ClassINET, TTL: 60},
			dnsmessage.AResource{A: [4]byte{10, 96, byte(i >> 8), byte(i)}})
	}
	out, err := b.Finish()
	if err != nil {
		panic(err)
	}
	return out
}

func header(t interface{ Fatal(...any) }, msg []byte) dnsmessage.Header {
	var p dnsmessage.Parser
	h, err := p.Start(msg)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// fakeUpstream answers with n records and records the names it was asked.
type fakeUpstream struct {
	mu      sync.Mutex
	asked   []string
	records int
	err     error
	tcp     []string // asked over TCP
	tcpOnly bool     // UDP answers come back truncated
}

func (f *fakeUpstream) Exchange(_ context.Context, q []byte) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	pq, _ := parseQuery(q)
	f.asked = append(f.asked, pq.name)
	if f.err != nil {
		return nil, f.err
	}
	a := buildAnswer(q, f.records)
	if f.tcpOnly {
		a[2] |= 0x02
	}
	return a, nil
}

func (f *fakeUpstream) ExchangeTCP(_ context.Context, q []byte) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	pq, _ := parseQuery(q)
	f.tcp = append(f.tcp, pq.name)
	return buildAnswer(q, f.records), nil
}

func (f *fakeUpstream) names() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.asked)
}

// memPacketConn is an in-memory net.PacketConn. Datagrams pushed with
// deliver are read by ReadFrom; WriteTo calls onWrite.
type memPacketConn struct {
	in      chan packet
	closed  chan struct{}
	once    sync.Once
	onWrite func(b []byte, to net.Addr)
}

type packet struct {
	b    []byte
	from net.Addr
}

func newMemPacketConn(onWrite func([]byte, net.Addr)) *memPacketConn {
	return &memPacketConn{in: make(chan packet, 64), closed: make(chan struct{}), onWrite: onWrite}
}

func (c *memPacketConn) deliver(b []byte, from net.Addr) {
	c.in <- packet{append([]byte(nil), b...), from}
}

func (c *memPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	select {
	case p := <-c.in:
		return copy(b, p.b), p.from, nil
	case <-c.closed:
		return 0, nil, net.ErrClosed
	}
}

func (c *memPacketConn) WriteTo(b []byte, to net.Addr) (int, error) {
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	default:
	}
	c.onWrite(append([]byte(nil), b...), to)
	return len(b), nil
}

func (c *memPacketConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

func (c *memPacketConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (c *memPacketConn) SetDeadline(time.Time) error      { return nil }
func (c *memPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *memPacketConn) SetWriteDeadline(time.Time) error { return nil }
