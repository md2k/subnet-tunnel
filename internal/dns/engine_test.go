package dns

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net"
	"slices"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/md2k/subnet-tunnel/internal/proto"
	"github.com/md2k/subnet-tunnel/internal/testutil"
)

func newEngine(t *testing.T, tunnel, fallback *fakeUpstream) *Engine {
	t.Helper()
	m, err := NewMatcher([]string{"svc.cluster.local", "company.com"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return &Engine{Match: m, Tunnels: []Tunnel{{Upstream: tunnel}}, Fallback: fallback, Log: slog.New(slog.DiscardHandler)}
}

func TestAnswerRoutesByName(t *testing.T) {
	tun, fb := &fakeUpstream{records: 1}, &fakeUpstream{records: 2}
	e := newEngine(t, tun, fb)
	for _, name := range []string{"web.ns.svc.cluster.local.", "Company.com.", "example.org."} {
		q := buildQuery(42, name, 0)
		got := e.Answer(context.Background(), q, true)
		want := buildAnswer(q, 1)
		if name == "example.org." {
			want = buildAnswer(q, 2)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s: answer not passed through unchanged", name)
		}
	}
	if want := []string{"web.ns.svc.cluster.local", "company.com"}; !slices.Equal(tun.names(), want) {
		t.Errorf("tunnel asked %q", tun.names())
	}
	if want := []string{"example.org"}; !slices.Equal(fb.names(), want) {
		t.Errorf("fallback asked %q", fb.names())
	}
}

func TestAnswerFailureIsServfail(t *testing.T) {
	e := newEngine(t, &fakeUpstream{err: errors.New("agent: timeout")}, &fakeUpstream{})
	q := buildQuery(7, "db.company.com.", 0)
	got := e.Answer(context.Background(), q, true)
	h := header(t, got)
	if h.ID != 7 || !h.Response || h.RCode != dnsmessage.RCodeServerFailure {
		t.Fatalf("got %+v", h)
	}
	pq, err := parseQuery(append(slices.Clone(got[:2]), q[2:]...)) // same question section
	if err != nil || pq.name != "db.company.com" {
		t.Fatalf("question not echoed: %v %v", pq, err)
	}
}

// Over UDP an answer bigger than the client accepts (512 bytes without
// EDNS0) becomes an empty truncated one; over TCP or with a large EDNS0 size
// it goes through whole.
func TestAnswerTruncatesForUDPClients(t *testing.T) {
	e := newEngine(t, &fakeUpstream{records: 60}, &fakeUpstream{})
	q := buildQuery(1, "big.company.com.", 0)
	full := buildAnswer(q, 60)
	if len(full) <= 512 {
		t.Fatalf("test answer only %d bytes", len(full))
	}

	got := e.Answer(context.Background(), q, true)
	h := header(t, got)
	if !h.Truncated || h.ID != 1 || len(got) > 512 {
		t.Fatalf("UDP: truncated=%v id=%d len=%d", h.Truncated, h.ID, len(got))
	}
	if got := e.Answer(context.Background(), q, false); !bytes.Equal(got, full) {
		t.Error("TCP: answer not whole")
	}
	qEDNS := buildQuery(2, "big.company.com.", 4096)
	if got := e.Answer(context.Background(), qEDNS, true); !bytes.Equal(got, buildAnswer(qEDNS, 60)) {
		t.Error("UDP with EDNS0 4096: answer not whole")
	}
}

// The fallback is asked over UDP; a truncated answer is retried over TCP for
// TCP clients and passed on (TC set) to UDP clients, who retry over TCP.
func TestAnswerFallbackTCP(t *testing.T) {
	fb := &fakeUpstream{records: 1, tcpOnly: true}
	e := newEngine(t, &fakeUpstream{}, fb)
	q := buildQuery(3, "example.org.", 0)
	if h := header(t, e.Answer(context.Background(), q, true)); !h.Truncated {
		t.Error("UDP client: want the truncated answer")
	}
	if h := header(t, e.Answer(context.Background(), q, false)); h.Truncated {
		t.Error("TCP client: want the TCP answer")
	}
	if want := []string{"example.org"}; !slices.Equal(fb.tcp, want) {
		t.Errorf("asked over TCP: %q", fb.tcp)
	}
}

func TestAnswerDropsWhatIsNotAQuery(t *testing.T) {
	e := newEngine(t, &fakeUpstream{records: 1}, &fakeUpstream{records: 1})
	q := buildQuery(5, "web.company.com.", 0)
	for name, msg := range map[string][]byte{
		"garbage":  []byte("hello, not dns"),
		"response": buildAnswer(q, 1),
	} {
		if got := e.Answer(context.Background(), msg, true); got != nil {
			t.Errorf("%s: answered", name)
		}
	}
}

func TestAnswerWithWrongIDIsServfail(t *testing.T) {
	e := newEngine(t, &fakeUpstream{}, &fakeUpstream{})
	e.Tunnels[0].Upstream = UpstreamFunc(func(_ context.Context, q []byte) ([]byte, error) {
		a := buildAnswer(q, 1)
		a[0] ^= 0xff
		return a, nil
	})
	if h := header(t, e.Answer(context.Background(), buildQuery(9, "x.company.com.", 0), true)); h.RCode != dnsmessage.RCodeServerFailure || h.ID != 9 {
		t.Fatalf("got %+v", h)
	}
}

func TestServeUDP(t *testing.T) {
	e := newEngine(t, &fakeUpstream{records: 1}, &fakeUpstream{records: 1})
	type sent struct {
		b  []byte
		to net.Addr
	}
	out := make(chan sent, 1)
	pc := newMemPacketConn(func(b []byte, to net.Addr) { out <- sent{b, to} })
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- e.ServeUDP(ctx, pc) }()

	client := &net.UDPAddr{IP: net.IPv4(192, 168, 1, 20), Port: 53000}
	q := buildQuery(11, "web.company.com.", 0)
	pc.deliver(q, client)
	select {
	case s := <-out:
		if !bytes.Equal(s.b, buildAnswer(q, 1)) || s.to.String() != client.String() {
			t.Fatalf("sent %d bytes to %v", len(s.b), s.to)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no answer")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

type memListener struct {
	conns  chan net.Conn
	closed chan struct{}
	once   sync.Once
}

func (l *memListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}
func (l *memListener) Close() error   { l.once.Do(func() { close(l.closed) }); return nil }
func (l *memListener) Addr() net.Addr { return &net.TCPAddr{} }

// Two queries pipelined on one TCP connection are answered in order.
func TestServeTCP(t *testing.T) {
	e := newEngine(t, &fakeUpstream{records: 1}, &fakeUpstream{records: 3})
	ln := &memListener{conns: make(chan net.Conn, 1), closed: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- e.ServeTCP(ctx, ln) }()

	client, server := testutil.Pair()
	ln.conns <- server
	q1, q2 := buildQuery(1, "web.company.com.", 0), buildQuery(2, "example.org.", 0)
	go func() {
		_ = proto.WriteDNS(client, q1)
		_ = proto.WriteDNS(client, q2)
	}()
	for _, want := range [][]byte{buildAnswer(q1, 1), buildAnswer(q2, 3)} {
		got, err := proto.ReadDNS(client)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("answer %d out of order or changed", header(t, got).ID)
		}
	}
	_ = client.Close()
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// Several tunnels: each name goes to its tunnel, named in the log.
func TestAnswerRoutesToTunnels(t *testing.T) {
	m, err := NewMultiMatcher([]Names{{Domains: []string{"work.example"}}, {Domains: []string{"dev.example"}}})
	if err != nil {
		t.Fatal(err)
	}
	work, dev, fb := &fakeUpstream{records: 1}, &fakeUpstream{records: 2}, &fakeUpstream{records: 3}
	e := &Engine{Match: m, Tunnels: []Tunnel{{Name: "work", Upstream: work}, {Name: "dev", Upstream: dev}},
		Fallback: fb, Log: slog.New(slog.DiscardHandler)}
	for name, records := range map[string]int{"a.work.example.": 1, "b.dev.example.": 2, "example.org.": 3} {
		q := buildQuery(7, name, 0)
		if got := e.Answer(context.Background(), q, true); !bytes.Equal(got, buildAnswer(q, records)) {
			t.Errorf("%s: wrong upstream", name)
		}
	}
	m.SetOn(1, false)
	q := buildQuery(8, "b.dev.example.", 0)
	if got := e.Answer(context.Background(), q, true); !bytes.Equal(got, buildAnswer(q, 3)) {
		t.Error("a tunnel switched off still answers")
	}
}
