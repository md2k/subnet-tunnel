package dns

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/md2k/subnet-tunnel/internal/proto"
	"github.com/md2k/subnet-tunnel/internal/testutil"
)

var (
	serverA = netip.MustParseAddrPort("192.168.1.1:53") // never answers
	serverB = netip.MustParseAddrPort("192.168.1.2:53")
	spoofer = netip.MustParseAddrPort("192.168.1.66:53")
)

func udpAddr(ap netip.AddrPort) *net.UDPAddr { return net.UDPAddrFromAddrPort(ap) }

// fallbackServers simulates resolvers behind the forwarder's socket: serverB
// answers every query (after a spoofed answer from another address with the
// same ID, which must be ignored); serverA stays silent.
func fallbackServers(t *testing.T) (*memPacketConn, *[]uint16) {
	var mu sync.Mutex
	var wireIDs []uint16
	var pc *memPacketConn
	pc = newMemPacketConn(func(b []byte, to net.Addr) {
		mu.Lock()
		wireIDs = append(wireIDs, uint16(b[0])<<8|uint16(b[1]))
		mu.Unlock()
		if addrPort(to) != serverB {
			return
		}
		a := buildAnswer(b, 1)
		spoofed := buildAnswer(b, 9)
		go func() {
			pc.deliver(spoofed, udpAddr(spoofer))
			pc.deliver(a, udpAddr(serverB))
		}()
	})
	t.Cleanup(func() { _ = pc.Close() })
	return pc, &wireIDs
}

func TestForwarderFailsOverAndRestoresID(t *testing.T) {
	pc, wireIDs := fallbackServers(t)
	f := NewForwarder(pc, nil, func() []netip.AddrPort { return []netip.AddrPort{serverA, serverB} })
	f.UDPTimeout = 50 * time.Millisecond

	q := buildQuery(0x4242, "example.org.", 0)
	got, err := f.Exchange(context.Background(), q)
	if err != nil {
		t.Fatal(err)
	}
	h := header(t, got)
	if h.ID != 0x4242 || !h.Response {
		t.Fatalf("got %+v", h)
	}
	if n := len(buildAnswer(q, 1)); len(got) != n {
		t.Fatalf("got the spoofed answer (%d bytes, want %d)", len(got), n)
	}
	if len(*wireIDs) != 2 {
		t.Fatalf("sent %d queries, want one per server", len(*wireIDs))
	}
}

// Two clients using the same query ID at the same time each get their own
// answer: the forwarder gives every query its own ID on the wire.
func TestForwarderConcurrentSameID(t *testing.T) {
	pc, _ := fallbackServers(t)
	f := NewForwarder(pc, nil, func() []netip.AddrPort { return []netip.AddrPort{serverB} })
	var wg sync.WaitGroup
	for _, name := range []string{"one.example.", "two.example."} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := f.Exchange(context.Background(), buildQuery(0x1111, name, 0))
			if err != nil {
				t.Error(err)
				return
			}
			q, err := parseQuery(append(append([]byte{}, got[:2]...), buildQuery(0x1111, name, 0)[2:]...))
			if err != nil || !strings.HasPrefix(q.name, strings.TrimSuffix(name, ".")) || header(t, got).ID != 0x1111 {
				t.Errorf("%s: wrong answer", name)
			}
			if !strings.Contains(string(got), strings.Split(name, ".")[0]) {
				t.Errorf("%s: answer is for another name", name)
			}
		}()
	}
	wg.Wait()
}

func TestForwarderTCP(t *testing.T) {
	var mu sync.Mutex
	var dialed []netip.AddrPort
	dial := func(_ context.Context, s netip.AddrPort) (net.Conn, error) {
		mu.Lock()
		dialed = append(dialed, s)
		mu.Unlock()
		if s != serverB {
			return nil, &net.OpError{Op: "dial", Net: "tcp", Err: errRefused}
		}
		c, srv := testutil.Pair()
		go func() {
			defer srv.Close()
			q, err := proto.ReadDNS(srv)
			if err == nil {
				_ = proto.WriteDNS(srv, buildAnswer(q, 40))
			}
		}()
		return c, nil
	}
	f := NewForwarder(newMemPacketConn(func([]byte, net.Addr) {}), dial, func() []netip.AddrPort { return []netip.AddrPort{serverA, serverB} })
	defer f.Close()
	q := buildQuery(5, "big.example.", 0)
	got, err := f.ExchangeTCP(context.Background(), q)
	if err != nil {
		t.Fatal(err)
	}
	if want := buildAnswer(q, 40); string(got) != string(want) {
		t.Fatal("TCP answer changed")
	}
	if want := []netip.AddrPort{serverA, serverB}; !slices.Equal(dialed, want) {
		t.Fatalf("dialed %v", dialed)
	}
}

type refusedErr struct{}

func (refusedErr) Error() string { return "connection refused" }

var errRefused = refusedErr{}
