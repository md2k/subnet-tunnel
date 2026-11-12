package netstack

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"

	"github.com/md2k/subnet-tunnel/internal/relay"
)

func TestLoopGuardCaps(t *testing.T) {
	now := time.Unix(1000, 0)
	g := newLoopGuard(2, 3, 10*time.Second)
	g.now = func() time.Time { return now }
	const a, b = "10.1.2.3:443", "10.1.2.4:443"

	// Two opening at once is fine; a third trips the opening cap.
	for i := range 2 {
		if ok, _, _ := g.acquire(a); !ok {
			t.Fatalf("connection %d refused below the cap", i+1)
		}
	}
	if ok, _, _ := g.acquire(b); !ok {
		t.Fatal("another destination refused")
	}
	ok, warn, refused := g.acquire(a)
	if ok || !warn || refused != 1 {
		t.Fatalf("opening cap: ok=%v warn=%v refused=%d", ok, warn, refused)
	}
	if !g.looping(a) || g.looping(b) {
		t.Fatal("looping state wrong")
	}

	// Held: refused even though both finish dialing, without more warnings.
	g.dialed(a)
	g.dialed(a)
	for range 3 {
		if ok, warn, _ := g.acquire(a); ok || warn {
			t.Fatalf("while held: ok=%v warn=%v", ok, warn)
		}
	}

	// After the hold: accepted again, until the open cap (3) trips.
	now = now.Add(10 * time.Second)
	if ok, _, _ := g.acquire(a); !ok {
		t.Fatal("refused after the hold")
	}
	g.dialed(a) // 3 open, none opening
	if ok, warn, _ := g.acquire(a); ok || warn {
		t.Fatalf("open cap: ok=%v warn=%v (a warning came less than a minute ago)", ok, warn)
	}

	// A minute after the first warning the next refusal warns again,
	// counting the quiet ones.
	now = now.Add(loopWarnEvery)
	if ok, warn, refused := g.acquire(a); ok || !warn || refused != 5 {
		t.Fatalf("a minute later: ok=%v warn=%v refused=%d", ok, warn, refused)
	}

	// Releasing everything forgets the destination.
	now = now.Add(time.Hour)
	for range 3 {
		g.release(a)
	}
	g.dialed(b)
	g.release(b)
	if len(g.opening) != 0 || len(g.open) != 0 {
		t.Fatalf("counts left: opening %v open %v", g.opening, g.open)
	}
	if g.looping(a) {
		t.Fatal("still looping long after the last refusal")
	}
}

func TestReportFailureOncePerMinute(t *testing.T) {
	now := time.Unix(1000, 0)
	g := newLoopGuard(1, 1, time.Second)
	g.now = func() time.Time { return now }
	if !g.reportFailure("a:1") || g.reportFailure("a:1") || !g.reportFailure("b:1") {
		t.Fatal("first failure per destination not reported, or a repeat reported")
	}
	now = now.Add(failInfoEvery)
	if !g.reportFailure("a:1") {
		t.Fatal("not reported again a minute later")
	}
}

// Through the stack: at the open cap the next connection to that
// destination is reset at once, other destinations work, and after the hold
// it's accepted again.
func TestLoopGuardRefusesAtCap(t *testing.T) {
	client := setupWith(t, map[string]func(net.Conn){"10.1.2.3:7": echo, "10.1.2.3:8": echo},
		Options{DialTimeout: 5 * time.Second, MaxOpen: 2, LoopHold: 300 * time.Millisecond})
	first, err := dial(t, client, 7)
	if err != nil {
		t.Fatal(err)
	}
	second, err := dial(t, client, 7)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()

	start := time.Now()
	if c, err := dial(t, client, 7); err == nil {
		c.Close()
		t.Fatal("third connection accepted above the cap")
	}
	if took := time.Since(start); took > 3*time.Second {
		t.Fatalf("refusal took %v", took)
	}
	other, err := dial(t, client, 8)
	if err != nil {
		t.Fatalf("other destination: %v", err)
	}
	other.Close()

	first.Close()
	deadline := time.Now().Add(3 * time.Second)
	for {
		c, err := dial(t, client, 7)
		if err == nil {
			c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("still refused after closing one and the hold: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// loopDialer is a target that reaches every destination back through the
// capture before its own dial completes, like Docker Desktop's proxy, which
// connects onward before accepting: each level waits on the next.
type loopDialer struct {
	client *stack.Stack
	levels atomic.Int32
}

func (d *loopDialer) DialContext(ctx context.Context, _, addr string) (net.Conn, error) {
	d.levels.Add(1)
	ap := netip.MustParseAddrPort(addr)
	return gonet.DialContextTCP(ctx, d.client, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4(ap.Addr().As4()), Port: ap.Port()}, ipv4.ProtocolNumber)
}

func TestLoopGuardCutsADialFirstLoop(t *testing.T) {
	d := &loopDialer{}
	d.client = setupDialer(t, d, Options{DialTimeout: 5 * time.Second, MaxOpening: 8})
	start := time.Now()
	if c, err := dial(t, d.client, 7); err == nil {
		c.Close()
		t.Fatal("the looping connection was accepted")
	}
	if took := time.Since(start); took > 3*time.Second {
		t.Fatalf("cutting the loop took %v", took)
	}
	if n := d.levels.Load(); n != 8 {
		t.Fatalf("loop went %d levels deep, want the opening cap (8)", n)
	}
	// Held: a retry is refused at once, without building a new chain.
	if c, err := dial(t, d.client, 7); err == nil {
		c.Close()
		t.Fatal("retry accepted while held")
	}
	if n := d.levels.Load(); n != 8 {
		t.Fatalf("a retry built %d more levels", n-8)
	}
}

// An accept-first loop: the "target" accepts, then reaches the destination
// back through the capture. The chain of open connections grows to the
// open cap, the next is refused, and it all unwinds: the app's connection
// ends instead of hanging.
func TestLoopGuardCutsALoop(t *testing.T) {
	var client *stack.Stack
	var levels atomic.Int32
	loop := func(c net.Conn) {
		defer c.Close()
		levels.Add(1)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		up, err := gonet.DialContextTCP(ctx, client, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4([4]byte{10, 1, 2, 3}), Port: 7}, ipv4.ProtocolNumber)
		if err != nil {
			return
		}
		relay.Pipe(c, up)
	}
	client = setupWith(t, map[string]func(net.Conn){"10.1.2.3:7": loop}, Options{DialTimeout: 5 * time.Second, MaxOpen: 8})

	conn, err := dial(t, client, 7)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.ReadAll(conn); err != nil && errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal("the looping connection hung instead of ending")
	}
	if n := levels.Load(); n != 8 {
		t.Fatalf("loop went %d levels deep, want the open cap (8)", n)
	}
}

// recDevice hands the stack packets from in and records what it writes.
type recDevice struct {
	in     chan []byte
	out    chan []byte
	closed chan struct{}
	once   sync.Once
}

func (d *recDevice) Headroom() int { return 0 }
func (d *recDevice) MTU() int      { return testMTU }
func (d *recDevice) Read(buf []byte) (int, error) {
	select {
	case p := <-d.in:
		return copy(buf, p), nil
	case <-d.closed:
		return 0, net.ErrClosed
	}
}
func (d *recDevice) Write(buf []byte) error {
	d.out <- append([]byte(nil), buf...)
	return nil
}
func (d *recDevice) Close() error {
	d.once.Do(func() { close(d.closed) })
	return nil
}

func udpPacket(src, dst [4]byte) []byte {
	pkt := make([]byte, header.IPv4MinimumSize+header.UDPMinimumSize)
	ip := header.IPv4(pkt)
	ip.Encode(&header.IPv4Fields{TotalLength: uint16(len(pkt)), TTL: 64, Protocol: uint8(header.UDPProtocolNumber),
		SrcAddr: tcpip.AddrFrom4(src), DstAddr: tcpip.AddrFrom4(dst)})
	ip.SetChecksum(^ip.CalculateChecksum())
	u := header.UDP(pkt[header.IPv4MinimumSize:])
	u.Encode(&header.UDPFields{SrcPort: 53, DstPort: 50000, Length: header.UDPMinimumSize})
	return pkt
}

// An answer the system sends to the device's own address (a DNS server
// redirected to a local listener, answering an app whose query went into
// the device) goes back to the system unchanged; anything else doesn't.
func TestPacketsForTunAddrGoBack(t *testing.T) {
	dev := &recDevice{in: make(chan []byte, 4), out: make(chan []byte, 4), closed: make(chan struct{})}
	st, err := New(dev, fakeTunnel{}, Options{TunAddr: netip.MustParseAddr("198.18.249.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	other := udpPacket([4]byte{203, 0, 113, 53}, [4]byte{10, 1, 2, 3})
	self := udpPacket([4]byte{203, 0, 113, 53}, [4]byte{198, 18, 249, 1})
	dev.in <- other
	dev.in <- self
	select {
	case got := <-dev.out:
		if !bytes.Equal(got, self) {
			t.Fatalf("wrote back %x, want the packet for the device's address", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("packet for the device's own address not handed back")
	}
	// The other packet goes to the stack, which may answer it (ICMP
	// protocol unreachable: the stack carries TCP only), but never hands it
	// back as it is.
	deadline := time.After(200 * time.Millisecond)
	for {
		select {
		case got := <-dev.out:
			if bytes.Equal(got, other) {
				t.Fatal("packet for another address handed back")
			}
		case <-deadline:
			return
		}
	}
}
