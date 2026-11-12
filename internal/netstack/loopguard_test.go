package netstack

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"

	"github.com/md2k/subnet-tunnel/internal/relay"
)

func TestLoopGuardCap(t *testing.T) {
	now := time.Unix(1000, 0)
	g := newLoopGuard(2)
	g.now = func() time.Time { return now }
	const a, b = "10.1.2.3:443", "10.1.2.4:443"

	for i := range 2 {
		if ok, _, _ := g.acquire(a); !ok {
			t.Fatalf("connection %d refused below the cap", i+1)
		}
	}
	if ok, _, _ := g.acquire(b); !ok {
		t.Fatal("another destination refused")
	}
	if g.looping(a) {
		t.Fatal("looping before the cap was hit")
	}

	// At the cap: refused, with a warning the first time only.
	ok, warn, refused := g.acquire(a)
	if ok || !warn || refused != 1 {
		t.Fatalf("at the cap: ok=%v warn=%v refused=%d", ok, warn, refused)
	}
	if !g.looping(a) || g.looping(b) {
		t.Fatal("looping state wrong")
	}
	for range 3 {
		if ok, warn, _ := g.acquire(a); ok || warn {
			t.Fatalf("repeat refusal: ok=%v warn=%v", ok, warn)
		}
	}

	// A minute later the next refusal warns again, counting the quiet ones.
	now = now.Add(loopWarnEvery)
	if ok, warn, refused := g.acquire(a); ok || !warn || refused != 4 {
		t.Fatalf("after a minute: ok=%v warn=%v refused=%d", ok, warn, refused)
	}

	// Closing one makes room again; closing all forgets the destination.
	g.release(a)
	if ok, _, _ := g.acquire(a); !ok {
		t.Fatal("refused after a release")
	}
	g.release(a)
	g.release(a)
	g.release(b)
	if len(g.open) != 0 {
		t.Fatalf("open counts left: %v", g.open)
	}
	now = now.Add(loopWarnEvery)
	if g.looping(a) {
		t.Fatal("still looping a minute after the last refusal")
	}
}

// Through the stack: at the cap the next connection to that destination is
// reset at once, other destinations work, and closing one makes room.
func TestLoopGuardRefusesAtCap(t *testing.T) {
	client := setupWith(t, map[string]func(net.Conn){"10.1.2.3:7": echo, "10.1.2.3:8": echo},
		Options{DialTimeout: 5 * time.Second, MaxPerDestination: 2})
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

	// The echo handler ends once it sees the close, and the count drops.
	first.Close()
	deadline := time.Now().Add(3 * time.Second)
	for {
		c, err := dial(t, client, 7)
		if err == nil {
			c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("still refused after closing one: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// A real loop: the "target" reaches the destination back through the
// capture, as a target on this machine does in a full tunnel. The chain of
// connections grows to the cap, the next is refused, and it all unwinds:
// the app's connection ends instead of hanging.
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
	client = setupWith(t, map[string]func(net.Conn){"10.1.2.3:7": loop}, Options{DialTimeout: 5 * time.Second, MaxPerDestination: 8})

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
		t.Fatalf("loop went %d levels deep, want the cap (8)", n)
	}
}
