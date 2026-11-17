package netstack

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"

	"github.com/md2k/subnet-tunnel/internal/testutil"
)

const testMTU = 9000

// memDevice is the capture side of an in-memory "wire" to a client stack:
// what the client stack sends arrives on in, what we write is injected into
// the client stack.
type memDevice struct {
	in     chan []byte
	client *channel.Endpoint
	closed chan struct{}
	once   sync.Once
}

func (d *memDevice) Headroom() int { return 0 }
func (d *memDevice) MTU() int      { return testMTU }

func (d *memDevice) Read(buf []byte) (int, error) {
	select {
	case p := <-d.in:
		return copy(buf, p), nil
	case <-d.closed:
		return 0, net.ErrClosed
	}
}

func (d *memDevice) Write(buf []byte) error {
	pb := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(append([]byte(nil), buf...))})
	d.client.InjectInbound(header.IPv4ProtocolNumber, pb)
	pb.DecRef()
	return nil
}

func (d *memDevice) Close() error {
	d.once.Do(func() { close(d.closed) })
	return nil
}

// fakeTunnel stands in for tunnel.Client: in-memory connections per address.
type fakeTunnel struct{ handlers map[string]func(net.Conn) }

func (f fakeTunnel) DialContext(_ context.Context, _, addr string) (net.Conn, error) {
	h, ok := f.handlers[addr]
	if !ok {
		return nil, &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}
	}
	local, remote := testutil.Pair()
	go h(remote)
	return local, nil
}

// setup returns a client stack ("the app on the laptop", 198.18.249.1) whose
// packets go through our capture Stack and on to the fake tunnel.
func setup(t *testing.T, handlers map[string]func(net.Conn)) *stack.Stack {
	t.Helper()
	return setupWith(t, handlers, Options{DialTimeout: 5 * time.Second})
}

func setupWith(t *testing.T, handlers map[string]func(net.Conn), opts Options) *stack.Stack {
	t.Helper()
	return setupDialer(t, fakeTunnel{handlers}, opts)
}

func setupDialer(t *testing.T, dialer Dialer, opts Options) *stack.Stack {
	t.Helper()
	client := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	cep := channel.New(outQueueLen, testMTU, "")
	if err := client.CreateNIC(1, cep); err != nil {
		t.Fatal(err)
	}
	addr := tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber, AddressWithPrefix: tcpip.AddrFrom4([4]byte{198, 18, 249, 1}).WithPrefix()}
	if err := client.AddProtocolAddress(1, addr, stack.AddressProperties{}); err != nil {
		t.Fatal(err)
	}
	client.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})

	dev := &memDevice{in: make(chan []byte, outQueueLen), client: cep, closed: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { // client stack -> capture device
		for {
			pb := cep.ReadContext(ctx)
			if pb == nil {
				return
			}
			v := pb.ToView()
			pkt := append([]byte(nil), v.AsSlice()...)
			v.Release()
			pb.DecRef()
			select {
			case dev.in <- pkt:
			case <-ctx.Done():
				return
			}
		}
	}()

	st, err := New(dev, dialer, opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		if err := st.Close(); err != nil {
			t.Error(err)
		}
		cep.Close()
		client.Close()
	})
	return client
}

func dial(t *testing.T, client *stack.Stack, port uint16) (*gonet.TCPConn, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return gonet.DialContextTCP(ctx, client, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4([4]byte{10, 1, 2, 3}), Port: port}, ipv4.ProtocolNumber)
}

func echo(c net.Conn) {
	defer c.Close()
	_, _ = io.Copy(c, c)
}

func TestCapturedConnectionReachesTunnel(t *testing.T) {
	client := setup(t, map[string]func(net.Conn){"10.1.2.3:7": echo})
	conn, err := dial(t, client, 7)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	payload := bytes.Repeat([]byte("subtun"), 200_000) // 1.2 MB, many segments
	go func() { _, _ = conn.Write(payload) }()
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("echo mismatch")
	}
}

func TestHalfCloseThroughStack(t *testing.T) {
	reply := func(c net.Conn) {
		defer c.Close()
		b, _ := io.ReadAll(c)
		_, _ = c.Write(append([]byte("got:"), b...))
	}
	client := setup(t, map[string]func(net.Conn){"10.1.2.3:80": reply})
	conn, err := dial(t, client, 80)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	if err := conn.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "got:ping" {
		t.Fatalf("got %q", got)
	}
}

func TestUnreachableDestinationIsRefused(t *testing.T) {
	client := setup(t, nil)
	start := time.Now()
	_, err := dial(t, client, 9)
	if err == nil {
		t.Fatal("connection accepted although the tunnel refused it")
	}
	var oe *net.OpError
	if !errors.As(err, &oe) || time.Since(start) > 3*time.Second {
		t.Fatalf("got %v after %v, want a prompt refusal", err, time.Since(start))
	}
}

// udpEcho answers each datagram with "re:" + it.
func udpEcho(c net.Conn) {
	defer c.Close()
	buf := make([]byte, 65535)
	for {
		n, err := c.Read(buf)
		if err != nil {
			return
		}
		if _, err := c.Write(append([]byte("re:"), buf[:n]...)); err != nil {
			return
		}
	}
}

// An application's UDP datagrams become a flow through the tunnel, the
// answers come back from the destination's address, and the flow closes
// once idle; the next datagram opens a new one.
func TestUDPFlowThroughStack(t *testing.T) {
	var ended sync.WaitGroup
	var opened atomic.Int32
	handler := func(c net.Conn) {
		opened.Add(1)
		udpEcho(c)
		ended.Done()
	}
	ended.Add(2)
	client := setupWith(t, map[string]func(net.Conn){"10.1.2.3:53": handler}, Options{DialTimeout: 5 * time.Second, UDPIdle: 300 * time.Millisecond})
	conn, err := gonet.DialUDP(client, nil, &tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4([4]byte{10, 1, 2, 3}), Port: 53}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, 65535)
	exchange := func(d string) {
		t.Helper()
		if _, err := conn.Write([]byte(d)); err != nil {
			t.Fatal(err)
		}
		n, err := conn.Read(buf)
		if err != nil || string(buf[:n]) != "re:"+d {
			t.Fatalf("%q: got %q %v", d, buf[:n], err)
		}
	}
	exchange("query")
	exchange("")
	exchange(strings.Repeat("big", 2500)) // 7.5 KB, under the 9000 MTU
	time.Sleep(800 * time.Millisecond)    // idle: the flow closes
	exchange("again")                     // a new flow
	if n := opened.Load(); n != 2 {
		t.Errorf("%d flows opened, want 2 (one closed when idle)", n)
	}
	time.Sleep(800 * time.Millisecond)
	done := make(chan struct{})
	go func() { ended.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Error("an idle flow wasn't closed")
	}
}
