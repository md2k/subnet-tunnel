package tunnel_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/md2k/subnet-tunnel/internal/agent"
	"github.com/md2k/subnet-tunnel/internal/proto"
	"github.com/md2k/subnet-tunnel/internal/testutil"
	"github.com/md2k/subnet-tunnel/internal/tunnel"
)

// fakeNet hands the agent in-memory connections instead of real sockets.
// Each dial to a known address starts that address's handler on the far end.
type fakeNet struct {
	mu       sync.Mutex
	handlers map[string]func(net.Conn)
	dialed   []string
}

// DialContext keys handlers by address, and by "udp/" + address for UDP.
func (f *fakeNet) DialContext(_ context.Context, network, addr string) (net.Conn, error) {
	if strings.HasPrefix(network, "udp") {
		addr = "udp/" + addr
	}
	f.mu.Lock()
	f.dialed = append(f.dialed, addr)
	h, ok := f.handlers[addr]
	f.mu.Unlock()
	if !ok {
		return nil, &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}
	}
	local, remote := testutil.Pair()
	go h(remote)
	return local, nil
}

func echo(c net.Conn) {
	defer c.Close()
	_, _ = io.Copy(c, c)
}

// startSession wires a tunnel client to an agent over an in-memory carrier.
func startSession(t *testing.T, fn *fakeNet, opts tunnel.Options, agentSum string) (*tunnel.Client, error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	clientEnd, agentEnd := testutil.Pair()
	done := make(chan error, 1)
	go func() {
		done <- agent.Serve(ctx, agentEnd, agent.Config{Version: "test", SHA256: agentSum, Dialer: fn, ResolvConf: "testdata/resolv.conf"})
	}()
	t.Cleanup(func() {
		cancel()
		_ = clientEnd.Close()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("agent.Serve: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("agent did not stop")
		}
	})
	hctx, hcancel := context.WithTimeout(ctx, 5*time.Second)
	defer hcancel()
	return tunnel.NewClient(hctx, clientEnd, opts)
}

func TestDialEcho(t *testing.T) {
	fn := &fakeNet{handlers: map[string]func(net.Conn){"echo.svc:7": echo}}
	c, err := startSession(t, fn, tunnel.Options{ExpectSHA256: "beef"}, "beef")
	if err != nil {
		t.Fatal(err)
	}
	if c.Agent().Version != "test" {
		t.Fatalf("agent version %q", c.Agent().Version)
	}

	// Several streams at once, each with more data than one smux frame.
	payload := bytes.Repeat([]byte("0123456789abcdef"), 64<<10) // 1 MiB
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := c.DialContext(context.Background(), "tcp", "echo.svc:7")
			if err != nil {
				t.Error(err)
				return
			}
			defer conn.Close()
			go func() { _, _ = conn.Write(payload) }()
			got := make([]byte, len(payload))
			if _, err := io.ReadFull(conn, got); err != nil {
				t.Error(err)
				return
			}
			if !bytes.Equal(got, payload) {
				t.Error("echo mismatch")
			}
		}()
	}
	wg.Wait()
}

func TestHalfClosePassesThrough(t *testing.T) {
	// Server reads until EOF, then answers: only works if the client's
	// CloseWrite reaches it while the reverse direction stays open.
	reply := func(c net.Conn) {
		defer c.Close()
		got, _ := io.ReadAll(c)
		_, _ = c.Write(append([]byte("got:"), got...))
	}
	fn := &fakeNet{handlers: map[string]func(net.Conn){"rr.svc:80": reply}}
	c, err := startSession(t, fn, tunnel.Options{}, "")
	if err != nil {
		t.Fatal(err)
	}
	conn, err := c.DialContext(context.Background(), "tcp", "rr.svc:80")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	if err := conn.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
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

func TestDialErrorFromAgent(t *testing.T) {
	fn := &fakeNet{}
	c, err := startSession(t, fn, tunnel.Options{}, "")
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.DialContext(context.Background(), "tcp", "nothing.svc:1")
	var de *proto.DialError
	if !errors.As(err, &de) || de.Status != proto.StatusRefused {
		t.Fatalf("got %v, want refused DialError", err)
	}
	if _, err := c.DialContext(context.Background(), "udp", "x:1"); err == nil {
		t.Fatal("udp accepted")
	}
}

func TestChecksumMismatch(t *testing.T) {
	_, err := startSession(t, &fakeNet{}, tunnel.Options{ExpectSHA256: "aaaa"}, "bbbb")
	if err == nil {
		t.Fatal("mismatched agent accepted")
	}
}

func TestHelloTimeout(t *testing.T) {
	clientEnd, _ := testutil.Pair() // nobody answers
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := tunnel.NewClient(ctx, clientEnd, tunnel.Options{}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v, want deadline exceeded", err)
	}
}

func TestAgentEndsCleanlyWhenClientLeaves(t *testing.T) {
	clientEnd, agentEnd := testutil.Pair()
	done := make(chan error, 1)
	go func() { done <- agent.Serve(context.Background(), agentEnd, agent.Config{Version: "test"}) }()
	c, err := tunnel.NewClient(context.Background(), clientEnd, tunnel.Options{})
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	_ = clientEnd.Close() // what exec does when subtun exits: agent stdin hits EOF
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("agent.Serve returned %v, want nil on EOF", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("agent did not stop on EOF")
	}
}

func TestDoneOnCarrierLoss(t *testing.T) {
	clientEnd, agentEnd := testutil.Pair()
	go func() { _ = agent.Serve(context.Background(), agentEnd, agent.Config{Version: "test"}) }()
	c, err := tunnel.NewClient(context.Background(), clientEnd, tunnel.Options{})
	if err != nil {
		t.Fatal(err)
	}
	_ = agentEnd.Close()
	select {
	case <-c.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("Done not closed after carrier loss")
	}
}
