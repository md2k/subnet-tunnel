//go:build !windows

package privhelper

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/md2k/subnet-tunnel/internal/platform/fake"
)

// startHelper runs the helper's command loop with fake drivers and returns
// subtun's end of the connection.
func startHelper(t *testing.T, ctx context.Context, d *fake.Drivers) (*net.UnixConn, <-chan error) {
	t.Helper()
	a, b := socketPair(t)
	h := &helper{conn: a, log: slog.New(slog.DiscardHandler), drivers: d.Platform()}
	done := make(chan error, 1)
	go func() { done <- h.loop(ctx) }()
	return b, done
}

func call(t *testing.T, c *net.UnixConn, req Request) Response {
	t.Helper()
	if err := writeMsg(c, req); err != nil {
		t.Fatal(err)
	}
	var resp Response
	files, err := readMsg(c, &resp, time.Now().Add(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	want := 0
	if req.Op == OpCreateTun && resp.OK {
		want = 1
	}
	if len(files) != want {
		t.Fatalf("%s: got %d descriptors, want %d", req.Op, len(files), want)
	}
	closeAll(files)
	return resp
}

func wait(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("helper loop did not return")
		return nil
	}
}

func checkCalls(t *testing.T, d *fake.Drivers, want ...string) {
	t.Helper()
	if got := d.Calls(); !slices.Equal(got, want) {
		t.Fatalf("driver calls:\n got %q\nwant %q", got, want)
	}
}

var (
	createReq = Request{Op: OpCreateTun, MTU: 9000, Addr: "198.18.249.1"}
	created   = "create utun0 9000 198.18.249.1"
)

func TestHelperSetup(t *testing.T) {
	d := &fake.Drivers{}
	c, done := startHelper(t, context.Background(), d)

	if r := call(t, c, createReq); !r.OK || r.Name != "utun0" {
		t.Fatalf("create_tun: %+v", r)
	}
	for _, cidr := range []string{"10.244.0.0/16", "10.96.0.10"} {
		if r := call(t, c, Request{Op: OpAddRoute, CIDR: cidr}); !r.OK {
			t.Fatalf("add_route %s: %+v", cidr, r)
		}
	}
	if r := call(t, c, Request{Op: OpDone}); !r.OK {
		t.Fatalf("done: %+v", r)
	}
	if err := wait(t, done); err != nil {
		t.Fatal(err)
	}
	// After done the helper only drops its own descriptor: the interface and
	// routes stay with subtun.
	checkCalls(t, d, created, "add 10.244.0.0/16 utun0", "add 10.96.0.10/32 utun0", "release utun0")
}

// subtun going away before done (crash, Ctrl-C at the wrong moment) makes the
// helper remove its routes, newest first, and destroy the interface.
func TestHelperUndoesWhenSubtunDisconnects(t *testing.T) {
	d := &fake.Drivers{}
	c, done := startHelper(t, context.Background(), d)
	call(t, c, createReq)
	call(t, c, Request{Op: OpAddRoute, CIDR: "10.244.0.0/16"})
	call(t, c, Request{Op: OpAddRoute, CIDR: "10.96.0.0/12"})
	_ = c.Close()

	if err := wait(t, done); err == nil || !strings.Contains(err.Error(), "changes undone") {
		t.Fatalf("got %v", err)
	}
	checkCalls(t, d, created, "add 10.244.0.0/16 utun0", "add 10.96.0.0/12 utun0",
		"delete 10.96.0.0/12 utun0", "delete 10.244.0.0/16 utun0", "close utun0")
}

func TestHelperUndoesWhenInterrupted(t *testing.T) {
	d := &fake.Drivers{}
	ctx, cancel := context.WithCancel(context.Background())
	c, done := startHelper(t, ctx, d)
	call(t, c, createReq)
	call(t, c, Request{Op: OpAddRoute, CIDR: "10.244.0.0/16"})
	cancel()

	if err := wait(t, done); err == nil {
		t.Fatal("loop returned nil after interrupt")
	}
	checkCalls(t, d, created, "add 10.244.0.0/16 utun0", "delete 10.244.0.0/16 utun0", "close utun0")
}

// Invalid commands are answered with an error and never reach a driver.
func TestHelperRefusesInvalidCommands(t *testing.T) {
	d := &fake.Drivers{}
	c, done := startHelper(t, context.Background(), d)

	refuse := func(req Request, want string) {
		t.Helper()
		r := call(t, c, req)
		if r.OK || !strings.Contains(r.Error, want) {
			t.Errorf("%+v: got %+v, want error containing %q", req, r, want)
		}
	}
	refuse(Request{Op: OpAddRoute, CIDR: "10.244.0.0/16"}, "create the utun first")
	refuse(Request{Op: OpCreateTun, MTU: 100, Addr: "198.18.249.1"}, "MTU")
	refuse(Request{Op: OpCreateTun, MTU: 9000, Addr: "127.0.0.1"}, "unicast IPv4")
	refuse(Request{Op: OpCreateTun, MTU: 9000, Addr: "utun0; rm"}, "utun address")
	call(t, c, createReq)
	refuse(createReq, "already created")
	refuse(Request{Op: OpAddRoute, CIDR: "0.0.0.0/0"}, "default route")
	refuse(Request{Op: OpAddRoute, CIDR: "10.244.1.0/16"}, "host bits")
	refuse(Request{Op: OpAddRoute, CIDR: "127.0.0.0/8"}, "loopback")
	refuse(Request{Op: OpAddRoute, CIDR: "10.0.0.0/8 -ifscope en0"}, "not an IP")
	refuse(Request{Op: "run", CIDR: "/bin/sh"}, "unknown op")

	_ = c.Close()
	wait(t, done)
	checkCalls(t, d, created, "close utun0")
}

// A failing driver call is reported, and only what succeeded is undone.
func TestHelperDriverFailures(t *testing.T) {
	bad := netip.MustParsePrefix("10.1.0.0/16")
	d := &fake.Drivers{AddErr: map[netip.Prefix]error{bad: errors.New("route: File exists")}}
	c, done := startHelper(t, context.Background(), d)
	call(t, c, createReq)
	call(t, c, Request{Op: OpAddRoute, CIDR: "10.244.0.0/16"})
	if r := call(t, c, Request{Op: OpAddRoute, CIDR: bad.String()}); r.OK || !strings.Contains(r.Error, "File exists") {
		t.Fatalf("got %+v", r)
	}
	_ = c.Close()
	wait(t, done)
	checkCalls(t, d, created, "add 10.244.0.0/16 utun0", "delete 10.244.0.0/16 utun0", "close utun0")

	d = &fake.Drivers{CreateErr: errors.New("creating utun: operation not permitted")}
	c, done = startHelper(t, context.Background(), d)
	if r := call(t, c, createReq); r.OK || !strings.Contains(r.Error, "not permitted") {
		t.Fatalf("got %+v", r)
	}
	_ = c.Close()
	wait(t, done)
	checkCalls(t, d)
}
