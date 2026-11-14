package cli

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/md2k/subnet-tunnel/internal/agentbin"
	"github.com/md2k/subnet-tunnel/internal/transport"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

// --max-duration also covers connecting: a connect that never finishes
// ends with a clear error. DNS on a dev listener needs no routes, so this
// run can't reach sudo, and nothing listens before connecting.
func TestMaxDurationWhileConnecting(t *testing.T) {
	orig := systemDNS
	systemDNS = func() ([]netip.Addr, []string, error) {
		return []netip.Addr{netip.MustParseAddr("192.0.2.53")}, nil, nil
	}
	t.Cleanup(func() { systemDNS = orig })

	s := settings{dnsListen: "127.0.0.1:15353", dnsDomains: []string{"example.com"}, agent: transport.AgentAuto,
		maxDuration:       50 * time.Millisecond,
		reconnectAttempts: defaultReconnectAttempts, reconnectDelay: defaultReconnectDelay, reconnectMaxDelay: defaultReconnectMaxDelay}
	connect := func(ctx context.Context, _ []agentbin.Binary, _ *slog.Logger) (*transport.Carrier, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	start := time.Now()
	err := run(context.Background(), io.Discard, &globalOpts{}, &tunnelSpec{s: s, connect: connect})
	if err == nil || !strings.Contains(err.Error(), "--max-duration reached before the tunnel was up") {
		t.Fatalf("got %v", err)
	}
	if took := time.Since(start); took > 5*time.Second {
		t.Fatalf("took %v", took)
	}
}

func TestMaxDurationNegative(t *testing.T) {
	_, err := runCLI(t, "up", "--k8s", "10.0.0.0/8", "--dry-run", "--max-duration", "-1s")
	if err == nil || !strings.Contains(err.Error(), "must be positive") {
		t.Fatalf("got %v", err)
	}
}

func TestMaxDurationWatchdog(t *testing.T) {
	origGrace, origExit := stopGrace, hardExit
	t.Cleanup(func() { stopGrace, hardExit = origGrace, origExit })
	stopGrace = 20 * time.Millisecond
	exited := make(chan int, 1)
	hardExit = func(code int) { exited <- code }

	// Stopping hangs: the watchdog exits the process.
	ctx, _ := withMaxDuration(context.Background(), 10*time.Millisecond, quiet)
	<-ctx.Done()
	if !maxDurationReached(ctx) {
		t.Fatalf("cause %v", context.Cause(ctx))
	}
	select {
	case code := <-exited:
		if code != 3 {
			t.Fatalf("exit code %d", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no hard exit")
	}

	// Stopped in time: no exit.
	ctx, done := withMaxDuration(context.Background(), 10*time.Millisecond, quiet)
	<-ctx.Done()
	done()
	select {
	case <-exited:
		t.Fatal("exited although stopping finished")
	case <-time.After(100 * time.Millisecond):
	}

	// A signal before the deadline isn't --max-duration.
	parent, cancel := context.WithCancel(context.Background())
	ctx, done = withMaxDuration(parent, time.Hour, quiet)
	cancel()
	<-ctx.Done()
	done()
	if maxDurationReached(ctx) {
		t.Fatal("cancel reported as --max-duration")
	}

	// Off: the context is returned as is.
	if ctx, _ := withMaxDuration(context.Background(), 0, quiet); ctx != context.Background() {
		t.Fatal("zero duration wrapped the context")
	}
}
