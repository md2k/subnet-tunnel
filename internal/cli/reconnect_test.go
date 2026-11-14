package cli

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestReconnectPolicyWait(t *testing.T) {
	p := reconnectPolicy{attempts: 10, delay: time.Second, maxDelay: time.Minute}
	mid := func() float64 { return 0.5 } // no jitter
	var got []time.Duration
	for n := 1; n <= 8; n++ {
		got = append(got, p.wait(n, mid))
	}
	want := []time.Duration{1, 2, 4, 8, 16, 32, 60, 60}
	for i := range want {
		want[i] *= time.Second
	}
	if !slices.Equal(got, want) {
		t.Fatalf("waits %v, want %v", got, want)
	}
	// Jitter stays within ±20 %.
	if lo, hi := p.wait(3, func() float64 { return 0 }), p.wait(3, func() float64 { return 0.999999 }); lo != 3200*time.Millisecond || hi < 4790*time.Millisecond || hi > 4800*time.Millisecond {
		t.Fatalf("jitter range %v..%v", lo, hi)
	}
}

func TestReconnectPolicyValidate(t *testing.T) {
	for _, p := range []reconnectPolicy{
		{attempts: -1, delay: time.Second, maxDelay: time.Minute},
		{attempts: 3, delay: 0, maxDelay: time.Minute},
		{attempts: 3, delay: time.Minute, maxDelay: time.Second},
	} {
		if p.validate() == nil {
			t.Errorf("%+v accepted", p)
		}
	}
	if err := (reconnectPolicy{attempts: 0, delay: time.Second, maxDelay: time.Second}).validate(); err != nil {
		t.Errorf("attempts 0 (off) refused: %v", err)
	}
}

func TestReconnectLoop(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	p := reconnectPolicy{attempts: 4, delay: time.Millisecond, maxDelay: 4 * time.Millisecond}
	ok := &session{}

	// Fails twice, then works.
	calls := 0
	try := func(context.Context) (*session, error) {
		calls++
		if calls < 3 {
			return nil, errors.New("pod not ready")
		}
		return ok, nil
	}
	s, err := reconnect(context.Background(), p, nil, try, log, nil)
	if err != nil || s != ok || calls != 3 {
		t.Fatalf("got %v, %v after %d calls", s, err, calls)
	}

	// Never works: gives up after the attempts.
	calls = 0
	never := func(context.Context) (*session, error) { calls++; return nil, errors.New("gone") }
	if _, err := reconnect(context.Background(), p, nil, never, log, nil); err == nil || calls != 4 || !strings.Contains(err.Error(), "gave up after 4") {
		t.Fatalf("got %v after %d calls", err, calls)
	}

	// Ctrl-C or the helper going away end it early.
	slow := reconnectPolicy{attempts: 4, delay: time.Hour, maxDelay: time.Hour}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := reconnect(ctx, slow, nil, never, log, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled: %v", err)
	}
	stop := make(chan struct{})
	close(stop)
	if _, err := reconnect(context.Background(), slow, stop, never, log, nil); !errors.Is(err, errHelperGone) {
		t.Fatalf("helper gone: %v", err)
	}
}

// While reconnecting, dials and DNS fail at once.
func TestLiveTunnelWithoutClient(t *testing.T) {
	var l liveTunnel
	if _, err := l.DialContext(context.Background(), "tcp", "10.0.0.1:80"); !errors.Is(err, errReconnecting) {
		t.Fatalf("dial: %v", err)
	}
	if _, err := l.ExchangeDNS(context.Background(), nil); !errors.Is(err, errReconnecting) {
		t.Fatalf("dns: %v", err)
	}
}

func TestReconnectSettings(t *testing.T) {
	out, err := runCLI(t, "up", "--k8s", "debug", "--socks", "127.0.0.1:1080", "--dry-run")
	if err != nil || !strings.Contains(out, "reconnect: up to 10 attempts, waiting 1s, then twice as long each time, at most 1m0s") {
		t.Fatalf("default: %v\n%s", err, out)
	}
	out, err = runCLI(t, "up", "--k8s", "debug", "--socks", "127.0.0.1:1080", "--reconnect-attempts", "0", "--dry-run")
	if err != nil || !strings.Contains(out, "reconnect: off") {
		t.Fatalf("off: %v\n%s", err, out)
	}
	if _, err := runCLI(t, "up", "--k8s", "debug", "--socks", "127.0.0.1:1080", "--reconnect-delay", "2m", "--reconnect-max-delay", "1m", "--dry-run"); err == nil {
		t.Fatal("max delay below delay accepted")
	}
}
