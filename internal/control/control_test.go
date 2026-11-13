package control

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/md2k/subnet-tunnel/internal/logring"
	"github.com/md2k/subnet-tunnel/internal/meter"
)

func testServer() *Server {
	ring := logring.New(0, 0)
	ring.Add(logring.Line{Text: "line 1"})
	ring.Add(logring.Line{Text: "line 2"})
	return &Server{
		Status: func() Status {
			return Status{PID: 42, Control: "status", Tunnels: []Tunnel{{Name: "work", State: "up", Counts: meter.Counts{Open: 3}}}}
		},
		Conns: func() []TunnelConns {
			return []TunnelConns{{Name: "work", Conns: []meter.ConnInfo{{Dst: "10.0.0.1:443", Via: meter.ViaUtun}}}}
		},
		Logs: ring,
	}
}

// handlerTransport answers requests with a handler: no sockets.
type handlerTransport struct{ h http.Handler }

func (t handlerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	rec := httptest.NewRecorder()
	t.h.ServeHTTP(rec, r)
	return rec.Result(), nil
}

func TestAPI(t *testing.T) {
	c := &Client{hc: &http.Client{Transport: handlerTransport{testServer().Handler()}}}
	var st Status
	if err := c.Get(context.Background(), "/v1/status", &st); err != nil {
		t.Fatal(err)
	}
	if st.PID != 42 || len(st.Tunnels) != 1 || st.Tunnels[0].Counts.Open != 3 {
		t.Fatalf("status: %+v", st)
	}
	var conns []TunnelConns
	if err := c.Get(context.Background(), "/v1/connections", &conns); err != nil || len(conns) != 1 || conns[0].Conns[0].Dst != "10.0.0.1:443" {
		t.Fatalf("connections: %+v %v", conns, err)
	}
	var lines []string
	err := c.Stream(context.Background(), "/v1/logs", func(b []byte) error {
		var l logring.Line
		if err := json.Unmarshal(b, &l); err != nil {
			return err
		}
		lines = append(lines, l.Text)
		return nil
	})
	if err != nil || strings.Join(lines, ",") != "line 1,line 2" {
		t.Fatalf("logs: %v %v", lines, err)
	}
	if err := c.Get(context.Background(), "/v1/nope", &st); err == nil {
		t.Fatal("unknown endpoint worked")
	}
}

// streamRecorder records a streaming response, safe to read meanwhile.
type streamRecorder struct {
	mu    sync.Mutex
	body  strings.Builder
	hdr   http.Header
	wrote chan struct{}
}

func (s *streamRecorder) Header() http.Header { return s.hdr }
func (s *streamRecorder) WriteHeader(int)     {}
func (s *streamRecorder) Flush()              {}
func (s *streamRecorder) Write(p []byte) (int, error) {
	s.mu.Lock()
	n, err := s.body.Write(p)
	s.mu.Unlock()
	select {
	case s.wrote <- struct{}{}:
	default:
	}
	return n, err
}

func (s *streamRecorder) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.body.String()
}

// With ?follow=1 the log lines held come first, then new ones, until the
// client goes away.
func TestLogsFollow(t *testing.T) {
	s := testServer()
	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest("GET", "/v1/logs?follow=1", nil).WithContext(ctx)
	rec := &streamRecorder{hdr: http.Header{}, wrote: make(chan struct{}, 16)}
	done := make(chan struct{})
	go func() { s.Handler().ServeHTTP(rec, req); close(done) }()
	deadline := time.After(5 * time.Second)
	for !strings.Contains(rec.String(), "line 2") {
		select {
		case <-rec.wrote:
		case <-deadline:
			t.Fatal("held lines not sent")
		}
	}
	time.Sleep(20 * time.Millisecond) // the handler is subscribed by now
	s.Logs.Add(logring.Line{Text: "line 3"})
	for !strings.Contains(rec.String(), "line 3") {
		select {
		case <-rec.wrote:
		case <-deadline:
			t.Fatal("new line not streamed")
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("stream didn't end with the client")
	}
}

// Sockets whose process is gone are removed; other files are left alone.
func TestRunningRemovesStale(t *testing.T) {
	dir := t.TempDir()
	stale := filepath.Join(dir, SocketName(999999))
	other := filepath.Join(dir, "helper-1.sock")
	for _, p := range []string{stale, other} {
		if err := os.WriteFile(p, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	got, err := Running(dir)
	if err != nil || len(got) != 0 {
		t.Fatalf("running: %v %v", got, err)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Error("stale socket left")
	}
	if _, err := os.Stat(other); err != nil {
		t.Error("another file removed")
	}
}

func TestOwnedByMe(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := ownedByMe(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := ownedByMe(dir); err == nil {
		t.Fatal("a directory others can read was accepted")
	}
}

// Changes go to the Change function with their kind; a read-only run and
// a refused change answer with the reason.
func TestChange(t *testing.T) {
	srv := testServer()
	c := &Client{hc: &http.Client{Transport: handlerTransport{srv.Handler()}}}
	var res Result
	err := c.Post(context.Background(), "/v1/routes", Change{Op: "add", CIDRs: []string{"10.9.0.0/16"}}, &res)
	if err == nil || !strings.Contains(err.Error(), "read only (control: status)") {
		t.Fatalf("read only: %v", err)
	}
	var got []Change
	srv.Change = func(_ context.Context, ch Change) (Result, error) {
		got = append(got, ch)
		if ch.Profile == "nope" {
			return Result{}, errors.New(`no profile "nope" in this run`)
		}
		return Result{Profile: ch.Profile, Changed: true, Message: "done"}, nil
	}
	c = &Client{hc: &http.Client{Transport: handlerTransport{srv.Handler()}}}
	for endpoint, kind := range map[string]string{"/v1/routes": KindRoute, "/v1/dns": KindDNS, "/v1/profiles": KindProfile} {
		got = nil
		// The kind comes from the endpoint, whatever the body says.
		if err := c.Post(context.Background(), endpoint, Change{Kind: "other", Op: "x", Profile: "work"}, &res); err != nil {
			t.Fatalf("%s: %v", endpoint, err)
		}
		if len(got) != 1 || got[0].Kind != kind || got[0].Profile != "work" || !res.Changed || res.Message != "done" {
			t.Errorf("%s: %+v %+v", endpoint, got, res)
		}
	}
	if err := c.Post(context.Background(), "/v1/dns", Change{Op: "add", Profile: "nope"}, &res); err == nil || err.Error() != `no profile "nope" in this run` {
		t.Errorf("refused: %v", err)
	}
	// Unknown fields and other methods are refused.
	if err := c.Post(context.Background(), "/v1/routes", map[string]any{"op": "add", "cidr": "10.0.0.0/8"}, &res); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Errorf("unknown field: %v", err)
	}
	if err := c.Get(context.Background(), "/v1/routes", &res); err == nil {
		t.Error("GET on a change endpoint worked")
	}
}
