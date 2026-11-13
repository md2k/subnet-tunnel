// Package control is a running subtun's local API: one Unix socket per
// process in the private run directory, user-only (the peer's uid is
// checked too), JSON over HTTP under /v1/. `subtun status` and `subtun
// logs` use it, and later a terminal or web UI. It lives in the user
// process, never in the root helper.
package control

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/md2k/subnet-tunnel/internal/logring"
	"github.com/md2k/subnet-tunnel/internal/meter"
)

// Status is a running subtun.
type Status struct {
	PID        int         `json:"pid"`
	Version    string      `json:"version"`
	Started    time.Time   `json:"started"`
	Control    string      `json:"control"`        // status (full: later)
	Utun       string      `json:"utun,omitempty"` // empty: no capture (yet)
	TunAddr    string      `json:"tunAddr,omitempty"`
	Helper     string      `json:"helper,omitempty"` // one-shot, session
	Tunnels    []Tunnel    `json:"tunnels"`
	DNS        *DNS        `json:"dns,omitempty"`
	KillSwitch *KillSwitch `json:"killSwitch,omitempty"`
	BlockIPv6  bool        `json:"blockIPv6,omitempty"`
}

// Tunnel is one profile's tunnel.
type Tunnel struct {
	Name       string       `json:"name"` // empty: one profile from the command line
	Target     string       `json:"target,omitempty"`
	Agent      string       `json:"agent,omitempty"`
	State      string       `json:"state"` // connecting, up, reconnecting, gave up
	Since      time.Time    `json:"since"`
	Attempt    int          `json:"attempt,omitempty"` // while reconnecting
	Attempts   int          `json:"attempts,omitempty"`
	NextTry    time.Time    `json:"nextTry,omitzero"`
	LastError  string       `json:"lastError,omitempty"`
	Routes     []string     `json:"routes,omitempty"`
	RoutesOn   bool         `json:"routesOn"` // on the utun now
	Domains    []string     `json:"domains,omitempty"`
	Patterns   int          `json:"patterns,omitempty"`
	SOCKS      string       `json:"socks,omitempty"`
	KillSwitch string       `json:"killSwitch,omitempty"`
	Counts     meter.Counts `json:"counts"`
	DNSCounts  DNSCounts    `json:"dnsCounts"`
}

// DNSCounts are the names a tunnel (or the fallback) answered.
type DNSCounts struct {
	Answered uint64 `json:"answered"`
	Failed   uint64 `json:"failed"`
}

// DNS is the shared DNS capture.
type DNS struct {
	Servers  []string  `json:"servers"`
	Follow   bool      `json:"followSystem"`
	Fallback []string  `json:"fallback"`
	Local    []string  `json:"stayLocal,omitempty"`
	Own      []string  `json:"ownNames,omitempty"`
	Counts   DNSCounts `json:"fallbackCounts"`
}

// KillSwitch is the shared kill switch.
type KillSwitch struct {
	Mode     string `json:"mode"`
	Guarded  int    `json:"guardedPrefixes"`
	Lockdown int    `json:"lockdownPrefixes"`
	DNS      string `json:"dnsWhileHolding"` // blocked, allowed
}

// TunnelConns are one tunnel's open connections.
type TunnelConns struct {
	Name  string           `json:"name"`
	Conns []meter.ConnInfo `json:"conns"`
}

// Server answers the API.
type Server struct {
	Status func() Status
	Conns  func() []TunnelConns
	Logs   *logring.Ring
	Log    *slog.Logger
}

// Handler returns the API's routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/status", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, s.Status()) })
	mux.HandleFunc("GET /v1/connections", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, s.Conns()) })
	mux.HandleFunc("GET /v1/logs", s.logs)
	return mux
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

// logs returns the ring buffer as newline-delimited JSON; with ?follow=1
// it then streams new lines until the client goes away.
func (s *Server) logs(w http.ResponseWriter, r *http.Request) {
	follow := r.URL.Query().Get("follow") == "1"
	var ch <-chan logring.Line
	if follow {
		var stop func()
		ch, stop = s.Logs.Subscribe(256)
		defer stop()
	}
	w.Header().Set("Content-Type", "application/x-ndjson")
	enc := json.NewEncoder(w)
	for _, l := range s.Logs.Lines() {
		if enc.Encode(l) != nil {
			return
		}
	}
	if !follow {
		return
	}
	fl, _ := w.(http.Flusher)
	if fl != nil {
		fl.Flush()
	}
	for {
		select {
		case <-r.Context().Done():
			return
		case l := <-ch:
			if enc.Encode(l) != nil {
				return
			}
			if fl != nil {
				fl.Flush()
			}
		}
	}
}

// SocketName is a process's socket in the run directory.
func SocketName(pid int) string { return fmt.Sprintf("control-%d.sock", pid) }

// Listen creates this process's control socket in dir (the private run
// directory), owner-only.
func Listen(dir string) (net.Listener, string, error) {
	path := filepath.Join(dir, SocketName(os.Getpid()))
	_ = os.Remove(path)
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, "", err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = ln.Close()
		return nil, "", err
	}
	return ownerOnly{ln}, path, nil
}

// Serve answers on ln until ctx ends, then removes the socket.
func (s *Server) Serve(ctx context.Context, ln net.Listener, path string) error {
	srv := &http.Server{Handler: s.Handler(), ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	err := srv.Serve(ln)
	_ = os.Remove(path)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// ownerOnly refuses connections from other users (defence in depth: the
// directory and the socket are already the owner's only).
type ownerOnly struct{ net.Listener }

func (o ownerOnly) Accept() (net.Conn, error) {
	for {
		c, err := o.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if uc, ok := c.(*net.UnixConn); ok && !peerIsMe(uc) {
			_ = c.Close()
			continue
		}
		return c, nil
	}
}

// RunDir is the private run directory (the root helper's sockets and the
// control sockets): created 0700, and refused unless it is ours alone.
func RunDir() (string, error) {
	base, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(base, "subtun", "run")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return "", err
	}
	if err := ownedByMe(dir); err != nil {
		return "", err
	}
	return dir, nil
}

// Instance is a running subtun's control socket.
type Instance struct {
	PID  int
	Path string
}

// Running finds the control sockets in dir whose process answers;
// sockets of processes that are gone are removed.
func Running(dir string) ([]Instance, error) {
	names, err := filepath.Glob(filepath.Join(dir, "control-*.sock"))
	if err != nil {
		return nil, err
	}
	var out []Instance
	for _, path := range names {
		base := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(path), "control-"), ".sock")
		pid, err := strconv.Atoi(base)
		if err != nil {
			continue
		}
		c, err := net.DialTimeout("unix", path, time.Second)
		if err != nil {
			if !alive(pid) {
				_ = os.Remove(path)
			}
			continue
		}
		_ = c.Close()
		out = append(out, Instance{PID: pid, Path: path})
	}
	slices.SortFunc(out, func(a, b Instance) int { return a.PID - b.PID })
	return out, nil
}

func alive(pid int) bool {
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return p.Signal(syscall.Signal(0)) == nil
}

// Client talks to one instance.
type Client struct {
	hc *http.Client
}

// NewClient returns a client for the socket at path.
func NewClient(path string) *Client {
	tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", path)
	}}
	return &Client{hc: &http.Client{Transport: tr}}
}

// Get decodes the JSON at endpoint (e.g. /v1/status) into v.
func (c *Client) Get(ctx context.Context, endpoint string, v any) error {
	resp, err := c.get(ctx, endpoint)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return json.NewDecoder(resp.Body).Decode(v)
}

// Stream calls fn with each line of a newline-delimited JSON endpoint until
// it ends, ctx ends or fn fails.
func (c *Client) Stream(ctx context.Context, endpoint string, fn func([]byte) error) error {
	resp, err := c.get(ctx, endpoint)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		if err := fn(sc.Bytes()); err != nil {
			return err
		}
	}
	if err := sc.Err(); err != nil && ctx.Err() == nil && !errors.Is(err, io.ErrUnexpectedEOF) {
		return err
	}
	return nil
}

func (c *Client) get(ctx context.Context, endpoint string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://subtun"+endpoint, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("%s: %s", endpoint, resp.Status)
	}
	return resp, nil
}
