package agentpy_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/md2k/subnet-tunnel/internal/agentpy"
	"github.com/md2k/subnet-tunnel/internal/proto"
	"github.com/md2k/subnet-tunnel/internal/tunnel"
)

func TestSupported(t *testing.T) {
	for v, want := range map[string]bool{"3.6": true, "3.12": true, "4.0": true, "3.5": false, "2.7": false, "x": false, "3": false} {
		if got := agentpy.Supported(v); got != want {
			t.Errorf("Supported(%q) = %v, want %v", v, got, want)
		}
	}
}

func TestSourceVersion(t *testing.T) {
	if !bytes.Contains(agentpy.Source("v1.2.3"), []byte(`VERSION = "v1.2.3"`)) {
		t.Error("version not filled in")
	}
	if !bytes.Contains(agentpy.Source(`v1"; import os`), []byte(`VERSION = "dev"`)) {
		t.Error("unsafe version not replaced")
	}
}

// pipeCarrier is the python process's stdin/stdout.
type pipeCarrier struct {
	io.Reader
	io.WriteCloser
}

// lockedBuf is the agent's stderr, read while the agent runs.
type lockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// waitLine waits for a log line containing all of parts and returns it.
func (l *lockedBuf) waitLine(t *testing.T, parts ...string) string {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
	lines:
		for _, line := range strings.Split(l.String(), "\n") {
			for _, p := range parts {
				if !strings.Contains(line, p) {
					continue lines
				}
			}
			return line
		}
	}
	t.Fatalf("no log line with %q", parts) // the cleanup prints the log
	return ""
}

// startAgent runs the Python agent locally over pipes, with dial() and
// dns_connect() replaced by in-process socket pairs (testdata/fakenet.py),
// and connects a tunnel client to it. Skips if there is no suitable python3.
func startAgent(t *testing.T) *tunnel.Client {
	t.Helper()
	c, _ := startAgentLog(t)
	return c
}

// startAgentLog is startAgent with the agent's log (debug level).
func startAgentLog(t *testing.T) (*tunnel.Client, *lockedBuf) {
	t.Helper()
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not found")
	}
	out, err := exec.Command(python, "-c", agentpy.VersionProbe).Output()
	if err != nil || !agentpy.Supported(string(out)) {
		t.Skipf("python3 %q is too old or broken", strings.TrimSpace(string(out)))
	}
	shim, err := filepath.Abs("testdata/fakenet.py")
	if err != nil {
		t.Fatal(err)
	}
	resolvConf, err := filepath.Abs("testdata/resolv.conf")
	if err != nil {
		t.Fatal(err)
	}

	src := agentpy.Source("test")
	// Like agentpy.Command, but run as a module first so the shim can swap
	// dial() and dns_connect() and point RESOLV_CONF at testdata before
	// starting main().
	loader := fmt.Sprintf("import sys;_src=sys.stdin.buffer.read(%d);g={'__name__':'subtun_agent','_src':_src};"+
		"exec(compile(_src,'subtun-agent.py','exec'),g);g['RESOLV_CONF']=%q;"+
		"exec(compile(open(%q).read(),'fakenet.py','exec'),g)",
		len(src), resolvConf, shim)
	cmd := exec.Command(python, "-c", loader, "-v")
	stdin, _ := cmd.StdinPipe()
	stdout, _ := cmd.StdoutPipe()
	stderr := &lockedBuf{}
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = stdin.Close()
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = cmd.Process.Kill()
			t.Error("python agent did not exit on EOF")
		}
		if t.Failed() {
			t.Logf("agent stderr:\n%s", stderr.String())
		}
	})
	if _, err := stdin.Write(src); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(src)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := tunnel.NewClient(ctx, pipeCarrier{stdout, stdin}, tunnel.Options{ExpectSHA256: hex.EncodeToString(sum[:])})
	if err != nil {
		t.Fatalf("%v\nagent stderr:\n%s", err, stderr.String())
	}
	t.Cleanup(func() { _ = c.Close() })
	return c, stderr
}

func TestPythonAgentEcho(t *testing.T) {
	c := startAgent(t)
	if !strings.HasPrefix(c.Agent().Version, "test+py3.") {
		t.Fatalf("agent version %q", c.Agent().Version)
	}
	// Four 1 MiB streams in parallel and one 9 MiB stream: well past both the
	// initial 256 KiB window and the 4 MiB stream window, in both directions.
	sizes := []int{1 << 20, 1 << 20, 1 << 20, 1 << 20, 9 << 20}
	var wg sync.WaitGroup
	for i, size := range sizes {
		wg.Add(1)
		go func() {
			defer wg.Done()
			payload := bytes.Repeat([]byte{byte('a' + i)}, size)
			conn, err := c.DialContext(context.Background(), "tcp", "echo.svc:7")
			if err != nil {
				t.Error(err)
				return
			}
			defer conn.Close()
			go func() { _, _ = conn.Write(payload) }()
			got := make([]byte, size)
			if _, err := io.ReadFull(conn, got); err != nil {
				t.Errorf("stream %d: %v", i, err)
				return
			}
			if !bytes.Equal(got, payload) {
				t.Errorf("stream %d: echo mismatch", i)
			}
		}()
	}
	wg.Wait()
}

// A TCP connection's closing line has each direction's bytes, writes and
// time spent waiting to write.
func TestPythonAgentRelayStats(t *testing.T) {
	c, logs := startAgentLog(t)
	conn, err := c.DialContext(context.Background(), "tcp", "echo.svc:7")
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("x"), 100000)
	go func() {
		_, _ = conn.Write(payload)
		_ = conn.(interface{ CloseWrite() error }).CloseWrite()
	}()
	if got, err := io.ReadAll(conn); err != nil || len(got) != len(payload) {
		t.Fatalf("echo: %d bytes, %v", len(got), err)
	}
	_ = conn.Close()
	logs.waitLine(t, "msg=closed", "up=100000", "up_writes=", "up_wait=", "up_read=", "down=100000", "down_writes=", "down_wait=", "down_read=")
}

// The Python agent reads at most a smux frame's worth from a socket, so each
// read goes out as one frame (reading 65536 bytes made a 65535-byte frame and
// a 1-byte one). A stream Read returns one frame's data at most.
func TestPythonAgentWholeFrames(t *testing.T) {
	c := startAgent(t)
	conn, err := c.DialContext(context.Background(), "tcp", "blob.svc:80")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, 1<<20)
	total, tiny, largest := 0, 0, 0
	for {
		n, err := conn.Read(buf)
		total += n
		if n == 1 {
			tiny++
		}
		largest = max(largest, n)
		if err != nil {
			break
		}
	}
	if total != 1<<20 {
		t.Fatalf("got %d bytes, want 1 MiB", total)
	}
	if tiny > 0 || largest > 65535 {
		t.Errorf("%d one-byte frames, the largest %d bytes: reads split across frames", tiny, largest)
	}
}

func TestPythonAgentHalfClose(t *testing.T) {
	c := startAgent(t)
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

func TestPythonAgentRefused(t *testing.T) {
	c := startAgent(t)
	_, err := c.DialContext(context.Background(), "tcp", "nothing.svc:1")
	var de *proto.DialError
	if !errors.As(err, &de) || de.Status != proto.StatusRefused {
		t.Fatalf("got %v, want refused DialError", err)
	}
	// The session survives a failed dial.
	conn, err := c.DialContext(context.Background(), "tcp", "echo.svc:7")
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
}

func dnsQuery(id byte, name string) []byte {
	q := []byte{0, id, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, label := range strings.Split(name, ".") {
		q = append(q, byte(len(label)))
		q = append(q, label...)
	}
	return append(q, 0, 0, 1, 0, 1)
}

// The Python agent reads resolv.conf, skips the server that refuses, ignores
// a stray datagram and returns the answer unchanged; a truncated answer is
// fetched again over TCP.
func TestPythonAgentDNS(t *testing.T) {
	c := startAgent(t)
	for name, marker := range map[string]string{"web.example": "udp", "big.example": "tcp"} {
		q := dnsQuery(9, name)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		got, err := c.ExchangeDNS(ctx, q)
		cancel()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(got) != len(q)+len(marker) || got[1] != 9 || got[2]&0x80 == 0 || got[2]&0x02 != 0 || !strings.HasSuffix(string(got), marker) {
			t.Errorf("%s: got %q, want the %s answer", name, got, marker)
		}
	}
}

// A UDP flow: datagrams keep their boundaries both ways (an empty one too);
// an unknown destination is refused.
func TestPythonAgentUDP(t *testing.T) {
	c := startAgent(t)
	conn, err := c.DialContext(context.Background(), "udp", "dns.svc:53")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, 65535)
	// (The test's socket pair takes datagrams up to 2 KB on macOS; real UDP
	// sockets take 64 KB.)
	for _, d := range []string{"first", "", strings.Repeat("x", 1500)} {
		if _, err := conn.Write([]byte(d)); err != nil {
			t.Fatal(err)
		}
		n, err := conn.Read(buf)
		if err != nil || string(buf[:n]) != "re:"+d {
			t.Fatalf("datagram %.10q: got %.13q %v", d, buf[:n], err)
		}
	}
	if _, err := c.DialContext(context.Background(), "udp", "nowhere.svc:53"); err == nil || !strings.Contains(err.Error(), "connection refused") {
		t.Errorf("unknown destination: %v", err)
	}
}

// An ICMP error for one datagram doesn't end the flow: the agent logs it and
// carries on, and says why the flow ended when it does.
func TestPythonAgentUDPSurvivesErrors(t *testing.T) {
	c, logs := startAgentLog(t)
	conn, err := c.DialContext(context.Background(), "udp", "quic.svc:443")
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 100)
	for _, d := range []string{"initial", "handshake"} {
		if _, err := conn.Write([]byte(d)); err != nil {
			t.Fatal(err)
		}
		n, err := conn.Read(buf)
		if err != nil || string(buf[:n]) != "re:"+d {
			t.Fatalf("%q after read errors: got %q, %v", d, buf[:n], err)
		}
	}
	logs.waitLine(t, "udp flow error", "kind=EHOSTUNREACH")
	logs.waitLine(t, "udp flow error", "kind=EMSGSIZE")
	_ = conn.Close()
	line := logs.waitLine(t, "udp flow closed", "reason=")
	for _, want := range []string{"read: EHOSTUNREACH (2)", "read: EMSGSIZE (1)", "read: ECONNREFUSED (1)"} {
		if !strings.Contains(line, want) {
			t.Errorf("the closing line doesn't count %q: %s", want, line)
		}
	}
}

// A socket that only fails ends the flow after a while, and subtun hears of
// it (the stream ends) rather than waiting on a flow the agent dropped.
func TestPythonAgentUDPEndsWhenItsSocketKeepsFailing(t *testing.T) {
	c, logs := startAgentLog(t)
	conn, err := c.DialContext(context.Background(), "udp", "dead.svc:9")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	_, err = conn.Read(make([]byte, 100))
	if !errors.Is(err, io.EOF) {
		t.Fatalf("read: %v, want EOF: the flow ended by the agent", err)
	}
	logs.waitLine(t, "udp flow closed", "reason=", "ENETUNREACH")
}

// On a real UDP socket the agent ends the flow promptly when subtun closes it
// (its reader, blocked in recv, wakes up).
func TestPythonAgentUDPRealSocketCloses(t *testing.T) {
	src, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	c, logs := startAgentLog(t)
	conn, err := c.DialContext(context.Background(), "udp", src.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	_ = src.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 100)
	n, agentAddr, err := src.ReadFromUDP(buf)
	if err != nil || string(buf[:n]) != "ping" {
		t.Fatalf("at the destination: %q %v", buf[:n], err)
	}
	if _, err := src.WriteToUDP([]byte("pong"), agentAddr); err != nil {
		t.Fatal(err)
	}
	if n, err := conn.Read(buf); err != nil || string(buf[:n]) != "pong" {
		t.Fatalf("answer: %q %v", buf[:n], err)
	}
	start := time.Now()
	_ = conn.Close()
	logs.waitLine(t, "udp flow closed", "closed by subtun")
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("the flow ended %v after the close: the reader didn't wake", d)
	}
}

// TestPythonAgentUDPThroughput measures a paced UDP download through the
// Python agent (real sockets on 127.0.0.1): how fast it reaches the client
// and how much is lost. Set SUBTUN_UDP_BENCH=1 to run it; SUBTUN_UDP_RATE is
// the sender's rate in MB/s (default 40), SUBTUN_UDP_COUNT the number of
// datagrams (default 40000, 1350 bytes each).
func TestPythonAgentUDPThroughput(t *testing.T) {
	if os.Getenv("SUBTUN_UDP_BENCH") == "" {
		t.Skip("set SUBTUN_UDP_BENCH=1 to run")
	}
	rate := 40.0
	if v, err := strconv.ParseFloat(os.Getenv("SUBTUN_UDP_RATE"), 64); err == nil {
		rate = v
	}
	src, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	c := startAgent(t)
	conn, err := c.DialContext(context.Background(), "udp", src.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("go")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 65535)
	_ = src.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, agentAddr, err := src.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}
	n, size := 40000, 1350
	if v, err := strconv.Atoi(os.Getenv("SUBTUN_UDP_COUNT")); err == nil {
		n = v
	}
	go func() {
		d := make([]byte, size)
		start := time.Now()
		for i := range n {
			_, _ = src.WriteToUDP(d, agentAddr)
			if i%20 == 19 {
				due := time.Duration(float64((i+1)*size) / (rate * 1e6) * float64(time.Second))
				if wait := due - time.Since(start); wait > 0 {
					time.Sleep(wait)
				}
			}
		}
	}()
	got, total := 0, 0
	start := time.Now()
	last := start
	for {
		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		k, err := conn.Read(buf)
		if err != nil {
			break // a second without a datagram: done
		}
		got++
		total += k
		last = time.Now()
	}
	el := last.Sub(start).Seconds()
	t.Logf("sent %d datagrams of %d B at %.0f MB/s: got %d (%.1f %% lost), %.1f MB/s over %.2f s",
		n, size, rate, got, 100*float64(n-got)/float64(n), float64(total)/el/1e6, el)
}

// A connection the agent aborts (the target reset it) ends for subtun too.
func TestPythonAgentAbortReachesSubtun(t *testing.T) {
	c := startAgent(t)
	conn, err := c.DialContext(context.Background(), "tcp", "reset.svc:80")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Read(make([]byte, 100)); !errors.Is(err, io.EOF) {
		t.Fatalf("read: %v, want EOF after the agent's abort", err)
	}
}
