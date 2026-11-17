package agentpy_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
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

// startAgent runs the Python agent locally over pipes, with dial() and
// dns_connect() replaced by in-process socket pairs (testdata/fakenet.py),
// and connects a tunnel client to it. Skips if there is no suitable python3.
func startAgent(t *testing.T) *tunnel.Client {
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
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
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
	return c
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
