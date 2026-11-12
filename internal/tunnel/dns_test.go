package tunnel_test

import (
	"bytes"
	"context"
	"errors"
	"net"
	"slices"
	"testing"
	"time"

	"github.com/md2k/subnet-tunnel/internal/proto"
	"github.com/md2k/subnet-tunnel/internal/tunnel"
)

// query builds a DNS query for web.example, type A.
func query(id uint16) []byte {
	return append([]byte{byte(id >> 8), byte(id), 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0},
		"\x03web\x07example\x00\x00\x01\x00\x01"...)
}

// answerFor turns a query into a response carrying a marker, optionally
// with the TC bit.
func answerFor(q []byte, marker string, tc bool) []byte {
	a := append(slices.Clone(q), marker...)
	a[2] |= 0x80
	if tc {
		a[2] |= 0x02
	}
	return a
}

// udpServer answers each datagram; before that it sends a stray response
// with the wrong ID, which the agent must skip.
func udpServer(marker string, tc bool) func(net.Conn) {
	return func(c net.Conn) {
		defer c.Close()
		buf := make([]byte, 512)
		n, err := c.Read(buf)
		if err != nil {
			return
		}
		stray := answerFor(buf[:n], "stray", false)
		stray[0] ^= 0xff
		_, _ = c.Write(stray)
		_, _ = c.Write(answerFor(buf[:n], marker, tc))
	}
}

func tcpServer(marker string) func(net.Conn) {
	return func(c net.Conn) {
		defer c.Close()
		q, err := proto.ReadDNS(c)
		if err != nil {
			return
		}
		_ = proto.WriteDNS(c, answerFor(q, marker, false))
	}
}

func exchange(t *testing.T, c *tunnel.Client, q []byte) ([]byte, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return c.ExchangeDNS(ctx, q)
}

// The agent reads the target's resolv.conf, skips the server that doesn't
// answer and returns the next one's answer unchanged.
func TestDNSThroughAgent(t *testing.T) {
	fn := &fakeNet{handlers: map[string]func(net.Conn){"udp/10.96.0.10:53": udpServer("udp", false)}}
	c, err := startSession(t, fn, tunnel.Options{}, "")
	if err != nil {
		t.Fatal(err)
	}
	q := query(0x1234)
	got, err := exchange(t, c, q)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, answerFor(q, "udp", false)) {
		t.Fatalf("got %q", got)
	}
	fn.mu.Lock()
	defer fn.mu.Unlock()
	if want := []string{"udp/192.0.2.53:53", "udp/10.96.0.10:53"}; !slices.Equal(fn.dialed, want) {
		t.Fatalf("dialed %q, want %q", fn.dialed, want)
	}
}

func TestDNSTruncatedAnswerRetriesOverTCP(t *testing.T) {
	fn := &fakeNet{handlers: map[string]func(net.Conn){
		"udp/10.96.0.10:53": udpServer("udp", true),
		"10.96.0.10:53":     tcpServer("tcp"),
	}}
	c, err := startSession(t, fn, tunnel.Options{}, "")
	if err != nil {
		t.Fatal(err)
	}
	q := query(7)
	got, err := exchange(t, c, q)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, answerFor(q, "tcp", false)) {
		t.Fatalf("got %q", got)
	}
}

func TestDNSNoServerAnswers(t *testing.T) {
	c, err := startSession(t, &fakeNet{}, tunnel.Options{}, "")
	if err != nil {
		t.Fatal(err)
	}
	_, err = exchange(t, c, query(1))
	var de *proto.DialError
	if !errors.As(err, &de) || de.Status != proto.StatusRefused {
		t.Fatalf("got %v, want a refused DialError", err)
	}
	// The session survives.
	if _, err := exchange(t, c, query(2)); !errors.As(err, &de) {
		t.Fatalf("second query: %v", err)
	}
}
