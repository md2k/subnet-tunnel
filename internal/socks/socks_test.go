package socks

import (
	"bytes"
	"io"
	"net"
	"testing"
)

// run feeds the client bytes to Handshake over an in-memory pipe and returns
// what Handshake returned plus everything it wrote back.
func run(t *testing.T, client []byte) (string, error, []byte) {
	t.Helper()
	srv, cli := net.Pipe()
	type result struct {
		addr string
		err  error
	}
	done := make(chan result, 1)
	go func() {
		a, err := Handshake(srv)
		_ = srv.Close()
		done <- result{a, err}
	}()
	go func() { _, _ = cli.Write(client) }()
	reply, _ := io.ReadAll(cli)
	r := <-done
	return r.addr, r.err, reply
}

func TestHandshakeAddressTypes(t *testing.T) {
	greet := []byte{5, 1, 0}
	cases := []struct {
		name string
		req  []byte
		want string
	}{
		{"ipv4", []byte{5, 1, 0, 1, 10, 96, 0, 1, 0x01, 0xbb}, "10.96.0.1:443"},
		{"domain", append(append([]byte{5, 1, 0, 3, 11}, "web.svc.dev"...), 0x1f, 0x90), "web.svc.dev:8080"},
		{"ipv6", append(append([]byte{5, 1, 0, 4}, net.ParseIP("fd00::1").To16()...), 0, 80), "[fd00::1]:80"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			addr, err, reply := run(t, append(append([]byte{}, greet...), tc.req...))
			if err != nil {
				t.Fatal(err)
			}
			if addr != tc.want {
				t.Fatalf("addr %q, want %q", addr, tc.want)
			}
			if !bytes.Equal(reply, []byte{5, 0}) {
				t.Fatalf("reply %v, want method selection only", reply)
			}
		})
	}
}

func TestHandshakeRejects(t *testing.T) {
	// Only username/password offered.
	_, err, reply := run(t, []byte{5, 1, 2})
	if err == nil || !bytes.Equal(reply, []byte{5, 0xff}) {
		t.Fatalf("auth: err %v, reply %v", err, reply)
	}
	// BIND instead of CONNECT.
	_, err, reply = run(t, []byte{5, 1, 0, 5, 2, 0, 1, 127, 0, 0, 1, 0, 80})
	if err == nil || len(reply) < 4 || reply[3] != repCmdNotSupported {
		t.Fatalf("bind: err %v, reply %v", err, reply)
	}
	// SOCKS4.
	if _, err, _ := run(t, []byte{4, 1, 0, 80, 127, 0, 0, 1, 0}); err == nil {
		t.Fatal("socks4 accepted")
	}
}
