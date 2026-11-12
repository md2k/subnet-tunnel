package proto

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestRequestRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	in := Request{Cmd: CmdConnectTCP, Addr: "web.subtun-dev.svc.cluster.local:8080"}
	if err := WriteRequest(&buf, in); err != nil {
		t.Fatal(err)
	}
	out, err := ReadRequest(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if out != in {
		t.Fatalf("got %+v, want %+v", out, in)
	}
}

func TestRequestRejects(t *testing.T) {
	if err := WriteRequest(&bytes.Buffer{}, Request{Cmd: CmdConnectTCP}); !errors.Is(err, ErrAddr) {
		t.Fatalf("empty addr: got %v", err)
	}
	long := strings.Repeat("a", MaxAddrLen+1)
	if err := WriteRequest(&bytes.Buffer{}, Request{Cmd: CmdConnectTCP, Addr: long}); !errors.Is(err, ErrAddr) {
		t.Fatalf("long addr: got %v", err)
	}
	if _, err := ReadRequest(bytes.NewReader([]byte{Version + 1, 1, 0, 1, 'x'})); !errors.Is(err, ErrVersion) {
		t.Fatalf("version: got %v", err)
	}
	if _, err := ReadRequest(bytes.NewReader([]byte{Version, 1, 0xff, 0xff})); !errors.Is(err, ErrAddr) {
		t.Fatalf("oversize length: got %v", err)
	}
}

func TestResponseRoundTripTruncates(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteResponse(&buf, Response{Status: StatusRefused, Msg: strings.Repeat("e", MaxMsgLen+50)}); err != nil {
		t.Fatal(err)
	}
	out, err := ReadResponse(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if out.Status != StatusRefused || len(out.Msg) != MaxMsgLen {
		t.Fatalf("got status %v, msg len %d", out.Status, len(out.Msg))
	}
}

func TestHello(t *testing.T) {
	h := Hello{Proto: Version, Version: "v0.1.0", SHA256: "abc123"}
	r := strings.NewReader(h.Line() + "MUXBYTES")
	got, err := ReadHello(r)
	if err != nil {
		t.Fatal(err)
	}
	if got != h {
		t.Fatalf("got %+v, want %+v", got, h)
	}
	rest := make([]byte, 8)
	if n, _ := r.Read(rest); string(rest[:n]) != "MUXBYTES" {
		t.Fatalf("ReadHello consumed past the newline, left %q", rest[:n])
	}

	noSum, err := ParseHello(Hello{Proto: 1, Version: "dev"}.Line())
	if err != nil || noSum.SHA256 != "" {
		t.Fatalf("missing sha: got %+v, %v", noSum, err)
	}
	if _, err := ParseHello("sh: 1: not found"); err == nil {
		t.Fatal("garbage accepted as hello")
	}
	if _, err := ReadHello(strings.NewReader(strings.Repeat("x", MaxHelloLen+1))); err == nil {
		t.Fatal("unbounded hello accepted")
	}
}

func TestDNSFraming(t *testing.T) {
	msg := append([]byte{0xab, 0xcd, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}, "\x03web\x00\x00\x01\x00\x01"...)
	var buf bytes.Buffer
	if err := WriteDNS(&buf, msg); err != nil {
		t.Fatal(err)
	}
	if got := buf.Bytes()[:2]; got[0] != 0 || int(got[1]) != len(msg) {
		t.Fatalf("length prefix %x", got)
	}
	out, err := ReadDNS(&buf)
	if err != nil || !bytes.Equal(out, msg) {
		t.Fatalf("got %x, %v", out, err)
	}
	if err := WriteDNS(&buf, msg[:5]); err == nil {
		t.Error("short message written")
	}
	if _, err := ReadDNS(bytes.NewReader([]byte{0, 3, 1, 2, 3})); err == nil {
		t.Error("short message read")
	}
	if _, err := ReadDNS(bytes.NewReader([]byte{0, 20, 1, 2})); err == nil {
		t.Error("truncated message read")
	}
}
