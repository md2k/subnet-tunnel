//go:build !windows

package privhelper

import (
	"io"
	"net"
	"os"
	"syscall"
	"testing"
	"time"
)

// socketPair returns two connected unix stream sockets, in process.
func socketPair(t *testing.T) (*net.UnixConn, *net.UnixConn) {
	t.Helper()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	conn := func(fd int) *net.UnixConn {
		f := os.NewFile(uintptr(fd), "sp")
		c, err := net.FileConn(f)
		_ = f.Close()
		if err != nil {
			t.Fatal(err)
		}
		return c.(*net.UnixConn)
	}
	a, b := conn(fds[0]), conn(fds[1])
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	return a, b
}

// The utun handoff in miniature: a descriptor sent with a response arrives
// usable on the other side.
func TestPassDescriptor(t *testing.T) {
	a, b := socketPair(t)
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	go func() {
		_ = writeMsg(a, Response{OK: true, Name: "utun9"}, int(w.Fd()))
		_ = w.Close() // our copy; the receiver has its own now
	}()
	var resp Response
	files, err := readMsg(b, &resp, time.Now().Add(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if !resp.OK || resp.Name != "utun9" || len(files) != 1 {
		t.Fatalf("got %+v with %d files", resp, len(files))
	}
	if _, err := files[0].WriteString("through the fd"); err != nil {
		t.Fatal(err)
	}
	_ = files[0].Close()
	got, _ := io.ReadAll(r)
	if string(got) != "through the fd" {
		t.Fatalf("read %q from the pipe", got)
	}
}

func TestMessageWithoutDescriptor(t *testing.T) {
	a, b := socketPair(t)
	go func() { _ = writeMsg(a, Request{Op: OpAddRoute, CIDR: "10.244.0.0/16"}) }()
	var req Request
	files, err := readMsg(b, &req, time.Now().Add(5*time.Second))
	if err != nil || len(files) != 0 || req.Op != OpAddRoute || req.CIDR != "10.244.0.0/16" {
		t.Fatalf("got %+v, %d files, %v", req, len(files), err)
	}
}

func TestReadMsgRejectsGarbage(t *testing.T) {
	a, b := socketPair(t)
	go func() { _, _ = a.Write([]byte("not json\n")) }()
	var req Request
	if _, err := readMsg(b, &req, time.Now().Add(5*time.Second)); err == nil {
		t.Fatal("garbage accepted")
	}
}
