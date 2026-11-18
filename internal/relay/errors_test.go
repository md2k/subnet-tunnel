package relay_test

import (
	"errors"
	"net"
	"os"
	"syscall"
	"testing"

	"github.com/md2k/subnet-tunnel/internal/relay"
)

func TestErrors(t *testing.T) {
	var e relay.Errors
	if e.String() != "" || e.Total() != 0 {
		t.Fatalf("empty: %q %d", e.String(), e.Total())
	}
	sys := func(errno syscall.Errno) error {
		return &net.OpError{Op: "read", Net: "udp", Err: os.NewSyscallError("recvfrom", errno)}
	}
	for i, c := range []struct {
		dir   string
		err   error
		first bool
	}{
		{"read", sys(syscall.EHOSTUNREACH), true},
		{"read", sys(syscall.EHOSTUNREACH), false},
		{"write", sys(syscall.EHOSTUNREACH), true},
		{"read", &net.OpError{Op: "read", Net: "udp", Err: errors.New("connection refused")}, true}, // gVisor's kind
		{"read", errors.New("odd"), true},
	} {
		if got := e.Add(c.dir, c.err); got != c.first {
			t.Errorf("add %d (%s %v): first %v, want %v", i, c.dir, c.err, got, c.first)
		}
	}
	want := "read: no route to host (2), write: no route to host (1), read: connection refused (1), read: odd (1)"
	if e.String() != want || e.Total() != 5 {
		t.Errorf("got %q %d, want %q 5", e.String(), e.Total(), want)
	}
}
