package control

import (
	"net"
	"os"

	"golang.org/x/sys/unix"
)

// peerIsMe reports whether the other end of c runs as this user.
func peerIsMe(c *net.UnixConn) bool {
	rc, err := c.SyscallConn()
	if err != nil {
		return false
	}
	ok := false
	_ = rc.Control(func(fd uintptr) {
		cred, err := unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		ok = err == nil && int(cred.Uid) == os.Getuid()
	})
	return ok
}
