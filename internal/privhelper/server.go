//go:build darwin || linux

package privhelper

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Serve is the helper process (`subtun helper --socket PATH`, run by sudo).
// It reads the token from stdin, connects to subtun's socket and executes
// commands until Done or until subtun goes away, using this OS's drivers
// (osDrivers).
func Serve(ctx context.Context, socketPath string, stdin io.Reader, log *slog.Logger) error {
	if os.Geteuid() != 0 {
		return errors.New("the helper must run as root (subtun starts it with sudo)")
	}
	uid, err := strconv.Atoi(os.Getenv("SUDO_UID"))
	if err != nil {
		return errors.New("SUDO_UID not set: the helper is started by subtun through sudo, not by hand")
	}
	// Only talk to a socket in a private directory of the user who ran sudo.
	if !filepath.IsAbs(socketPath) {
		return fmt.Errorf("socket path %q must be absolute", socketPath)
	}
	if err := checkPrivate(filepath.Dir(socketPath), uid); err != nil {
		return fmt.Errorf("refusing socket: %w", err)
	}
	if err := checkPrivate(socketPath, uid); err != nil {
		return fmt.Errorf("refusing socket: %w", err)
	}

	token, err := bufio.NewReader(io.LimitReader(stdin, tokenLen+2)).ReadString('\n')
	if err != nil {
		return fmt.Errorf("reading token: %w", err)
	}
	token = strings.TrimSpace(token)
	if len(token) != tokenLen {
		return errors.New("bad token")
	}

	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := writeMsg(conn, struct {
		Token string `json:"token"`
	}{token}); err != nil {
		return err
	}

	h := &helper{
		conn:    conn,
		log:     log,
		drivers: osDrivers(log),
		state:   fileState{dir: "/var/run/subtun"},
		alive:   processAlive,
		pid:     os.Getpid(),
		grace:   5 * time.Second,
	}
	return h.loop(ctx)
}
