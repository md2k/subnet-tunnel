//go:build darwin

package privhelper

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/tun"
)

// Serve is the helper process (`subtun helper --socket PATH`, run by sudo).
// It reads the token from stdin, connects to subtun's socket and executes
// commands until Done or until subtun goes away.
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

	h := &helper{conn: conn, log: log}
	return h.loop(ctx)
}

type helper struct {
	conn   *net.UnixConn
	log    *slog.Logger
	dev    tun.Device
	name   string
	routes []netip.Prefix
}

func (h *helper) loop(ctx context.Context) error {
	stop := context.AfterFunc(ctx, func() { _ = h.conn.Close() })
	defer stop()
	for {
		var req Request
		if _, err := readMsg(h.conn, &req, time.Time{}); err != nil {
			// subtun went away (or was interrupted) before finishing setup.
			h.undo()
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				return errors.New("subtun disconnected before setup finished; changes undone")
			}
			return err
		}
		if req.Op == OpDone {
			h.log.Info("setup complete", "utun", h.name, "routes", len(h.routes))
			if h.dev != nil {
				// Our copy only. The interface lives as long as subtun keeps its
				// descriptor, and its routes go away with it.
				_ = h.dev.File().Close()
			}
			return writeMsg(h.conn, Response{OK: true})
		}
		resp, fds := h.handle(req)
		if err := writeMsg(h.conn, resp, fds...); err != nil {
			h.undo()
			return err
		}
	}
}

func (h *helper) handle(req Request) (Response, []int) {
	fail := func(err error) (Response, []int) {
		h.log.Warn("refused", "op", req.Op, "err", err)
		return Response{Error: err.Error()}, nil
	}
	switch req.Op {
	case OpCreateTun:
		if h.dev != nil {
			return fail(errors.New("utun already created"))
		}
		if err := ValidateMTU(req.MTU); err != nil {
			return fail(err)
		}
		addr, err := ValidateTunAddr(req.Addr)
		if err != nil {
			return fail(err)
		}
		dev, err := tun.CreateTUN("utun", req.MTU)
		if err != nil {
			return fail(fmt.Errorf("creating utun: %w", err))
		}
		name, err := dev.Name()
		if err != nil {
			_ = dev.Close()
			return fail(err)
		}
		if err := run("/sbin/ifconfig", name, "inet", addr.String(), addr.String(), "up"); err != nil {
			_ = dev.Close()
			return fail(err)
		}
		h.dev, h.name = dev, name
		h.log.Info("utun created", "name", name, "mtu", req.MTU, "addr", addr)
		fd, err := rawFD(dev.File())
		if err != nil {
			h.undo()
			return fail(err)
		}
		return Response{OK: true, Name: name}, []int{fd}

	case OpAddRoute:
		if h.dev == nil {
			return fail(errors.New("create the utun first"))
		}
		p, err := ParseCIDR(req.CIDR)
		if err != nil {
			return fail(err)
		}
		if err := run("/sbin/route", routeArgs("add", p, h.name)...); err != nil {
			return fail(err)
		}
		h.routes = append(h.routes, p)
		h.log.Info("route added", "cidr", p, "utun", h.name)
		return Response{OK: true}, nil

	default:
		return fail(fmt.Errorf("unknown op %q", req.Op))
	}
}

// undo removes what this helper added. Used only when setup didn't finish.
func (h *helper) undo() {
	for i := len(h.routes) - 1; i >= 0; i-- {
		if err := run("/sbin/route", routeArgs("delete", h.routes[i], h.name)...); err != nil {
			h.log.Warn("removing route", "cidr", h.routes[i], "err", err)
		}
	}
	h.routes = nil
	if h.dev != nil {
		_ = h.dev.Close()
		h.dev = nil
		h.log.Info("utun closed", "name", h.name)
	}
}

// rawFD returns f's descriptor without File.Fd's side effect of switching it
// to blocking mode (which would carry over to the copy we pass to subtun:
// the mode belongs to the shared open file).
func rawFD(f *os.File) (int, error) {
	rc, err := f.SyscallConn()
	if err != nil {
		return 0, err
	}
	fd := -1
	if err := rc.Control(func(p uintptr) { fd = int(p) }); err != nil {
		return 0, err
	}
	return fd, nil
}

func run(name string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}
