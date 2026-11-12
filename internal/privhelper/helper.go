//go:build !windows

package privhelper

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"time"

	"github.com/md2k/subnet-tunnel/internal/platform"
)

// helper executes validated commands from subtun with the platform drivers.
// The OS-specific work lives in the drivers; this loop is the same on every
// OS and is tested with fake drivers.
type helper struct {
	conn    *net.UnixConn
	log     *slog.Logger
	drivers platform.Drivers
	dev     platform.TunDevice
	routes  []netip.Prefix
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
			name := ""
			if h.dev != nil {
				name = h.dev.Name()
				// Our copy only. The interface lives as long as subtun keeps its
				// descriptor, and its routes go away with it.
				_ = h.dev.Release()
			}
			h.log.Info("setup complete", "utun", name, "routes", len(h.routes))
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
		dev, err := h.drivers.Tun.Create(req.MTU, addr)
		if err != nil {
			return fail(err)
		}
		h.dev = dev
		h.log.Info("utun created", "name", dev.Name(), "mtu", req.MTU, "addr", addr)
		fd, err := rawFD(dev.File())
		if err != nil {
			h.undo()
			return fail(err)
		}
		return Response{OK: true, Name: dev.Name()}, []int{fd}

	case OpAddRoute:
		if h.dev == nil {
			return fail(errors.New("create the utun first"))
		}
		p, err := ParseCIDR(req.CIDR)
		if err != nil {
			return fail(err)
		}
		if err := h.drivers.Routes.Add(p, h.dev.Name()); err != nil {
			return fail(err)
		}
		h.routes = append(h.routes, p)
		h.log.Info("route added", "cidr", p, "utun", h.dev.Name())
		return Response{OK: true}, nil

	default:
		return fail(fmt.Errorf("unknown op %q", req.Op))
	}
}

// undo removes what this helper added. Used only when setup didn't finish.
func (h *helper) undo() {
	if h.dev == nil {
		return
	}
	name := h.dev.Name()
	for i := len(h.routes) - 1; i >= 0; i-- {
		if err := h.drivers.Routes.Delete(h.routes[i], name); err != nil {
			h.log.Warn("removing route", "cidr", h.routes[i], "err", err)
		}
	}
	h.routes = nil
	_ = h.dev.Close()
	h.dev = nil
	h.log.Info("utun closed", "name", name)
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
