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
	"sync/atomic"
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
	state   stateStore         // who holds subtun's firewall rules, across sessions
	alive   func(pid int) bool // is that helper still running
	pid     int
	grace   time.Duration // how long a signalled session waits for subtun's word

	dev      platform.TunDevice
	routes   []netip.Prefix
	owned    bool            // the firewall anchor is ours to use (checked once)
	firewall bool            // our rules are loaded
	persist  *platform.Rules // what stays if the tunnel goes away; nil: nothing
	adopted  bool            // rules taken over from an earlier session
	applied  bool            // this session applied rules of its own
	session  atomic.Bool     // setup done, staying up for the session
	until    atomic.Int64    // read deadline after a signal (unix nanos), 0: none
}

func (h *helper) loop(ctx context.Context) error {
	// During a session a signal decides nothing by itself (Ctrl-C reaches
	// the helper as well as subtun): subtun says whether the rules stay.
	// Wait for that, or for subtun to go away, then apply the policy.
	stop := context.AfterFunc(ctx, func() {
		if !h.session.Load() {
			_ = h.conn.Close()
			return
		}
		dl := time.Now().Add(h.grace)
		h.until.Store(dl.UnixNano())
		_ = h.conn.SetReadDeadline(dl)
	})
	defer stop()
	for {
		var req Request
		if _, err := readMsg(h.conn, &req, h.deadline()); err != nil {
			gone := errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || errors.Is(err, os.ErrDeadlineExceeded)
			if h.session.Load() {
				// subtun exited, crashed or was killed without saying how
				// to end, or didn't answer after a signal.
				h.leave("subtun went away")
				h.log.Info("session ended")
				if gone {
					return nil
				}
				return err
			}
			// subtun went away (or was interrupted) before finishing setup.
			h.undo()
			if gone {
				return errors.New("subtun disconnected before setup finished; changes undone")
			}
			return err
		}
		switch {
		case req.Op == OpDone && !h.session.Load():
			end, err := h.finishSetup(req.Session)
			if end || err != nil {
				return err
			}
			continue
		case req.Op == OpEnd && h.session.Load():
			if req.Keep {
				h.leave("kept on stop")
			} else {
				h.flushFirewall()
			}
			h.log.Info("session ended")
			return writeMsg(h.conn, Response{OK: true})
		}
		resp, fds := h.handle(req)
		if err := writeMsg(h.conn, resp, fds...); err != nil {
			if h.session.Load() {
				h.leave("connection lost")
			} else {
				h.undo()
			}
			return err
		}
	}
}

func (h *helper) deadline() time.Time {
	if n := h.until.Load(); n != 0 {
		return time.Unix(0, n)
	}
	return time.Time{}
}

// finishSetup answers done: the interface is subtun's from now on. In
// session mode the helper stays up (end is false) to look after the
// firewall rules.
func (h *helper) finishSetup(session bool) (end bool, err error) {
	if !session && h.firewall && h.adopted && !h.applied {
		// Leftovers taken over by a session that needs no firewall rules:
		// it replaces them with nothing.
		h.flushFirewall()
	}
	if h.firewall && !session {
		if err := writeMsg(h.conn, Response{Error: "firewall rules need session mode"}); err != nil {
			h.undo()
			return true, err
		}
		return false, nil
	}
	name := ""
	if h.dev != nil {
		name = h.dev.Name()
		// Our copy only. The interface lives as long as subtun keeps its
		// descriptor, and its routes go away with it.
		_ = h.dev.Release()
		h.dev = nil
	}
	if name != "" {
		h.log.Info("setup complete", "utun", name, "routes", len(h.routes), "session", session)
	} else {
		h.log.Info("done")
	}
	if err := writeMsg(h.conn, Response{OK: true}); err != nil {
		h.leave("connection lost")
		return true, err
	}
	h.session.Store(session)
	return !session, nil
}

func (h *helper) handle(req Request) (Response, []int) {
	fail := func(err error) (Response, []int) {
		h.log.Warn("refused", "op", req.Op, "err", err)
		return Response{Error: err.Error()}, nil
	}
	if h.session.Load() && req.Op != OpApplyFirewall {
		return fail(fmt.Errorf("%s: setup is finished; only firewall updates are accepted", req.Op))
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

	case OpApplyFirewall:
		if h.drivers.Firewall == nil {
			return fail(errors.New("no firewall driver on this system"))
		}
		if err := ValidateRules(req.Rules); err != nil {
			return fail(err)
		}
		if req.Persist != nil {
			if err := ValidatePersist(req.Persist); err != nil {
				return fail(err)
			}
		}
		if err := h.claim(); err != nil {
			return fail(err)
		}
		if err := h.drivers.Firewall.Apply(*req.Rules); err != nil {
			// Apply replaces the anchor in one step: on failure the previous
			// rules (if any) are still in place and still ours to remove.
			return fail(err)
		}
		h.firewall, h.applied = true, true
		h.persist = req.Persist
		h.saveState()
		h.log.Info("firewall rules applied", "dns", req.Rules.DNS != nil, "kill_switch", req.Rules.KillSwitch != nil,
			"block_ipv6", req.Rules.BlockIPv6, "kept_if_tunnel_lost", req.Persist != nil)
		return Response{OK: true}, nil

	case OpAdopt:
		if h.owned || h.dev != nil {
			return fail(errors.New("adopt must be the first command"))
		}
		msg, running, err := h.adoptLeftovers()
		if err != nil {
			return fail(err)
		}
		return Response{OK: true, Message: msg, Kept: h.adopted, Running: running}, nil

	case OpCleanup:
		if h.owned || h.dev != nil {
			return fail(errors.New("cleanup must be the first command"))
		}
		msg, err := h.cleanup()
		if err != nil {
			return fail(err)
		}
		return Response{OK: true, Message: msg}, nil

	default:
		return fail(fmt.Errorf("unknown op %q", req.Op))
	}
}

// claim makes sure subtun's firewall anchor is ours: empty, or left behind
// by a session whose helper is gone, in which case its rules and pf
// reference are taken over (and replaced by the next Apply). Rules of a
// helper that is still running, or that nobody recorded, are refused.
func (h *helper) claim() error {
	if h.owned {
		return nil
	}
	busy, err := h.drivers.Firewall.Busy()
	if err != nil {
		return err
	}
	st, err := h.state.load()
	if err != nil {
		h.log.Warn("reading the helper state", "err", err)
	}
	if !busy {
		if st != nil {
			_ = h.state.remove() // stale, e.g. from before a reboot
		}
		h.owned = true
		return nil
	}
	if st == nil {
		return errors.New("subtun's pf anchor already has rules that no session recorded; if no subtun is running, remove them with: subtun cleanup")
	}
	if h.alive(st.Owner) {
		return fmt.Errorf("another subtun session (helper pid %d) has firewall rules in place; stop it first", st.Owner)
	}
	h.drivers.Firewall.Adopt(st.Token)
	h.persist = st.Persist
	h.firewall, h.adopted, h.owned = true, true, true
	h.log.Info("taking over the firewall rules an earlier session left", "pid", st.Owner)
	return nil
}

// adoptLeftovers runs before subtun connects: blocking rules an earlier
// session left stay, except a DNS block, so subtun can resolve its API
// server. Leftovers that don't block anything are removed. A running
// session's rules are left alone (running): this session can still go
// ahead without firewall rules of its own.
func (h *helper) adoptLeftovers() (msg string, running bool, err error) {
	if busy, err := h.drivers.Firewall.Busy(); err == nil && busy {
		if st, _ := h.state.load(); st != nil && h.alive(st.Owner) {
			return fmt.Sprintf("another subtun session (helper pid %d) is running; its firewall rules are left alone", st.Owner), true, nil
		}
	}
	if err := h.claim(); err != nil {
		return "", false, err
	}
	if !h.adopted {
		return "nothing left behind", false, nil
	}
	var relaxed platform.Rules
	if h.persist != nil {
		relaxed = *h.persist
		relaxed.DNSBlock = nil
	}
	if relaxed.Empty() {
		h.flushFirewall()
		h.adopted = false
		return "removed firewall rules an earlier session left", false, nil
	}
	if err := h.drivers.Firewall.Apply(relaxed); err != nil {
		return "", false, err
	}
	h.saveState()
	return "kill switch from an earlier session taken over (DNS allowed while connecting)", false, nil
}

// cleanup removes whatever an earlier session left (subtun cleanup).
func (h *helper) cleanup() (string, error) {
	busy, err := h.drivers.Firewall.Busy()
	if err != nil {
		return "", err
	}
	st, _ := h.state.load()
	if st != nil && busy && h.alive(st.Owner) {
		return "", fmt.Errorf("a subtun session (helper pid %d) is running; stop it instead", st.Owner)
	}
	if !busy && st == nil {
		return "nothing to clean up", nil
	}
	released := st != nil && st.Token != ""
	if released {
		h.drivers.Firewall.Adopt(st.Token)
	}
	if err := h.drivers.Firewall.Flush(); err != nil {
		return "", err
	}
	_ = h.state.remove()
	if released {
		return "removed subtun's firewall rules and released pf", nil
	}
	return "removed subtun's firewall rules (pf stays enabled until reboot: its reference was not recorded)", nil
}

// leave ends a session. With rules meant to stay (kill switch), they
// replace the running ones and pf stays enabled for them; the state names
// this helper, which is about to exit, so a later session can take them
// over. Without, everything is removed.
func (h *helper) leave(why string) {
	if !h.firewall {
		return
	}
	if h.persist == nil {
		h.flushFirewall()
		return
	}
	if err := h.drivers.Firewall.Apply(*h.persist); err != nil {
		h.log.Warn("applying the kill switch's blocking rules; the session's rules stay instead", "err", err)
	}
	h.saveState()
	h.log.Info("kill switch: blocking rules stay until the next session or subtun cleanup", "reason", why)
}

// flushFirewall removes subtun's firewall rules, if any were applied.
func (h *helper) flushFirewall() {
	if !h.firewall {
		return
	}
	if err := h.drivers.Firewall.Flush(); err != nil {
		h.log.Warn("removing firewall rules", "err", err)
		return
	}
	h.firewall = false
	if err := h.state.remove(); err != nil {
		h.log.Warn("removing the helper state", "err", err)
	}
	h.log.Info("firewall rules removed")
}

func (h *helper) saveState() {
	st := &state{Owner: h.pid, Token: h.drivers.Firewall.Token(), Persist: h.persist}
	if err := h.state.save(st); err != nil {
		h.log.Warn("saving the helper state", "err", err)
	}
}

// undo removes what this helper added. Used only when setup didn't finish.
// Firewall rules go first, so DNS isn't redirected to a listener that is
// about to disappear; rules taken over from an earlier session are put
// back as they were.
func (h *helper) undo() {
	if h.adopted {
		h.leave("setup did not finish")
	} else {
		h.flushFirewall()
	}
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
