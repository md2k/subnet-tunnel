//go:build darwin

package privhelper

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"github.com/md2k/subnet-tunnel/internal/platform"
)

const sudoPrompt = "[subtun] root is needed to create the utun interface and routes (and firewall rules for DNS capture). Password for %u: "

// Client is subtun's side of a running helper.
type Client struct {
	conn    *net.UnixConn
	cmd     *exec.Cmd
	stdin   io.WriteCloser
	exited  chan struct{} // closed when the helper process exits
	exitErr error         // valid after exited is closed
	log     *slog.Logger
}

// Start runs the helper through sudo (sudo asks for the password on the
// terminal) and waits for it to connect back and prove it's ours.
// helperLog receives the helper's log lines.
func Start(ctx context.Context, helperLog io.Writer, log *slog.Logger) (*Client, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	if exe, err = filepath.EvalSymlinks(exe); err != nil {
		return nil, err
	}
	dir, err := runtimeDir()
	if err != nil {
		return nil, err
	}
	sock := filepath.Join(dir, fmt.Sprintf("helper-%d.sock", os.Getpid()))
	_ = os.Remove(sock)
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		return nil, err
	}
	defer os.Remove(sock) // one connection only; unlinked once it's made
	defer ln.Close()
	if err := os.Chmod(sock, 0o600); err != nil {
		return nil, err
	}

	raw := make([]byte, tokenLen/2)
	if _, err := rand.Read(raw); err != nil {
		return nil, err
	}
	token := hex.EncodeToString(raw)

	cmd := exec.Command("/usr/bin/sudo", "-p", sudoPrompt, "--", exe, "helper", "--socket", sock)
	cmd.Stdout = helperLog
	cmd.Stderr = helperLog
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	log.Info("asking sudo for the utun setup")
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("starting sudo: %w", err)
	}
	c := &Client{cmd: cmd, stdin: stdin, exited: make(chan struct{}), log: log}
	go func() {
		c.exitErr = cmd.Wait()
		close(c.exited)
	}()
	if _, err := io.WriteString(stdin, token+"\n"); err != nil {
		c.kill()
		return nil, fmt.Errorf("sending token to helper: %w", err)
	}

	type accepted struct {
		conn *net.UnixConn
		err  error
	}
	acc := make(chan accepted, 1)
	_ = ln.SetDeadline(time.Now().Add(connTimeout))
	go func() {
		conn, err := ln.AcceptUnix()
		acc <- accepted{conn, err}
	}()
	select {
	case a := <-acc:
		if a.err != nil {
			c.kill()
			return nil, fmt.Errorf("waiting for the helper: %w", a.err)
		}
		c.conn = a.conn
	case <-c.exited:
		return nil, fmt.Errorf("sudo helper exited before connecting (wrong password, or not allowed to sudo?): %v", c.exitErr)
	case <-ctx.Done():
		c.kill()
		return nil, ctx.Err()
	}

	var hello struct {
		Token string `json:"token"`
	}
	if _, err := readMsg(c.conn, &hello, time.Now().Add(ioTimeout)); err != nil {
		c.Close()
		return nil, fmt.Errorf("helper hello: %w", err)
	}
	if subtle.ConstantTimeCompare([]byte(hello.Token), []byte(token)) != 1 {
		c.Close()
		return nil, errors.New("helper presented the wrong token")
	}
	return c, nil
}

func (c *Client) call(req Request) (Response, []*os.File, error) {
	if err := writeMsg(c.conn, req); err != nil {
		return Response{}, nil, err
	}
	var resp Response
	files, err := readMsg(c.conn, &resp, time.Now().Add(ioTimeout))
	if err != nil {
		return Response{}, nil, err
	}
	if !resp.OK {
		closeAll(files)
		return resp, nil, fmt.Errorf("helper: %s", resp.Error)
	}
	return resp, files, nil
}

// CreateTun asks for a utun interface with the given MTU and address and
// returns its name and file descriptor.
func (c *Client) CreateTun(mtu int, addr netip.Addr) (string, *os.File, error) {
	resp, files, err := c.call(Request{Op: OpCreateTun, MTU: mtu, Addr: addr.String()})
	if err != nil {
		return "", nil, err
	}
	if len(files) != 1 {
		closeAll(files)
		return "", nil, fmt.Errorf("helper sent %d file descriptors, want 1", len(files))
	}
	return resp.Name, files[0], nil
}

// AddRoute routes p into the utun.
func (c *Client) AddRoute(p netip.Prefix) error {
	_, _, err := c.call(Request{Op: OpAddRoute, CIDR: p.String()})
	return err
}

// ApplyFirewall replaces subtun's firewall rules. Rules applied during setup
// need DoneSession.
func (c *Client) ApplyFirewall(r platform.Rules) error {
	_, _, err := c.call(Request{Op: OpApplyFirewall, Rules: &r})
	return err
}

// Done ends setup; the helper exits and leaves the interface and routes to
// this process.
func (c *Client) Done() error {
	if _, _, err := c.call(Request{Op: OpDone}); err != nil {
		return err
	}
	return c.Close()
}

// DoneSession ends setup but keeps the helper running: it accepts firewall
// updates and removes the firewall rules when this process closes the
// connection, exits or dies. Exited reports if the helper goes away first.
func (c *Client) DoneSession() error {
	_, _, err := c.call(Request{Op: OpDone, Session: true})
	return err
}

// Exited is closed when the helper process has exited.
func (c *Client) Exited() <-chan struct{} { return c.exited }

// Close disconnects. Before Done, that makes the helper undo its changes; in
// a session, it removes the firewall rules.
func (c *Client) Close() error {
	if c.conn != nil {
		_ = c.conn.Close()
	}
	_ = c.stdin.Close()
	select {
	case <-c.exited:
		var ee *exec.ExitError
		if c.exitErr != nil && !errors.As(c.exitErr, &ee) {
			return c.exitErr
		}
	case <-time.After(10 * time.Second):
		c.log.Warn("helper did not exit in time")
	}
	return nil
}

// kill interrupts sudo, which forwards the signal to the helper.
func (c *Client) kill() {
	_ = c.cmd.Process.Signal(syscall.SIGINT)
	select {
	case <-c.exited:
	case <-time.After(5 * time.Second):
	}
}

// runtimeDir is a directory only this user can enter, for the helper socket.
func runtimeDir() (string, error) {
	base, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(base, "subtun", "run")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return "", err
	}
	if err := checkPrivate(dir, os.Getuid()); err != nil {
		return "", err
	}
	return dir, nil
}

// checkPrivate verifies that path is owned by uid and not accessible to
// group or others.
func checkPrivate(path string, uid int) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%s: can't read owner", path)
	}
	if int(st.Uid) != uid {
		return fmt.Errorf("%s is owned by uid %d, not %d", path, st.Uid, uid)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s is accessible to other users (%v)", path, fi.Mode().Perm())
	}
	return nil
}
