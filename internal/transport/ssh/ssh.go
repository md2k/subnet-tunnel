// Package ssh runs the agent on a host reached over SSH, as the login user,
// the way sshuttle does: nothing to install there but sshd and a POSIX sh
// (the binary agent on Linux, the Python agent elsewhere).
//
// The client is built in (golang.org/x/crypto/ssh). It connects the way
// OpenSSH would: ~/.ssh/config as ssh -G resolves it, the agent and key
// files, certificates, known_hosts, ProxyJump and ProxyCommand. Logins are by
// key only.
package ssh

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/md2k/subnet-tunnel/internal/agentbin"
	"github.com/md2k/subnet-tunnel/internal/config"
	"github.com/md2k/subnet-tunnel/internal/transport"
)

// Target is a host to run the agent on. Unset fields come from
// ~/.ssh/config.
type Target struct {
	Host     string // a name, an address, or a ~/.ssh/config Host
	User     string
	Port     int
	Identity string // a private key file, tried first
	Jump     string // ProxyJump: [user@]host[:port], comma-separated
}

const (
	dialTimeout      = 30 * time.Second
	handshakeTimeout = 2 * time.Minute // long enough to answer a host key or passphrase question
)

// Connect logs in to t, starts the agent there and returns its carrier;
// closing the carrier closes the SSH connection.
func Connect(ctx context.Context, t Target, agents []agentbin.Binary, opts transport.Options, log *slog.Logger) (*transport.Carrier, error) {
	c, err := dial(ctx, t, log)
	if err != nil {
		return nil, err
	}
	ex := &sshExec{client: c.client, desc: c.desc}
	carrier, err := transport.Bootstrap(ctx, ex, agents, opts, log.With("host", c.desc))
	if err != nil {
		c.close()
		return nil, err
	}
	carrier.ReadWriteCloser = &closeBoth{ReadWriteCloser: carrier.ReadWriteCloser, also: c.close}
	carrier.Host = c.first
	if ap, err := netip.ParseAddrPort(c.firstAddr); err == nil {
		carrier.Endpoints = []netip.Addr{ap.Addr().Unmap()}
	}
	carrier.Local = c.first != "" && transport.IsLocal(c.first, carrier.Endpoints)
	return carrier, nil
}

// Endpoint is the address subtun's own SSH connection goes to: the first
// jump host, or the host itself; "" behind a ProxyCommand (whatever it
// connects to isn't known).
func Endpoint(t Target) (string, error) {
	ctx := context.Background()
	c, err := resolve(ctx, t.Host, t.User, t.Port, t.Identity, t.Jump)
	if err != nil {
		return "", err
	}
	switch {
	case set(c.proxyCmd):
		return "", nil
	case set(c.jump):
		hc, err := resolveHop(ctx, firstHop(c.jump))
		if err != nil {
			return "", err
		}
		return hc.addr(), nil
	}
	return c.addr(), nil
}

// set reports whether a ProxyJump or ProxyCommand value is one.
func set(v string) bool { return v != "" && v != "none" }

func firstHop(jump string) string {
	hop, _, _ := strings.Cut(jump, ",")
	return strings.TrimSpace(hop)
}

func resolveHop(ctx context.Context, hop string) (*hostConfig, error) {
	user, host, port, err := config.SplitSSHHost(strings.TrimPrefix(hop, "ssh://"))
	if err != nil {
		return nil, fmt.Errorf("ProxyJump %v", err)
	}
	return resolve(ctx, host, user, port, "", "")
}

// conn is a logged-in SSH connection, through its jump hosts.
type conn struct {
	client    *ssh.Client
	hops      []*ssh.Client // the jump hosts', outermost first
	desc      string
	first     string // host:port of the TCP connection; "" behind a ProxyCommand
	firstAddr string // its resolved address
	stopAlive func()
	once      sync.Once
}

func (c *conn) close() {
	c.once.Do(func() {
		if c.stopAlive != nil {
			c.stopAlive()
		}
		if c.client != nil {
			_ = c.client.Close()
		}
		for i := len(c.hops) - 1; i >= 0; i-- {
			_ = c.hops[i].Close()
		}
	})
}

func dial(ctx context.Context, t Target, log *slog.Logger) (*conn, error) {
	dest, err := resolve(ctx, t.Host, t.User, t.Port, t.Identity, t.Jump)
	if err != nil {
		return nil, err
	}
	c := &conn{desc: dest.user + "@" + dest.addr()}
	var raw net.Conn
	switch {
	case set(dest.proxyCmd):
		c.desc += " (proxy command)"
		if raw, err = proxyCommand(dest, log); err != nil {
			return nil, err
		}
	case set(dest.jump):
		var via *ssh.Client
		for _, hop := range strings.Split(dest.jump, ",") {
			hc, err := resolveHop(ctx, strings.TrimSpace(hop))
			if err != nil {
				c.close()
				return nil, err
			}
			var hr net.Conn
			if via == nil {
				hr, err = dialTCP(ctx, hc)
				if err == nil {
					c.first, c.firstAddr = hc.addr(), hr.RemoteAddr().String()
				}
			} else {
				hr, err = via.DialContext(ctx, "tcp", hc.addr())
			}
			if err != nil {
				c.close()
				return nil, fmt.Errorf("jump host %s: %w", hc.addr(), err)
			}
			if via, err = handshake(ctx, hr, hc, log); err != nil {
				c.close()
				return nil, fmt.Errorf("jump host: %w", err)
			}
			c.hops = append(c.hops, via)
		}
		c.desc += " via " + dest.jump
		if raw, err = via.DialContext(ctx, "tcp", dest.addr()); err != nil {
			c.close()
			return nil, fmt.Errorf("%s through the jump host: %w", dest.addr(), err)
		}
	default:
		if raw, err = dialTCP(ctx, dest); err != nil {
			return nil, err
		}
		c.first, c.firstAddr = dest.addr(), raw.RemoteAddr().String()
	}
	if c.client, err = handshake(ctx, raw, dest, log); err != nil {
		c.close()
		return nil, err
	}
	c.stopAlive = keepalive(c.client, dest.alive, dest.aliveMax, log)
	return c, nil
}

func dialTCP(ctx context.Context, c *hostConfig) (net.Conn, error) {
	timeout := c.timeout
	if timeout <= 0 {
		timeout = dialTimeout
	}
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", c.addr())
	if err != nil {
		return nil, fmt.Errorf("ssh %s: %w", c.addr(), err)
	}
	return conn, nil
}

// handshake logs in over raw, which it owns from now on.
func handshake(ctx context.Context, raw net.Conn, hc *hostConfig, log *slog.Logger) (*ssh.Client, error) {
	au, err := newAuth(ctx, hc, log)
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	defer au.close()
	hk, err := newHostKeys(ctx, hc, log)
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	cfg := &ssh.ClientConfig{
		User:              hc.user,
		Auth:              []ssh.AuthMethod{au.method()},
		HostKeyCallback:   hk.callback,
		HostKeyAlgorithms: hk.algorithms(hc.addr()),
	}
	stop := context.AfterFunc(ctx, func() { _ = raw.Close() })
	_ = raw.SetDeadline(time.Now().Add(handshakeTimeout))
	sc, chans, reqs, err := ssh.NewClientConn(raw, hc.addr(), cfg)
	stop()
	if err != nil {
		_ = raw.Close()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("ssh %s@%s: %w", hc.user, hc.addr(), err)
	}
	_ = raw.SetDeadline(time.Time{})
	return ssh.NewClient(sc, chans, reqs), nil
}

// keepalive asks the server every interval (ServerAliveInterval) and
// closes the connection when it hasn't answered max (ServerAliveCountMax)
// intervals long: a dead network shows up without waiting for TCP.
func keepalive(client *ssh.Client, every time.Duration, max int, log *slog.Logger) func() {
	if every <= 0 {
		return func() {}
	}
	done := make(chan struct{})
	go func() {
		tick := time.NewTicker(every)
		defer tick.Stop()
		for {
			select {
			case <-done:
				return
			case <-tick.C:
			}
			answered := make(chan error, 1)
			go func() {
				_, _, err := client.SendRequest("keepalive@openssh.com", true, nil)
				answered <- err
			}()
			select {
			case err := <-answered:
				if err != nil {
					return // closed
				}
			case <-time.After(every * time.Duration(max)):
				log.Warn("the SSH server stopped answering: closing the connection")
				_ = client.Close()
				return
			case <-done:
				return
			}
		}
	}()
	return sync.OnceFunc(func() { close(done) })
}

// proxyCommand runs ProxyCommand (OpenSSH's %h %p %r %n tokens) and talks
// SSH over its stdin and stdout.
func proxyCommand(c *hostConfig, log *slog.Logger) (net.Conn, error) {
	line := strings.NewReplacer("%%", "%", "%h", c.hostname, "%p", strconv.Itoa(c.port), "%r", c.user, "%n", c.alias).Replace(c.proxyCmd)
	cmd := exec.Command("/bin/sh", "-c", "exec "+line)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	cmd.Stderr = &transport.LineLog{Log: log, Prefix: "proxy command: "}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("ProxyCommand %q: %w", line, err)
	}
	return &cmdConn{cmd: cmd, w: stdin, r: stdout}, nil
}

// cmdConn is a command's stdio as a connection.
type cmdConn struct {
	cmd  *exec.Cmd
	w    io.WriteCloser
	r    io.Reader
	once sync.Once
}

func (c *cmdConn) Read(p []byte) (int, error)  { return c.r.Read(p) }
func (c *cmdConn) Write(p []byte) (int, error) { return c.w.Write(p) }
func (c *cmdConn) Close() error {
	c.once.Do(func() {
		_ = c.w.Close()
		_ = c.cmd.Process.Kill()
		_ = c.cmd.Wait()
	})
	return nil
}
func (c *cmdConn) LocalAddr() net.Addr              { return cmdAddr{} }
func (c *cmdConn) RemoteAddr() net.Addr             { return cmdAddr{} }
func (c *cmdConn) SetDeadline(time.Time) error      { return nil }
func (c *cmdConn) SetReadDeadline(time.Time) error  { return nil }
func (c *cmdConn) SetWriteDeadline(time.Time) error { return nil }

type cmdAddr struct{}

func (cmdAddr) Network() string { return "proxycommand" }
func (cmdAddr) String() string  { return "proxycommand" }

// sshExec runs commands on the host, each in its own session of one
// connection.
type sshExec struct {
	client *ssh.Client
	desc   string
}

func (e *sshExec) Describe() string { return "ssh " + e.desc }

func (e *sshExec) Run(ctx context.Context, cmd []string, stdin io.Reader) (string, error) {
	s, err := e.client.NewSession()
	if err != nil {
		return "", err
	}
	defer s.Close()
	var stdout, stderr bytes.Buffer
	s.Stdin, s.Stdout, s.Stderr = stdin, &stdout, &stderr
	done := make(chan error, 1)
	go func() { done <- s.Run(shellJoin(cmd)) }()
	select {
	case err = <-done:
	case <-ctx.Done():
		_ = s.Signal(ssh.SIGKILL)
		_ = s.Close()
		return "", ctx.Err()
	}
	var exit *ssh.ExitError
	if errors.As(err, &exit) {
		return "", fmt.Errorf("command exited with status %d: %s", exit.ExitStatus(), strings.TrimSpace(stderr.String()))
	}
	if err != nil {
		return "", err
	}
	return stdout.String(), nil
}

func (e *sshExec) Stream(ctx context.Context, cmd []string, stderr io.Writer) (io.ReadWriteCloser, error) {
	s, err := e.client.NewSession()
	if err != nil {
		return nil, err
	}
	s.Stderr = stderr
	w, err := s.StdinPipe()
	if err != nil {
		_ = s.Close()
		return nil, err
	}
	r, err := s.StdoutPipe()
	if err != nil {
		_ = s.Close()
		return nil, err
	}
	if err := s.Start(shellJoin(cmd)); err != nil {
		_ = s.Close()
		return nil, err
	}
	st := &stream{Reader: r, w: w, s: s}
	st.stop = context.AfterFunc(ctx, func() { _ = st.Close() })
	return st, nil
}

type stream struct {
	io.Reader
	w    io.WriteCloser
	s    *ssh.Session
	stop func() bool
	once sync.Once
}

func (st *stream) Write(p []byte) (int, error) { return st.w.Write(p) }

func (st *stream) Close() error {
	st.once.Do(func() {
		st.stop()
		_ = st.w.Close()
		_ = st.s.Close()
	})
	return nil
}

// closeBoth closes the carrier, then the connection it runs on.
type closeBoth struct {
	io.ReadWriteCloser
	also func()
}

func (c *closeBoth) Close() error {
	err := c.ReadWriteCloser.Close()
	c.also()
	return err
}

// shellJoin makes the command line the remote login shell runs: each
// argument single-quoted unless it's plain.
func shellJoin(cmd []string) string {
	parts := make([]string, len(cmd))
	for i, a := range cmd {
		parts[i] = shellQuote(a)
	}
	return strings.Join(parts, " ")
}

func shellQuote(s string) string {
	if s != "" && strings.Trim(s, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_@%+=:,./-") == "" {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
