// Package tunnel is the laptop end of the tunnel: it checks the agent's hello,
// runs the multiplexer over the carrier and opens connections through it.
package tunnel

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/xtaci/smux"

	"github.com/md2k/subnet-tunnel/internal/proto"
)

// Options configures NewClient.
type Options struct {
	// ExpectSHA256, if set, must match the sha256 the agent reports for its
	// own binary. It catches truncated uploads and stale agents.
	ExpectSHA256 string
	Logger       *slog.Logger
}

// Client opens connections through one agent session.
type Client struct {
	sess  *smux.Session
	hello proto.Hello
	log   *slog.Logger
}

// NewClient reads the agent hello from conn and starts the multiplexer.
// ctx bounds the hello wait only; once NewClient returns, the session lives
// until Close or until the carrier fails. conn is closed if NewClient fails.
func NewClient(ctx context.Context, conn io.ReadWriteCloser, opts Options) (*Client, error) {
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.DiscardHandler)
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	hello, err := proto.ReadHello(conn)
	if !stop() {
		_ = conn.Close()
		return nil, fmt.Errorf("waiting for agent hello: %w", ctx.Err())
	}
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	if hello.Proto != proto.Version {
		_ = conn.Close()
		return nil, fmt.Errorf("agent speaks protocol %d, this subtun speaks %d", hello.Proto, proto.Version)
	}
	if opts.ExpectSHA256 != "" && hello.SHA256 != "" && hello.SHA256 != opts.ExpectSHA256 {
		_ = conn.Close()
		return nil, fmt.Errorf("agent binary checksum mismatch: running %s, uploaded %s", short(hello.SHA256), short(opts.ExpectSHA256))
	}
	sess, err := smux.Client(conn, proto.MuxConfig())
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	c := &Client{sess: sess, hello: hello, log: opts.Logger}
	go c.watch()
	return c, nil
}

// watch ends the session as soon as the carrier fails. smux only records a
// carrier read error and leaves closing to the keepalive timeout; blocking in
// AcceptStream surfaces it immediately. The agent never opens streams.
func (c *Client) watch() {
	for {
		st, err := c.sess.AcceptStream()
		if err != nil {
			_ = c.sess.Close()
			return
		}
		c.log.Warn("agent opened an unexpected stream, closing it", "stream", st.ID())
		_ = st.Close()
	}
}

// Agent returns the hello the agent sent.
func (c *Client) Agent() proto.Hello { return c.hello }

// Done is closed when the session ends (carrier lost or Close called).
func (c *Client) Done() <-chan struct{} { return c.sess.CloseChan() }

// Close ends the session and every stream in it.
func (c *Client) Close() error { return c.sess.Close() }

// DialContext opens a TCP connection ("tcp") or a UDP flow ("udp") to addr
// from the agent's side. addr may use a hostname; it is resolved by the
// agent. A failure reported by the agent is a *proto.DialError. A UDP flow
// reads and writes one datagram per call.
func (c *Client) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	cmd := proto.CmdConnectTCP
	switch network {
	case "tcp", "tcp4", "tcp6":
	case "udp", "udp4", "udp6":
		cmd = proto.CmdUDP
	default:
		return nil, fmt.Errorf("tunnel: unsupported network %q", network)
	}
	st, err := c.sess.OpenStream()
	if err != nil {
		return nil, fmt.Errorf("tunnel: open stream: %w", err)
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = st.SetDeadline(dl)
	}
	stop := context.AfterFunc(ctx, func() { _ = st.SetDeadline(time.Now()) })

	resp, err := handshake(st, cmd, addr)
	if !stop() {
		_ = st.Close()
		return nil, ctx.Err()
	}
	if err != nil {
		_ = st.Close()
		if errors.Is(err, smux.ErrTimeout) && ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("tunnel: dial %s: %w", addr, err)
	}
	if resp.Status != proto.StatusOK {
		_ = st.Close()
		return nil, &proto.DialError{Addr: addr, Status: resp.Status, Msg: resp.Msg}
	}
	_ = st.SetDeadline(time.Time{})
	if cmd == proto.CmdUDP {
		return &datagramConn{Stream: st}, nil
	}
	return st, nil
}

// datagramConn is a UDP flow through the agent: each Write sends one
// datagram, each Read returns one (a buffer too small for it is an error).
type datagramConn struct {
	*smux.Stream
	rmu sync.Mutex
}

func (d *datagramConn) Read(p []byte) (int, error) {
	d.rmu.Lock()
	defer d.rmu.Unlock()
	return proto.ReadDatagram(d.Stream, p)
}

func (d *datagramConn) Write(p []byte) (int, error) {
	if err := proto.WriteDatagram(d.Stream, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

// WriteTo copies the flow's datagrams to w, one Write each (the stream's
// own WriteTo would copy the framing).
func (d *datagramConn) WriteTo(w io.Writer) (int64, error) {
	buf := make([]byte, proto.MaxDatagramLen)
	var total int64
	for {
		n, err := d.Read(buf)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return total, nil
			}
			return total, err
		}
		m, err := w.Write(buf[:n])
		total += int64(m)
		if err != nil {
			return total, err
		}
	}
}

// ExchangeDNS sends one DNS query through the agent to the target's own
// resolver and returns the answer. A failure reported by the agent is a
// *proto.DialError.
func (c *Client) ExchangeDNS(ctx context.Context, query []byte) ([]byte, error) {
	st, err := c.sess.OpenStream()
	if err != nil {
		return nil, fmt.Errorf("tunnel: open stream: %w", err)
	}
	defer st.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = st.SetDeadline(dl)
	}
	stop := context.AfterFunc(ctx, func() { _ = st.SetDeadline(time.Now()) })
	defer stop()

	answer, err := exchangeDNS(st, query)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("tunnel: DNS: %w", err)
	}
	return answer, nil
}

func exchangeDNS(st *smux.Stream, query []byte) ([]byte, error) {
	if err := proto.WriteRequest(st, proto.Request{Cmd: proto.CmdDNS, Addr: proto.ResolverSystem}); err != nil {
		return nil, err
	}
	if err := proto.WriteDNS(st, query); err != nil {
		return nil, err
	}
	resp, err := proto.ReadResponse(st)
	if err != nil {
		return nil, err
	}
	if resp.Status != proto.StatusOK {
		return nil, &proto.DialError{Addr: "target resolver", Status: resp.Status, Msg: resp.Msg}
	}
	return proto.ReadDNS(st)
}

func handshake(st *smux.Stream, cmd proto.Cmd, addr string) (proto.Response, error) {
	if err := proto.WriteRequest(st, proto.Request{Cmd: cmd, Addr: addr}); err != nil {
		return proto.Response{}, err
	}
	return proto.ReadResponse(st)
}

func short(sum string) string {
	if len(sum) > 12 {
		return sum[:12]
	}
	return sum
}
