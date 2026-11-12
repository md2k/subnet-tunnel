// Package agent is the remote end of the tunnel. It runs inside the target
// (pod, container or host), serves the multiplexer on the carrier connection
// (normally its own stdin/stdout) and opens the connections subtun asks for,
// from inside the target's network.
package agent

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"syscall"
	"time"

	"github.com/xtaci/smux"

	"github.com/md2k/subnet-tunnel/internal/proto"
	"github.com/md2k/subnet-tunnel/internal/relay"
)

// Dialer opens outbound connections ("tcp", and "udp" for DNS). *net.Dialer
// satisfies it.
type Dialer interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

// Config configures Serve.
type Config struct {
	Version     string        // agent build version, sent in the hello
	SHA256      string        // hex sha256 of the agent binary, sent in the hello
	Dialer      Dialer        // nil: net.Dialer
	DialTimeout time.Duration // 0: 10s
	ResolvConf  string        // resolver config for DNS queries; "": /etc/resolv.conf
	Logger      *slog.Logger  // nil: discard
}

const requestTimeout = 30 * time.Second

// Serve writes the hello, then accepts streams until conn closes or ctx is
// cancelled. A closed carrier is the normal way for a session to end and
// returns nil.
func Serve(ctx context.Context, conn io.ReadWriteCloser, cfg Config) error {
	if cfg.Dialer == nil {
		cfg.Dialer = &net.Dialer{}
	}
	if cfg.DialTimeout == 0 {
		cfg.DialTimeout = 10 * time.Second
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	log := cfg.Logger

	hello := proto.Hello{Proto: proto.Version, Version: cfg.Version, SHA256: cfg.SHA256}
	if _, err := io.WriteString(conn, hello.Line()); err != nil {
		return err
	}
	sess, err := smux.Server(conn, proto.MuxConfig())
	if err != nil {
		return err
	}
	defer sess.Close()
	stop := context.AfterFunc(ctx, func() { _ = sess.Close() })
	defer stop()

	log.Info("agent ready", "proto", proto.Version, "version", cfg.Version)
	for {
		st, err := sess.AcceptStream()
		if err != nil {
			if ctx.Err() != nil || sess.IsClosed() || errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) {
				log.Info("session closed")
				return nil
			}
			return err
		}
		go handle(ctx, st, cfg)
	}
}

func handle(ctx context.Context, st *smux.Stream, cfg Config) {
	log := cfg.Logger.With("stream", st.ID())
	defer st.Close()

	_ = st.SetReadDeadline(time.Now().Add(requestTimeout))
	req, err := proto.ReadRequest(st)
	if err != nil {
		log.Warn("bad request", "err", err)
		return
	}
	_ = st.SetReadDeadline(time.Time{})

	switch req.Cmd {
	case proto.CmdConnectTCP:
	case proto.CmdDNS:
		handleDNS(ctx, st, req, cfg)
		return
	default:
		_ = proto.WriteResponse(st, proto.Response{Status: proto.StatusBadRequest, Msg: "unsupported command"})
		return
	}

	dctx, cancel := context.WithTimeout(ctx, cfg.DialTimeout)
	c, err := cfg.Dialer.DialContext(dctx, "tcp", req.Addr)
	cancel()
	if err != nil {
		log.Debug("dial failed", "addr", req.Addr, "err", err)
		_ = proto.WriteResponse(st, proto.Response{Status: StatusFor(err), Msg: err.Error()})
		return
	}
	if err := proto.WriteResponse(st, proto.Response{Status: proto.StatusOK}); err != nil {
		_ = c.Close()
		return
	}
	start := time.Now()
	log.Debug("connected", "addr", req.Addr)
	up, down := relay.Pipe(st, c)
	log.Debug("closed", "addr", req.Addr, "up", up, "down", down, "dur", time.Since(start).Round(time.Millisecond))
}

// StatusFor maps a dial error to the status reported to the client.
func StatusFor(err error) proto.Status {
	var dnsErr *net.DNSError
	var netErr net.Error
	switch {
	case errors.As(err, &dnsErr):
		return proto.StatusDNS
	case errors.Is(err, syscall.ECONNREFUSED):
		return proto.StatusRefused
	case errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, syscall.ENETUNREACH):
		return proto.StatusUnreachable
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &netErr) && netErr.Timeout():
		return proto.StatusTimeout
	default:
		return proto.StatusFailure
	}
}
