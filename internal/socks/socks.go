// Package socks is a minimal SOCKS5 server (RFC 1928): no authentication and
// CONNECT only. Hostnames are passed to the dialer unresolved, so with
// `curl --socks5-hostname` or similar they resolve on the far side of the
// tunnel.
package socks

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"time"

	"github.com/md2k/subnet-tunnel/internal/proto"
	"github.com/md2k/subnet-tunnel/internal/relay"
)

// Dialer opens the upstream connection, normally *tunnel.Client.
type Dialer interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

// Server accepts SOCKS5 clients and connects them through Dialer.
type Server struct {
	Dialer      Dialer
	Logger      *slog.Logger  // nil: discard
	DialTimeout time.Duration // 0: 15s
}

const handshakeTimeout = 15 * time.Second

// Reply codes (RFC 1928 §6).
const (
	repSucceeded          = 0x00
	repFailure            = 0x01
	repNetworkUnreachable = 0x03
	repHostUnreachable    = 0x04
	repConnRefused        = 0x05
	repCmdNotSupported    = 0x07
	repAddrNotSupported   = 0x08
)

// Serve accepts connections on ln until ctx is cancelled or ln fails.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	if s.Logger == nil {
		s.Logger = slog.New(slog.DiscardHandler)
	}
	if s.DialTimeout == 0 {
		s.DialTimeout = 15 * time.Second
	}
	stop := context.AfterFunc(ctx, func() { _ = ln.Close() })
	defer stop()
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go s.handle(ctx, c)
	}
}

func (s *Server) handle(ctx context.Context, c net.Conn) {
	_ = c.SetDeadline(time.Now().Add(handshakeTimeout))
	addr, err := Handshake(c)
	if err != nil {
		s.Logger.Debug("socks handshake failed", "client", c.RemoteAddr(), "err", err)
		_ = c.Close()
		return
	}

	dctx, cancel := context.WithTimeout(ctx, s.DialTimeout)
	up, err := s.Dialer.DialContext(dctx, "tcp", addr)
	cancel()
	if err != nil {
		s.Logger.Info("connect failed", "dst", addr, "err", err)
		_ = writeReply(c, replyFor(err))
		_ = c.Close()
		return
	}
	if err := writeReply(c, repSucceeded); err != nil {
		_ = up.Close()
		_ = c.Close()
		return
	}
	_ = c.SetDeadline(time.Time{})

	start := time.Now()
	s.Logger.Debug("connected", "dst", addr)
	sent, recv := relay.Pipe(c, up)
	attrs := append([]any{"dst", addr}, sent.Attrs("sent")...)
	attrs = append(attrs, recv.Attrs("recv")...)
	s.Logger.Debug("closed", append(attrs, "dur", time.Since(start).Round(time.Millisecond))...)
}

// Handshake runs the SOCKS5 greeting and request on c and returns the
// requested "host:port". On a protocol error it sends the matching failure
// reply (where the protocol allows one) and returns an error; on success no
// reply has been sent yet.
func Handshake(c io.ReadWriter) (string, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(c, hdr[:]); err != nil {
		return "", err
	}
	if hdr[0] != 5 {
		return "", fmt.Errorf("not SOCKS5 (version byte %d)", hdr[0])
	}
	methods := make([]byte, hdr[1])
	if _, err := io.ReadFull(c, methods); err != nil {
		return "", err
	}
	noAuth := false
	for _, m := range methods {
		if m == 0x00 {
			noAuth = true
		}
	}
	if !noAuth {
		_, _ = c.Write([]byte{5, 0xff})
		return "", errors.New("client offers no acceptable auth method (only 'no auth' is supported)")
	}
	if _, err := c.Write([]byte{5, 0x00}); err != nil {
		return "", err
	}

	var req [4]byte // VER CMD RSV ATYP
	if _, err := io.ReadFull(c, req[:]); err != nil {
		return "", err
	}
	if req[0] != 5 {
		return "", fmt.Errorf("bad request version %d", req[0])
	}

	var host string
	switch req[3] {
	case 0x01:
		var ip [4]byte
		if _, err := io.ReadFull(c, ip[:]); err != nil {
			return "", err
		}
		host = net.IP(ip[:]).String()
	case 0x04:
		var ip [16]byte
		if _, err := io.ReadFull(c, ip[:]); err != nil {
			return "", err
		}
		host = net.IP(ip[:]).String()
	case 0x03:
		var n [1]byte
		if _, err := io.ReadFull(c, n[:]); err != nil {
			return "", err
		}
		name := make([]byte, n[0])
		if _, err := io.ReadFull(c, name); err != nil {
			return "", err
		}
		host = string(name)
	default:
		_ = writeReply(c, repAddrNotSupported)
		return "", fmt.Errorf("unsupported address type %d", req[3])
	}
	var port [2]byte
	if _, err := io.ReadFull(c, port[:]); err != nil {
		return "", err
	}
	if req[1] != 0x01 {
		_ = writeReply(c, repCmdNotSupported)
		return "", fmt.Errorf("unsupported command %d (only CONNECT)", req[1])
	}
	if host == "" {
		_ = writeReply(c, repAddrNotSupported)
		return "", errors.New("empty host")
	}
	return net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(port[:])))), nil
}

func writeReply(w io.Writer, rep byte) error {
	// BND.ADDR/BND.PORT are not meaningful through the tunnel: 0.0.0.0:0.
	_, err := w.Write([]byte{5, rep, 0, 0x01, 0, 0, 0, 0, 0, 0})
	return err
}

func replyFor(err error) byte {
	var de *proto.DialError
	if errors.As(err, &de) {
		switch de.Status {
		case proto.StatusRefused:
			return repConnRefused
		case proto.StatusUnreachable:
			return repNetworkUnreachable
		case proto.StatusTimeout, proto.StatusDNS:
			return repHostUnreachable
		}
	}
	return repFailure
}
