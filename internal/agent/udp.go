package agent

import (
	"context"
	"errors"
	"net"
	"syscall"
	"time"

	"github.com/xtaci/smux"

	"github.com/md2k/subnet-tunnel/internal/proto"
)

// handleUDP relays one UDP flow: datagrams from the stream go to req.Addr
// from a socket of the agent's own, and what comes back goes into the
// stream, until subtun closes the stream (the flow went idle) or the
// session ends. An ICMP "port unreachable" for a datagram doesn't end the
// flow: the next datagram may get through.
func handleUDP(ctx context.Context, st *smux.Stream, req proto.Request, cfg Config) {
	log := cfg.Logger.With("stream", st.ID(), "addr", req.Addr)
	dctx, cancel := context.WithTimeout(ctx, cfg.DialTimeout)
	c, err := cfg.Dialer.DialContext(dctx, "udp", req.Addr)
	cancel()
	if err != nil {
		log.Debug("udp dial failed", "err", err)
		_ = proto.WriteResponse(st, proto.Response{Status: StatusFor(err), Msg: err.Error()})
		return
	}
	defer c.Close()
	if err := proto.WriteResponse(st, proto.Response{Status: proto.StatusOK}); err != nil {
		return
	}
	start := time.Now()
	var up, down int
	done := make(chan struct{})
	go func() { // the target's answers into the stream
		defer close(done)
		buf := make([]byte, proto.MaxDatagramLen)
		for {
			n, err := c.Read(buf)
			if err != nil {
				if errors.Is(err, syscall.ECONNREFUSED) {
					continue // an ICMP error for an earlier datagram
				}
				_ = st.Close()
				return
			}
			if proto.WriteDatagram(st, buf[:n]) != nil {
				return
			}
			down += n
		}
	}()
	buf := make([]byte, proto.MaxDatagramLen)
	for {
		n, err := proto.ReadDatagram(st, buf)
		if err != nil {
			break
		}
		if _, err := c.Write(buf[:n]); err != nil && !errors.Is(err, syscall.ECONNREFUSED) {
			var ne net.Error
			if !errors.As(err, &ne) {
				break
			}
		}
		up += n
	}
	_ = c.Close()
	<-done
	log.Debug("udp flow closed", "up", up, "down", down, "dur", time.Since(start).Round(time.Millisecond))
}
