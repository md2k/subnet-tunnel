package agent

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/xtaci/smux"

	"github.com/md2k/subnet-tunnel/internal/proto"
)

const (
	defaultResolvConf = "/etc/resolv.conf"
	dnsUDPTimeout     = 2 * time.Second
	dnsTCPTimeout     = 5 * time.Second
	dnsTotalTimeout   = 10 * time.Second
	maxNameservers    = 3 // like the C library
)

// handleDNS answers a CmdDNS stream: one query in, one answer out. The query
// goes unchanged to the target's resolver, so every record type works and the
// answer is exactly what the target itself would get.
func handleDNS(ctx context.Context, st *smux.Stream, req proto.Request, cfg Config) {
	log := cfg.Logger.With("stream", st.ID())
	if req.Addr != proto.ResolverSystem {
		_ = proto.WriteResponse(st, proto.Response{Status: proto.StatusBadRequest, Msg: "unsupported resolver " + req.Addr})
		return
	}
	_ = st.SetReadDeadline(time.Now().Add(requestTimeout))
	query, err := proto.ReadDNS(st)
	if err != nil {
		log.Warn("bad DNS query", "err", err)
		return
	}
	servers, err := nameservers(cfg.ResolvConf)
	if err != nil {
		_ = proto.WriteResponse(st, proto.Response{Status: proto.StatusFailure, Msg: err.Error()})
		return
	}
	qctx, cancel := context.WithTimeout(ctx, dnsTotalTimeout)
	defer cancel()
	answer, err := exchangeAny(qctx, cfg.Dialer, servers, query)
	if err != nil {
		log.Debug("DNS query failed", "err", err)
		_ = proto.WriteResponse(st, proto.Response{Status: StatusFor(err), Msg: err.Error()})
		return
	}
	if err := proto.WriteResponse(st, proto.Response{Status: proto.StatusOK}); err != nil {
		return
	}
	_ = proto.WriteDNS(st, answer)
}

// nameservers reads the resolver addresses ("ip:53") from a resolv.conf.
func nameservers(path string) ([]string, error) {
	if path == "" {
		path = defaultResolvConf
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() && len(out) < maxNameservers {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 || fields[0] != "nameserver" {
			continue
		}
		if a, err := netip.ParseAddr(fields[1]); err == nil {
			out = append(out, netip.AddrPortFrom(a, 53).String())
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no nameserver in %s", path)
	}
	return out, nil
}

// exchangeAny tries each server in turn: UDP first, TCP if the answer was
// truncated.
func exchangeAny(ctx context.Context, d Dialer, servers []string, query []byte) ([]byte, error) {
	var lastErr error
	for _, s := range servers {
		answer, err := exchange(ctx, d, "udp", s, query, dnsUDPTimeout)
		if err == nil && truncated(answer) {
			answer, err = exchange(ctx, d, "tcp", s, query, dnsTCPTimeout)
		}
		if err == nil {
			return answer, nil
		}
		lastErr = fmt.Errorf("%s: %w", s, err)
		if ctx.Err() != nil {
			break
		}
	}
	return nil, lastErr
}

func exchange(ctx context.Context, d Dialer, network, server string, query []byte, timeout time.Duration) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	c, err := d.DialContext(ctx, network, server)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	defer stop()
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	}

	if network == "tcp" {
		if err := proto.WriteDNS(c, query); err != nil {
			return nil, ctxErr(ctx, err)
		}
		answer, err := proto.ReadDNS(c)
		if err != nil {
			return nil, ctxErr(ctx, err)
		}
		if !answers(answer, query) {
			return nil, errors.New("answer does not match the query")
		}
		return answer, nil
	}

	if _, err := c.Write(query); err != nil {
		return nil, ctxErr(ctx, err)
	}
	buf := make([]byte, proto.MaxDNSLen)
	for {
		n, err := c.Read(buf)
		if err != nil {
			return nil, ctxErr(ctx, err)
		}
		// Ignore stray datagrams (late answers to an earlier try).
		if answers(buf[:n], query) {
			return append([]byte(nil), buf[:n]...), nil
		}
	}
}

// answers reports whether msg is a response with the query's ID.
func answers(msg, query []byte) bool {
	return len(msg) >= proto.MinDNSLen && msg[0] == query[0] && msg[1] == query[1] && msg[2]&0x80 != 0
}

// truncated reports the TC bit.
func truncated(msg []byte) bool { return len(msg) >= proto.MinDNSLen && msg[2]&0x02 != 0 }

// ctxErr prefers the deadline over the error caused by closing the
// connection when it fired.
func ctxErr(ctx context.Context, err error) error {
	if ctx.Err() != nil && (errors.Is(err, net.ErrClosed) || errors.Is(err, io.ErrClosedPipe) || errors.Is(err, os.ErrDeadlineExceeded)) {
		return ctx.Err()
	}
	return err
}
