package capture

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/md2k/subnet-tunnel/internal/dns"
	"github.com/md2k/subnet-tunnel/internal/platform"
)

// DNSOptions configures DNS capture.
type DNSOptions struct {
	Match    *dns.Matcher
	Servers  []netip.Addr     // captured: the system's DNS servers, or a pinned list
	Auto     bool             // follow the system's servers when the network changes
	Fallback []netip.AddrPort // for names not matched; nil: the captured servers
	Tunnel   dns.Upstream     // resolves matched names through the agent
}

// dnsRuntime is the running DNS engine: listener, fallback forwarder and the
// servers currently captured.
type dnsRuntime struct {
	opts       *DNSOptions
	servers    atomic.Pointer[[]netip.Addr]
	pc         net.PacketConn
	ln         net.Listener
	listenPort uint16
	fwd        *dns.Forwarder
	bypassPort uint16
	cancel     context.CancelFunc
	wg         sync.WaitGroup
}

// startDNS starts the engine. It keeps answering after ctx ends, until
// close: the firewall may still redirect queries to it until the helper has
// removed the rules.
func startDNS(ctx context.Context, opts *DNSOptions, log *slog.Logger) (*dnsRuntime, error) {
	pc, ln, port, err := dns.Listen()
	if err != nil {
		return nil, err
	}
	bpc, bport, dial, err := dns.ListenBypass()
	if err != nil {
		_ = pc.Close()
		_ = ln.Close()
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	r := &dnsRuntime{opts: opts, pc: pc, ln: ln, listenPort: port, bypassPort: bport, cancel: cancel}
	servers := opts.Servers
	r.servers.Store(&servers)
	r.fwd = dns.NewForwarder(bpc, dial, r.fallback)
	eng := &dns.Engine{Match: opts.Match, Tunnel: opts.Tunnel, Fallback: r.fwd, Log: log}
	r.wg.Add(2)
	go func() {
		defer r.wg.Done()
		if err := eng.ServeUDP(ctx, pc); err != nil {
			log.Warn("DNS listener (udp) stopped", "err", err)
		}
	}()
	go func() {
		defer r.wg.Done()
		if err := eng.ServeTCP(ctx, ln); err != nil {
			log.Warn("DNS listener (tcp) stopped", "err", err)
		}
	}()
	return r, nil
}

// fallback is where unmatched names go: the configured fallback, else the
// servers the query was meant for.
func (r *dnsRuntime) fallback() []netip.AddrPort {
	if r.opts.Fallback != nil {
		return r.opts.Fallback
	}
	servers := *r.servers.Load()
	out := make([]netip.AddrPort, len(servers))
	for i, a := range servers {
		out[i] = netip.AddrPortFrom(a, 53)
	}
	return out
}

func (r *dnsRuntime) redirect() *platform.DNSRedirect {
	return &platform.DNSRedirect{
		Servers:    *r.servers.Load(),
		ListenPort: r.listenPort,
		BypassPort: r.bypassPort,
	}
}

func (r *dnsRuntime) logReady(log *slog.Logger) {
	log.Info("DNS capture ready", "servers", *r.servers.Load(), "fallback", r.fallback(), "following_system", r.opts.Auto)
}

// follow re-points the capture when the system's DNS servers change
// (network switch, VPN up or down): apply re-sends the firewall rules.
func (r *dnsRuntime) follow(ctx context.Context, interval time.Duration, log *slog.Logger, apply func() error) {
	read := func() ([]netip.Addr, []string, error) { return dns.SystemServers(dns.ResolvConf) }
	dns.WatchServers(ctx, interval, *r.servers.Load(), read, func(servers []netip.Addr, notes []string) {
		r.servers.Store(&servers)
		for _, n := range notes {
			log.Warn(n)
		}
		if err := apply(); err != nil {
			if ctx.Err() == nil {
				log.Warn("DNS servers changed, but updating the capture failed", "servers", servers, "err", err)
			}
			return
		}
		log.Info("DNS servers changed, capture follows", "servers", servers)
	})
}

func (r *dnsRuntime) close() {
	r.cancel()
	_ = r.pc.Close()
	_ = r.ln.Close()
	_ = r.fwd.Close()
	r.wg.Wait()
}
