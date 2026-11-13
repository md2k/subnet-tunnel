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
	// Tunnel answers pointing at addresses Unreachable reports (private, no
	// route covers them) are handled by Unrouted (dns.unrouted); nil: no
	// check.
	Unrouted    string
	Unreachable func(netip.Addr) bool
}

// Engine builds the DNS engine for these options.
func (o *DNSOptions) Engine(fallback dns.TCPUpstream, log *slog.Logger) *dns.Engine {
	e := &dns.Engine{Match: o.Match, Tunnel: o.Tunnel, Fallback: fallback, Log: log}
	if o.Unreachable != nil {
		e.Unrouted = &dns.Unrouted{Mode: o.Unrouted, Unreachable: o.Unreachable, Log: log}
	}
	return e
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
	eng := opts.Engine(r.fwd, log)
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
	attrs := []any{"servers", *r.servers.Load(), "fallback", r.fallback(), "following_system", r.opts.Auto}
	if r.opts.Match.CatchAll() {
		attrs = append(attrs, "stay_local", r.opts.Match.Local())
	}
	log.Info("DNS capture ready", attrs...)
}

// follow re-points the capture when the system's DNS servers change
// (network switch, VPN up or down): apply re-sends the firewall rules.
func (r *dnsRuntime) follow(ctx context.Context, interval time.Duration, log *slog.Logger, apply func() error) {
	read := func() ([]netip.Addr, []string, error) {
		servers, notes, err := dns.SystemServers(dns.ResolvConf)
		// The search domains change with the network too; skip the moments
		// mid-change when the file is empty.
		if err == nil && len(servers) > 0 && r.opts.Match.CatchAll() {
			if search, err := dns.SearchDomains(dns.ResolvConf); err == nil && r.opts.Match.SetLocal(search) {
				log.Info("DNS search domains changed; names under them stay local", "stay_local", r.opts.Match.Local())
			}
		}
		return servers, notes, err
	}
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
