package cli

import (
	"context"
	"log/slog"
	"net/netip"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/md2k/subnet-tunnel/internal/capture"
	"github.com/md2k/subnet-tunnel/internal/control"
	"github.com/md2k/subnet-tunnel/internal/dns"
	"github.com/md2k/subnet-tunnel/internal/logring"
	"github.com/md2k/subnet-tunnel/internal/meter"
	"github.com/md2k/subnet-tunnel/internal/version"
)

// Control modes (control / --control): status answers questions; full
// also takes changes while running; off has no socket.
const (
	controlStatus = "status"
	controlFull   = "full"
	controlOff    = "off"
)

// tunnelInfo is a tunnel's state for status, shared between the engine's
// loop, the tunnel's goroutine (reconnect attempts) and the control server.
type tunnelInfo struct {
	mu                sync.Mutex
	target, agent     string
	state             tunnelState
	since             time.Time
	attempt, attempts int
	nextTry           time.Time
	lastErr           string
	routesOn          bool
}

func (t *tunnelInfo) update(f func(*tunnelInfo)) {
	t.mu.Lock()
	f(t)
	t.mu.Unlock()
}

func (s tunnelState) String() string {
	switch s {
	case stateUp:
		return "up"
	case stateReconnecting:
		return "reconnecting"
	case stateGaveUp:
		return "gave up"
	case stateStopped:
		return "stopped"
	}
	return "connecting"
}

// engineStatus is what a run shares with its control socket.
type engineStatus struct {
	start     time.Time
	control   string
	mp        *multiPlan
	infos     []*tunnelInfo
	meters    []*meter.Meter
	dnsCounts []*dns.Counts
	fallback  *dns.Counts
	dnsOpts   *capture.DNSOptions // captured or development DNS; nil: none
	devDNS    bool                // dnsOpts is the development listener
	capt      atomic.Pointer[capture.Capture]
	// change makes a change through the engine's loop; nil: read only.
	change func(context.Context, control.Change) (control.Result, error)
}

// matcher is the run's DNS matcher; nil: no DNS.
func (es *engineStatus) matcher() *dns.Matcher {
	if es.dnsOpts == nil {
		return nil
	}
	return es.dnsOpts.Match
}

func newEngineStatus(mp *multiPlan, control string) *engineStatus {
	n := len(mp.specs)
	es := &engineStatus{start: time.Now(), control: control, mp: mp, infos: make([]*tunnelInfo, n),
		meters: make([]*meter.Meter, n), dnsCounts: make([]*dns.Counts, n), fallback: &dns.Counts{}}
	for i := range n {
		es.infos[i] = &tunnelInfo{since: es.start}
		es.meters[i] = meter.New()
		es.dnsCounts[i] = &dns.Counts{}
	}
	return es
}

// routesOn records which tunnels have all their routes on the utun.
func (es *engineStatus) routesOn(active []bool, onUtun []netip.Prefix) {
	for i, on := range active {
		in := on && !slices.ContainsFunc(es.mp.final(i), func(p netip.Prefix) bool { return !slices.Contains(onUtun, p) })
		es.infos[i].update(func(t *tunnelInfo) { t.routesOn = in })
	}
}

// sample takes the meters' 1 s samples until ctx ends.
func (es *engineStatus) sample(ctx context.Context) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			for _, m := range es.meters {
				m.Sample(now)
			}
		}
	}
}

// status is the run now.
func (es *engineStatus) status() control.Status {
	mp := es.mp
	st := control.Status{PID: os.Getpid(), Version: version.String(), Started: es.start, Control: es.control}
	c := es.capt.Load()
	if c != nil {
		st.BlockIPv6 = c.BlockingIPv6()
		st.Utun, st.TunAddr = c.Name, mp.tunAddr.String()
		st.Helper = "one-shot"
		if c.Session() {
			st.Helper = "session"
		}
	}
	mp.smu.RLock()
	defer mp.smu.RUnlock()
	for i, sp := range mp.specs {
		info := es.infos[i]
		info.mu.Lock()
		t := control.Tunnel{Name: sp.name, Target: info.target, Agent: info.agent, State: info.state.String(),
			Since: info.since, LastError: info.lastErr, RoutesOn: info.routesOn && c != nil, SOCKS: sp.s.socks}
		if info.state == stateReconnecting || info.state == stateConnecting && info.attempt > 0 {
			t.Attempt, t.Attempts, t.NextTry = info.attempt, info.attempts, info.nextTry
		}
		info.mu.Unlock()
		for _, p := range mp.final(i) {
			t.Routes = append(t.Routes, p.String())
		}
		if es.dnsOpts != nil {
			t.Domains, t.Patterns = mp.dnsNames[i].Domains, len(mp.dnsNames[i].Patterns)
		}
		if mp.ks[i] != "off" {
			t.KillSwitch = mp.ks[i]
		}
		t.Changes = runtimeChanges(sp.base, sp.s)
		t.Counts = es.meters[i].Counts()
		t.DNSCounts = control.DNSCounts{Answered: es.dnsCounts[i].Answered.Load(), Failed: es.dnsCounts[i].Failed.Load()}
		st.Tunnels = append(st.Tunnels, t)
	}
	if d := es.dnsOpts; d != nil {
		servers, fallback := d.Servers, d.Fallback
		if c != nil {
			if s, f := c.DNS(); s != nil {
				servers, fallback = s, f
			}
		}
		sd := &control.DNS{Development: es.devDNS, Follow: d.Auto && !es.devDNS, Own: d.Match.Own(),
			Counts: control.DNSCounts{Answered: es.fallback.Answered.Load(), Failed: es.fallback.Failed.Load()}}
		for _, a := range servers {
			sd.Servers = append(sd.Servers, a.String())
		}
		for _, a := range fallback {
			sd.Fallback = append(sd.Fallback, a.String())
		}
		if len(sd.Fallback) == 0 {
			sd.Fallback = []string{"the captured servers"}
		}
		if d.Match.CatchAll() {
			sd.Local = d.Match.Local()
		}
		st.DNS = sd
	}
	if mode := mp.ksMode(); mode != "off" {
		ks := &control.KillSwitch{Mode: mode, DNS: dnsHold(es.dnsOpts != nil && !es.devDNS, !mp.allowDNS)}
		if c != nil {
			ks.Guarded, ks.Lockdown = c.GuardCounts()
			if ks.DNS != control.HoldNoCapture {
				ks.DNS = dnsHold(true, c.HoldsDNS())
			}
		}
		st.KillSwitch = ks
	}
	return st
}

// dnsHold is what happens to DNS while the kill switch holds: nothing to
// hold without DNS capture.
func dnsHold(captured, blocked bool) string {
	switch {
	case !captured:
		return control.HoldNoCapture
	case blocked:
		return control.HoldBlocked
	}
	return control.HoldAllowed
}

// conns are the open connections per tunnel.
func (es *engineStatus) conns() []control.TunnelConns {
	es.mp.smu.RLock()
	defer es.mp.smu.RUnlock()
	out := make([]control.TunnelConns, len(es.mp.specs))
	for i, sp := range es.mp.specs {
		out[i] = control.TunnelConns{Name: sp.name, Conns: es.meters[i].Conns()}
	}
	return out
}

// startControl opens this run's control socket; a failure only costs
// status, so it's a warning. Replaced in tests.
var startControl = func(ctx context.Context, es *engineStatus, ring *logring.Ring, log *slog.Logger) {
	dir, err := control.RunDir()
	if err != nil {
		log.Warn("no control socket, so subtun status can't see this run", "err", err)
		return
	}
	ln, path, err := control.Listen(dir)
	if err != nil {
		log.Warn("no control socket, so subtun status can't see this run", "err", err)
		return
	}
	srv := &control.Server{Status: es.status, Conns: es.conns, Logs: ring, Change: es.change, Log: log}
	go func() {
		if err := srv.Serve(ctx, ln, path); err != nil {
			log.Debug("control socket stopped", "err", err)
		}
	}()
	log.Debug("control socket ready", "path", path)
}

// newRunLogger is newLogger plus a ring buffer of the same lines (for
// subtun logs).
func newRunLogger(verbose bool) (*slog.Logger, *logring.Ring) {
	ring := logring.New(0, 0)
	opts := logOptions(verbose)
	return slog.New(logring.Tee(slog.NewTextHandler(os.Stderr, opts), ring.Handler(opts))), ring
}
