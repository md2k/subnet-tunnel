package cli

import (
	"context"
	"log/slog"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/md2k/subnet-tunnel/internal/capture"
	"github.com/md2k/subnet-tunnel/internal/config"
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
	// configPath is the config file profiles are added from.
	configPath string
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

// grow adds a profile's status (a profile added while running); the caller
// holds mp.smu.
func (es *engineStatus) grow(info *tunnelInfo, m *meter.Meter, dc *dns.Counts) {
	es.infos = append(es.infos, info)
	es.meters = append(es.meters, m)
	es.dnsCounts = append(es.dnsCounts, dc)
}

// meter returns profile i's meter, from any goroutine.
func (es *engineStatus) meter(i int) *meter.Meter {
	es.mp.smu.RLock()
	defer es.mp.smu.RUnlock()
	return es.meters[i]
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
			es.mp.smu.RLock()
			meters := slices.Clone(es.meters)
			es.mp.smu.RUnlock()
			for _, m := range meters {
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
		t.Include, t.Exclude = slices.Clone(sp.s.routes), slices.Clone(sp.s.excludes)
		if es.dnsOpts != nil {
			t.Domains, t.Patterns = mp.dnsNames[i].Domains, mp.dnsNames[i].Patterns
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

// samples are every tunnel's 1 s traffic samples.
func (es *engineStatus) samples() []control.TunnelSamples {
	es.mp.smu.RLock()
	defer es.mp.smu.RUnlock()
	out := make([]control.TunnelSamples, len(es.mp.specs))
	for i, sp := range es.mp.specs {
		out[i] = control.TunnelSamples{Name: sp.name, Samples: es.meters[i].Samples()}
	}
	return out
}

// configProfiles reads the profiles of the run's config file (path), and
// says which are in the run; nil config: none (no config file to read).
func (es *engineStatus) configProfiles(path string) control.ConfigProfiles {
	cp := control.ConfigProfiles{Path: path, Profiles: []control.ConfigProfile{}}
	f, err := config.Load(path)
	if err != nil {
		cp.Error = err.Error()
		return cp
	}
	es.mp.smu.RLock()
	var running []string
	for _, sp := range es.mp.specs {
		running = append(running, sp.name)
	}
	es.mp.smu.RUnlock()
	for _, name := range f.Names() {
		p, _ := f.Profile(name) // fails only for a name the file doesn't have
		c := control.ConfigProfile{Name: name, Target: configTarget(p.Target), Routes: p.Routes, Exclude: p.Exclude,
			Domains: p.DNS.Domains, Patterns: p.DNS.Patterns, SOCKS: p.Socks, InRun: slices.Contains(running, name)}
		if m := string(p.KillSwitch.Mode); m != "" && m != "off" {
			c.KillSwitch = m
		}
		cp.Profiles = append(cp.Profiles, c)
	}
	return cp
}

// configTarget is a configured target for people: "pod ns/name",
// "container name".
func configTarget(t config.Target) string {
	switch {
	case t.K8s != nil:
		pod := strings.TrimPrefix(t.K8s.Pod, "pod/")
		if t.K8s.Namespace != "" {
			pod = t.K8s.Namespace + "/" + pod
		}
		return "pod " + pod
	case t.Docker != nil:
		return "container " + t.Docker.Container
	}
	return ""
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
	srv := &control.Server{Status: es.status, Conns: es.conns, Samples: es.samples, Logs: ring, Change: es.change, Log: log}
	if es.configPath != "" {
		path := es.configPath
		srv.Config = func() control.ConfigProfiles { return es.configProfiles(path) }
	}
	go func() {
		if err := srv.Serve(ctx, ln, path); err != nil {
			log.Debug("control socket stopped", "err", err)
		}
	}()
	log.Debug("control socket ready", "path", path)
}
