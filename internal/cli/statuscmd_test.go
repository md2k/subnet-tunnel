package cli

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/md2k/subnet-tunnel/internal/config"
	"github.com/md2k/subnet-tunnel/internal/control"
	"github.com/md2k/subnet-tunnel/internal/logx"
	"github.com/md2k/subnet-tunnel/internal/meter"
)

func TestWriteStatus(t *testing.T) {
	now := time.Date(2026, 11, 13, 15, 0, 0, 0, time.UTC)
	is := instanceStatus{Status: control.Status{
		PID: 4242, Version: "v0.1.0", Started: now.Add(-time.Hour), Control: "full", Utun: "utun10", TunAddr: "198.18.249.1", Helper: "session",
		Tunnels: []control.Tunnel{
			{Name: "work", State: "up", Since: now.Add(-2 * time.Minute), Target: "pod ops/toolbox, binary agent",
				Routes: []string{"0.0.0.0/1", "128.0.0.0/1"}, RoutesOn: true, Domains: []string{"."}, KillSwitch: "on",
				Counts:    meter.Counts{Open: 3, Total: 120, Failed: 2, ViaSOCKS: 10, Up: 1_200_000, Down: 34_000_000, UpRate: 5000, DownRate: 120_000},
				DNSCounts: control.DNSCounts{Answered: 340, Failed: 2}},
			{Name: "dev", State: "reconnecting", Since: now.Add(-10 * time.Second), Attempt: 2, Attempts: 10, NextTry: now.Add(3 * time.Second),
				Routes: []string{"10.50.0.0/16"}, RoutesOn: true, LastError: "pod tools/debug: not found", Changes: []string{"+route 10.50.0.0/16", "-dns x.example"}},
		},
		DNS:        &control.DNS{Servers: []string{"192.168.1.1"}, Follow: true, Fallback: []string{"the captured servers"}, Local: []string{"local", "lan"}},
		KillSwitch: &control.KillSwitch{Mode: "on", Guarded: 98, DNS: "blocked"},
		BlockIPv6:  true,
	}, Connections: []control.TunnelConns{{Name: "work", Conns: []meter.ConnInfo{{Dst: "140.82.112.3:443", Via: "utun", Opened: now.Add(-5 * time.Second), Up: 900, Down: 4200}}}}}
	var b bytes.Buffer
	writeStatus(&b, is, now)
	out := b.String()
	for _, want := range []string{
		"subtun pid 4242, v0.1.0, up 1h0m0s, control full; utun10 (198.18.249.1), session root helper\n",
		"changed while running: +route 10.50.0.0/16, -dns x.example\n",
		"  work  up for 2m0s; pod ops/toolbox, binary agent\n",
		"routes 0.0.0.0/1, 128.0.0.0/1 (on the utun); DNS .; kill switch on\n",
		"connections 3 open, 120 total, 2 failed (10 through SOCKS)\n",
		"up 1.2 MB (5.0 kB/s), down 34.0 MB (120.0 kB/s); DNS 340 answered, 2 failed\n",
		"  dev   reconnecting for 10s (attempt 2 of 10, next in 3s)\n",
		"last error: pod tools/debug: not found\n",
		"  DNS capture: queries to 192.168.1.1, following the system's; other names: the captured servers (0 answered, 0 failed)\n",
		"    stay local: local, lan\n",
		"  kill switch on: 98 guarded prefixes (0 stay after Ctrl-C); DNS while holding: blocked\n",
		"  outgoing IPv6 blocked\n",
		"  open connections through work:\n    140.82.112.3:443             utun        5s  up 900 B, down 4.2 kB\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
}

// The status a run reports, from its plan, its tunnels' state and meters.
func TestEngineStatus(t *testing.T) {
	mp := multiPlanFor(t, "work", "dev")
	es := newEngineStatus(mp, controlStatus)
	es.dnsOpts = mp.dns
	es.infos[0].update(func(ti *tunnelInfo) { ti.state, ti.target, ti.routesOn = stateUp, "container work", true })
	es.infos[1].update(func(ti *tunnelInfo) { ti.state, ti.attempt, ti.attempts = stateReconnecting, 2, 10 })
	es.dnsCounts[0].Answered.Add(7)
	d := es.meters[1].Dialer(meter.ViaSOCKS, &liveTunnel{})
	_, _ = d.DialContext(context.Background(), "tcp", "x:1") // fails: counted
	st := es.status()
	if st.Control != controlStatus || len(st.Tunnels) != 2 || st.Utun != "" {
		t.Fatalf("status: %+v", st)
	}
	w, dv := st.Tunnels[0], st.Tunnels[1]
	if w.Name != "work" || w.State != "up" || w.KillSwitch != "on" || w.DNSCounts.Answered != 7 || len(w.Domains) != 2 || w.RoutesOn {
		t.Errorf("work: %+v", w) // RoutesOn needs a capture
	}
	if dv.State != "reconnecting" || dv.Attempt != 2 || dv.Counts.Failed != 1 || dv.SOCKS != "127.0.0.1:1081" {
		t.Errorf("dev: %+v", dv)
	}
	if st.DNS == nil || st.DNS.Servers[0] != "192.0.2.53" || st.KillSwitch == nil || st.KillSwitch.Mode != "on" {
		t.Errorf("shared: %+v %+v", st.DNS, st.KillSwitch)
	}
	if c := es.conns(); len(c) != 2 || c[1].Name != "dev" {
		t.Errorf("conns: %+v", c)
	}
	if !slices.Equal(w.Include, []string{"10.0.0.0/8", "203.0.113.0/24"}) || len(w.Exclude) != 0 {
		t.Errorf("work's routes asked for: %v %v", w.Include, w.Exclude)
	}
	// What of its routes work doesn't carry: dev's more specific route, and
	// subtun's own endpoint (work's Docker host) once known.
	if n := w.RouteNotes["10.0.0.0/8"]; n != "parts carried by dev (more specific)" {
		t.Errorf("route notes: %q", w.RouteNotes)
	}
	if w.Endpoint != "tcp://203.0.113.200:2376" {
		t.Errorf("work's endpoint: %q", w.Endpoint)
	}
	if w.Unrouted != "warn" || dv.Unrouted != "warn" {
		t.Errorf("unrouted: %q %q", w.Unrouted, dv.Unrouted)
	}
	if _, err := mp.addEndpoints([]netip.Addr{netip.MustParseAddr("203.0.113.200")}); err != nil {
		t.Fatal(err)
	}
	if n := routeNotes(mp, 0, mp.endpointList()); !strings.Contains(n["203.0.113.0/24"], "minus 203.0.113.200/32: subtun's own endpoint") {
		t.Errorf("carved endpoint: %q", n)
	}
	es.meters[0].Sample(time.Now())
	if s := es.samples(); len(s) != 2 || s[0].Name != "work" || len(s[0].Samples) != 1 || len(s[1].Samples) != 0 {
		t.Errorf("samples: %+v", s)
	}
	// The config file's profiles, which are in the run, and the file's
	// error if it can't be read.
	cp := es.configProfiles("testdata/multi.yaml")
	byName := map[string]control.ConfigProfile{}
	for _, p := range cp.Profiles {
		byName[p.Name] = p
	}
	if cp.Error != "" || !byName["work"].InRun || byName["vault"].InRun || byName["dev"].Target != "container dev" ||
		byName["work"].KillSwitch != "on" || byName["dev"].SOCKS != "127.0.0.1:1081" || !slices.Equal(byName["dev"].Domains, []string{"cluster.local"}) {
		t.Errorf("config profiles: %+v", cp)
	}
	if cp := es.configProfiles("testdata/no-such-config.yaml"); cp.Error == "" || len(cp.Profiles) != 0 {
		t.Errorf("missing file: %+v", cp)
	}
	if got := configTarget(config.Target{K8s: &config.K8sTarget{Namespace: "ops", Pod: "pod/toolbox"}}); got != "pod ops/toolbox" {
		t.Errorf("k8s target: %q", got)
	}
	// DNS while the kill switch holds: blocked by default; nothing to hold
	// without DNS capture.
	if st.KillSwitch.DNS != control.HoldBlocked {
		t.Errorf("DNS while holding: %q", st.KillSwitch.DNS)
	}
	vault := multiPlanFor(t, "vault") // lockdown, no DNS names
	if ks := newEngineStatus(vault, controlStatus).status().KillSwitch; ks == nil || ks.DNS != control.HoldNoCapture {
		t.Errorf("without DNS capture: %+v", ks)
	}
}

// subtun k8s and subtun docker take the config file's control: and log:
// too, under the flags given.
func TestGlobalsFromConfig(t *testing.T) {
	cmd := newK8sCmd(&globalOpts{})
	var s settings
	s.control = controlStatus
	if err := globalsFromConfig(cmd, &globalOpts{config: "testdata/control-off.yaml"}, &s); err != nil {
		t.Fatal(err)
	}
	if s.control != controlOff || s.log.File != "off" || s.log.Level != "info,dns=debug" {
		t.Fatalf("from the file: %q %+v", s.control, s.log)
	}
	s.control = controlStatus
	_ = globalsFromConfig(cmd, &globalOpts{config: "testdata/no-such-config.yaml"}, &s)
	if s.control != controlStatus {
		t.Fatalf("no file: %q", s.control)
	}
	if err := cmd.Flags().Set("control", controlStatus); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Flags().Set("log-file", "on"); err != nil {
		t.Fatal(err)
	}
	s.log = config.Log{File: "on"}
	_ = globalsFromConfig(cmd, &globalOpts{config: "testdata/control-off.yaml"}, &s)
	if s.control != controlStatus || s.log.File != "on" || s.log.Level != "info,dns=debug" {
		t.Fatalf("the flags lost to the file: %q %+v", s.control, s.log)
	}
	if err := cmd.Flags().Set("log-level", "loud"); err != nil {
		t.Fatal(err)
	}
	s.log.Level = "loud"
	if err := globalsFromConfig(cmd, &globalOpts{config: "testdata/control-off.yaml"}, &s); err == nil {
		t.Fatal("a bad --log-level accepted")
	}
}

// subtun log level: the run's levels change at once, a dry run only says;
// the CLI checks the spec and needs a running subtun.
func TestSetLogLevel(t *testing.T) {
	lv := logx.NewLevels(logx.Spec{Default: slog.LevelInfo})
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	res, err := setLogLevel(lv, control.Change{Op: "set", Level: "info,dns=debug", DryRun: true}, quiet)
	if err != nil || res.Changed || !strings.Contains(res.Message, "would log at info,dns=debug (now info)") || lv.Get().String() != "info" {
		t.Fatalf("dry run: %+v %v %q", res, err, lv.Get().String())
	}
	res, err = setLogLevel(lv, control.Change{Op: "set", Level: "info,dns=debug"}, quiet)
	if err != nil || !res.Changed || lv.Get().String() != "info,dns=debug" {
		t.Fatalf("set: %+v %v", res, err)
	}
	if res, _ := setLogLevel(lv, control.Change{Op: "set", Level: "info,dns=debug"}, quiet); res.Changed || !strings.Contains(res.Message, "already") {
		t.Errorf("again: %+v", res)
	}
	if _, err := setLogLevel(lv, control.Change{Op: "set", Level: "loud"}, quiet); err == nil {
		t.Error("a bad level accepted")
	}
	if _, err := runCLI(t, "log", "level", "loud"); err == nil || !strings.Contains(err.Error(), "loud") {
		t.Errorf("CLI bad level: %v", err)
	}
	if _, err := runCLI(t, "log", "level", "debug"); err == nil || err.Error() != "no subtun running" {
		t.Errorf("CLI nothing running: %v", err)
	}
}
