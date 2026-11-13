package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/md2k/subnet-tunnel/internal/control"
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

func TestBytesText(t *testing.T) {
	for n, want := range map[uint64]string{0: "0 B", 999: "999 B", 1000: "1.0 kB", 1_500_000: "1.5 MB", 2_000_000_000_000_000: "2000.0 TB"} {
		if got := bytesText(n); got != want {
			t.Errorf("%d: %q, want %q", n, got, want)
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
}

// subtun k8s and subtun docker take the config file's control: too, unless
// --control is given.
func TestControlFromConfig(t *testing.T) {
	cmd := newK8sCmd(&globalOpts{})
	var s settings
	s.control = controlStatus
	controlFromConfig(cmd, &globalOpts{config: "testdata/control-off.yaml"}, &s)
	if s.control != controlOff {
		t.Fatalf("from the file: %q", s.control)
	}
	s.control = controlStatus
	controlFromConfig(cmd, &globalOpts{config: "testdata/no-such-config.yaml"}, &s)
	if s.control != controlStatus {
		t.Fatalf("no file: %q", s.control)
	}
	if err := cmd.Flags().Set("control", controlStatus); err != nil {
		t.Fatal(err)
	}
	controlFromConfig(cmd, &globalOpts{config: "testdata/control-off.yaml"}, &s)
	if s.control != controlStatus {
		t.Fatalf("the flag lost to the file: %q", s.control)
	}
}
