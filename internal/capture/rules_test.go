package capture

import (
	"net/netip"
	"testing"
)

func TestRules(t *testing.T) {
	guard := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	dr := &dnsRuntime{opts: &DNSOptions{}, listenPort: 53530, bypassPort: 53531}
	servers := []netip.Addr{netip.MustParseAddr("192.168.1.1")}
	dr.servers.Store(&servers)

	// DNS capture only: nothing stays behind.
	running, persist := rules(Options{}, nil, nil, "utun7", dr)
	if running.DNS == nil || running.KillSwitch != nil || persist != nil {
		t.Errorf("DNS only: %+v, %+v", running, persist)
	}
	// Routes only, no guards: no firewall at all (one-shot helper).
	if running, persist := rules(Options{}, nil, nil, "utun7", nil); !running.Empty() || persist != nil {
		t.Errorf("routes only: %+v, %+v", running, persist)
	}
	// Kill switch with DNS capture: DNS blocked while it holds.
	running, persist = rules(Options{KillSwitch: "on", BlockIPv6: true}, guard, guard, "utun7", dr)
	if running.KillSwitch == nil || running.KillSwitch.TunIface != "utun7" || !running.BlockIPv6 {
		t.Errorf("kill switch running: %+v", running)
	}
	if persist == nil || persist.KillSwitch.TunIface != "" || len(persist.DNSBlock) != 1 || !persist.BlockIPv6 || persist.DNS != nil {
		t.Errorf("kill switch persist: %+v", persist)
	}
	// killSwitch.dns: allow.
	if _, persist := rules(Options{KillSwitch: "lockdown", AllowDNS: true}, guard, guard, "utun7", dr); persist == nil || persist.DNSBlock != nil {
		t.Errorf("allow DNS: %+v", persist)
	}
	// IPv6 block alone: a session, but nothing stays behind.
	if running, persist := rules(Options{BlockIPv6: true}, nil, nil, "utun7", nil); !running.BlockIPv6 || persist != nil {
		t.Errorf("IPv6 only: %+v, %+v", running, persist)
	}
	// Several tunnels on a deliberate stop: guarded while running, only the
	// lockdown part kept.
	lock := []netip.Prefix{netip.MustParsePrefix("10.50.0.0/16")}
	running, persist = rules(Options{KillSwitch: "on"}, guard, lock, "utun7", nil)
	if running.KillSwitch == nil || running.KillSwitch.Prefixes[0] != guard[0] || persist == nil || persist.KillSwitch.Prefixes[0] != lock[0] {
		t.Errorf("narrowed: %+v, %+v", running, persist)
	}
	// Nothing kept: no persist rules.
	if _, persist := rules(Options{KillSwitch: "on"}, guard, nil, "utun7", nil); persist != nil {
		t.Errorf("nothing kept: %+v", persist)
	}
}
