package routes

import (
	"net/netip"
	"strings"
	"testing"
)

func TestCheck(t *testing.T) {
	plan, err := Compute(pfx("10.0.0.0/8", "100.77.1.0/24", "192.168.1.0/24"), nil)
	if err != nil {
		t.Fatal(err)
	}
	reserved := []Reserved{
		{netip.MustParseAddr("198.18.249.1"), "subtun's utun address"},
		{netip.MustParseAddr("192.168.1.1"), "the default gateway"},
	}
	locals := []Local{
		{"en0", netip.MustParsePrefix("192.168.1.0/24")},
		{"utun4", netip.MustParsePrefix("100.64.0.0/10")}, // e.g. a VPN client's interface
		{"en5", netip.MustParsePrefix("10.20.30.0/24")},
	}
	errs, warns := Check(plan, reserved, locals)
	if len(errs) != 1 || !strings.Contains(errs[0], "default gateway 192.168.1.1") {
		t.Fatalf("errs: %v", errs)
	}
	all := strings.Join(warns, "\n")
	for _, want := range []string{
		"route 192.168.1.0/24 takes over part of 192.168.1.0/24 on en0",
		"route 100.77.1.0/24 takes over part of 100.64.0.0/10 on utun4",
		"route 10.0.0.0/8 contains 10.20.30.0/24 on en5: that network stays on en5",
	} {
		if !strings.Contains(all, want) {
			t.Errorf("missing warning %q in\n%s", want, all)
		}
	}
}

func TestHostPrefixes(t *testing.T) {
	got := HostPrefixes([]netip.Addr{
		netip.MustParseAddr("34.120.1.2"),
		netip.MustParseAddr("127.0.0.1"),
		netip.MustParseAddr("::ffff:10.1.2.3"),
		netip.MustParseAddr("fd00::1"),
		{},
	})
	if join(got) != "34.120.1.2/32 10.1.2.3/32" {
		t.Fatalf("got %s", join(got))
	}
}
