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
		{Addr: netip.MustParseAddr("198.18.249.1"), What: "subtun's utun address"},
		{Addr: netip.MustParseAddr("192.168.1.1"), What: "the default gateway", ViaLocal: true},
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

// The default gateway may sit inside a broad route (10.0.0.0/8 in an office
// whose router is 10.x, or a full tunnel's 0.0.0.0/1 + 128.0.0.0/1): its LAN
// route is more specific and wins. Only a route at least as specific as the
// gateway's own network would capture it.
func TestGatewayInsideBroaderRoute(t *testing.T) {
	gw := []Reserved{{Addr: netip.MustParseAddr("10.20.30.1"), What: "the default gateway", ViaLocal: true}}
	lan := []Local{{"en0", netip.MustParsePrefix("10.20.30.0/24")}}
	for routes, wantErr := range map[string]bool{
		"10.0.0.0/8":                false, // broader than the LAN: fine
		"0.0.0.0/1 128.0.0.0/1":     false, // full tunnel: fine
		"10.20.30.0/24":             true,  // same as the LAN: refuse
		"10.20.30.0/25":             true,  // more specific: refuse
		"10.20.30.1/32":             true,  // the gateway itself: refuse
		"192.0.2.0/24 10.20.0.0/16": false,
	} {
		plan, err := Compute(pfx(strings.Fields(routes)...), nil)
		if err != nil {
			t.Fatal(err)
		}
		errs, _ := Check(plan, gw, lan)
		if (len(errs) > 0) != wantErr {
			t.Errorf("%s: errs %v, want error=%v", routes, errs, wantErr)
		}
	}
	// No local network holds the gateway (e.g. a point-to-point VPN route):
	// any route containing it is refused.
	plan, _ := Compute(pfx("10.0.0.0/8"), nil)
	if errs, _ := Check(plan, gw, nil); len(errs) == 0 {
		t.Error("gateway outside any local network accepted inside a route")
	}
	// subtun's own address is never allowed inside a route.
	own := []Reserved{{Addr: netip.MustParseAddr("10.20.30.200"), What: "subtun's utun address"}}
	if errs, _ := Check(plan, own, lan); len(errs) == 0 {
		t.Error("own address accepted inside a route")
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
