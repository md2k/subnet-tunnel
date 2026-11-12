package cli

import (
	"net/netip"
	"testing"

	"github.com/md2k/subnet-tunnel/internal/routes"
)

func TestAutoExcludes(t *testing.T) {
	mp := netip.MustParsePrefix
	// A full tunnel contains them all; a route exactly as specific as, or
	// more specific than, a candidate is an explicit choice and wins.
	got, notes := autoExcludes([]netip.Prefix{mp("0.0.0.0/1"), mp("128.0.0.0/1")}, neverRouted)
	if len(got) != len(neverRouted) || len(notes) != len(got) {
		t.Fatalf("full tunnel: %v", got)
	}
	if got, _ := autoExcludes([]netip.Prefix{mp("169.254.169.254/32")}, neverRouted); len(got) != 0 {
		t.Fatalf("explicit link-local route overridden: %v", got)
	}
	lan := localExcludes([]routes.Local{
		{Iface: "en0", Network: mp("192.168.1.0/24")},
		{Iface: "en1", Network: mp("192.168.1.0/24")},
		{Iface: "utun4", Network: mp("100.64.0.0/16")},
	})
	if len(lan) != 2 {
		t.Fatalf("duplicates not merged: %v", lan)
	}
	if got, _ := autoExcludes([]netip.Prefix{mp("192.168.1.0/24")}, lan); len(got) != 0 {
		t.Fatalf("route equal to the LAN overridden: %v", got)
	}
	if got, _ := autoExcludes([]netip.Prefix{mp("192.168.0.0/16")}, lan); len(got) != 1 || got[0] != mp("192.168.1.0/24") {
		t.Fatalf("LAN inside a route: %v", got)
	}
}
