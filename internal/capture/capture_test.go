package capture

import (
	"net/netip"
	"testing"
)

func TestCheckLoop(t *testing.T) {
	cidrs := []netip.Prefix{netip.MustParsePrefix("10.96.0.0/12"), netip.MustParsePrefix("10.244.0.0/16")}
	if err := CheckLoop(cidrs, []netip.Addr{netip.MustParseAddr("34.120.1.2")}); err != nil {
		t.Fatalf("remote API server outside the CIDRs: %v", err)
	}
	if err := CheckLoop(cidrs, nil); err != nil {
		t.Fatalf("no endpoints (unix socket): %v", err)
	}
	if err := CheckLoop(cidrs, []netip.Addr{netip.MustParseAddr("10.100.0.1")}); err == nil {
		t.Fatal("API server inside 10.96.0.0/12 accepted")
	}
}
