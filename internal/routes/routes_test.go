package routes

import (
	"math/rand"
	"net/netip"
	"strings"
	"testing"
)

func pfx(ss ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParsePrefix(s)
	}
	return out
}

func join(ps []netip.Prefix) string {
	s := make([]string, len(ps))
	for i, p := range ps {
		s[i] = p.String()
	}
	return strings.Join(s, " ")
}

func TestMostSpecificWins(t *testing.T) {
	plan, err := Compute(pfx("10.0.0.0/8", "10.205.188.50/32"), pfx("10.205.0.0/16"))
	if err != nil {
		t.Fatal(err)
	}
	want := "10.0.0.0/9 10.128.0.0/10 10.192.0.0/13 10.200.0.0/14 10.204.0.0/16 10.205.188.50/32 10.206.0.0/15 10.208.0.0/12 10.224.0.0/11"
	if got := join(plan.Routes); got != want {
		t.Fatalf("routes\n got %s\nwant %s", got, want)
	}
	if len(plan.Redundant) != 0 {
		t.Fatalf("unexpected redundant: %v", plan.Redundant)
	}
}

func TestExcludeSingleAddress(t *testing.T) {
	plan, err := Compute(pfx("170.170.0.0/16"), pfx("170.170.194.209/32"))
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Routes) != 16 {
		t.Fatalf("/16 minus one address should be 16 routes, got %d: %s", len(plan.Routes), join(plan.Routes))
	}
	if _, ok := plan.Routed(netip.MustParseAddr("170.170.194.209")); ok {
		t.Fatal("excluded address is routed")
	}
	for _, a := range []string{"170.170.194.208", "170.170.194.210", "170.170.0.1", "170.170.255.255"} {
		if _, ok := plan.Routed(netip.MustParseAddr(a)); !ok {
			t.Fatalf("%s not routed", a)
		}
	}
}

func TestRedundantRulesReported(t *testing.T) {
	plan, err := Compute(
		pfx("10.0.0.0/8", "10.205.120.100/32", "10.0.0.0/8", "172.16.0.0/12"),
		pfx("192.168.112.0/24", "10.1.0.0/16", "10.1.2.0/24"),
	)
	if err != nil {
		t.Fatal(err)
	}
	notes := map[string]string{}
	for _, n := range plan.Redundant {
		notes[n.String()] = n.Reason
	}
	for _, want := range []string{
		"route 10.0.0.0/8: listed twice",
		"route 10.205.120.100/32: already covered by 10.0.0.0/8",
		"exclude 192.168.112.0/24: outside every route, nothing to exclude",
		"exclude 10.1.2.0/24: already excluded by 10.1.0.0/16",
	} {
		if _, ok := notes[want]; !ok {
			t.Errorf("missing note %q; got %v", want, plan.Redundant)
		}
	}
	if _, ok := plan.Routed(netip.MustParseAddr("10.1.2.3")); ok {
		t.Error("10.1.2.3 routed although 10.1.0.0/16 is excluded")
	}
	if _, ok := plan.Routed(netip.MustParseAddr("172.20.0.1")); !ok {
		t.Error("172.16.0.0/12 lost")
	}
}

func TestBothRoutedAndExcluded(t *testing.T) {
	plan, err := Compute(pfx("10.1.0.0/16", "10.0.0.0/8"), pfx("10.1.0.0/16"))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := plan.Routed(netip.MustParseAddr("10.1.0.1")); ok {
		t.Fatal("prefix listed as route and exclude must be excluded")
	}
	if len(plan.Redundant) != 1 || !strings.Contains(plan.Redundant[0].Reason, "both routed and excluded") {
		t.Fatalf("notes: %v", plan.Redundant)
	}
}

// A full tunnel must stay two /1 routes: merged into 0.0.0.0/0 it would
// collide with (or replace) the real default route.
func TestFullTunnelStaysTwoHalves(t *testing.T) {
	plan, err := Compute(pfx("0.0.0.0/1", "128.0.0.0/1"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := join(plan.Routes); got != "0.0.0.0/1 128.0.0.0/1" {
		t.Fatalf("got %s", got)
	}
	plan, err = Compute(pfx("0.0.0.0/1", "128.0.0.0/1"), pfx("203.0.113.10/32"))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range plan.Routes {
		if p.Bits() == 0 {
			t.Fatalf("default route produced: %s", join(plan.Routes))
		}
	}
	if _, ok := plan.Routed(netip.MustParseAddr("203.0.113.10")); ok {
		t.Fatal("excluded address routed in full tunnel")
	}
}

func TestRejectsBadInput(t *testing.T) {
	if _, err := Compute([]netip.Prefix{netip.PrefixFrom(netip.MustParseAddr("10.1.2.3"), 8)}, nil); err == nil {
		t.Error("host bits accepted")
	}
	if _, err := Compute(pfx("fd00::/8"), nil); err == nil {
		t.Error("IPv6 accepted")
	}
}

// Random rule sets inside 10.0.0.0/24: every address must be routed exactly
// when its most specific matching rule is an include (exclude on a tie), and
// the output must be minimal.
func TestRandomAgainstBruteForce(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	base := netip.MustParseAddr("10.0.0.0")
	for iter := 0; iter < 500; iter++ {
		var inc, exc []netip.Prefix
		for n := rng.Intn(8); n >= 0; n-- {
			bits := 24 + rng.Intn(9)
			a := base.As4()
			a[3] = byte(rng.Intn(256))
			p := netip.PrefixFrom(netip.AddrFrom4(a), bits).Masked()
			if rng.Intn(3) == 0 {
				exc = append(exc, p)
			} else {
				inc = append(inc, p)
			}
		}
		plan, err := Compute(inc, exc)
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 256; i++ {
			a := base.As4()
			a[3] = byte(i)
			addr := netip.AddrFrom4(a)
			want, bestBits := false, -1
			for _, p := range inc {
				if p.Contains(addr) && p.Bits() > bestBits {
					want, bestBits = true, p.Bits()
				}
			}
			for _, p := range exc {
				if p.Contains(addr) && p.Bits() >= bestBits {
					want, bestBits = false, p.Bits()
				}
			}
			if _, got := plan.Routed(addr); got != want {
				t.Fatalf("iter %d: %s routed=%v, want %v\ninc %s\nexc %s\nroutes %s", iter, addr, got, want, join(inc), join(exc), join(plan.Routes))
			}
		}
		for i, a := range plan.Routes {
			for j, b := range plan.Routes {
				if i == j {
					continue
				}
				if a.Overlaps(b) {
					t.Fatalf("iter %d: overlapping routes %s %s", iter, a, b)
				}
				if a.Bits() == b.Bits() && a.Bits() > 0 {
					pa, _ := a.Addr().Prefix(a.Bits() - 1)
					pb, _ := b.Addr().Prefix(b.Bits() - 1)
					if pa == pb {
						t.Fatalf("iter %d: siblings %s and %s should be one route\ninc %s\nexc %s", iter, a, b, join(inc), join(exc))
					}
				}
			}
		}
	}
}
