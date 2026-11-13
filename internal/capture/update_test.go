package capture

import (
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"testing"

	"github.com/md2k/subnet-tunnel/internal/platform"
)

// fakeHelper records what a running capture asks of the root helper.
type fakeHelper struct {
	calls      []string
	failApply  int // fail this many firewall updates
	failDelete netip.Prefix
	failAdd    netip.Prefix
}

func (f *fakeHelper) AddRoute(p netip.Prefix) error {
	if p == f.failAdd {
		f.rec("add %s failed", p)
		return errors.New("route add failed: File exists")
	}
	return f.rec("add %s", p)
}
func (f *fakeHelper) DeleteRoute(p netip.Prefix) error {
	if p == f.failDelete {
		f.rec("delete %s failed", p)
		return errors.New("route delete failed")
	}
	return f.rec("delete %s", p)
}
func (f *fakeHelper) End(keep bool) error     { return f.rec("end keep=%v", keep) }
func (f *fakeHelper) FlushDNSCache() error    { return f.rec("flush dns cache") }
func (f *fakeHelper) Close() error            { return f.rec("close") }
func (f *fakeHelper) Exited() <-chan struct{} { return nil }
func (f *fakeHelper) ApplyFirewall(r platform.Rules, persist *platform.Rules) error {
	kept := "-"
	if persist != nil {
		kept = fmt.Sprint(persist.KillSwitch.Prefixes)
	}
	if f.failApply > 0 {
		f.failApply--
		f.rec("firewall guard=%v failed", r.KillSwitch.Prefixes)
		return errors.New("pfctl failed")
	}
	return f.rec("firewall guard=%v kept=%s", r.KillSwitch.Prefixes, kept)
}
func (f *fakeHelper) ClearFirewall() error { return f.rec("clear firewall") }
func (f *fakeHelper) rec(format string, args ...any) error {
	f.calls = append(f.calls, fmt.Sprintf(format, args...))
	return nil
}

func testCapture(t *testing.T, routes []netip.Prefix, g Guard) (*Capture, *fakeHelper) {
	t.Helper()
	guard, err := newGuardState(g, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := &fakeHelper{}
	return &Capture{Name: "utun7", helper: h, guard: guard, log: slog.New(slog.DiscardHandler),
		opts: Options{KillSwitch: "on"}, routes: slices.Clone(routes), stop: func() {}}, h
}

func checkHelperCalls(t *testing.T, h *fakeHelper, want ...string) {
	t.Helper()
	if !slices.Equal(h.calls, want) {
		t.Fatalf("helper calls:\n got %q\nwant %q", h.calls, want)
	}
	h.calls = nil
}

// A profile without a kill switch comes and goes inside one with it: its
// route is added before the guard shrinks, and removed after it grows back.
func TestUpdateOrder(t *testing.T) {
	work := mps("10.0.0.0/8")
	c, h := testCapture(t, work, Guard{Base: work})

	// The guard is unchanged: no firewall update.
	if err := c.Update(mps("10.0.0.0/8", "10.50.0.0/16"), Guard{Base: work}); err != nil {
		t.Fatal(err)
	}
	checkHelperCalls(t, h, "add 10.50.0.0/16")

	shrunk := mps("10.0.0.0/9", "10.192.0.0/10") // stands in for "10/8 minus dev's share"
	if err := c.Update(mps("10.0.0.0/8", "10.50.0.0/16"), Guard{Base: shrunk}); err != nil {
		t.Fatal(err)
	}
	checkHelperCalls(t, h, "firewall guard=[10.0.0.0/9 10.192.0.0/10] kept=[10.0.0.0/9 10.192.0.0/10]")

	// dev gives up: the guard grows back first, then its route goes.
	if err := c.Update(work, Guard{Base: work}); err != nil {
		t.Fatal(err)
	}
	checkHelperCalls(t, h, "firewall guard=[10.0.0.0/8] kept=[10.0.0.0/8]", "delete 10.50.0.0/16")
	if !slices.Equal(c.Routes(), work) {
		t.Fatalf("routes: %v", c.Routes())
	}
}

// Every profile with a kill switch stopped, and nothing else needs rules
// (no DNS capture, no IPv6 block): the rules go, the stopped profile's
// route too; they come back with the profile.
func TestUpdateClearsFirewall(t *testing.T) {
	work := mps("10.0.0.0/8")
	c, h := testCapture(t, work, Guard{Base: work})
	if err := c.Update(nil, Guard{}); err != nil {
		t.Fatal(err)
	}
	checkHelperCalls(t, h, "clear firewall", "delete 10.0.0.0/8")
	if n, _ := c.GuardCounts(); n != 0 {
		t.Errorf("guarded: %d", n)
	}
	if err := c.Update(work, Guard{Base: work}); err != nil {
		t.Fatal(err)
	}
	checkHelperCalls(t, h, "add 10.0.0.0/8", "firewall guard=[10.0.0.0/8] kept=[10.0.0.0/8]")
}

func TestUpdateNeedsSession(t *testing.T) {
	c := &Capture{}
	if err := c.Update(mps("10.0.0.0/8"), Guard{}); err == nil {
		t.Fatal("Update without a session helper worked")
	}
}

// A deliberate stop keeps only the lockdown part of the guard; any other
// stop keeps all of it.
func TestStopKeepsLockdownPart(t *testing.T) {
	base := mps("10.0.0.0/8", "172.16.0.0/12")
	for name, tc := range map[string]struct {
		lockdown []netip.Prefix
		want     []string
		left     bool
	}{
		"on":       {nil, []string{"end keep=false", "close"}, false},
		"lockdown": {base, []string{"end keep=true", "close"}, true},
		"mixed": {mps("172.16.0.0/12"), []string{
			"firewall guard=[10.0.0.0/8 172.16.0.0/12] kept=[172.16.0.0/12]", "end keep=true", "close"}, true},
	} {
		t.Run(name, func(t *testing.T) {
			c, h := testCapture(t, base, Guard{Base: base, Lockdown: tc.lockdown})
			if left := c.stopHelper(true); left != tc.left {
				t.Errorf("left behind: %v", left)
			}
			checkHelperCalls(t, h, tc.want...)
		})
	}
	c, h := testCapture(t, base, Guard{Base: base})
	if !c.stopHelper(false) {
		t.Error("a crash left nothing behind")
	}
	checkHelperCalls(t, h, "close")
}

// A guard that fails to apply is tried again by the next Update, and no
// route is removed until it is in place.
func TestUpdateRetriesTheGuard(t *testing.T) {
	work := mps("10.0.0.0/8")
	c, h := testCapture(t, mps("10.0.0.0/8", "10.50.0.0/16"), Guard{Base: mps("10.0.0.0/9")})
	h.failApply = 1
	if err := c.Update(work, Guard{Base: work}); err == nil {
		t.Fatal("a failed firewall update was not reported")
	}
	checkHelperCalls(t, h, "firewall guard=[10.0.0.0/8] failed")
	if err := c.Update(work, Guard{Base: work}); err != nil {
		t.Fatal(err)
	}
	checkHelperCalls(t, h, "firewall guard=[10.0.0.0/8] kept=[10.0.0.0/8]", "delete 10.50.0.0/16")
}

// One route that can't be removed doesn't keep the others on the utun; it
// is tried again next time.
func TestUpdateRemovesPastAFailure(t *testing.T) {
	c, h := testCapture(t, mps("10.1.0.0/16", "10.2.0.0/16", "10.3.0.0/16"), Guard{})
	c.guard = nil
	h.failDelete = netip.MustParsePrefix("10.1.0.0/16")
	if err := c.Update(mps("10.3.0.0/16"), Guard{}); err == nil {
		t.Fatal("the failed delete was not reported")
	}
	checkHelperCalls(t, h, "delete 10.1.0.0/16 failed", "delete 10.2.0.0/16")
	if !slices.Equal(c.Routes(), mps("10.1.0.0/16", "10.3.0.0/16")) {
		t.Fatalf("routes: %v", c.Routes())
	}
}

// Once stopping, a firewall update still queued (network change) is
// dropped: it would re-send the whole guard as what stays.
func TestNoFirewallUpdatesAfterStop(t *testing.T) {
	base := mps("10.0.0.0/8", "172.16.0.0/12")
	c, h := testCapture(t, base, Guard{Base: base, Lockdown: mps("172.16.0.0/12")})
	c.stopHelper(true)
	h.calls = nil
	if err := c.apply(); err != nil {
		t.Fatal(err)
	}
	if err := c.Update(base, Guard{Base: base}); err == nil {
		t.Error("Update after the stop worked")
	}
	checkHelperCalls(t, h)
}

// A route that can't be added (another VPN client holds it) doesn't hold up
// the other additions, the guard or the removals.
func TestUpdateAddsPastAFailure(t *testing.T) {
	c, h := testCapture(t, mps("10.9.0.0/16"), Guard{})
	c.guard = nil
	h.failAdd = netip.MustParsePrefix("10.1.0.0/16")
	if err := c.Update(mps("10.1.0.0/16", "10.2.0.0/16"), Guard{}); err == nil {
		t.Fatal("the failed add was not reported")
	}
	checkHelperCalls(t, h, "add 10.1.0.0/16 failed", "add 10.2.0.0/16", "delete 10.9.0.0/16")
	if !slices.Equal(c.Routes(), mps("10.2.0.0/16")) {
		t.Fatalf("routes: %v", c.Routes())
	}
}

// The DNS cache is flushed through the helper only with DNS capture, and
// not once stopping.
func TestFlushDNSCache(t *testing.T) {
	c, h := testCapture(t, nil, Guard{})
	if err := c.FlushDNSCache(); err != nil {
		t.Fatal(err)
	}
	checkHelperCalls(t, h) // no DNS capture: nothing to flush
	c.dns = &dnsRuntime{}
	if err := c.FlushDNSCache(); err != nil {
		t.Fatal(err)
	}
	checkHelperCalls(t, h, "flush dns cache")
	c.guard = nil
	c.stopHelper(true)
	h.calls = nil
	if err := c.FlushDNSCache(); err != nil {
		t.Fatal(err)
	}
	checkHelperCalls(t, h)
}
