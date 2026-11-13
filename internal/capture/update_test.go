package capture

import (
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"testing"

	"github.com/md2k/subnet-tunnel/internal/platform"
)

// fakeHelper records what a running capture asks of the root helper.
type fakeHelper struct{ calls []string }

func (f *fakeHelper) AddRoute(p netip.Prefix) error    { return f.rec("add %s", p) }
func (f *fakeHelper) DeleteRoute(p netip.Prefix) error { return f.rec("delete %s", p) }
func (f *fakeHelper) End(keep bool) error              { return f.rec("end keep=%v", keep) }
func (f *fakeHelper) Close() error                     { return f.rec("close") }
func (f *fakeHelper) Exited() <-chan struct{}          { return nil }
func (f *fakeHelper) ApplyFirewall(r platform.Rules, persist *platform.Rules) error {
	kept := "-"
	if persist != nil {
		kept = fmt.Sprint(persist.KillSwitch.Prefixes)
	}
	return f.rec("firewall guard=%v kept=%s", r.KillSwitch.Prefixes, kept)
}
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
