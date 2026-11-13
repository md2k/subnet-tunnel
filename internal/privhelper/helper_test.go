//go:build !windows

package privhelper

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/md2k/subnet-tunnel/internal/platform"
	"github.com/md2k/subnet-tunnel/internal/platform/fake"
)

// memState is an in-memory stateStore.
type memState struct {
	mu sync.Mutex
	st *state
}

func (m *memState) load() (*state, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.st == nil {
		return nil, nil
	}
	c := *m.st
	return &c, nil
}

func (m *memState) save(st *state) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c := *st
	m.st = &c
	return nil
}

func (m *memState) remove() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.st = nil
	return nil
}

func (m *memState) get() *state { st, _ := m.load(); return st }

const testPID = 4242

type helperOpts struct {
	state *memState
	alive func(int) bool
}

// startHelper runs the helper's command loop with fake drivers and returns
// subtun's end of the connection.
func startHelper(t *testing.T, ctx context.Context, d *fake.Drivers) (*net.UnixConn, <-chan error) {
	t.Helper()
	return startHelperOpts(t, ctx, d, helperOpts{})
}

func startHelperOpts(t *testing.T, ctx context.Context, d *fake.Drivers, o helperOpts) (*net.UnixConn, <-chan error) {
	t.Helper()
	if o.state == nil {
		o.state = &memState{}
	}
	if o.alive == nil {
		o.alive = func(int) bool { return false }
	}
	a, b := socketPair(t)
	h := &helper{conn: a, log: slog.New(slog.DiscardHandler), drivers: d.Platform(),
		state: o.state, alive: o.alive, pid: testPID, grace: 100 * time.Millisecond}
	done := make(chan error, 1)
	go func() { done <- h.loop(ctx) }()
	return b, done
}

func call(t *testing.T, c *net.UnixConn, req Request) Response {
	t.Helper()
	if err := writeMsg(c, req); err != nil {
		t.Fatal(err)
	}
	var resp Response
	files, err := readMsg(c, &resp, time.Now().Add(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	want := 0
	if req.Op == OpCreateTun && resp.OK {
		want = 1
	}
	if len(files) != want {
		t.Fatalf("%s: got %d descriptors, want %d", req.Op, len(files), want)
	}
	closeAll(files)
	return resp
}

func wait(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("helper loop did not return")
		return nil
	}
}

func checkCalls(t *testing.T, d *fake.Drivers, want ...string) {
	t.Helper()
	if got := d.Calls(); !slices.Equal(got, want) {
		t.Fatalf("driver calls:\n got %q\nwant %q", got, want)
	}
}

var (
	createReq = Request{Op: OpCreateTun, MTU: 9000, Addr: "198.18.249.1"}
	created   = "create utun0 9000 198.18.249.1"
)

func TestHelperSetup(t *testing.T) {
	d := &fake.Drivers{}
	c, done := startHelper(t, context.Background(), d)

	if r := call(t, c, createReq); !r.OK || r.Name != "utun0" {
		t.Fatalf("create_tun: %+v", r)
	}
	for _, cidr := range []string{"10.244.0.0/16", "10.96.0.10"} {
		if r := call(t, c, Request{Op: OpAddRoute, CIDR: cidr}); !r.OK {
			t.Fatalf("add_route %s: %+v", cidr, r)
		}
	}
	if r := call(t, c, Request{Op: OpDone}); !r.OK {
		t.Fatalf("done: %+v", r)
	}
	if err := wait(t, done); err != nil {
		t.Fatal(err)
	}
	// After done the helper only drops its own descriptor: the interface and
	// routes stay with subtun.
	checkCalls(t, d, created, "add 10.244.0.0/16 utun0", "add 10.96.0.10/32 utun0", "release utun0")
}

// subtun going away before done (crash, Ctrl-C at the wrong moment) makes the
// helper remove its routes, newest first, and destroy the interface.
func TestHelperUndoesWhenSubtunDisconnects(t *testing.T) {
	d := &fake.Drivers{}
	c, done := startHelper(t, context.Background(), d)
	call(t, c, createReq)
	call(t, c, Request{Op: OpAddRoute, CIDR: "10.244.0.0/16"})
	call(t, c, Request{Op: OpAddRoute, CIDR: "10.96.0.0/12"})
	_ = c.Close()

	if err := wait(t, done); err == nil || !strings.Contains(err.Error(), "changes undone") {
		t.Fatalf("got %v", err)
	}
	checkCalls(t, d, created, "add 10.244.0.0/16 utun0", "add 10.96.0.0/12 utun0",
		"delete 10.96.0.0/12 utun0", "delete 10.244.0.0/16 utun0", "close utun0")
}

func TestHelperUndoesWhenInterrupted(t *testing.T) {
	d := &fake.Drivers{}
	ctx, cancel := context.WithCancel(context.Background())
	c, done := startHelper(t, ctx, d)
	call(t, c, createReq)
	call(t, c, Request{Op: OpAddRoute, CIDR: "10.244.0.0/16"})
	cancel()

	if err := wait(t, done); err == nil {
		t.Fatal("loop returned nil after interrupt")
	}
	checkCalls(t, d, created, "add 10.244.0.0/16 utun0", "delete 10.244.0.0/16 utun0", "close utun0")
}

// Invalid commands are answered with an error and never reach a driver.
func TestHelperRefusesInvalidCommands(t *testing.T) {
	d := &fake.Drivers{}
	c, done := startHelper(t, context.Background(), d)

	refuse := func(req Request, want string) {
		t.Helper()
		r := call(t, c, req)
		if r.OK || !strings.Contains(r.Error, want) {
			t.Errorf("%+v: got %+v, want error containing %q", req, r, want)
		}
	}
	refuse(Request{Op: OpAddRoute, CIDR: "10.244.0.0/16"}, "create the utun first")
	refuse(Request{Op: OpCreateTun, MTU: 100, Addr: "198.18.249.1"}, "MTU")
	refuse(Request{Op: OpCreateTun, MTU: 9000, Addr: "127.0.0.1"}, "unicast IPv4")
	refuse(Request{Op: OpCreateTun, MTU: 9000, Addr: "utun0; rm"}, "utun address")
	call(t, c, createReq)
	refuse(createReq, "already created")
	refuse(Request{Op: OpAddRoute, CIDR: "0.0.0.0/0"}, "default route")
	refuse(Request{Op: OpAddRoute, CIDR: "10.244.1.0/16"}, "host bits")
	refuse(Request{Op: OpAddRoute, CIDR: "127.0.0.0/8"}, "loopback")
	refuse(Request{Op: OpAddRoute, CIDR: "10.0.0.0/8 -ifscope en0"}, "not an IP")
	refuse(Request{Op: "run", CIDR: "/bin/sh"}, "unknown op")

	_ = c.Close()
	wait(t, done)
	checkCalls(t, d, created, "close utun0")
}

// A failing driver call is reported, and only what succeeded is undone.
func TestHelperDriverFailures(t *testing.T) {
	bad := netip.MustParsePrefix("10.1.0.0/16")
	d := &fake.Drivers{AddErr: map[netip.Prefix]error{bad: errors.New("route: File exists")}}
	c, done := startHelper(t, context.Background(), d)
	call(t, c, createReq)
	call(t, c, Request{Op: OpAddRoute, CIDR: "10.244.0.0/16"})
	if r := call(t, c, Request{Op: OpAddRoute, CIDR: bad.String()}); r.OK || !strings.Contains(r.Error, "File exists") {
		t.Fatalf("got %+v", r)
	}
	_ = c.Close()
	wait(t, done)
	checkCalls(t, d, created, "add 10.244.0.0/16 utun0", "delete 10.244.0.0/16 utun0", "close utun0")

	d = &fake.Drivers{CreateErr: errors.New("creating utun: operation not permitted")}
	c, done = startHelper(t, context.Background(), d)
	if r := call(t, c, createReq); r.OK || !strings.Contains(r.Error, "not permitted") {
		t.Fatalf("got %+v", r)
	}
	_ = c.Close()
	wait(t, done)
	checkCalls(t, d)
}

func firewallReq(servers ...string) Request {
	d := &platform.DNSRedirect{ListenPort: 53530, BypassPort: 53531}
	for _, s := range servers {
		d.Servers = append(d.Servers, netip.MustParseAddr(s))
	}
	return Request{Op: OpApplyFirewall, Rules: &platform.Rules{DNS: d}}
}

// Session mode: after done the helper stays up, accepts firewall updates
// (network changed) and route changes, and removes its rules when subtun
// goes away. The utun is subtun's by then.
func TestHelperSession(t *testing.T) {
	d := &fake.Drivers{}
	c, done := startHelper(t, context.Background(), d)
	call(t, c, createReq)
	call(t, c, Request{Op: OpAddRoute, CIDR: "10.244.0.0/16"})
	if r := call(t, c, firewallReq("192.168.1.1")); !r.OK {
		t.Fatalf("apply_firewall: %+v", r)
	}
	if r := call(t, c, Request{Op: OpDone, Session: true}); !r.OK {
		t.Fatalf("done: %+v", r)
	}
	if r := call(t, c, firewallReq("10.0.0.1")); !r.OK {
		t.Fatalf("update: %+v", r)
	}
	for _, req := range []Request{createReq, {Op: OpDone, Session: true}, {Op: OpAdopt}} {
		if r := call(t, c, req); r.OK || !strings.Contains(r.Error, "setup is finished") {
			t.Errorf("%s after done: %+v", req.Op, r)
		}
	}
	_ = c.Close()
	if err := wait(t, done); err != nil {
		t.Fatalf("session end: %v", err)
	}
	checkCalls(t, d, created, "add 10.244.0.0/16 utun0",
		"firewall dns [192.168.1.1] 53530 53531", "release utun0",
		"firewall dns [10.0.0.1] 53530 53531", "flush")
}

// Several tunnels: a session adds and removes routes as tunnels come and
// go, on the utun it created, and only routes it added.
func TestHelperSessionRouteChanges(t *testing.T) {
	d := &fake.Drivers{}
	c, done := startHelper(t, context.Background(), d)
	if r := call(t, c, Request{Op: OpAddRoute, CIDR: "10.0.0.0/8"}); r.OK || !strings.Contains(r.Error, "create the utun first") {
		t.Fatalf("add_route before create_tun: %+v", r)
	}
	call(t, c, createReq)
	call(t, c, Request{Op: OpAddRoute, CIDR: "10.0.0.0/8"})
	if r := call(t, c, Request{Op: OpDone, Session: true}); !r.OK {
		t.Fatalf("done: %+v", r)
	}
	for _, req := range []Request{
		{Op: OpAddRoute, CIDR: "10.50.0.0/16"},
		{Op: OpAddRoute, CIDR: "172.20.0.0/16"},
		{Op: OpDeleteRoute, CIDR: "10.50.0.0/16"},
	} {
		if r := call(t, c, req); !r.OK {
			t.Fatalf("%s %s: %+v", req.Op, req.CIDR, r)
		}
	}
	for req, want := range map[Request]string{
		{Op: OpAddRoute, CIDR: "10.0.0.0/8"}:        "already routed",
		{Op: OpDeleteRoute, CIDR: "10.50.0.0/16"}:   "not a route this helper added",
		{Op: OpDeleteRoute, CIDR: "192.168.0.0/16"}: "not a route this helper added",
		{Op: OpAddRoute, CIDR: "0.0.0.0/0"}:         "default route",
		{Op: OpDeleteRoute, CIDR: "10.1.2.3/8"}:     "host bits",
	} {
		if r := call(t, c, req); r.OK || !strings.Contains(r.Error, want) {
			t.Errorf("%s %s: %+v, want error with %q", req.Op, req.CIDR, r, want)
		}
	}
	_ = c.Close()
	if err := wait(t, done); err != nil {
		t.Fatalf("session end: %v", err)
	}
	checkCalls(t, d, created, "add 10.0.0.0/8 utun0", "release utun0",
		"add 10.50.0.0/16 utun0", "add 172.20.0.0/16 utun0", "delete 10.50.0.0/16 utun0")
}

func TestHelperSessionEndsOnInterrupt(t *testing.T) {
	d := &fake.Drivers{}
	ctx, cancel := context.WithCancel(context.Background())
	c, done := startHelper(t, ctx, d)
	call(t, c, firewallReq("192.168.1.1"))
	call(t, c, Request{Op: OpDone, Session: true})
	cancel()
	if err := wait(t, done); err != nil {
		t.Fatal(err)
	}
	checkCalls(t, d, "firewall dns [192.168.1.1] 53530 53531", "flush")
}

// Firewall rules outlive a one-shot helper, so done without a session is
// refused once rules are applied; disconnecting then undoes everything,
// firewall first.
func TestHelperFirewallNeedsSession(t *testing.T) {
	d := &fake.Drivers{}
	c, done := startHelper(t, context.Background(), d)
	call(t, c, createReq)
	call(t, c, Request{Op: OpAddRoute, CIDR: "10.244.0.0/16"})
	call(t, c, firewallReq("192.168.1.1"))
	if r := call(t, c, Request{Op: OpDone}); r.OK || !strings.Contains(r.Error, "session") {
		t.Fatalf("done without session: %+v", r)
	}
	_ = c.Close()
	wait(t, done)
	checkCalls(t, d, created, "add 10.244.0.0/16 utun0", "firewall dns [192.168.1.1] 53530 53531",
		"flush", "delete 10.244.0.0/16 utun0", "close utun0")
}

func TestHelperRefusesBadFirewallRules(t *testing.T) {
	d := &fake.Drivers{}
	c, done := startHelper(t, context.Background(), d)
	many := make([]string, 17)
	for i := range many {
		many[i] = fmt.Sprintf("192.168.1.%d", i+1)
	}
	bad := map[string]Request{
		"no rules":   {Op: OpApplyFirewall},
		"no servers": firewallReq(),
		"loopback":   firewallReq("127.0.0.1"),
		"IPv6":       firewallReq("fd00::53"),
		"17 servers": firewallReq(many...),
	}
	samePorts := firewallReq("192.168.1.1")
	samePorts.Rules.DNS.BypassPort = samePorts.Rules.DNS.ListenPort
	bad["same ports"] = samePorts
	lowPort := firewallReq("192.168.1.1")
	lowPort.Rules.DNS.ListenPort = 53
	bad["port 53"] = lowPort
	for name, req := range bad {
		if r := call(t, c, req); r.OK {
			t.Errorf("%s: accepted", name)
		}
	}
	_ = c.Close()
	wait(t, done)
	checkCalls(t, d)
}

var guarded = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}

// killSwitchReq is a running session's rules plus what stays behind.
func killSwitchReq(iface string) Request {
	r := firewallReq("192.168.1.1")
	r.Rules.KillSwitch = &platform.KillSwitch{TunIface: iface, Prefixes: guarded}
	r.Rules.BlockIPv6 = true
	r.Persist = &platform.Rules{
		DNSBlock:   []netip.Addr{netip.MustParseAddr("192.168.1.1")},
		KillSwitch: &platform.KillSwitch{Prefixes: guarded},
		BlockIPv6:  true,
	}
	return r
}

const (
	runningRules = "firewall dns [192.168.1.1] 53530 53531 guard utun0 [10.0.0.0/8] ipv6"
	keptRules    = "firewall dnsblock [192.168.1.1] guard - [10.0.0.0/8] ipv6"
)

func startKillSwitchSession(t *testing.T, ctx context.Context, d *fake.Drivers, st *memState) (*net.UnixConn, <-chan error) {
	t.Helper()
	c, done := startHelperOpts(t, ctx, d, helperOpts{state: st})
	call(t, c, createReq)
	call(t, c, Request{Op: OpAddRoute, CIDR: "10.0.0.0/8"})
	if r := call(t, c, killSwitchReq("utun0")); !r.OK {
		t.Fatalf("apply_firewall: %+v", r)
	}
	call(t, c, Request{Op: OpDone, Session: true})
	return c, done
}

// Kill switch: when subtun disappears (crash, kill -9, lost tunnel exits
// without ending), the blocking rules replace the session's and stay, with
// pf's reference recorded for whoever comes next.
func TestHelperKillSwitchKeepsRulesWhenSubtunDisappears(t *testing.T) {
	d, st := &fake.Drivers{}, &memState{}
	c, done := startKillSwitchSession(t, context.Background(), d, st)
	_ = c.Close()
	if err := wait(t, done); err != nil {
		t.Fatal(err)
	}
	checkCalls(t, d, created, "add 10.0.0.0/8 utun0", runningRules, "release utun0", keptRules)
	got := st.get()
	if got == nil || got.Owner != testPID || got.Token != "fake-token" || got.Persist == nil {
		t.Fatalf("state %+v", got)
	}
}

func TestHelperEnd(t *testing.T) {
	for _, keep := range []bool{false, true} {
		d, st := &fake.Drivers{}, &memState{}
		c, done := startKillSwitchSession(t, context.Background(), d, st)
		if r := call(t, c, Request{Op: OpEnd, Keep: keep}); !r.OK {
			t.Fatalf("end keep=%v: %+v", keep, r)
		}
		if err := wait(t, done); err != nil {
			t.Fatal(err)
		}
		last := d.Calls()[len(d.Calls())-1]
		if keep && (last != keptRules || st.get() == nil) {
			t.Errorf("lockdown stop: last call %q, state %+v", last, st.get())
		}
		if !keep && (last != "flush" || st.get() != nil) {
			t.Errorf("release stop: last call %q, state %+v", last, st.get())
		}
	}
}

// Ctrl-C reaches the helper too: it waits for subtun's word instead of
// deciding itself.
func TestHelperSignalWaitsForSubtun(t *testing.T) {
	d := &fake.Drivers{}
	ctx, cancel := context.WithCancel(context.Background())
	c, done := startKillSwitchSession(t, ctx, d, &memState{})
	cancel()
	if r := call(t, c, Request{Op: OpEnd}); !r.OK {
		t.Fatalf("end after signal: %+v", r)
	}
	if err := wait(t, done); err != nil {
		t.Fatal(err)
	}
	if last := d.Calls()[len(d.Calls())-1]; last != "flush" {
		t.Fatalf("last call %q, want flush", last)
	}

	// No word from subtun within the grace period: the crash policy.
	d = &fake.Drivers{}
	ctx, cancel = context.WithCancel(context.Background())
	_, done = startKillSwitchSession(t, ctx, d, &memState{})
	cancel()
	if err := wait(t, done); err != nil {
		t.Fatal(err)
	}
	if last := d.Calls()[len(d.Calls())-1]; last != keptRules {
		t.Fatalf("last call %q, want the kept rules", last)
	}
}

// Rules an earlier session left are taken over when its helper is gone:
// its pf reference is adopted, the new rules replace them.
func TestHelperTakesOverLeftovers(t *testing.T) {
	d := &fake.Drivers{Busy: true}
	st := &memState{st: &state{Owner: 99, Token: "old"}}
	c, done := startHelperOpts(t, context.Background(), d, helperOpts{state: st})
	call(t, c, createReq)
	if r := call(t, c, killSwitchReq("utun0")); !r.OK {
		t.Fatalf("apply_firewall: %+v", r)
	}
	if r := call(t, c, Request{Op: OpDone, Session: true}); !r.OK {
		t.Fatal(r)
	}
	if got := st.get(); got.Owner != testPID || got.Token != "old" {
		t.Fatalf("state %+v", got)
	}
	call(t, c, Request{Op: OpEnd})
	wait(t, done)
	checkCalls(t, d, created, "adopt old", runningRules, "release utun0", "flush")
}

func TestHelperRefusesRulesItCannotTakeOver(t *testing.T) {
	cases := map[string]helperOpts{
		"another subtun session": {state: &memState{st: &state{Owner: 99, Token: "t"}}, alive: func(pid int) bool { return pid == 99 }},
		"no session recorded":    {},
	}
	for want, o := range cases {
		d := &fake.Drivers{Busy: true}
		c, done := startHelperOpts(t, context.Background(), d, o)
		call(t, c, createReq)
		if r := call(t, c, firewallReq("192.168.1.1")); r.OK || !strings.Contains(r.Error, want) {
			t.Errorf("got %+v, want error about %q", r, want)
		}
		_ = c.Close()
		wait(t, done)
		checkCalls(t, d, created, "close utun0")
	}
}

// adopt (before connecting): an earlier kill switch keeps blocking, but DNS
// is allowed so subtun can reach its API server. If setup then fails, the
// left-behind rules are put back.
func TestHelperAdopt(t *testing.T) {
	d := &fake.Drivers{Busy: true}
	persist := killSwitchReq("").Persist
	st := &memState{st: &state{Owner: 99, Token: "old", Persist: persist}}
	c, done := startHelperOpts(t, context.Background(), d, helperOpts{state: st})
	if r := call(t, c, Request{Op: OpAdopt}); !r.OK || !r.Kept || !strings.Contains(r.Message, "taken over") {
		t.Fatalf("adopt: %+v", r)
	}
	if r := call(t, c, Request{Op: OpAdopt}); r.OK {
		t.Error("second adopt accepted")
	}
	call(t, c, createReq)
	_ = c.Close() // e.g. connecting to the cluster failed
	wait(t, done)
	checkCalls(t, d, "adopt old", "firewall guard - [10.0.0.0/8] ipv6", created, keptRules, "close utun0")
	if got := st.get(); got == nil || got.Owner != testPID {
		t.Fatalf("state %+v", got)
	}
}

func TestHelperAdoptRemovesLeftoversThatDontBlock(t *testing.T) {
	d := &fake.Drivers{Busy: true}
	st := &memState{st: &state{Owner: 99, Token: "old"}} // e.g. a killed helper's DNS redirect
	c, done := startHelperOpts(t, context.Background(), d, helperOpts{state: st})
	if r := call(t, c, Request{Op: OpAdopt}); !r.OK || r.Kept || !strings.Contains(r.Message, "removed") {
		t.Fatalf("adopt: %+v", r)
	}
	call(t, c, Request{Op: OpDone})
	wait(t, done)
	checkCalls(t, d, "adopt old", "flush")
	if st.get() != nil {
		t.Fatal("state not removed")
	}
}

func TestHelperCleanup(t *testing.T) {
	d := &fake.Drivers{Busy: true}
	st := &memState{st: &state{Owner: 99, Token: "old"}}
	c, done := startHelperOpts(t, context.Background(), d, helperOpts{state: st})
	if r := call(t, c, Request{Op: OpCleanup}); !r.OK || !strings.Contains(r.Message, "released pf") {
		t.Fatalf("cleanup: %+v", r)
	}
	call(t, c, Request{Op: OpDone})
	wait(t, done)
	checkCalls(t, d, "adopt old", "flush")

	// A running session's rules are not touched.
	d = &fake.Drivers{Busy: true}
	c, done = startHelperOpts(t, context.Background(), d, helperOpts{state: &memState{st: &state{Owner: 99}}, alive: func(int) bool { return true }})
	if r := call(t, c, Request{Op: OpCleanup}); r.OK || !strings.Contains(r.Error, "running") {
		t.Fatalf("cleanup of a running session: %+v", r)
	}
	_ = c.Close()
	wait(t, done)
	checkCalls(t, d)

	// Nothing there.
	d = &fake.Drivers{}
	c, done = startHelperOpts(t, context.Background(), d, helperOpts{})
	if r := call(t, c, Request{Op: OpCleanup}); !r.OK || r.Message != "nothing to clean up" {
		t.Fatalf("empty cleanup: %+v", r)
	}
	_ = c.Close()
	wait(t, done)
}

func TestValidatePersist(t *testing.T) {
	ok := killSwitchReq("").Persist
	if err := ValidatePersist(ok); err != nil {
		t.Fatal(err)
	}
	for name, r := range map[string]*platform.Rules{
		"redirect": firewallReq("192.168.1.1").Rules,
		"pass":     {KillSwitch: &platform.KillSwitch{TunIface: "utun3", Prefixes: guarded}},
		"loopback": {KillSwitch: &platform.KillSwitch{Prefixes: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}}},
		"empty":    {},
	} {
		if err := ValidatePersist(r); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// A running session's rules aren't leftovers: adopt leaves them alone and
// this session may go ahead, as long as it needs no firewall rules itself.
func TestHelperAdoptLeavesARunningSessionAlone(t *testing.T) {
	d := &fake.Drivers{Busy: true}
	st := &memState{st: &state{Owner: 99, Token: "theirs"}}
	c, done := startHelperOpts(t, context.Background(), d, helperOpts{state: st, alive: func(pid int) bool { return pid == 99 }})
	if r := call(t, c, Request{Op: OpAdopt}); !r.OK || !r.Running || r.Kept {
		t.Fatalf("adopt: %+v", r)
	}
	call(t, c, createReq)
	call(t, c, Request{Op: OpAddRoute, CIDR: "192.0.2.0/24"})
	if r := call(t, c, firewallReq("192.168.1.1")); r.OK || !strings.Contains(r.Error, "another subtun session") {
		t.Fatalf("firewall rules of its own: %+v", r)
	}
	if r := call(t, c, Request{Op: OpDone}); !r.OK {
		t.Fatalf("routes-only setup: %+v", r)
	}
	wait(t, done)
	checkCalls(t, d, created, "add 192.0.2.0/24 utun0", "release utun0")
	if got := st.get(); got == nil || got.Owner != 99 || got.Token != "theirs" {
		t.Fatalf("the running session's state changed: %+v", got)
	}
}

// Leftovers taken over by a session without a kill switch or DNS capture:
// that session replaces them with nothing.
func TestHelperAdoptedLeftoversGoWithASessionWithoutFirewall(t *testing.T) {
	d := &fake.Drivers{Busy: true}
	st := &memState{st: &state{Owner: 99, Token: "old", Persist: killSwitchReq("").Persist}}
	c, done := startHelperOpts(t, context.Background(), d, helperOpts{state: st})
	if r := call(t, c, Request{Op: OpAdopt}); !r.Kept {
		t.Fatalf("adopt: %+v", r)
	}
	call(t, c, createReq)
	if r := call(t, c, Request{Op: OpDone}); !r.OK {
		t.Fatalf("one-shot done after adopting: %+v", r)
	}
	wait(t, done)
	checkCalls(t, d, "adopt old", "firewall guard - [10.0.0.0/8] ipv6", created, "flush", "release utun0")
	if st.get() != nil {
		t.Fatal("state left behind")
	}
}

// The same for a session that only changes routes (several profiles, none
// with firewall rules): the leftovers would otherwise block traffic even
// through the new utun, and stay behind after a crash.
func TestHelperAdoptedLeftoversGoWithASessionWithoutRules(t *testing.T) {
	d := &fake.Drivers{Busy: true}
	st := &memState{st: &state{Owner: 99, Token: "old", Persist: killSwitchReq("").Persist}}
	c, done := startHelperOpts(t, context.Background(), d, helperOpts{state: st})
	if r := call(t, c, Request{Op: OpAdopt}); !r.Kept {
		t.Fatalf("adopt: %+v", r)
	}
	call(t, c, createReq)
	if r := call(t, c, Request{Op: OpDone, Session: true}); !r.OK {
		t.Fatalf("session done after adopting: %+v", r)
	}
	if st.get() != nil {
		t.Fatal("state left behind")
	}
	_ = c.Close() // a crash: nothing to leave behind
	wait(t, done)
	checkCalls(t, d, "adopt old", "firewall guard - [10.0.0.0/8] ipv6", created, "flush", "release utun0")
}

// The DNS cache is flushed when the DNS redirect goes on and off: at the
// start, so earlier answers don't bypass the capture, and at the end, so
// answers obtained through the tunnel don't outlive it. Updates that keep
// the redirect (DNS servers followed) don't flush.
func TestHelperFlushesDNSCache(t *testing.T) {
	d := &fake.Drivers{DNSCache: true}
	c, done := startHelper(t, context.Background(), d)
	call(t, c, firewallReq("192.168.1.1"))
	call(t, c, Request{Op: OpDone, Session: true})
	call(t, c, firewallReq("10.0.0.1"))
	_ = c.Close()
	if err := wait(t, done); err != nil {
		t.Fatal(err)
	}
	checkCalls(t, d, "firewall dns [192.168.1.1] 53530 53531", "flush dns cache",
		"firewall dns [10.0.0.1] 53530 53531", "flush", "flush dns cache")

	// Kill switch: the rules that stay block DNS instead of redirecting it,
	// so the cache is flushed then too.
	d = &fake.Drivers{DNSCache: true}
	c, done = startKillSwitchSession(t, context.Background(), d, &memState{})
	_ = c.Close()
	if err := wait(t, done); err != nil {
		t.Fatal(err)
	}
	checkCalls(t, d, created, "add 10.0.0.0/8 utun0", runningRules, "flush dns cache", "release utun0",
		keptRules, "flush dns cache")

	// Rules without a DNS redirect never flush.
	d = &fake.Drivers{DNSCache: true}
	c, done = startHelper(t, context.Background(), d)
	r := Request{Op: OpApplyFirewall, Rules: &platform.Rules{BlockIPv6: true}}
	if resp := call(t, c, r); !resp.OK {
		t.Fatalf("apply: %+v", resp)
	}
	call(t, c, Request{Op: OpDone, Session: true})
	_ = c.Close()
	wait(t, done)
	checkCalls(t, d, "firewall ipv6", "flush")

	// Leftovers taken over or cleaned up may come with answers from the
	// earlier session's tunnel.
	d = &fake.Drivers{Busy: true, DNSCache: true}
	c, done = startHelperOpts(t, context.Background(), d, helperOpts{state: &memState{st: &state{Owner: 99, Token: "old"}}})
	if resp := call(t, c, Request{Op: OpCleanup}); !resp.OK {
		t.Fatalf("cleanup: %+v", resp)
	}
	call(t, c, Request{Op: OpDone})
	wait(t, done)
	checkCalls(t, d, "adopt old", "flush", "flush dns cache")
}

// A session may flush the DNS cache while DNS is redirected to subtun (a
// tunnel came back); without a redirect there is nothing to flush.
func TestHelperFlushDNSCacheOp(t *testing.T) {
	d := &fake.Drivers{DNSCache: true}
	c, done := startHelper(t, context.Background(), d)
	call(t, c, createReq)
	if r := call(t, c, Request{Op: OpFlushDNS}); r.OK || !strings.Contains(r.Error, "isn't redirected") {
		t.Fatalf("flush without a redirect: %+v", r)
	}
	call(t, c, firewallReq("192.168.1.1"))
	call(t, c, Request{Op: OpDone, Session: true})
	if r := call(t, c, Request{Op: OpFlushDNS}); !r.OK {
		t.Fatalf("flush in a session: %+v", r)
	}
	_ = c.Close()
	if err := wait(t, done); err != nil {
		t.Fatal(err)
	}
	checkCalls(t, d, created, "firewall dns [192.168.1.1] 53530 53531", "flush dns cache", "release utun0",
		"flush dns cache", "flush", "flush dns cache")
}
