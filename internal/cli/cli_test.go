package cli

import (
	"bytes"
	"net/netip"
	"strings"
	"testing"
)

// runCLI executes subtun with args and returns stdout and the error. Only
// dry runs and config listing here: nothing connects or asks for sudo.
func runCLI(t *testing.T, args ...string) (string, error) {
	t.Helper()
	root := newRoot()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs(args)
	err := root.Execute()
	return out.String(), err
}

func TestUpListsProfiles(t *testing.T) {
	out, err := runCLI(t, "--config", "testdata/config.yaml", "up")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "dev\n  socks-only") {
		t.Fatalf("got %q", out)
	}
}

func TestUpDryRun(t *testing.T) {
	out, err := runCLI(t, "--config", "testdata/config.yaml", "up", "dev", "--dry-run")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"routes on the utun (2, from 3 given, 1 excluded):\n  198.51.100.0/24\n  203.0.113.0/25\n",
		"route 203.0.113.7/32: already covered by 203.0.113.0/24",
		"utun 198.18.249.1, MTU 9000",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
}

func TestUpFlagsOverrideAndAdd(t *testing.T) {
	out, err := runCLI(t, "--config", "testdata/config.yaml", "up", "dev", "192.0.2.0/24",
		"-x", "198.51.100.0/25", "--tun-addr", "198.18.250.1", "--mtu", "4000", "--dry-run")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"  192.0.2.0/24\n",            // added on the command line
		"  198.51.100.128/25\n",       // profile route minus command-line exclude
		"  203.0.113.0/25\n",          // profile exclude still applies
		"utun 198.18.250.1, MTU 4000", // flags override the profile
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
}

func TestUpErrors(t *testing.T) {
	if _, err := runCLI(t, "--config", "testdata/config.yaml", "up", "nope"); err == nil || !strings.Contains(err.Error(), "dev, socks-only") {
		t.Errorf("unknown profile: %v", err)
	}
	if _, err := runCLI(t, "--config", "testdata/missing.yaml", "up"); err == nil {
		t.Error("missing config accepted")
	}
}

func TestK8sDryRunWithoutConfig(t *testing.T) {
	out, err := runCLI(t, "k8s", "debug", "203.0.113.0/24", "-x", "203.0.113.5", "--dry-run")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "routes on the utun (8, from 1 given, 1 excluded)") {
		t.Fatalf("got\n%s", out)
	}
}

func TestRouteSafetyChecks(t *testing.T) {
	cases := map[string][]string{
		"tun address inside a route": {"k8s", "debug", "198.18.0.0/15", "--dry-run"},
		"bad tun address":            {"k8s", "debug", "203.0.113.0/24", "--tun-addr", "127.0.0.1", "--dry-run"},
		"bad MTU":                    {"k8s", "debug", "203.0.113.0/24", "--mtu", "100", "--dry-run"},
		"host bits":                  {"k8s", "debug", "203.0.113.1/24", "--dry-run"},
		"excludes remove all":        {"k8s", "debug", "203.0.113.0/24", "-x", "203.0.113.0/24", "--dry-run"},
		"nothing to do":              {"k8s", "debug", "--dry-run"},
	}
	for name, args := range cases {
		if _, err := runCLI(t, args...); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestExcludeEndpoints(t *testing.T) {
	rp, _, err := planRoutes(settings{routes: []string{"203.0.113.0/24"}, tunAddr: "198.18.249.1", mtu: 9000})
	if err != nil {
		t.Fatal(err)
	}
	log := newLogger(false)

	// API server outside the routes: nothing changes.
	got, err := excludeEndpoints(rp, []netip.Addr{netip.MustParseAddr("192.0.2.10")}, log)
	if err != nil || len(got) != 1 || got[0].String() != "203.0.113.0/24" {
		t.Fatalf("outside: %v %v", got, err)
	}
	// API server inside: carved out, everything else still routed.
	api := netip.MustParseAddr("203.0.113.10")
	got, err = excludeEndpoints(rp, []netip.Addr{api}, log)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 8 {
		t.Fatalf("want the /24 minus one address = 8 routes, got %v", got)
	}
	for _, p := range got {
		if p.Contains(api) {
			t.Fatalf("API server %s still routed via %s", api, p)
		}
	}
}
