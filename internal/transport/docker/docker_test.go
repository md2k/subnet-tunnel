package docker

import (
	"strings"
	"testing"

	"github.com/moby/moby/api/types/container"
)

// testdata/dockerconfig is laid out like ~/.docker: config.json names the
// current context, contexts/meta/<sha256(name)>/meta.json holds each endpoint.
const fixture = "testdata/dockerconfig"

func TestResolveHost(t *testing.T) {
	t.Setenv("DOCKER_CONTEXT", "")

	if h, err := ResolveHost("", "", "testdata/does-not-exist"); err != nil || h != "" {
		t.Fatalf("no config dir: got %q, %v; want client default", h, err)
	}

	cases := []struct{ name, host, ctx, want string }{
		{"current context", "", "", "unix:///Users/me/.docker/run/docker.sock"},
		{"named context", "", "remote", "tcp://10.0.0.5:2375"},
		{"default context", "", "default", ""},
		{"explicit host wins", "unix:///x.sock", "remote", "unix:///x.sock"},
	}
	for _, tc := range cases {
		h, err := ResolveHost(tc.host, tc.ctx, fixture)
		if err != nil || h != tc.want {
			t.Errorf("%s: got %q, %v; want %q", tc.name, h, err, tc.want)
		}
	}

	t.Setenv("DOCKER_CONTEXT", "remote")
	if h, _ := ResolveHost("", "", fixture); h != "tcp://10.0.0.5:2375" {
		t.Errorf("DOCKER_CONTEXT ignored: got %q", h)
	}
	if _, err := ResolveHost("", "missing", fixture); err == nil {
		t.Error("unknown context accepted")
	}
}

// A followed container: running and not unhealthy or starting; the one
// picked before while it still is, else the newest.
func TestChoose(t *testing.T) {
	c := func(name string, created int64, state container.ContainerState, health container.HealthStatus) container.Summary {
		s := container.Summary{Names: []string{"/" + name}, Created: created, State: state}
		if health != "" {
			s.Health = &container.HealthSummary{Status: health}
		}
		return s
	}
	items := []container.Summary{
		c("web-1", 100, container.StateRunning, ""),
		c("web-2", 200, container.StateRunning, container.Healthy),
		c("web-3", 300, container.StateRunning, container.Starting),
		c("web-4", 400, container.StateExited, ""),
		c("web-5", 500, container.StateRunning, container.Unhealthy),
	}
	if got, err := choose(items, "app=web", ""); err != nil || got != "web-2" {
		t.Errorf("newest usable: %q %v", got, err)
	}
	if got, _ := choose(items, "app=web", "web-1"); got != "web-1" {
		t.Errorf("picked before: %q", got)
	}
	if got, _ := choose(items, "app=web", "web-5"); got != "web-2" {
		t.Errorf("picked before, now unhealthy: %q", got)
	}
	if _, err := choose(nil, "app=web", ""); err == nil || err.Error() != "containers with app=web: none running" {
		t.Errorf("none: %v", err)
	}
	if _, err := choose(items[2:], "app=web", ""); err == nil || !strings.Contains(err.Error(), "none running and healthy (3 found)") {
		t.Errorf("none usable: %v", err)
	}
	for _, sel := range []string{"", "a=b,", "=b", "a!=b"} {
		if _, err := ParseSelector(sel); err == nil {
			t.Errorf("selector %q accepted", sel)
		}
	}
	if parts, err := ParseSelector("com.docker.compose.service=web, tier"); err != nil || len(parts) != 2 || parts[1] != "tier" {
		t.Errorf("selector: %v %v", parts, err)
	}
}

// A container subtun creates: no capabilities, no new privileges, a
// read-only root with an exec-able /tmp, removed once it exits, with the
// limits given.
func TestHostConfig(t *testing.T) {
	hc, err := hostConfig(Target{Network: "dev_default", LimitCPU: "500m", LimitMem: "256Mi"})
	if err != nil {
		t.Fatal(err)
	}
	if !hc.AutoRemove || !hc.ReadonlyRootfs || hc.CapDrop[0] != "ALL" || hc.SecurityOpt[0] != "no-new-privileges" ||
		!strings.Contains(hc.Tmpfs["/tmp"], "exec") || strings.Contains(hc.Tmpfs["/tmp"], "noexec") {
		t.Errorf("security: %+v", hc)
	}
	if hc.NetworkMode != "dev_default" || hc.NanoCPUs != 500_000_000 || hc.Memory != 256<<20 {
		t.Errorf("network, limits: %q %d %d", hc.NetworkMode, hc.NanoCPUs, hc.Memory)
	}
	for _, bad := range []Target{{LimitMem: "lots"}, {LimitCPU: "0"}, {LimitMem: "-1"}} {
		if _, err := hostConfig(bad); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
	if n := generatedName("work"); !strings.HasPrefix(n, "subtun-work-") || len(n) != len("subtun-work-")+6 {
		t.Errorf("name: %q", n)
	}
}
