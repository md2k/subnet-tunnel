package config

import (
	"strings"
	"testing"
)

const sample = `
profiles:
  dev-cluster:
    target:
      k8s:
        context: kind-dev
        namespace: tools
        pod: debug
    routes:
      - 10.96.0.0/12
      - 10.244.0.0/16
      - 10.96.0.10
    exclude:
      - 10.96.0.1
      - 127.0.0.1/32
    socks: 127.0.0.1:1080
    agent: python
    tun:
      address: 198.18.250.1
      mtu: 4000
  local-docker:
    target:
      docker:
        container: subtun-dev-target-1
    socks: 127.0.0.1:1081
`

func TestParse(t *testing.T) {
	f, err := Parse([]byte(sample), "sample")
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(f.Names(), ","); got != "dev-cluster,local-docker" {
		t.Fatalf("names %q", got)
	}
	p, err := f.Profile("dev-cluster")
	if err != nil {
		t.Fatal(err)
	}
	if p.Target.K8s.Pod != "debug" || p.Target.K8s.Context != "kind-dev" || len(p.Routes) != 3 ||
		p.Agent != "python" || p.Tun.Address != "198.18.250.1" || p.Tun.MTU != 4000 {
		t.Fatalf("profile %+v", p)
	}
	if _, err := f.Profile("nope"); err == nil || !strings.Contains(err.Error(), "dev-cluster, local-docker") {
		t.Fatalf("unknown profile error: %v", err)
	}
}

func TestParseRejects(t *testing.T) {
	cases := map[string]string{
		"typo in key": `profiles: {a: {target: {k8s: {pod: p}}, socks: x, rotues: [10.0.0.0/8]}}`,
		"no target":   `profiles: {a: {socks: 127.0.0.1:1080}}`,
		"two targets": `profiles: {a: {target: {k8s: {pod: p}, docker: {container: c}}, socks: x}}`,
		"no pod":      `profiles: {a: {target: {k8s: {namespace: n}}, socks: x}}`,
		"bad route":   `profiles: {a: {target: {k8s: {pod: p}}, routes: [10.1.2.0/16]}}`,
		"loopback":    `profiles: {a: {target: {k8s: {pod: p}}, routes: [127.0.0.0/8]}}`,
		"bad agent":   `profiles: {a: {target: {k8s: {pod: p}}, socks: x, agent: perl}}`,
		"bad name":    `profiles: {"Dev Cluster": {target: {k8s: {pod: p}}, socks: x}}`,
		"nothing":     `profiles: {a: {target: {k8s: {pod: p}}}}`,
		"empty":       `profiles: {}`,
	}
	for name, doc := range cases {
		if _, err := Parse([]byte(doc), name); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
