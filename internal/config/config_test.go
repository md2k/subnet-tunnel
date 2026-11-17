package config

import (
	"fmt"
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
        create: false
        name: debug
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
    dns:
      domains: [svc.cluster.local, .*.privatelink.blob.core.windows.net]
      patterns: ['^db-[0-9]+\.']
      servers: [192.168.1.1, 192.168.1.2]
      fallback: 1.1.1.1:53
  local-docker:
    target:
      docker:
        create: false
        name: subtun-dev-target-1
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
	if p.Target.K8s.Name != "debug" || p.Target.K8s.Context != "kind-dev" || len(p.Routes) != 3 ||
		p.Agent != "python" || p.Tun.Address != "198.18.250.1" || p.Tun.MTU != 4000 {
		t.Fatalf("profile %+v", p)
	}
	if d := p.DNS; len(d.Domains) != 2 || len(d.Patterns) != 1 || len(d.Servers) != 2 || d.Fallback != "1.1.1.1:53" || d.Capture != "" {
		t.Fatalf("dns %+v", d)
	}
	auto, err := Parse([]byte(`profiles: {a: {target: {k8s: {create: false, name: p}}, routes: [10.0.0.0/8], dns: {servers: auto, domains: [.]}}}`), "auto")
	if err != nil {
		t.Fatal(err)
	}
	if s := auto.Profiles["a"].DNS.Servers; len(s) != 1 || s[0] != "auto" {
		t.Fatalf("servers: auto parsed as %q", s)
	}
	if _, err := f.Profile("nope"); err == nil || !strings.Contains(err.Error(), "dev-cluster, local-docker") {
		t.Fatalf("unknown profile error: %v", err)
	}
}

// A target is a pod or container subtun creates (the default), or an
// existing one by name or by labels; the messages say which keys go with
// which.
func TestTargets(t *testing.T) {
	f, err := Parse([]byte(`profiles:
  made: {target: {k8s: {namespace: ops, image: busybox:1.37, name: subtun-made, resources: {requests: {cpu: 50m}, limits: {memory: 512Mi}}}}, socks: 127.0.0.1:1}
  plain: {target: {k8s: {}}, socks: 127.0.0.1:2}
  named: {target: {k8s: {create: false, name: toolbox-0, container: tools}}, socks: 127.0.0.1:3}
  labels: {target: {k8s: {selector: "app=toolbox,tier!=db"}}, socks: 127.0.0.1:4}
  box: {target: {docker: {network: dev_default, resources: {limits: {cpu: "1"}}}}, socks: 127.0.0.1:5}
  web: {target: {docker: {selector: com.docker.compose.service=web}}, socks: 127.0.0.1:6}
  jump: {target: {ssh: {host: "me@[2001:db8::5]:2200", identity: ~/.ssh/work, jump: "a@j1:2222, j2"}}, socks: 127.0.0.1:7}
  alias: {target: {ssh: {host: db-prod, user: ops, port: 2022}}, socks: 127.0.0.1:8}
`), "t")
	if err != nil {
		t.Fatal(err)
	}
	for name, creates := range map[string]bool{"made": true, "plain": true, "named": false, "labels": false} {
		if p, _ := f.Profile(name); p.Target.K8s.Creates() != creates {
			t.Errorf("%s creates: %v", name, !creates)
		}
	}
	for name, creates := range map[string]bool{"box": true, "web": false} {
		if p, _ := f.Profile(name); p.Target.Docker.Creates() != creates {
			t.Errorf("%s creates: %v", name, !creates)
		}
	}
	for name, want := range map[string]string{"jump": "me 2001:db8::5 2200", "alias": "ops db-prod 2022"} {
		p, _ := f.Profile(name)
		user, host, port, err := p.Target.SSH.Dest()
		if got := fmt.Sprintf("%s %s %d", user, host, port); err != nil || got != want {
			t.Errorf("%s: %q %v, want %q", name, got, err, want)
		}
	}
	for doc, want := range map[string]string{
		`{ssh: {}}`:                                      "target.ssh.host: [user@]host[:port]",
		`{ssh: {host: "me@"}}`:                           `target.ssh.host "me@": not [user@]host[:port]`,
		`{ssh: {host: "h:0"}}`:                           `target.ssh.host "h:0": port 0 isn't 1-65535`,
		`{ssh: {host: "a@h", user: b}}`:                  "target.ssh: the user is in host (a@) and in user",
		`{ssh: {host: "h:22", port: 2222}}`:              "target.ssh: the port is in host (:22) and in port",
		`{ssh: {host: h, port: 70000}}`:                  "target.ssh.port 70000: 1-65535",
		`{ssh: {host: h, jump: "a b"}}`:                  `target.ssh.jump "a b": not [user@]host[:port]`,
		`{ssh: {host: "-oProxyCommand=x"}}`:              "not [user@]host[:port]",
		`{ssh: {host: h}, docker: {}}`:                   "target: set one of k8s, docker, ssh",
		`{}`:                                             "target: set k8s, docker or ssh",
		`{k8s: {create: false}}`:                         "target.k8s (an existing pod) needs one of name, selector",
		`{k8s: {create: false, name: p, selector: x}}`:   "target.k8s (an existing pod): name and selector don't go together",
		`{k8s: {create: false, name: p, image: i}}`:      "target.k8s.image: only with create (the default)",
		`{k8s: {create: false, name: p, resources: {}}}`: "target.k8s.resources: only with create (the default)",
		`{k8s: {create: true, selector: x}}`:             "target.k8s.selector: only with create: false (an existing pod)",
		`{k8s: {container: c}}`:                          "target.k8s.container: only with create: false (an existing pod)",
		`{k8s: {name: Not_A_Name}}`:                      `target.k8s.name "Not_A_Name": lowercase letters, digits and '-'`,
		`{k8s: {resources: {limits: {memory: lots}}}}`:   `target.k8s.resources.limits.memory "lots": a quantity`,
		`{k8s: {pod: p}}`:                                "target.k8s.pod is now name, with create: false for an existing pod (name: p, create: false)",
		`{docker: {container: c}}`:                       "target.docker.container is now name, with create: false",
		`{docker: {create: false, name: c, network: n}}`: "target.docker.network: only with create (the default)",
		`{docker: {resources: {requests: {cpu: "1"}}}}`:  "target.docker.resources.requests: a container takes limits only",
		`{docker: {create: false}}`:                      "target.docker (an existing container) needs one of name, selector",
	} {
		if _, err := Parse([]byte(`profiles: {a: {target: `+doc+`, socks: x}}`), "t"); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v, want %q", doc, err, want)
		}
	}
}

func TestParseRejects(t *testing.T) {
	cases := map[string]string{
		"typo in key":            `profiles: {a: {target: {k8s: {create: false, name: p}}, socks: x, rotues: [10.0.0.0/8]}}`,
		"no target":              `profiles: {a: {socks: 127.0.0.1:1080}}`,
		"two targets":            `profiles: {a: {target: {k8s: {create: false, name: p}, docker: {create: false, name: c}}, socks: x}}`,
		"container and selector": `profiles: {a: {target: {docker: {create: false, name: c, selector: app=x}}, socks: x}}`,
		"bad route":              `profiles: {a: {target: {k8s: {create: false, name: p}}, routes: [10.1.2.0/16]}}`,
		"loopback":               `profiles: {a: {target: {k8s: {create: false, name: p}}, routes: [127.0.0.0/8]}}`,
		"bad agent":              `profiles: {a: {target: {k8s: {create: false, name: p}}, socks: x, agent: perl}}`,
		"bad name":               `profiles: {"Dev Cluster": {target: {k8s: {create: false, name: p}}, socks: x}}`,
		"nothing":                `profiles: {a: {target: {k8s: {create: false, name: p}}}}`,
		"empty":                  `profiles: {}`,
		"dns capture":            `profiles: {a: {target: {k8s: {create: false, name: p}}, socks: x, dns: {capture: magic}}}`,
		"dns regex":              `profiles: {a: {target: {k8s: {create: false, name: p}}, socks: x, dns: {domains: ['.*\.x\.com']}}}`,
		"dns pattern":            `profiles: {a: {target: {k8s: {create: false, name: p}}, socks: x, dns: {patterns: ['(']}}}`,
		"dns servers":            `profiles: {a: {target: {k8s: {create: false, name: p}}, socks: x, dns: {servers: {a: b}}}}`,
	}
	for name, doc := range cases {
		if _, err := Parse([]byte(doc), name); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

const withDefaults = `
defaults:
  exclude: [192.168.1.0/24]
  agent: python
  killSwitch: {mode: on, dns: allow}
  blockIPv6: true
  dns: {domains: [company.com], fallback: 192.168.1.1, unrouted: fallback}
profiles:
  plain:
    target: {k8s: {create: false, name: p}}
    routes: [10.0.0.0/8]
  strict:
    target: {docker: {create: false, name: c}}
    routes: [0.0.0.0/1, 128.0.0.0/1]
    exclude: [10.1.0.0/16]
    agent: binary
    killSwitch: {mode: lockdown}
    blockIPv6: auto
    dns: {domains: [cluster.local], unrouted: block}
  loose:
    target: {k8s: {create: false, name: p}}
    routes: [10.0.0.0/8]
    killSwitch: {mode: off}
    blockIPv6: false
`

// Defaults fill in what a profile doesn't set; lists add up.
func TestDefaults(t *testing.T) {
	f, err := Parse([]byte(withDefaults), "defaults")
	if err != nil {
		t.Fatal(err)
	}
	plain, _ := f.Profile("plain")
	if plain.Agent != "python" || plain.KillSwitch.Mode != "on" || plain.KillSwitch.DNS != "allow" || plain.BlockIPv6 != "true" ||
		strings.Join(plain.Exclude, ",") != "192.168.1.0/24" || strings.Join(plain.DNS.Domains, ",") != "company.com" || plain.DNS.Fallback != "192.168.1.1" ||
		plain.DNS.Unrouted != "fallback" {
		t.Errorf("plain: %+v", plain)
	}
	strict, _ := f.Profile("strict")
	if strict.Agent != "binary" || strict.KillSwitch.Mode != "lockdown" || strict.KillSwitch.DNS != "allow" || strict.BlockIPv6 != "auto" ||
		strings.Join(strict.Exclude, ",") != "192.168.1.0/24,10.1.0.0/16" || strings.Join(strict.DNS.Domains, ",") != "company.com,cluster.local" ||
		strict.DNS.Unrouted != "block" {
		t.Errorf("strict: %+v", strict)
	}
	// YAML reads bare off/false as booleans.
	loose, _ := f.Profile("loose")
	if loose.KillSwitch.Mode != "off" || loose.BlockIPv6 != "false" {
		t.Errorf("loose: %+v", loose)
	}
}

func TestDefaultsRejects(t *testing.T) {
	cases := map[string]string{
		"target in defaults": `{defaults: {target: {k8s: {create: false, name: p}}}, profiles: {a: {target: {k8s: {create: false, name: p}}, socks: x}}}`,
		"bad default":        `{defaults: {agent: perl}, profiles: {a: {target: {k8s: {create: false, name: p}}, socks: x}}}`,
		"bad mode":           `{profiles: {a: {target: {k8s: {create: false, name: p}}, socks: x, killSwitch: {mode: always}}}}`,
		"bad ks dns":         `{profiles: {a: {target: {k8s: {create: false, name: p}}, socks: x, killSwitch: {dns: maybe}}}}`,
		"bad blockIPv6":      `{profiles: {a: {target: {k8s: {create: false, name: p}}, socks: x, blockIPv6: sometimes}}}`,
	}
	for name, doc := range cases {
		if _, err := Parse([]byte(doc), name); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// Routes from defaults count for "nothing to do".
	if _, err := Parse([]byte(`{defaults: {routes: [10.0.0.0/8]}, profiles: {a: {target: {k8s: {create: false, name: p}}}}}`), "routes"); err != nil {
		t.Errorf("routes from defaults: %v", err)
	}
}

// Bare off (a YAML 1.1 boolean) works for dns.capture too; on isn't a value.
func TestDNSCaptureWords(t *testing.T) {
	f, err := Parse([]byte("profiles:\n  p:\n    target: {k8s: {create: false, name: x}}\n    routes: [10.0.0.0/8]\n    dns: {domains: [a.example], capture: off}\n"), "t")
	if err != nil {
		t.Fatal(err)
	}
	if p, _ := f.Profile("p"); p.DNS.Capture != "off" {
		t.Fatalf("capture %q", p.DNS.Capture)
	}
	if _, err := Parse([]byte("profiles:\n  p:\n    target: {k8s: {create: false, name: x}}\n    routes: [10.0.0.0/8]\n    dns: {capture: on}\n"), "t"); err == nil || !strings.Contains(err.Error(), `"on": use firewall or off`) {
		t.Fatalf("capture on: %v", err)
	}
}

// reconnect: defaults for every profile, a profile's own values win, and
// attempts: 0 (off) is a value, not "unset".
func TestReconnectConfig(t *testing.T) {
	f, err := Parse([]byte(`defaults:
  reconnect: {attempts: 5, delay: 2s, maxDelay: 30s}
profiles:
  a:
    target: {k8s: {create: false, name: x}}
    socks: 127.0.0.1:1080
  b:
    target: {k8s: {create: false, name: x}}
    socks: 127.0.0.1:1080
    reconnect: {attempts: 0}
  c:
    target: {k8s: {create: false, name: x}}
    socks: 127.0.0.1:1080
    reconnect: {maxDelay: 5m}
`), "t")
	if err != nil {
		t.Fatal(err)
	}
	a, _ := f.Profile("a")
	b, _ := f.Profile("b")
	c, _ := f.Profile("c")
	if *a.Reconnect.Attempts != 5 || a.Reconnect.Delay != "2s" || a.Reconnect.MaxDelay != "30s" {
		t.Errorf("a: %+v", a.Reconnect)
	}
	if *b.Reconnect.Attempts != 0 || b.Reconnect.Delay != "2s" {
		t.Errorf("b: %+v", b.Reconnect)
	}
	if *c.Reconnect.Attempts != 5 || c.Reconnect.MaxDelay != "5m" {
		t.Errorf("c: %+v", c.Reconnect)
	}
	for _, bad := range []string{"{attempts: -1}", "{delay: soon}", "{maxDelay: 0s}"} {
		y := "profiles:\n  p:\n    target: {k8s: {create: false, name: x}}\n    socks: 127.0.0.1:1080\n    reconnect: " + bad + "\n"
		if _, err := Parse([]byte(y), "t"); err == nil {
			t.Errorf("reconnect %s accepted", bad)
		}
	}
}

// control is global (top level): status, full or off.
func TestControlKey(t *testing.T) {
	base := "profiles:\n  p:\n    target: {docker: {create: false, name: c}}\n    socks: 127.0.0.1:1080\n"
	for in, want := range map[string]string{"control: off\n": "off", "control: status\n": "status", "control: full\n": "full", "": ""} {
		f, err := Parse([]byte(in+base), "t")
		if err != nil || string(f.Control) != want {
			t.Errorf("%q: %v %q", in, err, f.Control)
		}
	}
	for _, in := range []string{"control: maybe\n", "control: true\n"} {
		if _, err := Parse([]byte(in+base), "t"); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
	if _, err := Parse([]byte("defaults:\n  control: off\n"+base), "t"); err == nil {
		t.Error("control in defaults accepted: it is global only")
	}
}

// log is global (top level), checked when loaded.
func TestLogKey(t *testing.T) {
	base := "profiles:\n  p:\n    target: {docker: {create: false, name: c}}\n    socks: 127.0.0.1:1080\n"
	good := "log:\n  file: off\n  format: text\n  level: warn,dns=debug\n  levels: {conn: info}\n  maxSize: 10MB\n  maxAge: 2d\n  maxTotal: 1GB\n  mask: [dns, destinations]\n"
	f, err := Parse([]byte(good+base), "t")
	if err != nil {
		t.Fatal(err)
	}
	if f.Log.File != "off" || f.Log.Levels["conn"] != "info" || len(f.Log.Mask) != 2 {
		t.Errorf("log: %+v", f.Log)
	}
	for _, bad := range []string{
		"log: {file: maybe}\n", "log: {format: xml}\n", "log: {level: loud}\n", "log: {levels: {disk: debug}}\n",
		"log: {maxSize: lots}\n", "log: {maxAge: 3w}\n", "log: {mask: [everything]}\n", "log: {colour: red}\n",
	} {
		if _, err := Parse([]byte(bad+base), "t"); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if _, err := Parse([]byte("defaults:\n  log: {file: off}\n"+base), "t"); err == nil {
		t.Error("log in defaults accepted: it is global only")
	}
}

func TestTUIKey(t *testing.T) {
	base := "profiles:\n  p:\n    target: {docker: {create: false, name: c}}\n    socks: 127.0.0.1:1080\n"
	f, err := Parse([]byte("tui: {layout: detail}\n"+base), "t")
	if err != nil || f.TUI.Layout != LayoutDetail {
		t.Fatalf("tui: %+v %v", f.TUI, err)
	}
	if _, err := Parse([]byte("tui: {layout: grid}\n"+base), "t"); err == nil || !strings.Contains(err.Error(), `tui.layout "grid"`) {
		t.Errorf("bad layout: %v", err)
	}
	if _, err := Parse([]byte("tui: {units: furlongs}\n"+base), "t"); err == nil || !strings.Contains(err.Error(), `tui.units "furlongs"`) {
		t.Errorf("bad units: %v", err)
	}
	if f, err := Parse([]byte("tui: {mouse: off}\n"+base), "t"); err != nil || f.TUI.Mouse != "off" {
		t.Errorf("bare off: %+v %v", f, err)
	}
	if _, err := Parse([]byte("tui: {mouse: sometimes}\n"+base), "t"); err == nil || !strings.Contains(err.Error(), `tui.mouse "sometimes"`) {
		t.Errorf("bad mouse: %v", err)
	}
	if _, err := Parse([]byte("defaults:\n  tui: {layout: table}\n"+base), "t"); err == nil {
		t.Error("tui in defaults accepted: it is global only")
	}
}
