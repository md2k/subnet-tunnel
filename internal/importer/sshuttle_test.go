package importer

import (
	"errors"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/md2k/subnet-tunnel/internal/config"
)

func noFiles(string) ([]byte, error) { return nil, errors.New("no files in this test") }

func importFile(t *testing.T, path string) *Profile {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	p, err := SSHuttle(f, noFiles)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func hasNote(p *Profile, sub string) bool {
	return slices.ContainsFunc(p.Notes, func(n string) bool { return strings.Contains(n, sub) })
}

func TestSSHuttleFile(t *testing.T) {
	p := importFile(t, "testdata/sshuttle.conf")

	if want := []string{"203.0.113.0/24", "198.51.100.0/24", "10.20.0.0/16", "192.0.2.10/32"}; !slices.Equal(p.Routes, want) {
		t.Errorf("routes %q, want %q", p.Routes, want)
	}
	if want := []string{"198.51.100.0/25"}; !slices.Equal(p.Exclude, want) {
		t.Errorf("exclude %q, want %q", p.Exclude, want)
	}
	if want := []string{"example.com", "privatelink.blob.core.windows.net"}; !slices.Equal(p.Domains, want) {
		t.Errorf("domains %q, want %q", p.Domains, want)
	}
	if want := []string{`^db-[0-9]+\.prod\.example\.org$`}; !slices.Equal(p.Patterns, want) {
		t.Errorf("patterns %q, want %q", p.Patterns, want)
	}
	if p.Fallback != "192.0.2.53" {
		t.Errorf("fallback %q", p.Fallback)
	}
	for _, want := range []string{
		"--method: left out", "--no-latency-control: left out", "--latency-buffer-size: left out",
		"--disable-ipv6", "--remote user@bastion.example.net", "--frobnicate: unknown",
		"port 8080 dropped", "written as 10.20.0.0/16", "gitlab.example.com: only IP addresses",
		"fd00::/8: subtun captures IPv4 only", "(unclosed: not valid", "4 pattern(s) of the form .*.suffix",
	} {
		if !hasNote(p, want) {
			t.Errorf("no note about %q in\n%s", want, strings.Join(p.Notes, "\n"))
		}
	}
	for _, want := range []string{
		"route 203.0.113.7/32", "exclude 127.0.0.1/32", "domain corp.example.com: already covered by example.com", "domain example.com: listed twice",
	} {
		if !slices.ContainsFunc(p.Dropped, func(d string) bool { return strings.HasPrefix(d, want) }) {
			t.Errorf("not dropped: %q in\n%s", want, strings.Join(p.Dropped, "\n"))
		}
	}
	if n := slices.IndexFunc(p.Dropped, func(d string) bool { return strings.HasPrefix(d, "route 203.0.113.0/24") }); n < 0 {
		t.Error("duplicate /24 not reported")
	}
}

// The generated YAML is a valid config file once a target is set.
func TestSSHuttleYAMLLoads(t *testing.T) {
	p := importFile(t, "testdata/sshuttle.conf")
	out := p.YAML("from-sshuttle", "{docker: {container: 'app'}}", "testdata/sshuttle.conf")
	f, err := config.Parse(out, "generated")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	got, err := f.Profile("from-sshuttle")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got.Routes, p.Routes) || !slices.Equal(got.DNS.Patterns, p.Patterns) || got.DNS.Fallback != "192.0.2.53" ||
		got.Target.Docker == nil || got.Target.Docker.Container != "app" {
		t.Fatalf("loaded %+v", got)
	}
	// Without a target the file says so and subtun refuses it until filled in.
	placeholder := p.YAML("from-sshuttle", "", "x")
	if !strings.Contains(string(placeholder), "target: {}  # set one") {
		t.Fatalf("no placeholder:\n%s", placeholder)
	}
	if _, err := config.Parse(placeholder, "placeholder"); err == nil {
		t.Fatal("profile without a target accepted")
	}
}

func TestSSHuttleShortForms(t *testing.T) {
	cases := []struct {
		in      string
		domains []string
		routes  []string
		note    string
	}{
		{in: "--dns\n10.0.0.0/8\n", domains: []string{"."}, routes: []string{"10.0.0.0/8"}},
		{in: "0/0\n-x\n192.0.2.0/24\n", routes: []string{"0.0.0.0/1", "128.0.0.0/1"}, note: "a full tunnel"},
		{in: "--dns-domains\n.*.example.com\n10.0.0.0/8\n", domains: []string{"example.com"}, routes: []string{"10.0.0.0/8"}, note: "without --dns had no effect"},
		{in: "--dns-to [2001:db8::53]:53\n10.0.0.0/8\n", routes: []string{"10.0.0.0/8"}, note: "IPv4 only"},
	}
	for _, c := range cases {
		p, err := SSHuttle(strings.NewReader(c.in), noFiles)
		if err != nil {
			t.Errorf("%q: %v", c.in, err)
			continue
		}
		if !slices.Equal(p.Domains, c.domains) || !slices.Equal(p.Routes, c.routes) {
			t.Errorf("%q: domains %q routes %q", c.in, p.Domains, p.Routes)
		}
		if c.note != "" && !hasNote(p, c.note) {
			t.Errorf("%q: no note %q in %q", c.in, c.note, p.Notes)
		}
	}
	if _, err := SSHuttle(strings.NewReader("--dns-to\n"), noFiles); err == nil {
		t.Error("option without a value accepted")
	}
}

func TestSSHuttleSubnetFiles(t *testing.T) {
	files := map[string]string{"nets.txt": "# corp\n10.0.0.0/8\n172.16.0.0/12\n", "skip.txt": "10.1.0.0/16\n"}
	read := func(name string) ([]byte, error) {
		if s, ok := files[name]; ok {
			return []byte(s), nil
		}
		return nil, os.ErrNotExist
	}
	p, err := SSHuttle(strings.NewReader("-s\nnets.txt\n--exclude-from=skip.txt\n"), read)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(p.Routes, []string{"10.0.0.0/8", "172.16.0.0/12"}) || !slices.Equal(p.Exclude, []string{"10.1.0.0/16"}) {
		t.Fatalf("routes %q exclude %q", p.Routes, p.Exclude)
	}
	if _, err := SSHuttle(strings.NewReader("-s\nmissing.txt\n"), read); err == nil {
		t.Fatal("missing subnets file accepted")
	}
}

func TestAddProfile(t *testing.T) {
	p := &Profile{Routes: []string{"10.0.0.0/8"}, Domains: []string{"example.com"}}
	entry := func(indent string) string { return p.Entry("work", "{docker: {container: 'app'}}", "x", indent) }
	cases := map[string]string{
		"two-space, defaults after": "# my config\nprofiles:\n  dev:\n    target: {k8s: {pod: p}}\n    socks: 127.0.0.1:1080\ndefaults:\n  exclude: [192.168.1.0/24]\n",
		"four-space":                "profiles:\n    dev:\n        target: {k8s: {pod: p}}\n        socks: 127.0.0.1:1080\n",
		"comment after profiles":    "profiles:  # mine\n  # first one\n  dev:\n    target: {k8s: {pod: p}}\n    socks: x\n",
		"no profiles key":           "defaults:\n  agent: python\n",
		"empty file":                "",
	}
	for name, existing := range cases {
		out, err := AddProfile([]byte(existing), entry)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		f, err := config.Parse(out, name)
		if err != nil {
			t.Errorf("%s: result doesn't load: %v\n%s", name, err, out)
			continue
		}
		work, err := f.Profile("work")
		if err != nil || work.Target.Docker == nil || len(work.Routes) != 1 {
			t.Errorf("%s: work profile %+v, %v", name, work, err)
		}
		if strings.Contains(existing, "dev:") {
			if _, err := f.Profile("dev"); err != nil {
				t.Errorf("%s: existing profile lost", name)
			}
		}
		if strings.Contains(existing, "# my config") && !strings.Contains(string(out), "# my config") {
			t.Errorf("%s: comments lost", name)
		}
	}
	if _, err := AddProfile([]byte("profiles: {dev: {target: {k8s: {pod: p}}, socks: x}}\n"), entry); err == nil {
		t.Error("inline profiles accepted")
	}
}
