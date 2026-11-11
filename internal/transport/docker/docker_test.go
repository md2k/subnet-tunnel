package docker

import "testing"

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
