package transport

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/md2k/subnet-tunnel/internal/agentbin"
	"github.com/md2k/subnet-tunnel/internal/testutil"
)

// fakeTarget answers the probe from fixed state and records what Bootstrap
// asks of it. No shell runs anywhere.
type fakeTarget struct {
	uname    string
	cached   map[string]bool
	writable bool

	uploaded map[string][]byte
	started  []string
}

func (f *fakeTarget) Describe() string { return "fake" }

func (f *fakeTarget) Run(_ context.Context, cmd []string, stdin io.Reader) (string, error) {
	switch cmd[2] {
	case probeScript:
		var b strings.Builder
		b.WriteString(f.uname + "\n")
		for _, p := range cmd[5:] { // sh -c script sh dir paths...
			if f.cached[p] {
				b.WriteString("have " + p + "\n")
			}
		}
		if f.writable {
			b.WriteString("writable\n")
		}
		return b.String(), nil
	case uploadScript:
		data, _ := io.ReadAll(stdin)
		if f.uploaded == nil {
			f.uploaded = map[string][]byte{}
		}
		f.uploaded[cmd[5]] = data // sh -c script sh dir path
		return "", nil
	}
	panic("unexpected command: " + strings.Join(cmd, " "))
}

func (f *fakeTarget) Stream(_ context.Context, cmd []string, _ io.Writer) (io.ReadWriteCloser, error) {
	f.started = cmd
	c, _ := testutil.Pair()
	return c, nil
}

var agents = []agentbin.Binary{
	{Arch: "amd64", Data: []byte("amd64-agent"), SHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
	{Arch: "arm64", Data: []byte("arm64-agent"), SHA256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
}

var discard = slog.New(slog.DiscardHandler)

func TestBootstrapUploadsMatchingArch(t *testing.T) {
	f := &fakeTarget{uname: "aarch64", writable: true}
	c, err := Bootstrap(context.Background(), f, agents, Options{AgentArgs: []string{"-v"}}, discard)
	if err != nil {
		t.Fatal(err)
	}
	want := "/tmp/subtun-agent-bbbbbbbbbbbbbbbb"
	if !bytes.Equal(f.uploaded[want], []byte("arm64-agent")) {
		t.Fatalf("uploaded %v, want arm64 agent at %s", f.uploaded, want)
	}
	if strings.Join(f.started, " ") != want+" -v" {
		t.Fatalf("started %q", f.started)
	}
	if c.SHA256 != agents[1].SHA256 || !strings.Contains(c.Desc, "linux/arm64") {
		t.Fatalf("carrier %+v", c)
	}
}

func TestBootstrapSkipsCachedAgent(t *testing.T) {
	path := "/work/subtun-agent-aaaaaaaaaaaaaaaa"
	f := &fakeTarget{uname: "x86_64", cached: map[string]bool{path: true}} // cached, dir not writable
	if _, err := Bootstrap(context.Background(), f, agents, Options{AgentDir: "/work"}, discard); err != nil {
		t.Fatal(err)
	}
	if len(f.uploaded) != 0 {
		t.Fatalf("re-uploaded a cached agent: %v", f.uploaded)
	}
	if f.started[0] != path {
		t.Fatalf("started %q, want %s", f.started, path)
	}
}

func TestBootstrapErrors(t *testing.T) {
	cases := []struct {
		name   string
		target *fakeTarget
		agents []agentbin.Binary
		want   string
	}{
		{"read-only dir", &fakeTarget{uname: "x86_64"}, agents, "--agent-dir"},
		{"unsupported arch", &fakeTarget{uname: "s390x", writable: true}, agents, "not supported"},
		{"no agent for arch", &fakeTarget{uname: "x86_64", writable: true}, agents[1:], "no agent for it"},
		{"no agents at all", &fakeTarget{uname: "x86_64", writable: true}, nil, "no agent binaries"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Bootstrap(context.Background(), tc.target, tc.agents, Options{}, discard)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want error containing %q", err, tc.want)
			}
			if len(tc.target.uploaded) != 0 || tc.target.started != nil {
				t.Fatal("uploaded or started despite the error")
			}
		})
	}
}
