package transport

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/md2k/subnet-tunnel/internal/agentbin"
	"github.com/md2k/subnet-tunnel/internal/agentpy"
	"github.com/md2k/subnet-tunnel/internal/testutil"
)

// fakeTarget answers the probes from fixed state and records what Bootstrap
// asks of it. No shell runs anywhere.
type fakeTarget struct {
	noShell bool
	uname   string
	dir     string          // usable dir reported by the probe, "" for none
	cached  map[string]bool // full paths of cached agents
	python  string          // python command, "" for none
	pyver   string

	mu       sync.Mutex
	uploaded map[string][]byte
	started  []string
	sent     bytes.Buffer  // what was written to the started agent
	readDone chan struct{} // closed when the reader of sent has stopped
}

func (f *fakeTarget) Describe() string { return "fake" }

func (f *fakeTarget) Run(_ context.Context, cmd []string, stdin io.Reader) (string, error) {
	switch {
	case cmd[0] == "sh" && f.noShell:
		return "", errors.New(`exec: "sh": executable file not found in $PATH`)
	case cmd[0] == "sh" && cmd[2] == probeScript:
		var b strings.Builder
		b.WriteString("arch " + f.uname + "\n")
		for _, name := range cmd[5:] { // sh -c script sh dir names...
			for p := range f.cached {
				if strings.HasSuffix(p, "/"+name) {
					b.WriteString("have " + p + "\n")
				}
			}
		}
		if f.dir != "" {
			b.WriteString("dir " + f.dir + "\n")
		} else {
			b.WriteString("skip /root/.cache/subtun read-only\nskip /tmp/subtun-0 no-exec\n")
		}
		if f.python != "" {
			b.WriteString("python " + f.python + " " + f.pyver + "\n")
		}
		return b.String(), nil
	case cmd[0] == "sh" && cmd[2] == uploadScript:
		data, _ := io.ReadAll(stdin)
		f.mu.Lock()
		if f.uploaded == nil {
			f.uploaded = map[string][]byte{}
		}
		f.uploaded[cmd[5]] = data // sh -c script sh dir path
		f.mu.Unlock()
		return "", nil
	case len(cmd) == 3 && cmd[1] == "-c" && cmd[2] == agentpy.VersionProbe:
		if cmd[0] != f.python {
			return "", errors.New("not found")
		}
		return f.pyver + "\n", nil
	}
	panic("unexpected command: " + strings.Join(cmd, " "))
}

func (f *fakeTarget) Stream(_ context.Context, cmd []string, _ io.Writer) (io.ReadWriteCloser, error) {
	f.mu.Lock()
	f.started = cmd
	f.mu.Unlock()
	local, remote := testutil.Pair()
	f.readDone = make(chan struct{})
	go func() {
		defer close(f.readDone)
		buf := make([]byte, 32<<10)
		for {
			n, err := remote.Read(buf)
			f.mu.Lock()
			f.sent.Write(buf[:n])
			f.mu.Unlock()
			if err != nil {
				return
			}
		}
	}()
	return local, nil
}

var agents = []agentbin.Binary{
	{Arch: "amd64", Data: []byte("amd64-agent"), SHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
	{Arch: "arm64", Data: []byte("arm64-agent"), SHA256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
}

var discard = slog.New(slog.DiscardHandler)

func TestBinaryUploadedToFirstUsableDir(t *testing.T) {
	f := &fakeTarget{uname: "aarch64", dir: "/root/.cache/subtun", python: "python3", pyver: "3.12"}
	c, err := Bootstrap(context.Background(), f, agents, Options{AgentArgs: []string{"-v"}}, discard)
	if err != nil {
		t.Fatal(err)
	}
	want := "/root/.cache/subtun/subtun-agent-bbbbbbbbbbbbbbbb"
	if !bytes.Equal(f.uploaded[want], []byte("arm64-agent")) {
		t.Fatalf("uploaded %v, want arm64 agent at %s", f.uploaded, want)
	}
	if strings.Join(f.started, " ") != want+" -v" {
		t.Fatalf("started %q", f.started)
	}
	if c.SHA256 != agents[1].SHA256 || !strings.Contains(c.Desc, "binary agent") {
		t.Fatalf("carrier %+v", c)
	}
}

func TestBinaryCachedNeedsNoWritableDir(t *testing.T) {
	path := "/work/subtun-agent-aaaaaaaaaaaaaaaa"
	f := &fakeTarget{uname: "x86_64", cached: map[string]bool{path: true}}
	if _, err := Bootstrap(context.Background(), f, agents, Options{AgentDir: "/work"}, discard); err != nil {
		t.Fatal(err)
	}
	if len(f.uploaded) != 0 || f.started[0] != path {
		t.Fatalf("uploaded %v, started %q", f.uploaded, f.started)
	}
}

func TestAutoFallsBackToPython(t *testing.T) {
	cases := map[string]*fakeTarget{
		"no usable dir": {uname: "x86_64", python: "python3", pyver: "3.11"},
		"no shell":      {noShell: true, python: "python3", pyver: "3.11"},
		"unknown arch":  {uname: "s390x", dir: "/tmp/subtun-0", python: "python3", pyver: "3.11"},
	}
	for name, f := range cases {
		t.Run(name, func(t *testing.T) {
			c, err := Bootstrap(context.Background(), f, agents, Options{Version: "v9.9.9"}, discard)
			if err != nil {
				t.Fatal(err)
			}
			src := agentpy.Source("v9.9.9")
			sum := sha256.Sum256(src)
			if c.SHA256 != hex.EncodeToString(sum[:]) || !strings.Contains(c.Desc, "Python agent") {
				t.Fatalf("carrier %+v", c)
			}
			if f.started[0] != "python3" || f.started[1] != "-c" {
				t.Fatalf("started %q", f.started)
			}
			_ = c.Close()
			select { // the reader records bytes after the write returns
			case <-f.readDone:
			case <-time.After(5 * time.Second):
				t.Fatal("fake agent reader did not stop")
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			if !bytes.Equal(f.sent.Bytes(), src) {
				t.Fatalf("sent %d bytes of source, want %d", f.sent.Len(), len(src))
			}
			if len(f.uploaded) != 0 {
				t.Fatal("binary uploaded although Python was used")
			}
		})
	}
}

func TestExplicitModes(t *testing.T) {
	// binary: no fallback even though python is there.
	f := &fakeTarget{uname: "x86_64", python: "python3", pyver: "3.12"}
	if _, err := Bootstrap(context.Background(), f, agents, Options{Agent: AgentBinary}, discard); err == nil || !strings.Contains(err.Error(), "--agent-dir") {
		t.Fatalf("binary mode: got %v", err)
	}
	// python: skips the shell probe entirely and never uploads.
	f = &fakeTarget{noShell: true, uname: "x86_64", dir: "/tmp/subtun-0", python: "python3", pyver: "3.6"}
	if _, err := Bootstrap(context.Background(), f, agents, Options{Agent: AgentPython}, discard); err != nil {
		t.Fatalf("python mode: %v", err)
	}
	if len(f.uploaded) != 0 {
		t.Fatal("python mode uploaded a binary")
	}
	if _, err := Bootstrap(context.Background(), f, agents, Options{Agent: "perl"}, discard); err == nil {
		t.Fatal("unknown agent kind accepted")
	}
}

func TestNoAgentCanRun(t *testing.T) {
	cases := []struct {
		name string
		f    *fakeTarget
		want []string
	}{
		{"no dir, no python", &fakeTarget{uname: "x86_64"}, []string{"--agent-dir", "no python3"}},
		{"no dir, old python", &fakeTarget{uname: "x86_64", python: "python3", pyver: "3.5"}, []string{"--agent-dir", "needs 3.6+"}},
		{"no shell, no python", &fakeTarget{noShell: true}, []string{"needs sh", "Python 3.6+"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Bootstrap(context.Background(), tc.f, agents, Options{}, discard)
			if err == nil {
				t.Fatal("expected an error")
			}
			for _, w := range tc.want {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("error %q lacks %q", err, w)
				}
			}
			if len(tc.f.uploaded) != 0 || tc.f.started != nil {
				t.Fatal("uploaded or started despite the error")
			}
		})
	}
}
