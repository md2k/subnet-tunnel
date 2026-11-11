// Package transport gets the agent running inside a target and hands back its
// stdin/stdout as the tunnel carrier. Each target kind (Kubernetes pod,
// Docker container, ...) only has to run commands in the target; Bootstrap
// does the rest the same way for all of them.
package transport

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/md2k/subnet-tunnel/internal/agentbin"
)

// Execer runs commands inside one target.
type Execer interface {
	// Run executes cmd to completion and returns its stdout. A non-zero exit
	// is an error that includes stderr.
	Run(ctx context.Context, cmd []string, stdin io.Reader) (string, error)
	// Stream starts cmd and returns its stdin/stdout as a connection; stderr
	// goes to the given writer. Cancelling ctx or closing the connection ends
	// the command.
	Stream(ctx context.Context, cmd []string, stderr io.Writer) (io.ReadWriteCloser, error)
	// Describe names the target for logs and errors.
	Describe() string
}

// Carrier is the running agent's stdio.
type Carrier struct {
	io.ReadWriteCloser
	SHA256 string // checksum of the agent binary that was started
	Desc   string // target description, including the architecture
}

// Options configures Bootstrap.
type Options struct {
	AgentDir  string   // where the agent is cached in the target; empty: /tmp
	AgentArgs []string // extra agent flags
}

// Bootstrap finds the target's architecture, uploads the matching agent
// unless the same build is already cached there, and starts it.
func Bootstrap(ctx context.Context, ex Execer, agents []agentbin.Binary, opts Options, log *slog.Logger) (*Carrier, error) {
	if len(agents) == 0 {
		return nil, errors.New("no agent binaries available: build with `make` or pass --agent-file")
	}
	dir := opts.AgentDir
	if dir == "" {
		dir = "/tmp"
	}

	// One round trip for the architecture and for which agents are cached.
	paths := make(map[string]string, len(agents))
	probe := []string{"sh", "-c", `uname -m; for p do [ -x "$p" ] && echo "have $p"; done; exit 0`, "sh"}
	for _, a := range agents {
		paths[a.Arch] = AgentPath(dir, a)
		probe = append(probe, paths[a.Arch])
	}
	out, err := ex.Run(ctx, probe, nil)
	if err != nil {
		return nil, fmt.Errorf("probing %s: %w (the agent upload needs sh and uname in the target)", ex.Describe(), err)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	arch, ok := agentbin.ArchFromUname(lines[0])
	if !ok {
		return nil, fmt.Errorf("%s: architecture %q is not supported", ex.Describe(), strings.TrimSpace(lines[0]))
	}
	var bin *agentbin.Binary
	for i := range agents {
		if agents[i].Arch == arch {
			bin = &agents[i]
		}
	}
	if bin == nil {
		return nil, fmt.Errorf("%s is linux/%s but no agent for it is available (have: %s)", ex.Describe(), arch, archList(agents))
	}
	remote := paths[arch]
	cached := false
	for _, l := range lines[1:] {
		if strings.TrimSpace(l) == "have "+remote {
			cached = true
		}
	}

	if cached {
		log.Debug("agent already in target", "path", remote)
	} else {
		start := time.Now()
		upload := []string{"sh", "-c",
			`set -e; umask 077; mkdir -p "$1"; cat > "$2.part.$$"; chmod 700 "$2.part.$$"; mv -f "$2.part.$$" "$2"`,
			"sh", dir, remote}
		if _, err := ex.Run(ctx, upload, bytes.NewReader(bin.Data)); err != nil {
			return nil, fmt.Errorf("uploading agent to %s in %s: %w (needs a writable directory, see --agent-dir)", remote, ex.Describe(), err)
		}
		log.Info("agent uploaded", "path", remote, "bytes", len(bin.Data), "took", time.Since(start).Round(time.Millisecond))
	}

	conn, err := ex.Stream(ctx, append([]string{remote}, opts.AgentArgs...), &LineLog{Log: log})
	if err != nil {
		return nil, fmt.Errorf("starting agent in %s: %w", ex.Describe(), err)
	}
	return &Carrier{
		ReadWriteCloser: conn,
		SHA256:          bin.SHA256,
		Desc:            fmt.Sprintf("%s, linux/%s", ex.Describe(), arch),
	}, nil
}

// AgentPath is where a given agent build is cached in the target.
func AgentPath(dir string, b agentbin.Binary) string {
	return path.Join(dir, "subtun-agent-"+b.SHA256[:16])
}

func archList(agents []agentbin.Binary) string {
	s := make([]string, len(agents))
	for i, a := range agents {
		s[i] = a.Arch
	}
	return strings.Join(s, ", ")
}

// LineLog relays the agent's stderr into our log, one record per line.
type LineLog struct {
	Log *slog.Logger
	mu  sync.Mutex
	buf []byte
}

func (l *LineLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.buf = append(l.buf, p...)
	for {
		i := bytes.IndexByte(l.buf, '\n')
		if i < 0 {
			break
		}
		l.emit(string(l.buf[:i]))
		l.buf = l.buf[i+1:]
	}
	if len(l.buf) > 4096 { // no newline in sight: flush anyway
		l.emit(string(l.buf))
		l.buf = l.buf[:0]
	}
	return len(p), nil
}

func (l *LineLog) emit(line string) {
	line = strings.TrimSpace(line)
	if line == "" {
		return
	}
	switch {
	case strings.Contains(line, "level=ERROR"):
		l.Log.Error("agent: " + line)
	case strings.Contains(line, "level=WARN"):
		l.Log.Warn("agent: " + line)
	case strings.Contains(line, "level=DEBUG"):
		l.Log.Debug("agent: " + line)
	default:
		l.Log.Info("agent: " + line)
	}
}
