// Package transport gets the agent running inside a target and hands back its
// stdin/stdout as the tunnel carrier. Each target kind (Kubernetes pod,
// Docker container, ...) only has to run commands in the target; Bootstrap
// does the rest the same way for all of them.
//
// Two agents speak the same protocol:
//   - binary: the static Go agent, uploaded once and cached in a private
//     directory in the target. Fastest; needs sh and a writable directory
//     that allows exec.
//   - python: the agent source sent over the exec session and run from
//     memory with python3 -c, like sshuttle. Writes nothing; needs Python
//     3.6+.
//
// auto (the default) uses the binary agent when it can run and falls back to
// Python otherwise.
package transport

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/md2k/subnet-tunnel/internal/agentbin"
	"github.com/md2k/subnet-tunnel/internal/agentpy"
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
	SHA256 string // checksum the agent must report in its hello
	Desc   string // target and agent description
	// Endpoints are the addresses the carrier itself connects to (the API
	// server, a remote Docker daemon). Routing them into the tunnel would
	// cut the tunnel's own connection.
	Endpoints []netip.Addr
	// Local means the carrier connects to this machine (a unix socket or
	// loopback): the target probably runs here, in a VM whose traffic
	// leaves through this machine (Docker Desktop, kind, minikube).
	Local bool
}

// IsLocal reports whether raw (a URL or host[:port]) with its resolved
// addresses points at this machine: a unix socket or named pipe, or only
// loopback addresses.
func IsLocal(raw string, addrs []netip.Addr) bool {
	if u, err := url.Parse(raw); err == nil && (u.Scheme == "unix" || u.Scheme == "npipe") {
		return true
	}
	if len(addrs) == 0 {
		return false
	}
	for _, a := range addrs {
		if !a.IsLoopback() {
			return false
		}
	}
	return true
}

// ResolveEndpoint returns the IP addresses of a URL or host[:port]; nothing
// for unix sockets or names that don't resolve.
func ResolveEndpoint(ctx context.Context, raw string) []netip.Addr {
	host := raw
	if u, err := url.Parse(raw); err == nil && u.Host != "" {
		if u.Scheme == "unix" || u.Scheme == "npipe" {
			return nil
		}
		host = u.Hostname()
	} else if h, _, err := net.SplitHostPort(raw); err == nil {
		host = h
	}
	if host == "" {
		return nil
	}
	if a, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{a.Unmap()}
	}
	rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupNetIP(rctx, "ip", host)
	if err != nil {
		return nil
	}
	for i := range addrs {
		addrs[i] = addrs[i].Unmap()
	}
	return addrs
}

// Agent kinds for Options.Agent.
const (
	AgentAuto   = "auto"
	AgentBinary = "binary"
	AgentPython = "python"
)

// Options configures Bootstrap.
type Options struct {
	Agent string // AgentAuto (default), AgentBinary or AgentPython
	// AgentDir pins where the binary agent goes. Empty: the first usable of
	// $XDG_CACHE_HOME or $HOME/.cache /subtun, /tmp/subtun-<uid>,
	// /var/tmp/subtun-<uid>, /dev/shm/subtun-<uid>.
	AgentDir  string
	AgentArgs []string // extra agent flags
	Version   string   // subtun version, stamped into the Python agent
}

const (
	probeTimeout  = 30 * time.Second
	uploadTimeout = 2 * time.Minute
	sendTimeout   = 30 * time.Second
)

// Bootstrap starts an agent in the target, as chosen by opts.Agent.
func Bootstrap(ctx context.Context, ex Execer, agents []agentbin.Binary, opts Options, log *slog.Logger) (*Carrier, error) {
	mode := opts.Agent
	if mode == "" {
		mode = AgentAuto
	}
	switch mode {
	case AgentPython:
		py, ver, err := probePython(ctx, ex)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", ex.Describe(), err)
		}
		return startPython(ctx, ex, py, ver, opts, log)
	case AgentBinary, AgentAuto:
	default:
		return nil, fmt.Errorf("unknown agent %q: use auto, binary or python", mode)
	}

	pr, err := probe(ctx, ex, agents, opts.AgentDir)
	if err != nil {
		if mode == AgentAuto {
			// No shell (distroless and the like): Python may still be there.
			py, ver, perr := probePython(ctx, ex)
			if perr == nil {
				log.Info("no shell in target, using the Python agent", "python", py+" "+ver)
				return startPython(ctx, ex, py, ver, opts, log)
			}
			return nil, fmt.Errorf("%s: no agent can run: the binary agent needs sh (%v); %v", ex.Describe(), err, perr)
		}
		return nil, fmt.Errorf("probing %s: %w (the binary agent needs sh, uname and basic tools)", ex.Describe(), err)
	}

	bin, binErr := pr.pick(agents)
	if binErr == nil {
		if cached := pr.cachedPath(*bin); cached != "" {
			log.Debug("agent already in target", "path", cached)
			return startBinary(ctx, ex, *bin, cached, pr, opts, log)
		}
		if pr.dir != "" {
			remote := path.Join(pr.dir, agentName(*bin))
			if err := upload(ctx, ex, *bin, pr.dir, remote, log); err != nil {
				return nil, err
			}
			return startBinary(ctx, ex, *bin, remote, pr, opts, log)
		}
		binErr = pr.noDirError(opts.AgentDir)
	}

	if mode == AgentAuto && pr.python != "" && agentpy.Supported(pr.pyver) {
		log.Info("binary agent can't run here, using the Python agent", "reason", binErr, "python", pr.python+" "+pr.pyver)
		return startPython(ctx, ex, pr.python, pr.pyver, opts, log)
	}
	if mode == AgentAuto {
		return nil, fmt.Errorf("%s: no agent can run: %v; and %s", ex.Describe(), binErr, pr.pythonStatus())
	}
	return nil, fmt.Errorf("%s: %w", ex.Describe(), binErr)
}

// probeScript reports, one item per line:
//
//	arch <uname -m>
//	have <path>     an executable agent build we own, in a candidate dir
//	dir <path>      the first candidate dir we can write to and exec from
//	skip <path> <why>
//	python <cmd> <major.minor>
//
// Without an explicit dir it creates private (0700) per-user dirs and skips
// any it doesn't own, so nobody else can plant a binary for us to run.
// Exec permission is tested by running a two-line script there: noexec
// mounts and security policies only show up that way. A failed redirect is
// kept in a subshell because on a special builtin it would exit the shell.
// Args: dir (or ""), agent file names...
const probeScript = `o=$1; shift
echo "arch $(uname -m)"
u=$(id -u 2>/dev/null) || u=0
if [ -n "$o" ]; then
  c=$o
else
  c=
  if [ -n "$HOME" ] && [ "$HOME" != / ]; then c="${XDG_CACHE_HOME:-$HOME/.cache}/subtun"; fi
  c="$c /tmp/subtun-$u /var/tmp/subtun-$u /dev/shm/subtun-$u"
fi
for d in $c; do
  if [ -z "$o" ]; then
    mkdir -p "$d" 2>/dev/null && chmod 700 "$d" 2>/dev/null
    if [ ! -d "$d" ]; then echo "skip $d cannot-create"; continue; fi
    if [ ! -O "$d" ]; then echo "skip $d not-ours"; continue; fi
  elif ! mkdir -p "$d" 2>/dev/null; then
    echo "skip $d cannot-create"; continue
  fi
  for n do [ -x "$d/$n" ] && [ -O "$d/$n" ] && echo "have $d/$n"; done
  t="$d/.subtun-probe.$$"
  if (printf '#!/bin/sh\nexit 0\n' > "$t") 2>/dev/null; then
    if (chmod 700 "$t" && "$t") 2>/dev/null; then rm -f "$t"; echo "dir $d"; break; fi
    rm -f "$t"; echo "skip $d no-exec"
  else
    echo "skip $d read-only"
  fi
done
for p in python3 python; do
  v=$("$p" -c 'import sys;print("%d.%d"%sys.version_info[:2])' 2>/dev/null) && { echo "python $p $v"; break; }
done
exit 0`

// uploadScript writes stdin to $2 atomically, then removes other agent
// builds in the directory (a running agent keeps its open file, so that is
// safe). On any failure it reads the rest of stdin before exiting: a
// Kubernetes exec whose process exits with stdin still arriving never
// completes (kubectl exec hangs the same way). Args: dir, path.
const uploadScript = `umask 077
t="$2.part.$$"
if cat > "$t" && chmod 700 "$t" && mv -f "$t" "$2"; then
  for f in "$1"/subtun-agent-*; do [ "$f" = "$2" ] || rm -f "$f"; done
  exit 0
fi
cat > /dev/null
rm -f "$t" 2>/dev/null
exit 1`

type probeResult struct {
	arch   string   // raw uname -m
	have   []string // cached agent paths
	dir    string   // usable dir for an upload, "" if none
	skips  []string // "<dir> <reason>" for candidates that didn't work
	python string   // python command, "" if none
	pyver  string
}

func probe(ctx context.Context, ex Execer, agents []agentbin.Binary, dir string) (*probeResult, error) {
	cmd := []string{"sh", "-c", probeScript, "sh", dir}
	for _, a := range agents {
		cmd = append(cmd, agentName(a))
	}
	pctx, cancel := context.WithTimeout(ctx, probeTimeout)
	out, err := ex.Run(pctx, cmd, nil)
	cancel()
	if err != nil {
		return nil, err
	}
	pr := &probeResult{}
	for _, line := range strings.Split(out, "\n") {
		key, val, _ := strings.Cut(strings.TrimSpace(line), " ")
		switch key {
		case "arch":
			pr.arch = val
		case "have":
			pr.have = append(pr.have, val)
		case "dir":
			pr.dir = val
		case "skip":
			pr.skips = append(pr.skips, val)
		case "python":
			pr.python, pr.pyver, _ = strings.Cut(val, " ")
		}
	}
	if pr.arch == "" {
		return nil, fmt.Errorf("probe returned no architecture: %q", strings.TrimSpace(out))
	}
	return pr, nil
}

func (pr *probeResult) pick(agents []agentbin.Binary) (*agentbin.Binary, error) {
	if len(agents) == 0 {
		return nil, errors.New("this subtun has no binary agents embedded (build with `make`)")
	}
	arch, ok := agentbin.ArchFromUname(pr.arch)
	if !ok {
		return nil, fmt.Errorf("architecture %q is not supported by the binary agent", pr.arch)
	}
	for i := range agents {
		if agents[i].Arch == arch {
			return &agents[i], nil
		}
	}
	return nil, fmt.Errorf("target is linux/%s but no binary agent for it is embedded (have: %s)", arch, archList(agents))
}

func (pr *probeResult) cachedPath(b agentbin.Binary) string {
	for _, p := range pr.have {
		if path.Base(p) == agentName(b) {
			return p
		}
	}
	return ""
}

func (pr *probeResult) noDirError(pinned string) error {
	tried := strings.Join(pr.skips, ", ")
	if pinned != "" {
		return fmt.Errorf("--agent-dir %s can't hold the binary agent (%s)", pinned, tried)
	}
	return fmt.Errorf("no writable, executable directory for the binary agent (tried: %s); "+
		"pass --agent-dir, for example an emptyDir mount", tried)
}

func (pr *probeResult) pythonStatus() string {
	switch {
	case pr.python == "":
		return "no python3 for the Python agent"
	case !agentpy.Supported(pr.pyver):
		return fmt.Sprintf("%s is %s, the Python agent needs %d.%d+", pr.python, pr.pyver, agentpy.MinMajor, agentpy.MinMinor)
	default:
		return "python ok"
	}
}

// probePython finds a usable python without relying on a shell.
func probePython(ctx context.Context, ex Execer) (string, string, error) {
	var errs []string
	for _, py := range []string{"python3", "python"} {
		pctx, cancel := context.WithTimeout(ctx, probeTimeout)
		out, err := ex.Run(pctx, []string{py, "-c", agentpy.VersionProbe}, nil)
		cancel()
		if err != nil {
			errs = append(errs, py+": not runnable")
			continue
		}
		ver := strings.TrimSpace(out)
		if !agentpy.Supported(ver) {
			errs = append(errs, fmt.Sprintf("%s is %s, need %d.%d+", py, ver, agentpy.MinMajor, agentpy.MinMinor))
			continue
		}
		return py, ver, nil
	}
	return "", "", fmt.Errorf("the Python agent needs Python %d.%d+ (%s)", agentpy.MinMajor, agentpy.MinMinor, strings.Join(errs, "; "))
}

func upload(ctx context.Context, ex Execer, bin agentbin.Binary, dir, remote string, log *slog.Logger) error {
	start := time.Now()
	uctx, cancel := context.WithTimeout(ctx, uploadTimeout)
	defer cancel()
	if _, err := ex.Run(uctx, []string{"sh", "-c", uploadScript, "sh", dir, remote}, bytes.NewReader(bin.Data)); err != nil {
		return fmt.Errorf("uploading agent to %s in %s: %w", remote, ex.Describe(), err)
	}
	log.Info("agent uploaded", "path", remote, "bytes", len(bin.Data), "took", time.Since(start).Round(time.Millisecond))
	return nil
}

func startBinary(ctx context.Context, ex Execer, bin agentbin.Binary, remote string, pr *probeResult, opts Options, log *slog.Logger) (*Carrier, error) {
	conn, err := ex.Stream(ctx, append([]string{remote}, opts.AgentArgs...), &LineLog{Log: log})
	if err != nil {
		return nil, fmt.Errorf("starting agent in %s: %w", ex.Describe(), err)
	}
	return &Carrier{
		ReadWriteCloser: conn,
		SHA256:          bin.SHA256,
		Desc:            fmt.Sprintf("%s, linux/%s, binary agent", ex.Describe(), bin.Arch),
	}, nil
}

func startPython(ctx context.Context, ex Execer, py, ver string, opts Options, log *slog.Logger) (*Carrier, error) {
	src := agentpy.Source(opts.Version)
	conn, err := ex.Stream(ctx, agentpy.Command(py, src, opts.AgentArgs), &LineLog{Log: log})
	if err != nil {
		return nil, fmt.Errorf("starting Python agent in %s: %w", ex.Describe(), err)
	}
	// The loader reads exactly len(src) bytes of source, then the agent
	// answers with its hello.
	errc := make(chan error, 1)
	go func() {
		_, err := conn.Write(src)
		errc <- err
	}()
	select {
	case err = <-errc:
	case <-time.After(sendTimeout):
		err = errors.New("timed out")
	case <-ctx.Done():
		err = ctx.Err()
	}
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("sending Python agent to %s: %w", ex.Describe(), err)
	}
	sum := sha256.Sum256(src)
	return &Carrier{
		ReadWriteCloser: conn,
		SHA256:          hex.EncodeToString(sum[:]),
		Desc:            fmt.Sprintf("%s, Python agent (%s %s)", ex.Describe(), py, ver),
	}, nil
}

func agentName(b agentbin.Binary) string { return "subtun-agent-" + b.SHA256[:16] }

func archList(agents []agentbin.Binary) string {
	s := make([]string, len(agents))
	for i, a := range agents {
		s[i] = a.Arch
	}
	return strings.Join(s, ", ")
}

// LineLog relays the agent's stderr into our log, one record per line.
type LineLog struct {
	Log    *slog.Logger
	Prefix string // default "agent: "
	mu     sync.Mutex
	buf    []byte
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
	p := l.Prefix
	if p == "" {
		p = "agent: "
	}
	switch {
	case strings.Contains(line, "level=ERROR"):
		l.Log.Error(p + line)
	case strings.Contains(line, "level=WARN"):
		l.Log.Warn(p + line)
	case strings.Contains(line, "level=DEBUG"):
		l.Log.Debug(p + line)
	default:
		l.Log.Info(p + line)
	}
}
