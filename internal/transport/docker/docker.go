// Package docker runs the agent inside a Docker container through the Docker
// Engine API's exec endpoint. The daemon is found the way the docker CLI
// finds it: an explicit host, $DOCKER_HOST, then the current docker context.
package docker

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/moby/moby/api/pkg/stdcopy"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"

	"github.com/md2k/subnet-tunnel/internal/agentbin"
	"github.com/md2k/subnet-tunnel/internal/transport"
)

// Target selects the daemon and container that runs the agent.
type Target struct {
	Host    string // empty: $DOCKER_HOST, then the docker context
	Context string // empty: $DOCKER_CONTEXT, then the current context
	// Create: subtun creates the container and removes it on stop; else
	// it is an existing one, by Name or Selector (a running container with
	// these labels, "key=value,key2", all must match, picked at each
	// connect: see pickContainer).
	Create   bool
	Name     string // the container (name or ID): to create, or the existing one
	Selector string
	Image    string // a created container's; empty: transport.DefaultImage
	Network  string // the network a created container joins; empty: the default bridge
	LimitCPU string // a created container's limits (Kubernetes quantities)
	LimitMem string
	Profile  string // names and labels the containers subtun creates
	// Picked remembers the container picked last.
	Picked *transport.Picked
}

// Connect starts the agent in the container and returns its stdio.
// Cancelling ctx tears the carrier down.
func Connect(ctx context.Context, t Target, agents []agentbin.Binary, opts transport.Options, log *slog.Logger) (*transport.Carrier, error) {
	cli, err := newClient(t)
	if err != nil {
		return nil, err
	}
	target := t.Name
	switch {
	case t.Create:
		if target, err = ensureContainer(ctx, cli, t, log); err != nil {
			return nil, err
		}
	case t.Selector != "":
		if target, err = pickContainer(ctx, cli, t); err != nil {
			return nil, err
		}
		if prev := t.Picked.Get(); prev != target {
			msg := "container picked"
			if prev != "" {
				msg = "container picked: the one before is gone or not running"
			}
			log.Info(msg, "follows", "containers with "+t.Selector, "container", target)
		}
	}
	res, err := cli.ContainerInspect(ctx, target, client.ContainerInspectOptions{})
	if err != nil {
		return nil, fmt.Errorf("container %s: %w", target, err)
	}
	c := res.Container
	name := strings.TrimPrefix(c.Name, "/")
	if c.State == nil || !c.State.Running {
		return nil, fmt.Errorf("container %s is not running", name)
	}
	d := &dockerExec{cli: cli, id: c.ID, name: name}
	switch {
	case t.Create:
		d.follows = "created by subtun"
	case t.Selector != "":
		d.follows = "containers with " + t.Selector
	}
	carrier, err := transport.Bootstrap(ctx, d, agents, opts, log.With("container", name))
	if err != nil {
		return nil, err
	}
	carrier.Host = cli.DaemonHost()
	carrier.Endpoints = transport.ResolveEndpoint(ctx, cli.DaemonHost())
	carrier.Local = transport.IsLocal(cli.DaemonHost(), carrier.Endpoints)
	if !t.Create { // a created container is remembered with its ID
		t.Picked.Set(target)
	}
	return carrier, nil
}

// ParseSelector checks a container label selector: "key=value" or "key"
// parts, comma-separated, all of which must match.
func ParseSelector(sel string) ([]string, error) {
	var parts []string
	for _, p := range strings.Split(sel, ",") {
		p = strings.TrimSpace(p)
		key, _, _ := strings.Cut(p, "=")
		if key == "" || strings.ContainsAny(p, "!") {
			return nil, fmt.Errorf("selector %q: use key=value or key, comma-separated", sel)
		}
		parts = append(parts, p)
	}
	return parts, nil
}

// pickContainer picks the container a followed target connects to:
// running, and healthy if it has a health check; the one picked last time
// while it still is, else the newest.
func pickContainer(ctx context.Context, cli *client.Client, t Target) (string, error) {
	parts, err := ParseSelector(t.Selector)
	if err != nil {
		return "", err
	}
	f := client.Filters{}
	f.Add("label", parts...)
	res, err := cli.ContainerList(ctx, client.ContainerListOptions{Filters: f})
	if err != nil {
		return "", fmt.Errorf("containers with %s: %w", t.Selector, err)
	}
	return choose(res.Items, t.Selector, t.Picked.Get())
}

// choose is pickContainer's choice among the containers listed.
func choose(items []container.Summary, sel, prev string) (string, error) {
	var usable []container.Summary
	for _, c := range items {
		if c.State != container.StateRunning || len(c.Names) == 0 {
			continue
		}
		if c.Health != nil && (c.Health.Status == container.Unhealthy || c.Health.Status == container.Starting) {
			continue
		}
		usable = append(usable, c)
	}
	if len(usable) == 0 {
		if len(items) == 0 {
			return "", fmt.Errorf("containers with %s: none running", sel)
		}
		return "", fmt.Errorf("containers with %s: none running and healthy (%d found)", sel, len(items))
	}
	name := func(c container.Summary) string { return strings.TrimPrefix(c.Names[0], "/") }
	for _, c := range usable {
		if name(c) == prev {
			return prev, nil
		}
	}
	newest := slices.MaxFunc(usable, func(a, b container.Summary) int {
		if a.Created != b.Created {
			return cmp.Compare(a.Created, b.Created)
		}
		return strings.Compare(name(a), name(b))
	})
	return name(newest), nil
}

// Endpoint returns the Docker daemon's address, without connecting
// (several tunnels exclude every endpoint from every route).
func Endpoint(t Target) (string, error) {
	if _, _, pinned := t.Picked.Pinned(); !pinned {
		t.Picked = nil // planning before the first connect: don't pin yet
	}
	cli, err := newClient(t)
	if err != nil {
		return "", err
	}
	defer cli.Close()
	return cli.DaemonHost(), nil
}

// newClient talks to t's daemon: the one of its first connect (Picked), so
// switching docker contexts meanwhile doesn't move the run, or what subtun
// removes. ($DOCKER_HOST can't change meanwhile: nothing to pin.)
func newClient(t Target) (*client.Client, error) {
	opts := []client.Opt{client.WithAPIVersionNegotiation()}
	fromEnv := t.Host == "" && t.Context == "" && os.Getenv("DOCKER_HOST") != ""
	if fromEnv {
		// Same as the docker CLI: DOCKER_HOST plus DOCKER_TLS_VERIFY / DOCKER_CERT_PATH.
		opts = append(opts, client.FromEnv)
	} else {
		if pinned, _, ok := t.Picked.Pinned(); ok && pinned != "" && t.Host == "" {
			t.Host, t.Context = pinned, ""
		}
		host, err := ResolveHost(t.Host, t.Context, configDir())
		if err != nil {
			return nil, err
		}
		if host != "" {
			opts = append(opts, client.WithHost(host))
		}
	}
	cli, err := client.New(opts...)
	if err != nil {
		return nil, fmt.Errorf("docker client: %w", err)
	}
	if strings.HasPrefix(cli.DaemonHost(), "ssh://") {
		return nil, fmt.Errorf("docker host %s: ssh:// hosts are not supported yet", cli.DaemonHost())
	}
	if !fromEnv {
		t.Picked.Pin(cli.DaemonHost(), "")
	}
	return cli, nil
}

func configDir() string {
	if d := os.Getenv("DOCKER_CONFIG"); d != "" {
		return d
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".docker")
}

// ResolveHost returns the daemon address for an explicit host or a docker
// context, reading contexts from dir (normally ~/.docker). An empty result
// means the client default (the local socket).
func ResolveHost(host, contextName, dir string) (string, error) {
	if host != "" {
		return host, nil
	}
	if contextName == "" {
		contextName = os.Getenv("DOCKER_CONTEXT")
	}
	if contextName == "" {
		data, err := os.ReadFile(filepath.Join(dir, "config.json"))
		switch {
		case errors.Is(err, fs.ErrNotExist):
		case err != nil:
			return "", err
		default:
			var cfg struct {
				CurrentContext string `json:"currentContext"`
			}
			if err := json.Unmarshal(data, &cfg); err != nil {
				return "", fmt.Errorf("%s: %w", filepath.Join(dir, "config.json"), err)
			}
			contextName = cfg.CurrentContext
		}
	}
	if contextName == "" || contextName == "default" {
		return "", nil
	}

	sum := sha256.Sum256([]byte(contextName))
	id := hex.EncodeToString(sum[:])
	data, err := os.ReadFile(filepath.Join(dir, "contexts", "meta", id, "meta.json"))
	if err != nil {
		return "", fmt.Errorf("docker context %q: %w", contextName, err)
	}
	var meta struct {
		Endpoints map[string]struct {
			Host string `json:"Host"`
		} `json:"Endpoints"`
	}
	if err := json.Unmarshal(data, &meta); err != nil {
		return "", fmt.Errorf("docker context %q: %w", contextName, err)
	}
	h := meta.Endpoints["docker"].Host
	if h == "" {
		return "", fmt.Errorf("docker context %q has no docker endpoint", contextName)
	}
	if _, err := os.Stat(filepath.Join(dir, "contexts", "tls", id, "docker")); err == nil {
		return "", fmt.Errorf("docker context %q uses TLS client certificates, not supported yet", contextName)
	}
	return h, nil
}

type dockerExec struct {
	cli      *client.Client
	id, name string
	follows  string // followed: what ("containers with ...")
}

func (d *dockerExec) Describe() string {
	if d.follows != "" {
		return "container " + d.name + " (" + d.follows + ")"
	}
	return "container " + d.name
}

func (d *dockerExec) start(ctx context.Context, cmd []string, stdin bool) (string, client.HijackedResponse, error) {
	cr, err := d.cli.ExecCreate(ctx, d.id, client.ExecCreateOptions{
		Cmd:          cmd,
		AttachStdin:  stdin,
		AttachStdout: true,
		AttachStderr: true,
	})
	if err != nil {
		return "", client.HijackedResponse{}, err
	}
	att, err := d.cli.ExecAttach(ctx, cr.ID, client.ExecAttachOptions{})
	if err != nil {
		return "", client.HijackedResponse{}, err
	}
	return cr.ID, att.HijackedResponse, nil
}

// Run implements transport.Execer.
func (d *dockerExec) Run(ctx context.Context, cmd []string, stdin io.Reader) (string, error) {
	id, hr, err := d.start(ctx, cmd, stdin != nil)
	if err != nil {
		return "", err
	}
	defer hr.Close()
	stop := context.AfterFunc(ctx, hr.Close)
	defer stop()

	if stdin != nil {
		go func() {
			_, _ = io.Copy(hr.Conn, stdin)
			_ = hr.CloseWrite()
		}()
	}
	var stdout, stderr bytes.Buffer
	if _, err := stdcopy.StdCopy(&stdout, &stderr, hr.Reader); err != nil {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		return "", err
	}
	code, err := d.exitCode(ctx, id)
	if err != nil {
		return "", err
	}
	if code != 0 {
		return "", fmt.Errorf("command exited with status %d: %s", code, strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), nil
}

// exitCode waits briefly for the exec to be reported as finished: the
// stream can end a moment before the daemon records the exit.
func (d *dockerExec) exitCode(ctx context.Context, id string) (int, error) {
	deadline := time.Now().Add(2 * time.Second)
	for {
		ins, err := d.cli.ExecInspect(ctx, id, client.ExecInspectOptions{})
		if err != nil {
			return 0, err
		}
		if !ins.Running || time.Now().After(deadline) {
			return ins.ExitCode, nil
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// Stream implements transport.Execer.
func (d *dockerExec) Stream(ctx context.Context, cmd []string, stderr io.Writer) (io.ReadWriteCloser, error) {
	_, hr, err := d.start(ctx, cmd, true)
	if err != nil {
		return nil, err
	}
	outR, outW := io.Pipe()
	c := &streamConn{hr: hr, out: outR, done: make(chan struct{})}
	go func() {
		defer close(c.done)
		_, err := stdcopy.StdCopy(outW, stderr, hr.Reader)
		if err == nil {
			err = io.EOF
		}
		_ = outW.CloseWithError(err)
	}()
	c.stop = context.AfterFunc(ctx, hr.Close)
	return c, nil
}

// streamConn writes straight to the hijacked connection; reads come through
// the stdout/stderr demultiplexer.
type streamConn struct {
	hr   client.HijackedResponse
	out  *io.PipeReader
	done chan struct{}
	stop func() bool
	once sync.Once
}

func (c *streamConn) Read(p []byte) (int, error)  { return c.out.Read(p) }
func (c *streamConn) Write(p []byte) (int, error) { return c.hr.Conn.Write(p) }

// Close sends EOF on the agent's stdin so it exits cleanly, then closes the
// connection.
func (c *streamConn) Close() error {
	c.once.Do(func() {
		_ = c.hr.CloseWrite()
		select {
		case <-c.done:
		case <-time.After(2 * time.Second):
		}
		c.stop()
		c.hr.Close()
		_ = c.out.Close()
	})
	return nil
}
