// Package k8s reaches the agent inside a Kubernetes pod through the API
// server's exec endpoint. It uses the caller's kubeconfig the way kubectl does
// (contexts, namespaces, exec auth plugins), so no kubectl binary and no
// separate port-forward are needed.
//
// Connect checks the container's architecture, uploads the matching agent
// once (cached under AgentDir by checksum) and starts it; the agent's
// stdin/stdout become the tunnel carrier.
package k8s

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/httpstream"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/remotecommand"

	"github.com/md2k/subnet-tunnel/internal/agentbin"
)

// Target selects the pod and container that runs the agent.
type Target struct {
	Kubeconfig string // empty: $KUBECONFIG or ~/.kube/config
	Context    string // empty: current context
	Namespace  string // empty: the context's namespace
	Pod        string
	Container  string // empty: kubectl's default container
	AgentDir   string // where the agent is cached in the container; empty: /tmp
	AgentArgs  []string
}

// Carrier is the running agent's stdin/stdout.
type Carrier struct {
	io.ReadWriteCloser
	SHA256 string // checksum of the agent binary that was started
	Desc   string // human-readable target description
}

const defaultContainerAnnotation = "kubectl.kubernetes.io/default-container"

// Connect starts the agent in the target pod and returns its stdio. agents
// are the binaries available for upload; the one matching the container's
// architecture is used. Cancelling ctx tears the carrier down.
func Connect(ctx context.Context, t Target, agents []agentbin.Binary, log *slog.Logger) (*Carrier, error) {
	if len(agents) == 0 {
		return nil, errors.New("no agent binaries available: build with `make` or pass --agent-file")
	}
	if t.AgentDir == "" {
		t.AgentDir = "/tmp"
	}
	k, err := newKube(ctx, t)
	if err != nil {
		return nil, err
	}
	log = log.With("pod", k.ns+"/"+k.pod, "container", k.container)

	// One exec for the architecture and for which agents are already cached.
	paths := make(map[string]string, len(agents))
	probe := []string{"sh", "-c", `uname -m; for p do [ -x "$p" ] && echo "have $p"; done; exit 0`, "sh"}
	for _, a := range agents {
		paths[a.Arch] = agentPath(t.AgentDir, a)
		probe = append(probe, paths[a.Arch])
	}
	out, err := k.run(ctx, probe, nil)
	if err != nil {
		return nil, fmt.Errorf("probing container: %w (the agent upload needs sh and uname in the container)", err)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	arch, ok := agentbin.ArchFromUname(lines[0])
	if !ok {
		return nil, fmt.Errorf("container architecture %q is not supported", strings.TrimSpace(lines[0]))
	}
	var bin *agentbin.Binary
	for i := range agents {
		if agents[i].Arch == arch {
			bin = &agents[i]
		}
	}
	if bin == nil {
		return nil, fmt.Errorf("container is linux/%s but no agent for it is available (have: %s)", arch, archList(agents))
	}
	remote := paths[arch]
	cached := false
	for _, l := range lines[1:] {
		if strings.TrimSpace(l) == "have "+remote {
			cached = true
		}
	}

	if cached {
		log.Debug("agent already in container", "path", remote)
	} else {
		start := time.Now()
		upload := []string{"sh", "-c",
			`set -e; umask 077; mkdir -p "$1"; cat > "$2.part.$$"; chmod 700 "$2.part.$$"; mv -f "$2.part.$$" "$2"`,
			"sh", t.AgentDir, remote}
		if _, err := k.run(ctx, upload, bytes.NewReader(bin.Data)); err != nil {
			return nil, fmt.Errorf("uploading agent to %s: %w (needs a writable directory, see --agent-dir)", remote, err)
		}
		log.Info("agent uploaded", "path", remote, "bytes", len(bin.Data), "took", time.Since(start).Round(time.Millisecond))
	}

	conn := k.stream(ctx, append([]string{remote}, t.AgentArgs...), &lineLog{log: log})
	return &Carrier{
		ReadWriteCloser: conn,
		SHA256:          bin.SHA256,
		Desc:            fmt.Sprintf("pod %s/%s, container %s, linux/%s", k.ns, k.pod, k.container, arch),
	}, nil
}

func agentPath(dir string, b agentbin.Binary) string {
	return path.Join(dir, "subtun-agent-"+b.SHA256[:16])
}

func archList(agents []agentbin.Binary) string {
	s := make([]string, len(agents))
	for i, a := range agents {
		s[i] = a.Arch
	}
	return strings.Join(s, ", ")
}

type kube struct {
	cfg       *rest.Config
	cs        kubernetes.Interface
	ns, pod   string
	container string
}

func newKube(ctx context.Context, t Target) (*kube, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if t.Kubeconfig != "" {
		rules.ExplicitPath = t.Kubeconfig
	}
	cc := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, &clientcmd.ConfigOverrides{CurrentContext: t.Context})
	cfg, err := cc.ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("kubeconfig: %w", err)
	}
	ns := t.Namespace
	if ns == "" {
		if ns, _, err = cc.Namespace(); err != nil {
			return nil, fmt.Errorf("kubeconfig namespace: %w", err)
		}
	}
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}
	pod, err := cs.CoreV1().Pods(ns).Get(ctx, t.Pod, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("pod %s/%s: %w", ns, t.Pod, err)
	}
	if pod.Status.Phase != corev1.PodRunning {
		return nil, fmt.Errorf("pod %s/%s is %s, not Running", ns, t.Pod, pod.Status.Phase)
	}
	container, err := pickContainer(pod, t.Container)
	if err != nil {
		return nil, err
	}
	return &kube{cfg: cfg, cs: cs, ns: ns, pod: t.Pod, container: container}, nil
}

// pickContainer follows kubectl: the named container, else the
// default-container annotation, else the first container. It must be running.
func pickContainer(pod *corev1.Pod, name string) (string, error) {
	if name == "" {
		name = pod.Annotations[defaultContainerAnnotation]
	}
	if name == "" && len(pod.Spec.Containers) > 0 {
		name = pod.Spec.Containers[0].Name
	}
	found := false
	for _, c := range pod.Spec.Containers {
		if c.Name == name {
			found = true
		}
	}
	if !found {
		return "", fmt.Errorf("pod %s/%s has no container %q", pod.Namespace, pod.Name, name)
	}
	for _, s := range pod.Status.ContainerStatuses {
		if s.Name == name && s.State.Running == nil {
			return "", fmt.Errorf("container %q in pod %s/%s is not running", name, pod.Namespace, pod.Name)
		}
	}
	return name, nil
}

func (k *kube) executor(cmd []string, stdin bool) (remotecommand.Executor, error) {
	req := k.cs.CoreV1().RESTClient().Post().
		Resource("pods").Namespace(k.ns).Name(k.pod).SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Container: k.container,
			Command:   cmd,
			Stdin:     stdin,
			Stdout:    true,
			Stderr:    true,
		}, scheme.ParameterCodec)
	return newExecutor(k.cfg, req.URL())
}

// newExecutor prefers WebSocket and falls back to SPDY, as kubectl does.
func newExecutor(cfg *rest.Config, u *url.URL) (remotecommand.Executor, error) {
	ws, err := remotecommand.NewWebSocketExecutor(cfg, "GET", u.String())
	if err != nil {
		return nil, err
	}
	spdy, err := remotecommand.NewSPDYExecutor(cfg, "POST", u)
	if err != nil {
		return nil, err
	}
	return remotecommand.NewFallbackExecutor(ws, spdy, func(err error) bool {
		return httpstream.IsUpgradeFailure(err) || httpstream.IsHTTPSProxyError(err)
	})
}

// run executes cmd to completion and returns its stdout. stderr is folded
// into the error.
func (k *kube) run(ctx context.Context, cmd []string, stdin io.Reader) (string, error) {
	ex, err := k.executor(cmd, stdin != nil)
	if err != nil {
		return "", err
	}
	var stdout, stderr bytes.Buffer
	err = ex.StreamWithContext(ctx, remotecommand.StreamOptions{Stdin: stdin, Stdout: &stdout, Stderr: &stderr})
	if err != nil {
		if msg := strings.TrimSpace(stderr.String()); msg != "" {
			return "", fmt.Errorf("%w: %s", err, msg)
		}
		return "", err
	}
	return stdout.String(), nil
}

// stream starts cmd and returns its stdin/stdout as a connection.
func (k *kube) stream(ctx context.Context, cmd []string, stderr io.Writer) *execConn {
	sctx, cancel := context.WithCancel(ctx)
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	c := &execConn{stdin: inW, stdout: outR, cancel: cancel, done: make(chan struct{})}
	go func() {
		defer close(c.done)
		ex, err := k.executor(cmd, true)
		if err == nil {
			err = ex.StreamWithContext(sctx, remotecommand.StreamOptions{Stdin: inR, Stdout: outW, Stderr: stderr})
		}
		if err == nil {
			err = io.EOF
		}
		_ = outW.CloseWithError(err)
		_ = inR.CloseWithError(err)
	}()
	return c
}

type execConn struct {
	stdin  *io.PipeWriter
	stdout *io.PipeReader
	cancel context.CancelFunc
	done   chan struct{}
	once   sync.Once
}

func (c *execConn) Read(p []byte) (int, error)  { return c.stdout.Read(p) }
func (c *execConn) Write(p []byte) (int, error) { return c.stdin.Write(p) }

// Close sends EOF on the agent's stdin so it exits cleanly, then tears the
// exec stream down.
func (c *execConn) Close() error {
	c.once.Do(func() {
		_ = c.stdin.Close()
		select {
		case <-c.done:
		case <-time.After(2 * time.Second):
		}
		c.cancel()
		_ = c.stdout.Close()
	})
	return nil
}

// lineLog relays the agent's stderr into our log, one record per line.
type lineLog struct {
	log *slog.Logger
	mu  sync.Mutex
	buf []byte
}

func (l *lineLog) Write(p []byte) (int, error) {
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

func (l *lineLog) emit(line string) {
	line = strings.TrimSpace(line)
	if line == "" {
		return
	}
	switch {
	case strings.Contains(line, "level=ERROR"):
		l.log.Error("agent: " + line)
	case strings.Contains(line, "level=WARN"):
		l.log.Warn("agent: " + line)
	case strings.Contains(line, "level=DEBUG"):
		l.log.Debug("agent: " + line)
	default:
		l.log.Info("agent: " + line)
	}
}
