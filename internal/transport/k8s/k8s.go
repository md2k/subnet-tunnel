// Package k8s runs the agent inside a Kubernetes pod through the API server's
// exec endpoint. It uses the caller's kubeconfig the way kubectl does
// (contexts, namespaces, exec auth plugins), so no kubectl binary and no
// separate port-forward are needed.
package k8s

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/url"
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
	"k8s.io/klog/v2"

	"github.com/md2k/subnet-tunnel/internal/agentbin"
	"github.com/md2k/subnet-tunnel/internal/transport"
)

// Target selects the pod and container that runs the agent.
type Target struct {
	Kubeconfig string // empty: $KUBECONFIG or ~/.kube/config
	Context    string // empty: current context
	Namespace  string // empty: the context's namespace
	Pod        string
	Container  string // empty: kubectl's default container
}

const defaultContainerAnnotation = "kubectl.kubernetes.io/default-container"

// Connect starts the agent in the target pod and returns its stdio.
// Cancelling ctx tears the carrier down.
func Connect(ctx context.Context, t Target, agents []agentbin.Binary, opts transport.Options, log *slog.Logger) (*transport.Carrier, error) {
	// client-go reports stream teardown noise through klog; keep it in our
	// log, at debug level.
	klog.SetSlogLogger(slog.New(debugOnly{log.Handler()}).With("src", "client-go"))
	k, err := newKube(ctx, t)
	if err != nil {
		return nil, err
	}
	c, err := transport.Bootstrap(ctx, k, agents, opts, log.With("pod", k.ns+"/"+k.pod, "container", k.container))
	if err != nil {
		return nil, err
	}
	c.Endpoints = transport.ResolveEndpoint(ctx, k.cfg.Host)
	c.Local = transport.IsLocal(k.cfg.Host, c.Endpoints)
	return c, nil
}

// Endpoint returns the API server's address from the kubeconfig, without
// connecting (several tunnels exclude every endpoint from every route).
func Endpoint(t Target) (string, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if t.Kubeconfig != "" {
		rules.ExplicitPath = t.Kubeconfig
	}
	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, &clientcmd.ConfigOverrides{CurrentContext: t.Context}).ClientConfig()
	if err != nil {
		return "", fmt.Errorf("kubeconfig: %w", err)
	}
	return cfg.Host, nil
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

func (k *kube) Describe() string {
	return fmt.Sprintf("pod %s/%s, container %s", k.ns, k.pod, k.container)
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

// Run implements transport.Execer.
func (k *kube) Run(ctx context.Context, cmd []string, stdin io.Reader) (string, error) {
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

// Stream implements transport.Execer. The exec runs in the background;
// failures to start it surface as read errors on the returned connection.
// It is detached from ctx: only Close ends it, after giving the agent a
// clean EOF, so Ctrl-C doesn't tear the stream down mid-flight.
func (k *kube) Stream(ctx context.Context, cmd []string, stderr io.Writer) (io.ReadWriteCloser, error) {
	ex, err := k.executor(cmd, true)
	if err != nil {
		return nil, err
	}
	sctx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	c := &execConn{stdin: inW, stdout: outR, cancel: cancel, done: make(chan struct{})}
	go func() {
		defer close(c.done)
		err := ex.StreamWithContext(sctx, remotecommand.StreamOptions{Stdin: inR, Stdout: outW, Stderr: stderr})
		if err == nil {
			err = io.EOF
		}
		_ = outW.CloseWithError(err)
		_ = inR.CloseWithError(err)
	}()
	return c, nil
}

// debugOnly logs every record at debug level.
type debugOnly struct{ slog.Handler }

func (d debugOnly) Enabled(ctx context.Context, _ slog.Level) bool {
	return d.Handler.Enabled(ctx, slog.LevelDebug)
}

func (d debugOnly) Handle(ctx context.Context, r slog.Record) error {
	r.Level = slog.LevelDebug
	return d.Handler.Handle(ctx, r)
}

func (d debugOnly) WithAttrs(a []slog.Attr) slog.Handler { return debugOnly{d.Handler.WithAttrs(a)} }
func (d debugOnly) WithGroup(n string) slog.Handler      { return debugOnly{d.Handler.WithGroup(n)} }

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
