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
	"maps"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
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
	// Create: subtun creates the pod (see pod.go) and deletes it on stop;
	// else it is an existing pod, by Name or Selector (a running, ready pod
	// with these labels, picked at each connect: see pickPod).
	Create    bool
	Name      string // the pod: to create (empty: generated), or the existing one
	Selector  string
	Container string // an existing pod's; empty: kubectl's default container
	Image     string // a created pod's; empty: DefaultImage
	Resources Resources
	Profile   string // names and labels the pods subtun creates
	// Picked remembers the pod picked last (a selector's choice, or the
	// pod subtun created).
	Picked *transport.Picked
}

// Resources are a created pod's requests and limits (Kubernetes
// quantities; empty: none).
type Resources struct {
	RequestCPU, RequestMemory, LimitCPU, LimitMemory string
}

func (t Target) followed() bool { return t.Selector != "" }

const defaultContainerAnnotation = "kubectl.kubernetes.io/default-container"

// Connect starts the agent in the target pod and returns its stdio.
// Cancelling ctx tears the carrier down.
func Connect(ctx context.Context, t Target, agents []agentbin.Binary, opts transport.Options, log *slog.Logger) (*transport.Carrier, error) {
	// client-go reports stream teardown noise through klog; keep it in our
	// log, at debug level.
	klog.SetSlogLogger(slog.New(debugOnly{log.Handler()}).With("src", "client-go"))
	k, err := newKube(ctx, t, log)
	if err != nil {
		return nil, err
	}
	if t.followed() && !t.Create {
		if prev := t.Picked.Get(); prev != k.pod {
			msg := "pod picked"
			if prev != "" {
				msg = "pod picked: the one before is gone or not ready"
			}
			log.Info(msg, "follows", k.follows, "pod", k.ns+"/"+k.pod)
		}
	}
	c, err := transport.Bootstrap(ctx, k, agents, opts, log.With("pod", k.ns+"/"+k.pod, "container", k.container))
	if err != nil {
		return nil, err
	}
	c.Host = k.cfg.Host
	c.Endpoints = transport.ResolveEndpoint(ctx, k.cfg.Host)
	c.Local = transport.IsLocal(k.cfg.Host, c.Endpoints)
	if !t.Create { // a created pod is remembered with its UID
		t.Picked.Set(k.pod)
	}
	return c, nil
}

// Endpoint returns the API server's address from the kubeconfig, without
// connecting (several tunnels exclude every endpoint from every route).
func Endpoint(t Target) (string, error) {
	if _, _, pinned := t.Picked.Pinned(); !pinned {
		t.Picked = nil // planning before the first connect: don't pin yet
	}
	cc, _, err := clientConfig(t)
	if err != nil {
		return "", err
	}
	cfg, err := cc.ClientConfig()
	if err != nil {
		return "", fmt.Errorf("kubeconfig: %w", err)
	}
	return cfg.Host, nil
}

// stdinBusy, when set, says why kubeconfig exec plugins (login helpers)
// can't read the terminal: a terminal UI has it.
var stdinBusy atomic.Pointer[string]

// StdinBusy keeps login plugins off the terminal, why being what they say
// when they'd need it; "" gives it back.
func StdinBusy(why string) {
	if why == "" {
		stdinBusy.Store(nil)
		return
	}
	stdinBusy.Store(&why)
}

type kube struct {
	cfg       *rest.Config
	cs        kubernetes.Interface
	ns, pod   string
	container string
	follows   string // followed: what, as pickPod says it ("deployment ns/name")
}

// clients reads the kubeconfig for t: the REST config, a clientset and
// the namespace. The context and namespace are those of t's first connect
// (Picked): switching kubectl's context meanwhile doesn't move the run, or
// what subtun deletes.
func clients(t Target) (*rest.Config, kubernetes.Interface, string, error) {
	cc, ns, err := clientConfig(t)
	if err != nil {
		return nil, nil, "", err
	}
	cfg, err := cc.ClientConfig()
	if err != nil {
		return nil, nil, "", fmt.Errorf("kubeconfig: %w", err)
	}
	if why := stdinBusy.Load(); why != nil && cfg.ExecProvider != nil {
		cfg.ExecProvider.StdinUnavailable, cfg.ExecProvider.StdinUnavailableMessage = true, *why
	}
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, nil, "", err
	}
	return cfg, cs, ns, nil
}

// clientConfig resolves t's context and namespace (pinned at the first
// connect).
func clientConfig(t Target) (clientcmd.ClientConfig, string, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if t.Kubeconfig != "" {
		rules.ExplicitPath = t.Kubeconfig
	}
	pinCtx, pinNS, pinned := t.Picked.Pinned()
	ctxName := t.Context
	if ctxName == "" && pinned {
		ctxName = pinCtx
	}
	if ctxName == "" {
		raw, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, &clientcmd.ConfigOverrides{}).RawConfig()
		if err != nil {
			return nil, "", fmt.Errorf("kubeconfig: %w", err)
		}
		ctxName = raw.CurrentContext
	}
	cc := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, &clientcmd.ConfigOverrides{CurrentContext: ctxName})
	ns := t.Namespace
	if ns == "" && pinned {
		ns = pinNS
	}
	if ns == "" {
		var err error
		if ns, _, err = cc.Namespace(); err != nil {
			return nil, "", fmt.Errorf("kubeconfig namespace: %w", err)
		}
	}
	t.Picked.Pin(ctxName, ns)
	return cc, ns, nil
}

func newKube(ctx context.Context, t Target, log *slog.Logger) (*kube, error) {
	cfg, cs, ns, err := clients(t)
	if err != nil {
		return nil, err
	}
	name, follows := t.Name, ""
	switch {
	case t.Create:
		if name, err = ensurePod(ctx, cs, ns, t, log); err != nil {
			return nil, err
		}
		follows = "created by subtun"
	case t.followed():
		if name, follows, err = pickPod(ctx, cs, ns, t); err != nil {
			return nil, err
		}
	}
	pod, err := cs.CoreV1().Pods(ns).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("pod %s/%s: %w", ns, name, err)
	}
	if pod.Status.Phase != corev1.PodRunning {
		return nil, fmt.Errorf("pod %s/%s is %s, not Running", ns, name, pod.Status.Phase)
	}
	container, err := pickContainer(pod, t.Container)
	if err != nil {
		return nil, err
	}
	return &kube{cfg: cfg, cs: cs, ns: ns, pod: name, container: container, follows: follows}, nil
}

// pickPod picks the existing pod a selector names: running, ready and
// not being deleted; the one picked last time while it still is (its
// agent is cached there), else the newest (during a rollout the older ones
// are going). follows says what was followed, for people.
func pickPod(ctx context.Context, cs kubernetes.Interface, ns string, t Target) (name, follows string, err error) {
	sel := t.Selector
	follows = "pods in " + ns + " with " + sel
	if _, err := labels.Parse(sel); err != nil {
		return "", follows, fmt.Errorf("selector %q: %w", sel, err)
	}
	list, err := cs.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{LabelSelector: sel})
	if err != nil {
		return "", follows, fmt.Errorf("%s: %w", follows, err)
	}
	var ready []corev1.Pod
	other := map[string]int{}
	for _, p := range list.Items {
		switch {
		case p.DeletionTimestamp != nil:
			other["terminating"]++
		case p.Status.Phase != corev1.PodRunning:
			other[strings.ToLower(string(p.Status.Phase))]++
		case !podReady(&p):
			other["not ready"]++
		default:
			ready = append(ready, p)
		}
	}
	if len(ready) == 0 {
		if len(list.Items) == 0 {
			return "", follows, fmt.Errorf("%s: no pods", follows)
		}
		var parts []string
		for _, k := range slices.Sorted(maps.Keys(other)) {
			parts = append(parts, fmt.Sprintf("%d %s", other[k], k))
		}
		return "", follows, fmt.Errorf("%s: no running, ready pod (%s)", follows, strings.Join(parts, ", "))
	}
	prev := t.Picked.Get()
	if i := slices.IndexFunc(ready, func(p corev1.Pod) bool { return p.Name == prev }); i >= 0 {
		return prev, follows, nil
	}
	newest := slices.MaxFunc(ready, func(a, b corev1.Pod) int {
		if c := startTime(a).Compare(startTime(b)); c != 0 {
			return c
		}
		return strings.Compare(a.Name, b.Name)
	})
	return newest.Name, follows, nil
}

func podReady(p *corev1.Pod) bool {
	for _, c := range p.Status.Conditions {
		if c.Type == corev1.PodReady {
			return c.Status == corev1.ConditionTrue
		}
	}
	return false
}

func startTime(p corev1.Pod) time.Time {
	if p.Status.StartTime != nil {
		return p.Status.StartTime.Time
	}
	return p.CreationTimestamp.Time
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
	if k.follows != "" {
		return fmt.Sprintf("pod %s/%s (%s), container %s", k.ns, k.pod, k.follows, k.container)
	}
	return fmt.Sprintf("pod %s/%s, container %s", k.ns, k.pod, k.container)
}

// ParseSelector checks a label selector (kubectl's syntax).
func ParseSelector(sel string) error {
	if _, err := labels.Parse(sel); err != nil {
		return fmt.Errorf("selector %q: %w", sel, err)
	}
	return nil
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
	// Error records reach Handle without Enabled being asked (logr's Error).
	if !d.Handler.Enabled(ctx, slog.LevelDebug) {
		return nil
	}
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
