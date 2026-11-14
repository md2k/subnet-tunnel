package k8s

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/user"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/md2k/subnet-tunnel/internal/transport"
)

// The labels on the pods subtun creates: who made them, so leftovers can
// be told from another running subtun's pods.
const (
	labelManagedBy = "app.kubernetes.io/managed-by"
	labelProfile   = "subtun.dev/profile"
	labelOwner     = "subtun.dev/owner" // this user on this machine, hashed
	labelPID       = "subtun.dev/pid"
	managedBy      = "subtun"
)

// The created pod's one container, and how long it may take to run.
const (
	podContainer = "subtun"
	startTimeout = 2 * time.Minute
	idleExit     = 5 * time.Minute // a pod left without an agent this long exits
)

// idleScript is a created pod's main process: it exits once no agent has
// run in it for idleExit, so a pod a killed subtun left behind stops using
// anything. The bracket keeps grep from finding itself.
var idleScript = fmt.Sprintf(`i=0; while sleep 30; do
if cat /proc/[0-9]*/cmdline 2>/dev/null | tr '\0' ' ' | grep -q '[s]ubtun-agent'; then i=0; else i=$((i+30)); fi
[ "$i" -ge %d ] && exit 0
done`, int(idleExit.Seconds()))

// owner is this user on this machine, hashed: a label value.
var owner = sync.OnceValue(func() string {
	who := strconv.Itoa(os.Getuid())
	if u, err := user.Current(); err == nil {
		who = u.Username
	}
	host, _ := os.Hostname()
	sum := sha256.Sum256([]byte(who + "@" + host))
	return hex.EncodeToString(sum[:])[:16]
})

// podSpec is the pod subtun creates: an unprivileged user, no token, no
// writable root, a scratch /tmp for the agent: the restricted pod
// security level.
func podSpec(t Target, ns string) (*corev1.Pod, error) {
	image := t.Image
	if image == "" {
		image = transport.DefaultImage
	}
	res, err := t.Resources.requirements()
	if err != nil {
		return nil, err
	}
	no, yes, nobody := false, true, int64(65534)
	grace := int64(1)
	p := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Labels: map[string]string{
			labelManagedBy: managedBy, labelOwner: owner(), labelPID: strconv.Itoa(os.Getpid()),
		}},
		Spec: corev1.PodSpec{
			RestartPolicy:                 corev1.RestartPolicyNever,
			AutomountServiceAccountToken:  &no,
			EnableServiceLinks:            &no,
			TerminationGracePeriodSeconds: &grace,
			SecurityContext: &corev1.PodSecurityContext{
				RunAsNonRoot: &yes, RunAsUser: &nobody, RunAsGroup: &nobody,
				SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
			},
			Containers: []corev1.Container{{
				Name:      podContainer,
				Image:     image,
				Command:   []string{"sh", "-c", idleScript},
				Env:       []corev1.EnvVar{{Name: "HOME", Value: "/tmp"}},
				Resources: res,
				SecurityContext: &corev1.SecurityContext{
					AllowPrivilegeEscalation: &no, ReadOnlyRootFilesystem: &yes, RunAsNonRoot: &yes,
					Capabilities: &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
				},
				VolumeMounts: []corev1.VolumeMount{{Name: "tmp", MountPath: "/tmp"}},
			}},
			Volumes: []corev1.Volume{{Name: "tmp", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}}},
		},
	}
	if t.Profile != "" {
		p.Labels[labelProfile] = t.Profile
	}
	if t.Name != "" {
		p.Name = t.Name
	} else if t.Profile != "" {
		p.GenerateName = "subtun-" + t.Profile + "-"
	} else {
		p.GenerateName = "subtun-"
	}
	return p, nil
}

// requirements are the created pod's requests and limits; none given:
// small requests, no limits.
func (r Resources) requirements() (corev1.ResourceRequirements, error) {
	var out corev1.ResourceRequirements
	if r == (Resources{}) {
		r.RequestCPU, r.RequestMemory = "10m", "32Mi"
	}
	add := func(l *corev1.ResourceList, name corev1.ResourceName, v string) error {
		if v == "" {
			return nil
		}
		q, err := resource.ParseQuantity(v)
		if err != nil {
			return fmt.Errorf("%s %q: %w", name, v, err)
		}
		if *l == nil {
			*l = corev1.ResourceList{}
		}
		(*l)[name] = q
		return nil
	}
	for _, e := range []error{
		add(&out.Requests, corev1.ResourceCPU, r.RequestCPU), add(&out.Requests, corev1.ResourceMemory, r.RequestMemory),
		add(&out.Limits, corev1.ResourceCPU, r.LimitCPU), add(&out.Limits, corev1.ResourceMemory, r.LimitMemory),
	} {
		if e != nil {
			return out, e
		}
	}
	return out, nil
}

func ours(p *corev1.Pod) bool {
	return p.Labels[labelManagedBy] == managedBy && p.Labels[labelOwner] == owner()
}

// ensurePod returns the pod subtun created for t, running: the one from
// before while it still runs (a reconnect), else a new one. This user's
// leftovers in the namespace are deleted first.
func ensurePod(ctx context.Context, cs kubernetes.Interface, ns string, t Target, log *slog.Logger) (string, error) {
	pods := cs.CoreV1().Pods(ns)
	if prev := t.Picked.Get(); prev != "" {
		p, err := pods.Get(ctx, prev, metav1.GetOptions{})
		switch {
		case err == nil && ours(p) && p.DeletionTimestamp == nil && p.Status.Phase == corev1.PodRunning && podReady(p):
			return prev, nil
		case err == nil && ours(p):
			log.Info("the pod subtun created is gone or not running: creating another", "pod", ns+"/"+prev, "phase", p.Status.Phase)
			deletePod(ctx, cs, ns, prev, log)
		case err != nil && !apierrors.IsNotFound(err):
			return "", fmt.Errorf("pod %s/%s: %w", ns, prev, err)
		}
	}
	cleanupLeftovers(ctx, cs, ns, t.Picked.Get(), log)
	spec, err := podSpec(t, ns)
	if err != nil {
		return "", err
	}
	if t.Name != "" { // a fixed name: one of ours left over is replaced; anyone else's is refused
		if err := freeName(ctx, cs, ns, t.Name, log); err != nil {
			return "", err
		}
	}
	p, err := pods.Create(ctx, spec, metav1.CreateOptions{})
	if err != nil {
		return "", fmt.Errorf("creating a pod in %s: %w", ns, err)
	}
	log.Info("pod created", "pod", ns+"/"+p.Name, "image", p.Spec.Containers[0].Image)
	t.Picked.Set(p.Name)
	if err := waitRunning(ctx, cs, ns, p.Name); err != nil {
		deletePod(context.WithoutCancel(ctx), cs, ns, p.Name, log)
		t.Picked.Set("")
		return "", err
	}
	return p.Name, nil
}

// freeName makes way for a pod of a fixed name: one of ours is deleted
// (and waited for), anyone else's refused.
func freeName(ctx context.Context, cs kubernetes.Interface, ns, name string, log *slog.Logger) error {
	pods := cs.CoreV1().Pods(ns)
	p, err := pods.Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("pod %s/%s: %w", ns, name, err)
	}
	if !ours(p) {
		return fmt.Errorf("pod %s/%s exists and isn't one subtun created for you: choose another name, or use it with create: false", ns, name)
	}
	deletePod(ctx, cs, ns, name, log)
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := pods.Get(ctx, name, metav1.GetOptions{}); apierrors.IsNotFound(err) {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
	return fmt.Errorf("pod %s/%s, left from before, is still being deleted", ns, name)
}

// waitRunning waits until the pod runs and is ready, or says why it
// doesn't: the image, scheduling, the container failing.
func waitRunning(ctx context.Context, cs kubernetes.Interface, ns, name string) error {
	pods := cs.CoreV1().Pods(ns)
	deadline := time.Now().Add(startTimeout)
	last := "pending"
	for {
		p, err := pods.Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("pod %s/%s: %w", ns, name, err)
		}
		if p.Status.Phase == corev1.PodRunning && podReady(p) {
			return nil
		}
		if why, fatal := podTrouble(p); why != "" {
			if fatal {
				return fmt.Errorf("pod %s/%s doesn't start: %s", ns, name, why)
			}
			last = why
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("pod %s/%s not running after %s: %s", ns, name, startTimeout, last)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
}

// podTrouble says what keeps a pod from running; fatal: waiting won't
// help.
func podTrouble(p *corev1.Pod) (string, bool) {
	if p.Status.Phase == corev1.PodFailed || p.Status.Phase == corev1.PodSucceeded {
		return "it ended (" + string(p.Status.Phase) + ")", true
	}
	for _, s := range p.Status.ContainerStatuses {
		if w := s.State.Waiting; w != nil {
			switch w.Reason {
			case "ErrImagePull", "ImagePullBackOff", "InvalidImageName", "CreateContainerConfigError", "CreateContainerError":
				return strings.TrimSpace(w.Reason + ": " + w.Message), true
			}
			if w.Reason != "" && w.Reason != "ContainerCreating" {
				return w.Reason, false
			}
		}
		if s.State.Terminated != nil {
			return "its container ended: " + s.State.Terminated.Reason, true
		}
	}
	for _, c := range p.Status.Conditions {
		if c.Type == corev1.PodScheduled && c.Status == corev1.ConditionFalse {
			return strings.TrimSpace(c.Reason + ": " + c.Message), false
		}
	}
	return "", false
}

// cleanupLeftovers deletes this user's pods in the namespace that have
// ended, or whose subtun no longer runs on this machine (keep: the pod in
// use).
func cleanupLeftovers(ctx context.Context, cs kubernetes.Interface, ns, keep string, log *slog.Logger) {
	list, err := cs.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{LabelSelector: labelManagedBy + "=" + managedBy + "," + labelOwner + "=" + owner()})
	if err != nil {
		log.Debug("listing leftover pods", "namespace", ns, "err", err)
		return
	}
	for _, p := range list.Items {
		if p.Name == keep || p.DeletionTimestamp != nil {
			continue
		}
		ended := p.Status.Phase == corev1.PodSucceeded || p.Status.Phase == corev1.PodFailed
		if ended || !alive(p.Labels[labelPID]) {
			log.Info("deleting a pod an earlier subtun left", "pod", ns+"/"+p.Name)
			deletePod(ctx, cs, ns, p.Name, log)
		}
	}
}

// alive reports whether the subtun of that process id still runs here.
func alive(pid string) bool {
	n, err := strconv.Atoi(pid)
	if err != nil || n <= 0 {
		return false
	}
	if n == os.Getpid() {
		return true
	}
	err = syscall.Kill(n, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}

func deletePod(ctx context.Context, cs kubernetes.Interface, ns, name string, log *slog.Logger) {
	zero := int64(0)
	err := cs.CoreV1().Pods(ns).Delete(ctx, name, metav1.DeleteOptions{GracePeriodSeconds: &zero})
	if err != nil && !apierrors.IsNotFound(err) {
		log.Warn("deleting the pod subtun created", "pod", ns+"/"+name, "err", err)
	}
}

// Release deletes the pod subtun created for t, when the profile stops
// for good (not on a reconnect, which uses it again).
func Release(ctx context.Context, t Target, log *slog.Logger) {
	name := t.Picked.Get()
	if !t.Create || name == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	_, cs, ns, err := clients(t)
	if err != nil {
		log.Warn("deleting the pod subtun created", "pod", name, "err", err)
		return
	}
	deletePod(ctx, cs, ns, name, log)
	t.Picked.Set("")
	log.Info("pod deleted", "pod", ns+"/"+name)
}
