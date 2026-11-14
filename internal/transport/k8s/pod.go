package k8s

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"

	"github.com/md2k/subnet-tunnel/internal/transport"
)

// The created pod's one container, and how long it may take to run.
const (
	podContainer   = "subtun"
	startTimeout   = 2 * time.Minute
	deleteTimeout  = 10 * time.Second
	labelCreate    = "subtun.dev/create"  // one create request: what it made if the answer never came
	annotationProf = "subtun.dev/profile" // an annotation: a profile name isn't always a label value
)

// The requests a created pod gets for what resources leaves unset (capped
// at its limits).
const (
	defaultRequestCPU    = "10m"
	defaultRequestMemory = "32Mi"
)

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
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Labels: transport.OwnLabels()},
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
				Command:   []string{"sh", "-c", transport.IdleScript},
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
		p.Annotations = map[string]string{annotationProf: t.Profile}
	}
	if t.Name != "" {
		p.Name = t.Name
	} else {
		p.GenerateName = generateName(t.Profile)
	}
	return p, nil
}

var notInName = regexp.MustCompile(`[^a-z0-9-]+`)

// generateName is "subtun-<profile>-", the profile made fit for a pod
// name (a profile name may have '_' and '.', and any length).
func generateName(profile string) string {
	p := strings.Trim(notInName.ReplaceAllString(strings.ToLower(profile), "-"), "-")
	if len(p) > 40 {
		p = strings.TrimRight(p[:40], "-")
	}
	if p == "" {
		return "subtun-"
	}
	return "subtun-" + p + "-"
}

// requirements are the created pod's requests and limits. A request left
// unset gets a small default, capped at its limit: with only a limit,
// Kubernetes would request all of it.
func (r Resources) requirements() (corev1.ResourceRequirements, error) {
	var out corev1.ResourceRequirements
	parse := func(name corev1.ResourceName, v string) (*resource.Quantity, error) {
		if v == "" {
			return nil, nil
		}
		q, err := resource.ParseQuantity(v)
		if err != nil {
			return nil, fmt.Errorf("%s %q: %w", name, v, err)
		}
		if q.Sign() <= 0 {
			return nil, fmt.Errorf("%s %q: more than 0", name, v)
		}
		return &q, nil
	}
	set := func(l *corev1.ResourceList, name corev1.ResourceName, q *resource.Quantity) {
		if q == nil {
			return
		}
		if *l == nil {
			*l = corev1.ResourceList{}
		}
		(*l)[name] = *q
	}
	for _, f := range []struct {
		name         corev1.ResourceName
		req, lim, df string
	}{
		{corev1.ResourceCPU, r.RequestCPU, r.LimitCPU, defaultRequestCPU},
		{corev1.ResourceMemory, r.RequestMemory, r.LimitMemory, defaultRequestMemory},
	} {
		req, err := parse(f.name, f.req)
		if err != nil {
			return out, err
		}
		lim, err := parse(f.name, f.lim)
		if err != nil {
			return out, err
		}
		if req == nil {
			d := resource.MustParse(f.df)
			if lim != nil && lim.Cmp(d) < 0 {
				d = *lim
			}
			req = &d
		}
		set(&out.Requests, f.name, req)
		set(&out.Limits, f.name, lim)
	}
	return out, nil
}

func ours(p *corev1.Pod) bool { return transport.Ours(p.Labels) }

// mine reports whether this process created the pod.
func mine(p *corev1.Pod) bool {
	return ours(p) && p.Labels[transport.LabelPID] == strconv.Itoa(os.Getpid())
}

// ensurePod returns the pod subtun created for t, running: the one from
// before while it still runs (a reconnect), else a new one. This user's
// leftovers in the namespace are deleted first.
func ensurePod(ctx context.Context, cs kubernetes.Interface, ns string, t Target, log *slog.Logger) (string, error) {
	pods := cs.CoreV1().Pods(ns)
	if prev, uid := t.Picked.Created(); uid != "" {
		p, err := pods.Get(ctx, prev, metav1.GetOptions{})
		switch {
		case err == nil && string(p.UID) == uid && mine(p) && p.DeletionTimestamp == nil && p.Status.Phase == corev1.PodRunning && podReady(p):
			return prev, nil
		case err == nil && string(p.UID) == uid:
			log.Info("the pod subtun created is gone or not running: creating another", "pod", ns+"/"+prev, "phase", p.Status.Phase)
			deletePod(ctx, cs, ns, prev, uid, log)
		case err != nil && !apierrors.IsNotFound(err):
			return "", fmt.Errorf("pod %s/%s: %w", ns, prev, err)
		}
		t.Picked.SetCreated("", "") // gone, or a pod of that name that isn't the one created
	}
	cleanupLeftovers(ctx, cs, ns, log)
	spec, err := podSpec(t, ns)
	if err != nil {
		return "", err
	}
	if t.Name != "" { // a fixed name: one of ours left over is replaced; anyone else's is refused
		if err := freeName(ctx, cs, ns, t.Name, log); err != nil {
			return "", err
		}
	}
	nonce := make([]byte, 6)
	_, _ = rand.Read(nonce)
	spec.Labels[labelCreate] = hex.EncodeToString(nonce)
	p, err := pods.Create(ctx, spec, metav1.CreateOptions{})
	if err != nil {
		// The answer may have been lost (a stop meanwhile) after the pod was made.
		dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), deleteTimeout)
		defer cancel()
		zero := int64(0)
		_ = pods.DeleteCollection(dctx, metav1.DeleteOptions{GracePeriodSeconds: &zero},
			metav1.ListOptions{LabelSelector: labelCreate + "=" + spec.Labels[labelCreate]})
		return "", fmt.Errorf("creating a pod in %s: %w", ns, err)
	}
	t.Picked.SetCreated(p.Name, string(p.UID))
	log.Info("pod created", "pod", ns+"/"+p.Name, "image", p.Spec.Containers[0].Image)
	if err := waitRunning(ctx, cs, ns, p.Name); err != nil {
		dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), deleteTimeout)
		defer cancel()
		deletePod(dctx, cs, ns, p.Name, string(p.UID), log)
		t.Picked.SetCreated("", "")
		return "", err
	}
	return p.Name, nil
}

// freeName makes way for a pod of a fixed name: one of ours left over is
// deleted (and waited for); one a running subtun uses, or anyone else's,
// is refused.
func freeName(ctx context.Context, cs kubernetes.Interface, ns, name string, log *slog.Logger) error {
	pods := cs.CoreV1().Pods(ns)
	p, err := pods.Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("pod %s/%s: %w", ns, name, err)
	}
	switch pid := p.Labels[transport.LabelPID]; {
	case !ours(p):
		return fmt.Errorf("pod %s/%s exists and isn't one subtun created for you: choose another name, or use it with create: false", ns, name)
	case !mine(p) && transport.Alive(pid) && p.Status.Phase != corev1.PodSucceeded && p.Status.Phase != corev1.PodFailed:
		return fmt.Errorf("pod %s/%s is in use by another subtun (pid %s): choose another name", ns, name, pid)
	}
	deletePod(ctx, cs, ns, name, string(p.UID), log)
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
// help. A first failed pull isn't (a registry's rate limit passes): the
// back-off after it is.
func podTrouble(p *corev1.Pod) (string, bool) {
	if p.Status.Phase == corev1.PodFailed || p.Status.Phase == corev1.PodSucceeded {
		return "it ended (" + string(p.Status.Phase) + ")", true
	}
	for _, s := range p.Status.ContainerStatuses {
		if w := s.State.Waiting; w != nil {
			switch w.Reason {
			case "ImagePullBackOff", "InvalidImageName", "CreateContainerConfigError", "CreateContainerError":
				return strings.TrimSpace(w.Reason + ": " + w.Message), true
			case "ErrImagePull":
				return strings.TrimSpace(w.Reason + ": " + w.Message), false
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
// ended, or whose subtun no longer runs on this machine.
func cleanupLeftovers(ctx context.Context, cs kubernetes.Interface, ns string, log *slog.Logger) {
	list, err := cs.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{LabelSelector: transport.LabelManagedBy + "=" + transport.ManagedBy + "," + transport.LabelOwner + "=" + transport.Owner()})
	if err != nil {
		log.Debug("listing leftover pods", "namespace", ns, "err", err)
		return
	}
	for _, p := range list.Items {
		ended := p.Status.Phase == corev1.PodSucceeded || p.Status.Phase == corev1.PodFailed
		if p.DeletionTimestamp != nil || mine(&p) && !ended {
			continue
		}
		if ended || !transport.Alive(p.Labels[transport.LabelPID]) {
			log.Info("deleting a pod an earlier subtun left", "pod", ns+"/"+p.Name)
			deletePod(ctx, cs, ns, p.Name, string(p.UID), log)
		}
	}
}

// deletePod deletes the pod of that name if it is still the one with that
// UID: never one that took its name meanwhile.
func deletePod(ctx context.Context, cs kubernetes.Interface, ns, name, uid string, log *slog.Logger) {
	zero := int64(0)
	opts := metav1.DeleteOptions{GracePeriodSeconds: &zero}
	if uid != "" {
		u := types.UID(uid)
		opts.Preconditions = &metav1.Preconditions{UID: &u}
	}
	err := cs.CoreV1().Pods(ns).Delete(ctx, name, opts)
	if err != nil && !apierrors.IsNotFound(err) && !apierrors.IsConflict(err) {
		log.Warn("deleting the pod subtun created", "pod", ns+"/"+name, "err", err)
	}
}

// Release deletes the pod subtun created for t, when the profile stops
// for good (not on a reconnect, which uses it again): by its UID, in the
// cluster and namespace it was created in.
func Release(ctx context.Context, t Target, log *slog.Logger) {
	name, uid := t.Picked.Created()
	if !t.Create || uid == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), deleteTimeout)
	defer cancel()
	_, cs, ns, err := clients(t)
	if err != nil {
		log.Warn("deleting the pod subtun created", "pod", name, "err", err)
		return
	}
	deletePod(ctx, cs, ns, name, uid, log)
	t.Picked.SetCreated("", "")
	log.Info("pod deleted", "pod", ns+"/"+name)
}
