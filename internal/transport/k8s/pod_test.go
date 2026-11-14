package k8s

import (
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/md2k/subnet-tunnel/internal/transport"
)

var quiet = slog.New(slog.DiscardHandler)

// The pod subtun creates: unprivileged, no token, read-only root with a
// scratch /tmp, labelled as this user's, named by profile or as given.
func TestPodSpec(t *testing.T) {
	p, err := podSpec(Target{Profile: "work"}, "ops")
	if err != nil {
		t.Fatal(err)
	}
	c := p.Spec.Containers[0]
	switch {
	case p.GenerateName != "subtun-work-" || p.Name != "" || p.Namespace != "ops":
		t.Errorf("name: %q %q", p.GenerateName, p.Name)
	case !transport.Ours(p.Labels) || p.Labels[transport.LabelProfile] != "work" || p.Labels[transport.LabelPID] == "":
		t.Errorf("labels: %v", p.Labels)
	case *p.Spec.AutomountServiceAccountToken || *p.Spec.EnableServiceLinks || p.Spec.RestartPolicy != corev1.RestartPolicyNever:
		t.Error("token, service links or restarts")
	case !*p.Spec.SecurityContext.RunAsNonRoot || *p.Spec.SecurityContext.RunAsUser != 65534:
		t.Error("runs as root")
	case !*c.SecurityContext.ReadOnlyRootFilesystem || *c.SecurityContext.AllowPrivilegeEscalation || c.SecurityContext.Capabilities.Drop[0] != "ALL":
		t.Error("container security")
	case c.Image != transport.DefaultImage || c.Command[0] != "sh" || !strings.Contains(c.Command[2], "[s]ubtun-agent"):
		t.Errorf("image or command: %q %q", c.Image, c.Command)
	case c.VolumeMounts[0].MountPath != "/tmp" || p.Spec.Volumes[0].EmptyDir == nil:
		t.Error("no scratch /tmp")
	case c.Resources.Requests.Cpu().String() != "10m" || c.Resources.Requests.Memory().String() != "32Mi" || len(c.Resources.Limits) != 0:
		t.Errorf("default resources: %v", c.Resources)
	}
	p, _ = podSpec(Target{Name: "gw", Image: "registry.example.com/busybox:1.37",
		Resources: Resources{LimitMemory: "512Mi"}}, "ops")
	if p.Name != "gw" || p.GenerateName != "" || p.Spec.Containers[0].Image != "registry.example.com/busybox:1.37" {
		t.Errorf("fixed name, image: %q %q", p.Name, p.Spec.Containers[0].Image)
	}
	if r := p.Spec.Containers[0].Resources; r.Limits.Memory().String() != "512Mi" || len(r.Requests) != 0 {
		t.Errorf("given resources: %v", r)
	}
	if _, err := podSpec(Target{Resources: Resources{LimitCPU: "lots"}}, "ops"); err == nil {
		t.Error("a bad quantity")
	}
}

// kubelet stands in for the node: pods created become running and ready.
func kubelet(cs *fake.Clientset) {
	cs.PrependReactor("create", "pods", func(a k8stesting.Action) (bool, runtime.Object, error) {
		p := a.(k8stesting.CreateAction).GetObject().(*corev1.Pod)
		if p.Name == "" {
			p.Name = p.GenerateName + "abcde"
		}
		p.Status.Phase = corev1.PodRunning
		p.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}
		return false, p, nil
	})
}

// A created pod is used again while it runs (a reconnect), replaced when
// it's gone; a pod of a fixed name that isn't this user's is refused;
// leftovers whose subtun is gone are deleted; Release deletes it.
func TestEnsurePod(t *testing.T) {
	ctx := context.Background()
	left := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "subtun-old", Namespace: "ops",
		Labels: map[string]string{transport.LabelManagedBy: transport.ManagedBy, transport.LabelOwner: transport.Owner(), transport.LabelPID: "999999999"}}}
	otherUser := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "subtun-theirs", Namespace: "ops",
		Labels: map[string]string{transport.LabelManagedBy: transport.ManagedBy, transport.LabelOwner: "someone-else", transport.LabelPID: "999999999"}}}
	cs := fake.NewClientset(left, otherUser)
	kubelet(cs)
	tg := Target{Create: true, Profile: "work", Picked: &transport.Picked{}}
	name, err := ensurePod(ctx, cs, "ops", tg, quiet)
	if err != nil || name != "subtun-work-abcde" || tg.Picked.Get() != name {
		t.Fatalf("created: %q %v", name, err)
	}
	if _, err := cs.CoreV1().Pods("ops").Get(ctx, "subtun-old", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Errorf("leftover kept: %v", err)
	}
	if _, err := cs.CoreV1().Pods("ops").Get(ctx, "subtun-theirs", metav1.GetOptions{}); err != nil {
		t.Errorf("another user's pod deleted: %v", err)
	}
	creates := func() int {
		n := 0
		for _, a := range cs.Actions() {
			if a.GetVerb() == "create" && a.GetResource().Resource == "pods" {
				n++
			}
		}
		return n
	}
	if again, err := ensurePod(ctx, cs, "ops", tg, quiet); err != nil || again != name || creates() != 1 {
		t.Errorf("reconnect: %q %v, %d created", again, err, creates())
	}
	_ = cs.CoreV1().Pods("ops").Delete(ctx, name, metav1.DeleteOptions{})
	if again, err := ensurePod(ctx, cs, "ops", tg, quiet); err != nil || creates() != 2 || again != name {
		t.Errorf("after the pod went: %q %v, %d created", again, err, creates())
	}

	if _, err := ensurePod(ctx, cs, "ops", Target{Create: true, Name: "subtun-theirs", Picked: &transport.Picked{}}, quiet); err == nil ||
		!strings.Contains(err.Error(), "exists and isn't one subtun created for you") {
		t.Errorf("someone else's name: %v", err)
	}

	Release(ctx, Target{}, quiet) // nothing created: nothing to do
	deletePod(ctx, cs, "ops", name, quiet)
	if _, err := cs.CoreV1().Pods("ops").Get(ctx, name, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Errorf("not deleted: %v", err)
	}
}

// A pod that can't run says why, at once when waiting can't help.
func TestPodTrouble(t *testing.T) {
	waiting := func(reason, msg string) *corev1.Pod {
		return &corev1.Pod{Status: corev1.PodStatus{Phase: corev1.PodPending, ContainerStatuses: []corev1.ContainerStatus{
			{State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: reason, Message: msg}}}}}}
	}
	for _, tc := range []struct {
		p     *corev1.Pod
		want  string
		fatal bool
	}{
		{waiting("ImagePullBackOff", "back-off pulling"), "ImagePullBackOff: back-off pulling", true},
		{waiting("ContainerCreating", ""), "", false},
		{&corev1.Pod{Status: corev1.PodStatus{Phase: corev1.PodPending, Conditions: []corev1.PodCondition{
			{Type: corev1.PodScheduled, Status: corev1.ConditionFalse, Reason: "Unschedulable", Message: "0/3 nodes"}}}}, "Unschedulable: 0/3 nodes", false},
		{&corev1.Pod{Status: corev1.PodStatus{Phase: corev1.PodSucceeded}}, "it ended (Succeeded)", true},
	} {
		if why, fatal := podTrouble(tc.p); why != tc.want || fatal != tc.fatal {
			t.Errorf("%q %v, want %q %v", why, fatal, tc.want, tc.fatal)
		}
	}
	cs := fake.NewClientset(&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "ops"}, Status: waiting("ErrImagePull", "nope").Status})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := waitRunning(ctx, cs, "ops", "p"); err == nil || !strings.Contains(err.Error(), "doesn't start: ErrImagePull: nope") {
		t.Errorf("waitRunning: %v", err)
	}
}
