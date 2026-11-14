package k8s

import (
	"context"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/md2k/subnet-tunnel/internal/transport"
)

func followPod(name string, labels map[string]string, phase corev1.PodPhase, ready bool, started time.Time) *corev1.Pod {
	p := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "ops", Labels: labels},
		Status: corev1.PodStatus{Phase: phase, StartTime: &metav1.Time{Time: started}}}
	status := corev1.ConditionFalse
	if ready {
		status = corev1.ConditionTrue
	}
	p.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: status}}
	return p
}

// A followed target picks a running, ready pod that isn't going: the one
// picked before while it still is, else the newest.
func TestPickPod(t *testing.T) {
	now := time.Now()
	app := map[string]string{"app": "toolbox"}
	going := followPod("toolbox-old", app, corev1.PodRunning, true, now.Add(-time.Hour))
	going.DeletionTimestamp = &metav1.Time{Time: now}
	cs := fake.NewClientset(
		&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "toolbox", Namespace: "ops"},
			Spec: appsv1.DeploymentSpec{Selector: &metav1.LabelSelector{MatchLabels: app}}},
		followPod("toolbox-a", app, corev1.PodRunning, true, now.Add(-30*time.Minute)),
		followPod("toolbox-b", app, corev1.PodRunning, true, now.Add(-time.Minute)),
		followPod("toolbox-c", app, corev1.PodPending, false, now),
		followPod("toolbox-d", app, corev1.PodRunning, false, now),
		going,
		followPod("other", map[string]string{"app": "other"}, corev1.PodRunning, true, now),
	)
	ctx := context.Background()
	picked := &transport.Picked{}
	name, follows, err := pickPod(ctx, cs, "ops", Target{Deployment: "toolbox", Picked: picked})
	if err != nil || name != "toolbox-b" || follows != "deployment ops/toolbox" {
		t.Fatalf("deployment: %q %q %v, want the newest ready", name, follows, err)
	}
	picked.Set("toolbox-a")
	if name, _, _ := pickPod(ctx, cs, "ops", Target{Selector: "app=toolbox", Picked: picked}); name != "toolbox-a" {
		t.Errorf("selector: %q, want the one picked before", name)
	}
	picked.Set("toolbox-old") // being deleted now
	if name, _, _ := pickPod(ctx, cs, "ops", Target{Selector: "app=toolbox", Picked: picked}); name != "toolbox-b" {
		t.Errorf("picked before is going: %q", name)
	}

	for what, tc := range map[string]struct {
		t    Target
		want string
	}{
		"no deployment": {Target{Deployment: "nope"}, `deployment ops/nope: deployments.apps "nope" not found`},
		"no pods":       {Target{Selector: "app=none"}, "pods in ops with app=none: no pods"},
		"none ready":    {Target{Selector: "app=toolbox,tier in (x)"}, "no pods"},
		"bad selector":  {Target{Selector: "x in (a"}, `selector "x in (a"`},
	} {
		if _, _, err := pickPod(ctx, cs, "ops", tc.t); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", what, err, tc.want)
		}
	}
	// Pods, none usable: the message counts them.
	cs2 := fake.NewClientset(followPod("x", app, corev1.PodPending, false, now), followPod("y", app, corev1.PodRunning, false, now))
	if _, _, err := pickPod(ctx, cs2, "ops", Target{Selector: "app=toolbox"}); err == nil ||
		!strings.Contains(err.Error(), "no running, ready pod (1 not ready, 1 pending)") {
		t.Errorf("none usable: %v", err)
	}
}
