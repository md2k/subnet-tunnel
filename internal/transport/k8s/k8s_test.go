package k8s

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func pod(annotation string, running map[string]bool, names ...string) *corev1.Pod {
	p := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "ns"}}
	if annotation != "" {
		p.Annotations = map[string]string{defaultContainerAnnotation: annotation}
	}
	for _, n := range names {
		p.Spec.Containers = append(p.Spec.Containers, corev1.Container{Name: n})
		st := corev1.ContainerStatus{Name: n}
		if running[n] {
			st.State.Running = &corev1.ContainerStateRunning{}
		}
		p.Status.ContainerStatuses = append(p.Status.ContainerStatuses, st)
	}
	return p
}

func TestPickContainer(t *testing.T) {
	all := map[string]bool{"app": true, "sidecar": true}
	cases := []struct {
		name, flag, annotation, want string
		running                      map[string]bool
		wantErr                      bool
	}{
		{name: "first by default", want: "app", running: all},
		{name: "annotation", annotation: "sidecar", want: "sidecar", running: all},
		{name: "flag beats annotation", flag: "app", annotation: "sidecar", want: "app", running: all},
		{name: "unknown container", flag: "nope", running: all, wantErr: true},
		{name: "not running", flag: "sidecar", running: map[string]bool{"app": true}, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := pickContainer(pod(tc.annotation, tc.running, "app", "sidecar"), tc.flag)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("got %q, want error", got)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("got %q, %v; want %q", got, err, tc.want)
			}
		})
	}
}

// client-go's messages are debug output: an error record (which reaches
// Handle without Enabled being asked) is dropped unless debug is on.
func TestDebugOnly(t *testing.T) {
	for _, verbose := range []bool{false, true} {
		var buf bytes.Buffer
		level := slog.LevelInfo
		if verbose {
			level = slog.LevelDebug
		}
		h := debugOnly{slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: level})}
		r := slog.NewRecord(time.Now(), slog.LevelError, "Copying stdin failed", 0)
		if err := h.Handle(context.Background(), r); err != nil {
			t.Fatal(err)
		}
		if got := strings.Contains(buf.String(), "level=DEBUG"); got != verbose {
			t.Errorf("verbose %v: %q", verbose, buf.String())
		}
	}
}
