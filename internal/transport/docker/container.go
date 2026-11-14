package docker

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
	"k8s.io/apimachinery/pkg/api/resource"

	"github.com/md2k/subnet-tunnel/internal/transport"
)

// ensureContainer returns the container subtun created for t, running:
// the one from before while it still runs (a reconnect), else a new one.
// This user's leftovers on the daemon are removed first.
func ensureContainer(ctx context.Context, cli *client.Client, t Target, log *slog.Logger) (string, error) {
	if prev := t.Picked.Get(); prev != "" {
		res, err := cli.ContainerInspect(ctx, prev, client.ContainerInspectOptions{})
		switch {
		case err == nil && transport.Ours(labels(res.Container.Config)) && res.Container.State != nil && res.Container.State.Running:
			return prev, nil
		case err == nil && transport.Ours(labels(res.Container.Config)):
			log.Info("the container subtun created is gone or not running: creating another", "container", prev)
			removeContainer(ctx, cli, prev, log)
		}
	}
	cleanupLeftovers(ctx, cli, t.Picked.Get(), log)
	name := t.Name
	if name != "" {
		res, err := cli.ContainerInspect(ctx, name, client.ContainerInspectOptions{})
		if err == nil {
			if !transport.Ours(labels(res.Container.Config)) {
				return "", fmt.Errorf("container %s exists and isn't one subtun created for you: choose another name, or use it with create: false", name)
			}
			removeContainer(ctx, cli, name, log)
		}
	} else {
		name = generatedName(t.Profile)
	}
	image := t.Image
	if image == "" {
		image = transport.DefaultImage
	}
	if _, err := cli.ImageInspect(ctx, image); err != nil {
		log.Info("pulling the image", "image", image)
		pull, err := cli.ImagePull(ctx, image, client.ImagePullOptions{})
		if err != nil {
			return "", fmt.Errorf("pulling %s: %w", image, err)
		}
		err = pull.Wait(ctx)
		_ = pull.Close()
		if err != nil {
			return "", fmt.Errorf("pulling %s: %w", image, err)
		}
	}
	hc, err := hostConfig(t)
	if err != nil {
		return "", err
	}
	created, err := cli.ContainerCreate(ctx, client.ContainerCreateOptions{
		Name: name,
		Config: &container.Config{
			Image:  image,
			Cmd:    []string{"sh", "-c", transport.IdleScript},
			Env:    []string{"HOME=/tmp"},
			User:   "65534:65534",
			Labels: transport.OwnLabels(t.Profile),
		},
		HostConfig: hc,
	})
	if err != nil {
		return "", fmt.Errorf("creating a container: %w", err)
	}
	t.Picked.Set(name)
	if _, err := cli.ContainerStart(ctx, created.ID, client.ContainerStartOptions{}); err != nil {
		removeContainer(context.WithoutCancel(ctx), cli, name, log)
		t.Picked.Set("")
		return "", fmt.Errorf("starting container %s: %w", name, err)
	}
	log.Info("container created", "container", name, "image", image)
	deadline := time.Now().Add(30 * time.Second)
	for {
		res, err := cli.ContainerInspect(ctx, created.ID, client.ContainerInspectOptions{})
		if err == nil && res.Container.State != nil && res.Container.State.Running {
			return name, nil
		}
		if err == nil && res.Container.State != nil && res.Container.State.Status == container.StateExited {
			return "", fmt.Errorf("container %s exited at start (code %d)", name, res.Container.State.ExitCode)
		}
		if time.Now().After(deadline) {
			return "", fmt.Errorf("container %s not running after 30s", name)
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
}

// hostConfig is the created container's: no capabilities, no new
// privileges, a read-only root with a scratch /tmp the agent can run from,
// removed once it exits.
func hostConfig(t Target) (*container.HostConfig, error) {
	hc := &container.HostConfig{
		AutoRemove:     true,
		ReadonlyRootfs: true,
		Tmpfs:          map[string]string{"/tmp": "rw,exec,nosuid,size=256m,mode=1777"},
		CapDrop:        []string{"ALL"},
		SecurityOpt:    []string{"no-new-privileges"},
	}
	if t.Network != "" {
		hc.NetworkMode = container.NetworkMode(t.Network)
	}
	if t.LimitCPU != "" {
		q, err := resource.ParseQuantity(t.LimitCPU)
		if err != nil {
			return nil, fmt.Errorf("cpu limit %q: %w", t.LimitCPU, err)
		}
		hc.NanoCPUs = q.MilliValue() * 1_000_000
	}
	if t.LimitMem != "" {
		q, err := resource.ParseQuantity(t.LimitMem)
		if err != nil {
			return nil, fmt.Errorf("memory limit %q: %w", t.LimitMem, err)
		}
		hc.Memory = q.Value()
	}
	return hc, nil
}

func labels(c *container.Config) map[string]string {
	if c == nil {
		return nil
	}
	return c.Labels
}

func generatedName(profile string) string {
	b := make([]byte, 3)
	_, _ = rand.Read(b)
	if profile == "" {
		return "subtun-" + hex.EncodeToString(b)
	}
	return "subtun-" + profile + "-" + hex.EncodeToString(b)
}

// cleanupLeftovers removes this user's containers that have ended, or
// whose subtun no longer runs on this machine (keep: the one in use).
func cleanupLeftovers(ctx context.Context, cli *client.Client, keep string, log *slog.Logger) {
	f := client.Filters{}
	f.Add("label", transport.LabelManagedBy+"="+transport.ManagedBy, transport.LabelOwner+"="+transport.Owner())
	res, err := cli.ContainerList(ctx, client.ContainerListOptions{All: true, Filters: f})
	if err != nil {
		log.Debug("listing leftover containers", "err", err)
		return
	}
	for _, c := range res.Items {
		if len(c.Names) == 0 {
			continue
		}
		name := strings.TrimPrefix(c.Names[0], "/")
		if name == keep {
			continue
		}
		if c.State != container.StateRunning || !transport.Alive(c.Labels[transport.LabelPID]) {
			log.Info("removing a container an earlier subtun left", "container", name)
			removeContainer(ctx, cli, name, log)
		}
	}
}

func removeContainer(ctx context.Context, cli *client.Client, name string, log *slog.Logger) {
	if _, err := cli.ContainerRemove(ctx, name, client.ContainerRemoveOptions{Force: true}); err != nil && !strings.Contains(err.Error(), "No such container") {
		log.Warn("removing the container subtun created", "container", name, "err", err)
	}
}

// Release removes the container subtun created for t, when the profile
// stops for good (not on a reconnect, which uses it again).
func Release(ctx context.Context, t Target, log *slog.Logger) {
	name := t.Picked.Get()
	if !t.Create || name == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	cli, err := newClient(t)
	if err != nil {
		log.Warn("removing the container subtun created", "container", name, "err", err)
		return
	}
	defer cli.Close()
	removeContainer(ctx, cli, name, log)
	t.Picked.Set("")
	log.Info("container removed", "container", name)
}
