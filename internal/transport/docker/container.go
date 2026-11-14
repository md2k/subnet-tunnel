package docker

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
	"k8s.io/apimachinery/pkg/api/resource"

	"github.com/md2k/subnet-tunnel/internal/transport"
)

const removeTimeout = 10 * time.Second

func mine(labels map[string]string) bool {
	return transport.Ours(labels) && labels[transport.LabelPID] == strconv.Itoa(os.Getpid())
}

// ensureContainer returns the container subtun created for t, running:
// the one from before while it still runs (a reconnect), else a new one.
// This user's leftovers on the daemon are removed first.
func ensureContainer(ctx context.Context, cli *client.Client, t Target, log *slog.Logger) (string, error) {
	if prev, id := t.Picked.Created(); id != "" {
		res, err := cli.ContainerInspect(ctx, id, client.ContainerInspectOptions{})
		switch {
		case err == nil && mine(labels(res.Container.Config)) && res.Container.State != nil && res.Container.State.Running:
			return prev, nil
		case err == nil:
			log.Info("the container subtun created is gone or not running: creating another", "container", prev)
			removeContainer(ctx, cli, id, log)
		}
		t.Picked.SetCreated("", "")
	}
	cleanupLeftovers(ctx, cli, log)
	name := t.Name
	if name != "" {
		res, err := cli.ContainerInspect(ctx, name, client.ContainerInspectOptions{})
		if err == nil {
			c := res.Container
			l := labels(c.Config)
			running := c.State != nil && (c.State.Running || c.State.Status == container.StateCreated)
			switch {
			case !transport.Ours(l):
				return "", fmt.Errorf("container %s exists and isn't one subtun created for you: choose another name, or use it with create: false", name)
			case !mine(l) && running && transport.Alive(l[transport.LabelPID]):
				return "", fmt.Errorf("container %s is in use by another subtun (pid %s): choose another name", name, l[transport.LabelPID])
			}
			removeContainer(ctx, cli, c.ID, log)
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
	l := transport.OwnLabels()
	if t.Profile != "" {
		l[transport.LabelProfile] = t.Profile
	}
	created, err := cli.ContainerCreate(ctx, client.ContainerCreateOptions{
		Name: name,
		Config: &container.Config{
			Image:      image,
			Entrypoint: []string{"sh", "-c", transport.IdleScript}, // the image's own entrypoint doesn't run
			Env:        []string{"HOME=/tmp"},
			User:       "65534:65534",
			Labels:     l,
		},
		HostConfig: hc,
	})
	if err != nil {
		// The answer may have been lost (a stop meanwhile) after it was made.
		rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), removeTimeout)
		defer cancel()
		if res, ierr := cli.ContainerInspect(rctx, name, client.ContainerInspectOptions{}); ierr == nil && mine(labels(res.Container.Config)) {
			removeContainer(rctx, cli, res.Container.ID, log)
		}
		return "", fmt.Errorf("creating a container: %w", err)
	}
	t.Picked.SetCreated(name, created.ID)
	fail := func(err error) (string, error) {
		rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), removeTimeout)
		defer cancel()
		removeContainer(rctx, cli, created.ID, log)
		t.Picked.SetCreated("", "")
		return "", err
	}
	if _, err := cli.ContainerStart(ctx, created.ID, client.ContainerStartOptions{}); err != nil {
		return fail(fmt.Errorf("starting container %s: %w", name, err))
	}
	log.Info("container created", "container", name, "image", image)
	deadline := time.Now().Add(30 * time.Second)
	for {
		res, err := cli.ContainerInspect(ctx, created.ID, client.ContainerInspectOptions{})
		switch {
		case err != nil && strings.Contains(err.Error(), "No such container"):
			return fail(fmt.Errorf("container %s exited at start (and was removed)", name)) // --rm
		case err == nil && res.Container.State != nil && res.Container.State.Running:
			return name, nil
		case err == nil && res.Container.State != nil:
			switch st := res.Container.State; st.Status {
			case container.StateExited, container.StateDead, container.StateRemoving:
				return fail(fmt.Errorf("container %s exited at start (code %d)", name, st.ExitCode))
			}
		}
		if time.Now().After(deadline) {
			return fail(fmt.Errorf("container %s not running after 30s", name))
		}
		select {
		case <-ctx.Done():
			return fail(ctx.Err())
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
		if err != nil || q.Sign() <= 0 {
			return nil, fmt.Errorf("cpu limit %q: a quantity more than 0", t.LimitCPU)
		}
		hc.NanoCPUs = q.MilliValue() * 1_000_000
	}
	if t.LimitMem != "" {
		q, err := resource.ParseQuantity(t.LimitMem)
		if err != nil || q.Sign() <= 0 {
			return nil, fmt.Errorf("memory limit %q: a quantity more than 0", t.LimitMem)
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
// whose subtun no longer runs on this machine (a live one's, starting or
// paused, are left alone).
func cleanupLeftovers(ctx context.Context, cli *client.Client, log *slog.Logger) {
	f := client.Filters{}
	f.Add("label", transport.LabelManagedBy+"="+transport.ManagedBy, transport.LabelOwner+"="+transport.Owner())
	res, err := cli.ContainerList(ctx, client.ContainerListOptions{All: true, Filters: f})
	if err != nil {
		log.Debug("listing leftover containers", "err", err)
		return
	}
	for _, c := range res.Items {
		ended := c.State == container.StateExited || c.State == container.StateDead
		if mine(c.Labels) && !ended {
			continue
		}
		if ended || !transport.Alive(c.Labels[transport.LabelPID]) {
			name := c.ID
			if len(c.Names) > 0 {
				name = strings.TrimPrefix(c.Names[0], "/")
			}
			log.Info("removing a container an earlier subtun left", "container", name)
			removeContainer(ctx, cli, c.ID, log)
		}
	}
}

// removeContainer removes a container by its ID: never another that took
// its name meanwhile.
func removeContainer(ctx context.Context, cli *client.Client, id string, log *slog.Logger) {
	if _, err := cli.ContainerRemove(ctx, id, client.ContainerRemoveOptions{Force: true}); err != nil &&
		!strings.Contains(err.Error(), "No such container") && !strings.Contains(err.Error(), "already in progress") {
		log.Warn("removing the container subtun created", "container", id, "err", err)
	}
}

// Release removes the container subtun created for t, when the profile
// stops for good (not on a reconnect, which uses it again): by its ID, on
// the daemon it was created on.
func Release(ctx context.Context, t Target, log *slog.Logger) {
	name, id := t.Picked.Created()
	if !t.Create || id == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), removeTimeout)
	defer cancel()
	cli, err := newClient(t)
	if err != nil {
		log.Warn("removing the container subtun created", "container", name, "err", err)
		return
	}
	defer cli.Close()
	removeContainer(ctx, cli, id, log)
	t.Picked.SetCreated("", "")
	log.Info("container removed", "container", name)
}
