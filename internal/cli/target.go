package cli

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/md2k/subnet-tunnel/internal/agentbin"
	"github.com/md2k/subnet-tunnel/internal/config"
	"github.com/md2k/subnet-tunnel/internal/transport"
	"github.com/md2k/subnet-tunnel/internal/transport/docker"
	"github.com/md2k/subnet-tunnel/internal/transport/k8s"
)

// targetFlags give subtun up a target on the command line, instead of a
// profile's.
type targetFlags struct {
	k8s, docker                   kindFlag
	namespace, container, context string
	kubeconfig, host, selector    string
}

// kindFlag is --k8s or --docker: bare, with the target's name as the
// first argument (--k8s deploy/toolbox), or with it (--k8s=deploy/toolbox).
type kindFlag struct {
	set  bool
	name string
}

func (f *kindFlag) String() string {
	if f.name != "" {
		return f.name
	}
	return strconv.FormatBool(f.set)
}

func (f *kindFlag) Set(s string) error {
	switch s {
	case "true":
		f.set, f.name = true, ""
	case "false":
		f.set, f.name = false, ""
	default:
		f.set, f.name = true, s
	}
	return nil
}

func (f *kindFlag) Type() string { return "bool" } // shown and parsed as a switch

func (tf *targetFlags) register(cmd *cobra.Command) {
	f := cmd.Flags()
	f.Var(&tf.k8s, "k8s", "the target is a Kubernetes pod, named first: POD, pod/POD or deploy/NAME (or -l)")
	f.Lookup("k8s").NoOptDefVal = "true"
	f.Var(&tf.docker, "docker", "the target is a Docker container, named first (or -l)")
	f.Lookup("docker").NoOptDefVal = "true"
	f.StringVarP(&tf.namespace, "namespace", "n", "", "--k8s: the namespace (default: the kubeconfig context's)")
	f.StringVarP(&tf.container, "container", "c", "", "--k8s: the container (default: kubectl's default container)")
	f.StringVar(&tf.context, "context", "", "--k8s: the kubeconfig context (default: its current one); --docker: the docker context (default: $DOCKER_CONTEXT, then the current one)")
	f.StringVar(&tf.kubeconfig, "kubeconfig", "", "--k8s: the kubeconfig file (default: $KUBECONFIG or ~/.kube/config)")
	f.StringVarP(&tf.host, "host", "H", "", "--docker: the daemon's address (default: $DOCKER_HOST, then the docker context)")
	f.StringVarP(&tf.selector, "selector", "l", "", "--k8s, --docker: follow a pod or container with these labels instead of naming one (k8s: kubectl's syntax; docker: key=value, comma-separated)")
}

// given reports whether a target was given here.
func (tf *targetFlags) given() bool { return tf.k8s.set || tf.docker.set }

// unused refuses the target's flags without a target given here.
func (tf *targetFlags) unused(flags *pflag.FlagSet) error {
	var used []string
	for _, n := range []string{"namespace", "container", "context", "kubeconfig", "host", "selector"} {
		if flags.Changed(n) {
			used = append(used, "--"+n)
		}
	}
	if len(used) == 0 {
		return nil
	}
	return fmt.Errorf("%s: for a target given here, with --k8s or --docker (a profile has them in its target)", strings.Join(used, ", "))
}

// spec is the run of the target given here: its name (from --k8s=NAME, or
// the first argument unless -l picks it) and the CIDRs.
func (tf *targetFlags) spec(args []string, s settings, g *globalOpts) (*tunnelSpec, error) {
	if tf.k8s.set && tf.docker.set {
		return nil, errors.New("--k8s and --docker don't go together")
	}
	kind, what := &tf.k8s, "pod"
	if tf.docker.set {
		kind, what = &tf.docker, "container"
	}
	name, routes := kind.name, args
	if name != "" {
		if tf.selector != "" {
			return nil, fmt.Errorf("--%s=%s and --selector don't go together", map[string]string{"pod": "k8s", "container": "docker"}[what], name)
		}
	} else {
		var err error
		if name, routes, err = targetArgs(args, tf.selector, what); err != nil {
			return nil, err
		}
	}
	s.routes = routes
	sp := &tunnelSpec{s: s}
	if tf.k8s.set {
		if tf.host != "" {
			return nil, errors.New("--host is for --docker")
		}
		t := k8s.Target{Kubeconfig: config.ExpandHome(tf.kubeconfig), Context: tf.context, Namespace: tf.namespace,
			Container: tf.container, Selector: tf.selector, Picked: &transport.Picked{}}
		if t.Selector != "" {
			if err := k8s.ParseSelector(t.Selector); err != nil {
				return nil, err
			}
		} else if err := k8sTargetArg(&t, name); err != nil {
			return nil, err
		}
		sp.connect = func(ctx context.Context, agents []agentbin.Binary, log *slog.Logger) (*transport.Carrier, error) {
			return k8s.Connect(ctx, t, agents, sp.s.transport(g), log)
		}
		return sp, nil
	}
	for n, v := range map[string]string{"namespace": tf.namespace, "container": tf.container, "kubeconfig": tf.kubeconfig} {
		if v != "" {
			return nil, fmt.Errorf("--%s is for --k8s", n)
		}
	}
	t := docker.Target{Host: tf.host, Context: tf.context, Container: name, Selector: tf.selector, Picked: &transport.Picked{}}
	if t.Selector != "" {
		if _, err := docker.ParseSelector(t.Selector); err != nil {
			return nil, err
		}
	}
	sp.connect = func(ctx context.Context, agents []agentbin.Binary, log *slog.Logger) (*transport.Carrier, error) {
		return docker.Connect(ctx, t, agents, sp.s.transport(g), log)
	}
	return sp, nil
}

// checkSelector refuses a target's label selector that can't be parsed,
// before anything starts.
func checkSelector(t config.Target) error {
	switch {
	case t.K8s != nil && t.K8s.Selector != "":
		return k8s.ParseSelector(t.K8s.Selector)
	case t.Docker != nil && t.Docker.Selector != "":
		_, err := docker.ParseSelector(t.Docker.Selector)
		return err
	}
	return nil
}

// targetArgs splits the arguments into the target's name and the CIDRs:
// with --selector there is no name.
func targetArgs(args []string, selector, what string) (string, []string, error) {
	if selector != "" {
		if len(args) > 0 {
			if _, err := netip.ParsePrefix(args[0]); err != nil {
				if _, err := netip.ParseAddr(args[0]); err != nil {
					return "", nil, fmt.Errorf("%q: with --selector, the arguments are CIDRs (no %s name)", args[0], what)
				}
			}
		}
		return "", args, nil
	}
	if len(args) == 0 {
		return "", nil, fmt.Errorf("name the %s, or pick one by its labels with --selector", what)
	}
	return args[0], args[1:], nil
}

// k8sTargetArg names the pod or the Deployment, kubectl style: NAME,
// pod/NAME, deploy/NAME.
func k8sTargetArg(t *k8s.Target, arg string) error {
	kind, name, ok := strings.Cut(arg, "/")
	if !ok {
		t.Pod = arg
		return nil
	}
	switch kind {
	case "pod", "pods", "po":
		t.Pod = name
	case "deploy", "deployment", "deployments", "deployment.apps":
		t.Deployment = name
	default:
		return fmt.Errorf("%q: name a pod (NAME, pod/NAME) or a Deployment (deploy/NAME)", arg)
	}
	if name == "" {
		return fmt.Errorf("%q: the name is missing", arg)
	}
	return nil
}
