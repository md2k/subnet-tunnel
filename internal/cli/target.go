package cli

import (
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/md2k/subnet-tunnel/internal/config"
	"github.com/md2k/subnet-tunnel/internal/transport"
	"github.com/md2k/subnet-tunnel/internal/transport/docker"
	"github.com/md2k/subnet-tunnel/internal/transport/k8s"
)

// targetFlags give subtun up a target on the command line, instead of a
// profile's: the same keys as a profile's target, as flags.
type targetFlags struct {
	k8s, docker bool
	create      bool
	name        string
	selector    string
	image       string
	network     string
	requests    string
	limits      string
	namespace   string
	container   string
	context     string
	kubeconfig  string
	host        string
}

// The flags that belong to a target given here.
var targetFlagNames = []string{"create", "name", "selector", "image", "network", "requests", "limits",
	"namespace", "container", "context", "kubeconfig", "host"}

func (tf *targetFlags) register(cmd *cobra.Command) {
	f := cmd.Flags()
	f.BoolVar(&tf.k8s, "k8s", false, "the target is a Kubernetes pod: one subtun creates (the default), or an existing one (--create=false with --name or -l)")
	f.BoolVar(&tf.docker, "docker", false, "the target is a Docker container: one subtun creates (the default), or an existing one (--create=false with --name or -l)")
	f.BoolVar(&tf.create, "create", true, "--k8s, --docker: create the pod or container (and delete it on stop); false: use an existing one")
	f.StringVar(&tf.name, "name", "", "--k8s, --docker: the pod's or container's name: to create (default: generated), or the existing one")
	f.StringVarP(&tf.selector, "selector", "l", "", "--k8s, --docker: an existing pod or container with these labels, picked at each connect (k8s: kubectl's syntax; docker: key=value, comma-separated); implies --create=false")
	f.StringVar(&tf.image, "image", "", "--k8s, --docker: the image of the pod or container subtun creates (default: "+transport.DefaultImage+")")
	f.StringVar(&tf.network, "network", "", "--docker: the network the container subtun creates joins (default: the default bridge)")
	f.StringVar(&tf.requests, "requests", "", "--k8s: the created pod's requests, e.g. cpu=50m,memory=64Mi")
	f.StringVar(&tf.limits, "limits", "", "--k8s, --docker: the created pod's or container's limits, e.g. cpu=1,memory=512Mi")
	f.StringVarP(&tf.namespace, "namespace", "n", "", "--k8s: the namespace (default: the kubeconfig context's)")
	f.StringVarP(&tf.container, "container", "c", "", "--k8s: an existing pod's container (default: kubectl's default container)")
	f.StringVar(&tf.context, "context", "", "--k8s: the kubeconfig context (default: its current one); --docker: the docker context (default: $DOCKER_CONTEXT, then the current one)")
	f.StringVar(&tf.kubeconfig, "kubeconfig", "", "--k8s: the kubeconfig file (default: $KUBECONFIG or ~/.kube/config)")
	f.StringVarP(&tf.host, "host", "H", "", "--docker: the daemon's address (default: $DOCKER_HOST, then the docker context)")
}

// given reports whether a target was given here.
func (tf *targetFlags) given() bool { return tf.k8s || tf.docker }

// unused refuses the target's flags without a target given here.
func (tf *targetFlags) unused(flags *pflag.FlagSet) error {
	var used []string
	for _, n := range targetFlagNames {
		if flags.Changed(n) {
			used = append(used, "--"+n)
		}
	}
	if len(used) == 0 {
		return nil
	}
	return fmt.Errorf("%s: for a target given here, with --k8s or --docker (a profile has them in its target)", strings.Join(used, ", "))
}

// target is the target given here, checked as a profile's would be.
func (tf *targetFlags) target(flags *pflag.FlagSet) (config.Target, error) {
	if tf.k8s && tf.docker {
		return config.Target{}, errors.New("--k8s and --docker don't go together")
	}
	var create *bool
	if flags.Changed("create") {
		create = &tf.create
	}
	res, err := parseResources(tf.requests, tf.limits)
	if err != nil {
		return config.Target{}, err
	}
	var tg config.Target
	if tf.k8s {
		if err := onlyFor(flags, "--docker", "network", "host"); err != nil {
			return config.Target{}, err
		}
		tg.K8s = &config.K8sTarget{Kubeconfig: tf.kubeconfig, Context: tf.context, Namespace: tf.namespace, Create: create,
			Name: tf.name, Selector: tf.selector, Container: tf.container, Image: tf.image, Resources: res}
	} else {
		if err := onlyFor(flags, "--k8s", "namespace", "container", "kubeconfig", "requests"); err != nil {
			return config.Target{}, err
		}
		tg.Docker = &config.DockerTarget{Host: tf.host, Context: tf.context, Create: create, Name: tf.name, Selector: tf.selector,
			Image: tf.image, Network: tf.network, Resources: res}
	}
	if err := tg.Validate(); err != nil {
		return config.Target{}, flagWords(err)
	}
	if err := checkSelector(tg); err != nil {
		return config.Target{}, err
	}
	return tg, nil
}

// spec is the run of the target given here; the arguments are CIDRs.
func (tf *targetFlags) spec(flags *pflag.FlagSet, args []string, s settings, g *globalOpts) (*tunnelSpec, error) {
	tg, err := tf.target(flags)
	if err != nil {
		return nil, err
	}
	s.routes = args
	sp := &tunnelSpec{s: s}
	sp.connect, sp.endpoint, sp.release = profileTarget("", tg, &sp.s, g)
	return sp, nil
}

// onlyFor refuses flags that belong to the other kind of target.
func onlyFor(flags *pflag.FlagSet, kind string, names ...string) error {
	for _, n := range names {
		if flags.Changed(n) {
			return fmt.Errorf("--%s is for %s", n, kind)
		}
	}
	return nil
}

// flagWords says a target error in flags: target.k8s.name → --name,
// target.k8s.resources.limits.cpu → --limits cpu.
func flagWords(err error) error {
	s := err.Error()
	for _, kind := range []string{"target.k8s", "target.docker"} {
		for _, r := range []string{"requests", "limits"} {
			for _, q := range []string{"cpu", "memory"} {
				s = strings.ReplaceAll(s, kind+".resources."+r+"."+q, "--"+r+" "+q)
			}
			s = strings.ReplaceAll(s, kind+".resources."+r, "--"+r)
		}
		s = strings.ReplaceAll(s, kind+".resources", "--requests/--limits")
		s = strings.ReplaceAll(s, kind+" (an existing pod)", "an existing pod")
		s = strings.ReplaceAll(s, kind+" (an existing container)", "an existing container")
		s = strings.ReplaceAll(s, kind+".", "--")
	}
	s = strings.ReplaceAll(s, "needs one of name, selector", "needs --name or -l (--selector)")
	s = strings.ReplaceAll(s, ": name and selector don't go together (one of name, selector)", ": --name and -l (--selector) don't go together")
	s = strings.ReplaceAll(s, "create: false", "--create=false")
	return errors.New(s)
}

// parseResources reads --requests and --limits: "cpu=50m,memory=64Mi".
func parseResources(requests, limits string) (*config.Resources, error) {
	if requests == "" && limits == "" {
		return nil, nil
	}
	r := &config.Resources{}
	for flag, pair := range map[string]struct {
		v string
		l *config.ResourceList
	}{"requests": {requests, &r.Requests}, "limits": {limits, &r.Limits}} {
		if pair.v == "" {
			continue
		}
		for _, kv := range strings.Split(pair.v, ",") {
			k, v, ok := strings.Cut(strings.TrimSpace(kv), "=")
			switch {
			case ok && v == "":
				return nil, fmt.Errorf("--%s %q: %s has no value", flag, pair.v, k)
			case ok && k == "cpu":
				pair.l.CPU = v
			case ok && k == "memory":
				pair.l.Memory = v
			default:
				return nil, fmt.Errorf("--%s %q: cpu=QUANTITY and memory=QUANTITY, comma-separated", flag, pair.v)
			}
		}
	}
	return r, nil
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
