// Package cli is subtun's command line.
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/md2k/subnet-tunnel/internal/agentbin"
	"github.com/md2k/subnet-tunnel/internal/capture"
	"github.com/md2k/subnet-tunnel/internal/config"
	"github.com/md2k/subnet-tunnel/internal/dns"
	"github.com/md2k/subnet-tunnel/internal/privhelper"
	"github.com/md2k/subnet-tunnel/internal/routes"
	"github.com/md2k/subnet-tunnel/internal/transport"
	"github.com/md2k/subnet-tunnel/internal/transport/docker"
	"github.com/md2k/subnet-tunnel/internal/transport/k8s"
	"github.com/md2k/subnet-tunnel/internal/version"
)

// Execute runs the CLI and returns the process exit code.
func Execute() int {
	// SIGHUP too (terminal closed): the helper must get to remove its
	// firewall rules, and subtun to stop its agent.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer stop()
	if err := newRoot().ExecuteContext(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "subtun:", err)
		return 1
	}
	return 0
}

type globalOpts struct {
	verbose bool
	config  string
}

func newRoot() *cobra.Command {
	g := &globalOpts{}
	root := &cobra.Command{
		Use:           "subtun",
		Short:         "Route subnets and DNS domains through a remote host, pod or container",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.PersistentFlags().BoolVarP(&g.verbose, "verbose", "v", false, "debug logging")
	root.PersistentFlags().StringVar(&g.config, "config", "", "config file (default: $SUBTUN_CONFIG or ~/.config/subtun/config.yaml)")
	root.AddCommand(newUpCmd(g), newK8sCmd(g), newDockerCmd(g), newStatusCmd(), newLogsCmd(), newRouteCmd(), newDNSCmd(), newProfileCmd(),
		newImportCmd(g), newCleanupCmd(g), newVersionCmd(), newHelperCmd())
	return root
}

// newHelperCmd is the root helper that `sudo` runs for utun setup. Not for
// direct use.
func newHelperCmd() *cobra.Command {
	var socketPath string
	cmd := &cobra.Command{
		Use:    "helper",
		Short:  "Root helper for utun setup (started by subtun through sudo)",
		Hidden: true,
		Args:   cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
				ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
					if len(groups) == 0 && a.Key == slog.TimeKey {
						return slog.Attr{}
					}
					return a
				},
			}))
			return privhelper.Serve(cmd.Context(), socketPath, os.Stdin, log)
		},
	}
	cmd.Flags().StringVar(&socketPath, "socket", "", "subtun's unix socket")
	_ = cmd.MarkFlagRequired("socket")
	return cmd
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the version",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, _ []string) {
			fmt.Fprintln(cmd.OutOrStdout(), "subtun", version.String())
		},
	}
}

// settings are what every target command accepts, from flags, positional
// CIDRs and (for `up`) a config profile.
type settings struct {
	socks     string
	agent     string
	agentFile string
	agentDir  string
	routes    []string
	excludes  []string
	tunAddr   string
	mtu       int
	dryRun    bool

	dnsCapture  string
	dnsListen   string // development: answer DNS here, no capture
	dnsServers  []string
	dnsDomains  []string
	dnsPatterns []string
	dnsFallback string
	dnsUnrouted string

	killSwitch    string
	killSwitchDNS string
	blockIPv6     string

	maxDuration time.Duration // testing: stop by itself after this long

	reconnectAttempts int
	reconnectDelay    time.Duration
	reconnectMaxDelay time.Duration

	control string     // the control socket: status, full or off (global for the run)
	log     config.Log // logging (global for the run)
}

func (s *settings) register(cmd *cobra.Command) {
	f := cmd.Flags()
	f.StringVar(&s.socks, "socks", "", "start a SOCKS5 proxy on this address (e.g. 127.0.0.1:1080)")
	f.StringArrayVarP(&s.excludes, "exclude", "x", nil, "never route this CIDR or IP through the tunnel (repeatable; most specific rule wins)")
	f.StringVar(&s.tunAddr, "tun-addr", capture.DefaultTunAddr, "subtun's own utun address")
	f.IntVar(&s.mtu, "mtu", capture.DefaultMTU, "utun MTU")
	f.BoolVar(&s.dryRun, "dry-run", false, "show the routes that would be installed and exit")
	f.StringVar(&s.agent, "agent", transport.AgentAuto,
		"agent to run in the target: auto (binary if it can run, else Python), binary, or python (python3 3.6+, writes nothing)")
	f.StringVar(&s.agentDir, "agent-dir", "",
		"directory for the binary agent in the target (default: first usable of ~/.cache/subtun, /tmp/subtun-<uid>, /var/tmp/subtun-<uid>, /dev/shm/subtun-<uid>)")
	f.StringVar(&s.agentFile, "agent-file", "", "upload this agent binary instead of the embedded one (development)")
	_ = f.MarkHidden("agent-file")
	f.StringSliceVar(&s.dnsDomains, "dns-domain", nil, "resolve names under this domain through the tunnel (repeatable or comma-separated; \".\" = all names)")
	f.StringArrayVar(&s.dnsPatterns, "dns-pattern", nil, "resolve names matching this regular expression through the tunnel (repeatable)")
	f.StringSliceVar(&s.dnsServers, "dns-servers", nil, "DNS servers whose queries are captured (default auto: the system's, followed when the network changes)")
	f.StringVar(&s.dnsFallback, "dns-fallback", "", "resolver for all other names: system (default) or IP[:port]")
	f.StringVar(&s.dnsCapture, "dns-capture", "", "how DNS is captured: firewall (default, pf on macOS) or off")
	f.StringVar(&s.dnsUnrouted, "dns-unrouted", "", "a name resolved through the tunnel to a private address no route covers: warn (default), fallback (answer from the normal resolver) or block (drop those addresses)")
	f.StringVar(&s.dnsListen, "dns-listen", "", "answer DNS on this address instead of capturing it, no root needed (development)")
	_ = f.MarkHidden("dns-listen")
	f.StringVar(&s.killSwitch, "kill-switch", "", "keep routed traffic from leaving outside the tunnel: off (default), on (blocks stay after a crash or a lost tunnel), lockdown (also after Ctrl-C)")
	f.StringVar(&s.killSwitchDNS, "kill-switch-dns", "", "while the kill switch holds, DNS to the captured servers is: block (default) or allow")
	f.StringVar(&s.blockIPv6, "block-ipv6", "", "block outgoing IPv6: auto (default: in a full tunnel), true or false")
	f.DurationVar(&s.maxDuration, "max-duration", 0, "stop by itself after this long, as on Ctrl-C (testing: a way back if the network is cut)")
	f.IntVar(&s.reconnectAttempts, "reconnect-attempts", defaultReconnectAttempts, "when the connection to the agent is lost, try this many times to reconnect (0: exit instead)")
	f.DurationVar(&s.reconnectDelay, "reconnect-delay", defaultReconnectDelay, "wait before the first reconnect attempt; it doubles after each one")
	f.DurationVar(&s.reconnectMaxDelay, "reconnect-max-delay", defaultReconnectMaxDelay, "longest wait between reconnect attempts")
	_ = f.MarkHidden("max-duration")
	f.StringVar(&s.control, "control", controlStatus, "the control socket: status (subtun status and subtun logs), full (also changes while running: subtun route, dns, profile) or off")
	registerLogFlags(cmd, &s.log)
}

// applyProfile fills settings from a profile; flags given on the command
// line win, and command-line routes and excludes are added to the profile's.
func (s *settings) applyProfile(p config.Profile, flags *pflag.FlagSet) {
	set := func(name string) bool { return flags.Changed(name) }
	if !set("socks") {
		s.socks = p.Socks
	}
	if !set("agent") && p.Agent != "" {
		s.agent = p.Agent
	}
	if !set("agent-dir") {
		s.agentDir = p.AgentDir
	}
	if !set("tun-addr") && p.Tun.Address != "" {
		s.tunAddr = p.Tun.Address
	}
	if !set("mtu") && p.Tun.MTU != 0 {
		s.mtu = p.Tun.MTU
	}
	s.routes = append(append([]string{}, p.Routes...), s.routes...)
	s.excludes = append(append([]string{}, p.Exclude...), s.excludes...)
	if !set("dns-capture") {
		s.dnsCapture = string(p.DNS.Capture)
	}
	if !set("dns-servers") {
		s.dnsServers = p.DNS.Servers
	}
	if !set("dns-fallback") {
		s.dnsFallback = p.DNS.Fallback
	}
	if !set("dns-unrouted") {
		s.dnsUnrouted = p.DNS.Unrouted
	}
	s.dnsDomains = append(append([]string{}, p.DNS.Domains...), s.dnsDomains...)
	s.dnsPatterns = append(append([]string{}, p.DNS.Patterns...), s.dnsPatterns...)
	if !set("kill-switch") {
		s.killSwitch = string(p.KillSwitch.Mode)
	}
	if !set("kill-switch-dns") {
		s.killSwitchDNS = p.KillSwitch.DNS
	}
	if !set("block-ipv6") {
		s.blockIPv6 = string(p.BlockIPv6)
	}
	if !set("reconnect-attempts") && p.Reconnect.Attempts != nil {
		s.reconnectAttempts = *p.Reconnect.Attempts
	}
	if d, err := time.ParseDuration(p.Reconnect.Delay); !set("reconnect-delay") && err == nil {
		s.reconnectDelay = d // the config checked it
	}
	if d, err := time.ParseDuration(p.Reconnect.MaxDelay); !set("reconnect-max-delay") && err == nil {
		s.reconnectMaxDelay = d
	}
}

func (s *settings) transport(g *globalOpts) transport.Options {
	opts := transport.Options{Agent: s.agent, AgentDir: s.agentDir, Version: version.Version}
	if g.verbose {
		opts.AgentArgs = []string{"-v"}
	}
	return opts
}

func newUpCmd(g *globalOpts) *cobra.Command {
	var s settings
	var profiles []string
	cmd := &cobra.Command{
		Use:   "up [PROFILE [CIDR...]] [--profile NAME...]",
		Short: "Start one or several profiles from the config file",
		Long: `Start a named profile from the config file. Flags override the profile's
values; CIDRs and --exclude given here are added to the profile's.

Several profiles (--profile, repeatable or comma-separated, plus the
argument) run at once, each through its own target: connections and DNS
names go to the profile whose route or domain matches most specifically.
They are configured in the config file only: the command line then takes
--dry-run, not settings or CIDRs.

Without a profile name, lists the profiles.`,
		Example: `  subtun up dev-cluster
  subtun up dev-cluster --dry-run
  subtun up dev-cluster 10.50.0.0/16 -x 10.50.1.0/24
  subtun up --profile work,dev-cluster`,
		RunE: func(cmd *cobra.Command, args []string) error {
			path := g.config
			if path == "" {
				path = config.DefaultPath()
			}
			f, err := config.Load(path)
			if err != nil {
				return err
			}
			var names []string
			if len(args) > 0 {
				names = append(names, args[0])
			}
			for _, n := range profiles {
				if !slices.Contains(names, n) {
					names = append(names, n)
				}
			}
			if len(names) == 0 {
				fmt.Fprintf(cmd.OutOrStdout(), "profiles in %s:\n  %s\n", path, strings.Join(f.Names(), "\n  "))
				return nil
			}
			if !cmd.Flags().Changed("control") && f.Control != "" {
				s.control = string(f.Control) // the config file's, for every run
			}
			if err := mergeLog(cmd.Flags(), &s.log, f.Log); err != nil {
				return err // the file's own log: was checked when loaded
			}
			if len(names) > 1 {
				return upSeveral(cmd, g, f, path, names, args, s)
			}
			var extra []string
			if len(args) > 0 {
				extra = args[1:]
			}
			sp, err := profileSpec(f, path, names[0], s, extra, cmd.Flags(), g)
			if err != nil {
				return err
			}
			return run(cmd.Context(), cmd.OutOrStdout(), g, sp)
		},
	}
	s.register(cmd)
	cmd.Flags().StringSliceVar(&profiles, "profile", nil, "start this profile; repeatable or comma-separated, several run at once")
	return cmd
}

// upSeveral starts several profiles. Their settings come from the config
// file only.
func upSeveral(cmd *cobra.Command, g *globalOpts, f *config.File, path string, names, args []string, defaults settings) error {
	if len(args) > 1 {
		return fmt.Errorf("with several profiles, CIDRs come from the config file (got %s)", strings.Join(args[1:], " "))
	}
	var refused []string
	cmd.Flags().Visit(func(fl *pflag.Flag) {
		switch fl.Name {
		case "profile", "dry-run", "max-duration", "verbose", "config", "control":
		default:
			if slices.Contains(logFlags, fl.Name) {
				return // global for the run
			}
			refused = append(refused, "--"+fl.Name)
		}
	})
	if len(refused) > 0 {
		return fmt.Errorf("with several profiles, settings come from the config file: %s only works with one profile", strings.Join(refused, ", "))
	}
	specs := make([]*tunnelSpec, len(names))
	for i, name := range names {
		sp, err := profileSpec(f, path, name, defaults, nil, cmd.Flags(), g)
		if err != nil {
			return err
		}
		specs[i] = sp
	}
	if err := config.ValidControl(defaults.control); err != nil {
		return err
	}
	return runMulti(cmd.Context(), cmd.OutOrStdout(), g, specs, defaults.dryRun, engineOpts{maxDuration: defaults.maxDuration, control: defaults.control, log: defaults.log})
}

// profileSpec builds a profile of the config file at path: base settings
// (the flags' defaults and values), then the profile's, flags given on the
// command line winning; extra routes are added to the profile's. Its
// reload reads the file again and builds it the same way.
func profileSpec(f *config.File, path, name string, base settings, extra []string, flags *pflag.FlagSet, g *globalOpts) (*tunnelSpec, error) {
	p, err := f.Profile(name)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	sp := &tunnelSpec{name: name, s: base, cfg: p}
	sp.s.routes = slices.Clone(extra)
	sp.s.applyProfile(p, flags)
	sp.base = sp.s
	sp.connect, sp.endpoint = profileTarget(p, &sp.s, g)
	sp.reload = func() (*tunnelSpec, error) {
		f, err := config.Load(path)
		if err != nil {
			return nil, err
		}
		return profileSpec(f, path, name, base, extra, flags, g)
	}
	return sp, nil
}

// configPath is the config file a run reads (--config, $SUBTUN_CONFIG or
// the default).
func configPath(g *globalOpts) string {
	if g.config != "" {
		return g.config
	}
	return config.DefaultPath()
}

// configSpecs builds profiles of the config file at path with the config's
// settings only (as several profiles take them): for profiles added to a
// running subtun.
func configSpecs(path string, g *globalOpts) func(name string) (*tunnelSpec, error) {
	var base settings
	cmd := &cobra.Command{}
	base.register(cmd) // the flags' defaults; none given
	return func(name string) (*tunnelSpec, error) {
		f, err := config.Load(path)
		if err != nil {
			return nil, err
		}
		return profileSpec(f, path, name, base, nil, cmd.Flags(), g)
	}
}

// profileTarget returns how to connect to a profile's target, and how to
// find its endpoint (API server, Docker daemon) without connecting.
func profileTarget(p config.Profile, s *settings, g *globalOpts) (connectFunc, func() (string, error)) {
	switch {
	case p.Target.K8s != nil:
		t := k8s.Target{
			Kubeconfig: config.ExpandHome(p.Target.K8s.Kubeconfig),
			Context:    p.Target.K8s.Context,
			Namespace:  p.Target.K8s.Namespace,
			Pod:        strings.TrimPrefix(p.Target.K8s.Pod, "pod/"),
			Container:  p.Target.K8s.Container,
		}
		return func(ctx context.Context, agents []agentbin.Binary, log *slog.Logger) (*transport.Carrier, error) {
				return k8s.Connect(ctx, t, agents, s.transport(g), log)
			}, func() (string, error) {
				return k8s.Endpoint(t)
			}
	default: // the config makes sure there is one
		t := docker.Target{Host: p.Target.Docker.Host, Context: p.Target.Docker.Context, Container: p.Target.Docker.Container}
		return func(ctx context.Context, agents []agentbin.Binary, log *slog.Logger) (*transport.Carrier, error) {
				return docker.Connect(ctx, t, agents, s.transport(g), log)
			}, func() (string, error) {
				return docker.Endpoint(t)
			}
	}
}

func newK8sCmd(g *globalOpts) *cobra.Command {
	var t k8s.Target
	var s settings
	cmd := &cobra.Command{
		Use:   "k8s POD [CIDR...]",
		Short: "Tunnel through a Kubernetes pod, using the exec API",
		Long: `Tunnel through a Kubernetes pod. subtun talks to the API server with your
kubeconfig, starts its agent in the pod over exec and opens connections from
there.

CIDRs (or single IPs) are captured transparently through a utun interface:
any program on this machine reaches them directly. Setting up the interface
and routes needs root once, so sudo asks for your password; everything else
runs as you. --socks adds a SOCKS5 proxy, for example for a browser.`,
		Example: `  subtun k8s -n team-a debug-pod 10.96.0.0/12 10.244.0.0/16
  subtun k8s -n team-a debug-pod 10.0.0.0/8 -x 10.1.0.0/16 --dry-run
  subtun k8s -n team-a debug-pod --socks 127.0.0.1:1080
  curl --socks5-hostname 127.0.0.1:1080 http://my-svc.team-a.svc.cluster.local`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			t.Pod = strings.TrimPrefix(args[0], "pod/")
			s.routes = args[1:]
			if err := globalsFromConfig(cmd, g, &s); err != nil {
				return err
			}
			return run(cmd.Context(), cmd.OutOrStdout(), g, &tunnelSpec{s: s, connect: func(ctx context.Context, agents []agentbin.Binary, log *slog.Logger) (*transport.Carrier, error) {
				return k8s.Connect(ctx, t, agents, s.transport(g), log)
			}})
		},
	}
	cmd.Flags().StringVarP(&t.Namespace, "namespace", "n", "", "namespace (default: from kubeconfig)")
	cmd.Flags().StringVarP(&t.Container, "container", "c", "", "container (default: kubectl's default container)")
	cmd.Flags().StringVar(&t.Context, "context", "", "kubeconfig context (default: current)")
	cmd.Flags().StringVar(&t.Kubeconfig, "kubeconfig", "", "kubeconfig file (default: $KUBECONFIG or ~/.kube/config)")
	s.register(cmd)
	return cmd
}

func newDockerCmd(g *globalOpts) *cobra.Command {
	var t docker.Target
	var s settings
	cmd := &cobra.Command{
		Use:   "docker CONTAINER [CIDR...]",
		Short: "Tunnel through a Docker container, using the exec API",
		Long: `Tunnel through a Docker container. subtun talks to the Docker daemon (found
like the docker CLI does: --host, $DOCKER_HOST, then the current docker
context), starts its agent over exec and opens connections from there, so
container IPs and names on its networks become reachable from this machine.

CIDRs are captured transparently through a utun interface (sudo asks once);
--socks adds a SOCKS5 proxy.`,
		Example: `  subtun docker my-app 172.20.0.0/16
  subtun docker my-app --socks 127.0.0.1:1080
  curl --socks5-hostname 127.0.0.1:1080 http://db:5432`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			t.Container = args[0]
			s.routes = args[1:]
			if err := globalsFromConfig(cmd, g, &s); err != nil {
				return err
			}
			return run(cmd.Context(), cmd.OutOrStdout(), g, &tunnelSpec{s: s, connect: func(ctx context.Context, agents []agentbin.Binary, log *slog.Logger) (*transport.Carrier, error) {
				return docker.Connect(ctx, t, agents, s.transport(g), log)
			}})
		},
	}
	cmd.Flags().StringVarP(&t.Host, "host", "H", "", "Docker daemon address (default: $DOCKER_HOST, then the docker context)")
	cmd.Flags().StringVar(&t.Context, "context", "", "docker context (default: $DOCKER_CONTEXT, then the current context)")
	s.register(cmd)
	return cmd
}

// globalsFromConfig applies the config file's top-level control: and log:
// to a run without a profile (subtun k8s, subtun docker), under the flags
// given: they are global for every run. No config file is fine; a broken
// one only loses those settings.
func globalsFromConfig(cmd *cobra.Command, g *globalOpts, s *settings) error {
	var f *config.File
	if path := configPath(g); fileExists(path) {
		var err error
		if f, err = config.Load(path); err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "warning: %v (its control: and log: settings are ignored)\n", err)
			f = nil
		}
	}
	if f == nil {
		f = &config.File{}
	}
	if !cmd.Flags().Changed("control") && f.Control != "" {
		s.control = string(f.Control)
	}
	return mergeLog(cmd.Flags(), &s.log, f.Log)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

type connectFunc func(ctx context.Context, agents []agentbin.Binary, log *slog.Logger) (*transport.Carrier, error)

// routePlan is the validated, checked capture setup derived from settings.
type routePlan struct {
	includes []netip.Prefix
	excludes []netip.Prefix
	plan     routes.Plan
	opts     capture.Options
}

// planRoutes parses and checks routes before anything connects or asks for
// sudo, so mistakes fail fast.
func planRoutes(s settings) (*routePlan, []string, error) {
	if len(s.routes) == 0 {
		return nil, nil, nil
	}
	inc, err := routes.ParseAll(s.routes, routes.ParseRoute)
	if err != nil {
		return nil, nil, err
	}
	exc, err := routes.ParseAll(s.excludes, routes.ParsePrefix)
	if err != nil {
		return nil, nil, fmt.Errorf("exclude: %w", err)
	}
	tunAddr, err := privhelper.ValidateTunAddr(s.tunAddr)
	if err != nil {
		return nil, nil, err
	}
	if err := privhelper.ValidateMTU(s.mtu); err != nil {
		return nil, nil, err
	}
	locals := localNetworks()
	never, notes := autoExcludes(inc, neverRouted)
	lan, lanNotes := autoExcludes(inc, localExcludes(locals))
	exc = append(append(exc, never...), lan...)
	notes = append(notes, lanNotes...)
	plan, err := routes.Compute(inc, exc)
	if err != nil {
		return nil, nil, err
	}
	// subtun's own utun address can't go through the tunnel; the utun's own
	// host route covers it. Inevitable in a full tunnel (0.0.0.0/1 +
	// 128.0.0.0/1), so exclude it rather than refuse.
	if _, ok := plan.Routed(tunAddr); ok {
		exc = append(exc, netip.PrefixFrom(tunAddr, 32))
		if plan, err = routes.Compute(inc, exc); err != nil {
			return nil, nil, err
		}
		plan.Redundant = append(plan.Redundant, routes.Note{Prefix: netip.PrefixFrom(tunAddr, 32), Exclude: true,
			Reason: "subtun's own utun address, excluded automatically"})
	}
	plan.Redundant = append(plan.Redundant, notes...)
	if len(plan.Routes) == 0 {
		return nil, nil, errors.New("the excludes remove every route")
	}
	reserved := []routes.Reserved{{Addr: tunAddr, What: "subtun's utun address"}}
	if gw, ok := defaultGateway(); ok {
		reserved = append(reserved, routes.Reserved{Addr: gw, What: "the default gateway", ViaLocal: true})
	}
	errs, warns := routes.Check(plan, reserved, locals)
	if len(errs) > 0 {
		return nil, warns, errors.New(strings.Join(errs, "; "))
	}
	return &routePlan{includes: inc, excludes: exc, plan: plan, opts: capture.Options{TunAddr: tunAddr, MTU: s.mtu}}, warns, nil
}

func printPlan(w io.Writer, rp *routePlan, warns []string) {
	fmt.Fprintf(w, "routes on the utun (%d, from %d given, %d excluded):\n", len(rp.plan.Routes), len(rp.includes), len(rp.excludes))
	for _, p := range rp.plan.Routes {
		fmt.Fprintf(w, "  %s\n", p)
	}
	if len(rp.plan.Redundant) > 0 {
		fmt.Fprintf(w, "dropped (%d):\n", len(rp.plan.Redundant))
		for _, n := range rp.plan.Redundant {
			fmt.Fprintf(w, "  %s\n", n)
		}
	}
	for _, wn := range warns {
		fmt.Fprintf(w, "warning: %s\n", wn)
	}
	fmt.Fprintf(w, "utun %s, MTU %d. The API server or Docker daemon address is excluded automatically when connecting.\n",
		rp.opts.TunAddr, rp.opts.MTU)
}

// run runs one profile (subtun up NAME, subtun k8s, subtun docker): it plans
// and checks everything before connecting, prints the plan with --dry-run,
// and otherwise runs it on the same engine as several profiles.
func run(ctx context.Context, out io.Writer, g *globalOpts, sp *tunnelSpec) error {
	s := sp.s
	if s.socks == "" && len(s.routes) == 0 && s.dnsListen == "" {
		return errors.New("nothing to do: give CIDRs to capture, --socks ADDR, or both")
	}
	if s.maxDuration < 0 {
		return errors.New("--max-duration must be positive")
	}
	if err := config.ValidControl(s.control); err != nil {
		return err
	}
	policy := reconnectPolicy{attempts: s.reconnectAttempts, delay: s.reconnectDelay, maxDelay: s.reconnectMaxDelay}
	if err := policy.validate(); err != nil {
		return err
	}
	rp, warns, err := planRoutes(s)
	var dnsOpts *capture.DNSOptions
	var gp *guardPlan
	if err == nil {
		var notes []string
		dnsOpts, notes, err = planDNS(s, rp)
		warns = append(warns, notes...)
	}
	if err == nil {
		var notes []string
		gp, notes, err = planGuard(s, rp)
		warns = append(warns, notes...)
	}
	if s.dryRun {
		if err != nil {
			for _, wn := range warns {
				fmt.Fprintf(out, "warning: %s\n", wn)
			}
			return err
		}
		if rp == nil {
			for _, wn := range warns {
				fmt.Fprintf(out, "warning: %s\n", wn)
			}
			fmt.Fprintln(out, "no routes: SOCKS only")
			fmt.Fprintf(out, "reconnect: %s\n", policy)
			return nil
		}
		printPlan(out, rp, warns)
		if dnsOpts != nil {
			printDNSPlan(out, dnsOpts, s.dnsDomains, s.dnsPatterns)
		}
		if gp != nil {
			guarded, err := guardPrefixes(rp.plan.Routes, localPrefixes())
			if err != nil {
				return err
			}
			printGuardPlan(out, gp, len(guarded), dnsOpts != nil)
		}
		fmt.Fprintf(out, "reconnect: %s\n", policy)
		return nil
	}
	if err != nil {
		return err
	}
	mp := singlePlan(sp, policy, rp, dnsOpts, gp, warns)
	return runEngine(ctx, g, mp, engineOpts{single: true, maxDuration: s.maxDuration, agentFile: s.agentFile, dnsListen: s.dnsListen,
		control: s.control, log: s.log})
}

// singlePlan turns one profile's checked plan into the engine's plan.
func singlePlan(sp *tunnelSpec, policy reconnectPolicy, rp *routePlan, dnsOpts *capture.DNSOptions, gp *guardPlan, warns []string) *multiPlan {
	s := sp.s
	sp.base = s
	mp := &multiPlan{
		specs:    []*tunnelSpec{sp},
		policies: []reconnectPolicy{policy},
		ks:       []string{"off"},
		rps:      []*routePlan{rp},
		hosts:    []string{""}, // known once connected: excluded then, as always
		finals:   newFinals(1),
		dnsNames: []dns.Names{{Domains: s.dnsDomains, Patterns: s.dnsPatterns}},
		unrouted: []string{""},
		dns:      dnsOpts,
		warns:    warns,
	}
	if rp != nil {
		final := rp.plan.Routes
		mp.finals[0].Store(&final)
		mp.tunAddr, mp.mtu = rp.opts.TunAddr, rp.opts.MTU
	}
	if gp != nil {
		mp.ks[0], mp.allowDNS = gp.killSwitch, gp.allowDNS && gp.on()
		mp.blockIPv6, mp.ipv6Why = gp.blockIPv6, gp.ipv6Why
	}
	if dnsOpts != nil {
		mp.unrouted[0] = dnsOpts.Tunnels[0].Unrouted
	}
	mp.noteDomains()
	return mp
}

// ipv6Endpoint finds an IPv6 address subtun itself connects to (API
// server, Docker daemon); blocking IPv6 would cut the tunnel.
func ipv6Endpoint(endpoints []netip.Addr) (netip.Addr, bool) {
	for _, a := range endpoints {
		if a.Unmap().Is6() && !a.IsLoopback() && !a.IsLinkLocalUnicast() {
			return a, true
		}
	}
	return netip.Addr{}, false
}

func loadAgents(file string) ([]agentbin.Binary, error) {
	if file != "" {
		b, err := agentbin.FromFile(file)
		if err != nil {
			return nil, err
		}
		return []agentbin.Binary{b}, nil
	}
	return agentbin.Embedded()
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func newLogger(verbose bool) *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, logOptions(verbose)))
}

// logOptions: info (debug with -v), times without the date.
func logOptions(verbose bool) *slog.HandlerOptions {
	level := slog.LevelInfo
	if verbose {
		level = slog.LevelDebug
	}
	return &slog.HandlerOptions{
		Level: level,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if len(groups) == 0 && a.Key == slog.TimeKey {
				return slog.String(slog.TimeKey, a.Value.Time().Format("15:04:05.000"))
			}
			return a
		},
	}
}
