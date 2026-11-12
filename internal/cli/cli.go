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
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/md2k/subnet-tunnel/internal/agentbin"
	"github.com/md2k/subnet-tunnel/internal/capture"
	"github.com/md2k/subnet-tunnel/internal/config"
	"github.com/md2k/subnet-tunnel/internal/dns"
	"github.com/md2k/subnet-tunnel/internal/netinfo"
	"github.com/md2k/subnet-tunnel/internal/privhelper"
	"github.com/md2k/subnet-tunnel/internal/routes"
	"github.com/md2k/subnet-tunnel/internal/socks"
	"github.com/md2k/subnet-tunnel/internal/transport"
	"github.com/md2k/subnet-tunnel/internal/transport/docker"
	"github.com/md2k/subnet-tunnel/internal/transport/k8s"
	"github.com/md2k/subnet-tunnel/internal/tunnel"
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
	root.AddCommand(newUpCmd(g), newK8sCmd(g), newDockerCmd(g), newImportCmd(g), newCleanupCmd(g), newVersionCmd(), newHelperCmd())
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

	killSwitch    string
	killSwitchDNS string
	blockIPv6     string

	maxDuration time.Duration // testing: stop by itself after this long
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
	f.StringVar(&s.dnsListen, "dns-listen", "", "answer DNS on this address instead of capturing it, no root needed (development)")
	_ = f.MarkHidden("dns-listen")
	f.StringVar(&s.killSwitch, "kill-switch", "", "keep routed traffic from leaving outside the tunnel: off (default), on (blocks stay after a crash or a lost tunnel), lockdown (also after Ctrl-C)")
	f.StringVar(&s.killSwitchDNS, "kill-switch-dns", "", "while the kill switch holds, DNS to the captured servers is: block (default) or allow")
	f.StringVar(&s.blockIPv6, "block-ipv6", "", "block outgoing IPv6: auto (default: in a full tunnel), true or false")
	f.DurationVar(&s.maxDuration, "max-duration", 0, "stop by itself after this long, as on Ctrl-C (testing: a way back if the network is cut)")
	_ = f.MarkHidden("max-duration")
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
		s.dnsCapture = p.DNS.Capture
	}
	if !set("dns-servers") {
		s.dnsServers = p.DNS.Servers
	}
	if !set("dns-fallback") {
		s.dnsFallback = p.DNS.Fallback
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
	cmd := &cobra.Command{
		Use:   "up PROFILE [CIDR...]",
		Short: "Start a profile from the config file",
		Long: `Start a named profile from the config file. Flags override the profile's
values; CIDRs and --exclude given here are added to the profile's.
Without a profile name, lists the profiles.`,
		Example: `  subtun up dev-cluster
  subtun up dev-cluster --dry-run
  subtun up dev-cluster 10.50.0.0/16 -x 10.50.1.0/24`,
		RunE: func(cmd *cobra.Command, args []string) error {
			path := g.config
			if path == "" {
				path = config.DefaultPath()
			}
			f, err := config.Load(path)
			if err != nil {
				return err
			}
			if len(args) == 0 {
				fmt.Fprintf(cmd.OutOrStdout(), "profiles in %s:\n  %s\n", path, strings.Join(f.Names(), "\n  "))
				return nil
			}
			p, err := f.Profile(args[0])
			if err != nil {
				return fmt.Errorf("%s: %w", path, err)
			}
			s.routes = args[1:]
			s.applyProfile(p, cmd.Flags())

			var connect connectFunc
			switch {
			case p.Target.K8s != nil:
				t := k8s.Target{
					Kubeconfig: config.ExpandHome(p.Target.K8s.Kubeconfig),
					Context:    p.Target.K8s.Context,
					Namespace:  p.Target.K8s.Namespace,
					Pod:        strings.TrimPrefix(p.Target.K8s.Pod, "pod/"),
					Container:  p.Target.K8s.Container,
				}
				connect = func(ctx context.Context, agents []agentbin.Binary, log *slog.Logger) (*transport.Carrier, error) {
					return k8s.Connect(ctx, t, agents, s.transport(g), log)
				}
			case p.Target.Docker != nil:
				t := docker.Target{Host: p.Target.Docker.Host, Context: p.Target.Docker.Context, Container: p.Target.Docker.Container}
				connect = func(ctx context.Context, agents []agentbin.Binary, log *slog.Logger) (*transport.Carrier, error) {
					return docker.Connect(ctx, t, agents, s.transport(g), log)
				}
			}
			return run(cmd.Context(), cmd.OutOrStdout(), g, s, connect)
		},
	}
	s.register(cmd)
	return cmd
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
			return run(cmd.Context(), cmd.OutOrStdout(), g, s, func(ctx context.Context, agents []agentbin.Binary, log *slog.Logger) (*transport.Carrier, error) {
				return k8s.Connect(ctx, t, agents, s.transport(g), log)
			})
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
			return run(cmd.Context(), cmd.OutOrStdout(), g, s, func(ctx context.Context, agents []agentbin.Binary, log *slog.Logger) (*transport.Carrier, error) {
				return docker.Connect(ctx, t, agents, s.transport(g), log)
			})
		},
	}
	cmd.Flags().StringVarP(&t.Host, "host", "H", "", "Docker daemon address (default: $DOCKER_HOST, then the docker context)")
	cmd.Flags().StringVar(&t.Context, "context", "", "docker context (default: $DOCKER_CONTEXT, then the current context)")
	s.register(cmd)
	return cmd
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
	if len(plan.Routes) == 0 {
		return nil, nil, errors.New("the excludes remove every route")
	}
	reserved := []routes.Reserved{{Addr: tunAddr, What: "subtun's utun address"}}
	if gw, ok := netinfo.DefaultGateway(); ok {
		reserved = append(reserved, routes.Reserved{Addr: gw, What: "the default gateway", ViaLocal: true})
	}
	errs, warns := routes.Check(plan, reserved, netinfo.LocalNetworks())
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

func run(ctx context.Context, out io.Writer, g *globalOpts, s settings, connect connectFunc) error {
	log := newLogger(g.verbose)
	if s.socks == "" && len(s.routes) == 0 && s.dnsListen == "" {
		return errors.New("nothing to do: give CIDRs to capture, --socks ADDR, or both")
	}
	if s.maxDuration < 0 {
		return errors.New("--max-duration must be positive")
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
		gp, err = planGuard(s, rp)
	}
	if s.dryRun {
		if err != nil {
			for _, wn := range warns {
				fmt.Fprintf(out, "warning: %s\n", wn)
			}
			return err
		}
		if rp == nil {
			fmt.Fprintln(out, "no routes: SOCKS only")
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
		return nil
	}
	if err != nil {
		return err
	}
	// From here on, including the sudo prompt and connecting.
	ctx, done := withMaxDuration(ctx, s.maxDuration, log)
	defer done() // last: the watchdog covers stopping
	if rp != nil {
		for _, n := range rp.plan.Redundant {
			log.Info("route rule dropped", "rule", n.String())
		}
		for _, wn := range warns {
			log.Warn(wn)
		}
	}

	agents, err := loadAgents(s.agentFile)
	if err != nil {
		return err
	}

	// Listen before connecting, so a busy port fails fast.
	var ln net.Listener
	if s.socks != "" {
		ln, err = net.Listen("tcp", s.socks)
		if err != nil {
			return fmt.Errorf("SOCKS listener: %w", err)
		}
		defer ln.Close()
		if host, _, _ := net.SplitHostPort(s.socks); !isLoopback(host) {
			log.Warn("SOCKS proxy is reachable from other hosts and has no authentication", "addr", ln.Addr())
		}
	}

	// Rules an earlier session may have left (kill switch, a killed helper)
	// can block DNS, which connecting needs: take them over first.
	var early *privhelper.Client
	marker := &leftovers{mark: privhelper.MarkLeftovers, clear: privhelper.ClearLeftovers}
	if privhelper.LeftoversMarked() {
		if rp == nil {
			log.Warn("firewall rules from another subtun session may be in place; if networking misbehaves and none is running, run: subtun cleanup")
		} else {
			log.Info("firewall rules from another subtun session may be in place; checking with the root helper before connecting")
			if early, err = privhelper.Start(ctx, &transport.LineLog{Log: log, Prefix: "helper: "}, log); err != nil {
				return startErr(ctx, err)
			}
			res, err := early.Adopt()
			if err != nil {
				_ = early.Close()
				return fmt.Errorf("taking over firewall rules: %w", err)
			}
			log.Info(res.Message)
			marker.adopted(res)
			// Until capture takes it, closing it puts the rules back.
			defer func() {
				if early != nil {
					_ = early.Close()
				}
			}()
		}
	}

	start := time.Now()
	carrier, err := connect(ctx, agents, log)
	if err != nil {
		return startErr(ctx, err)
	}
	hctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	client, err := tunnel.NewClient(hctx, carrier, tunnel.Options{ExpectSHA256: carrier.SHA256, Logger: log})
	cancel()
	if err != nil {
		return startErr(ctx, fmt.Errorf("starting agent in %s: %w", carrier.Desc, err))
	}
	defer func() {
		_ = client.Close()
		_ = carrier.Close()
	}()

	log.Info("tunnel up", "via", carrier.Desc, "agent", client.Agent().Version,
		"took", time.Since(start).Round(time.Millisecond))

	errc := make(chan error, 1)
	if s.dnsListen != "" && dnsOpts != nil {
		dnsOpts.Tunnel = dns.UpstreamFunc(client.ExchangeDNS)
		stopDNS, err := serveDNSDev(ctx, s.dnsListen, dnsOpts, log)
		if err != nil {
			return err
		}
		defer stopDNS()
		dnsOpts = nil // not captured
	}
	if ln != nil {
		srv := &socks.Server{Dialer: client, Logger: log}
		go func() { errc <- srv.Serve(ctx, ln) }()
		log.Info("SOCKS5 proxy ready", "addr", ln.Addr().String())
	}

	var helperExited <-chan struct{}
	deliberate := false // the user stopped subtun (signal), as opposed to a failure
	if rp != nil {
		final, err := excludeEndpoints(rp, carrier.Endpoints, log)
		if err != nil {
			return err
		}
		opts := rp.opts
		if dnsOpts != nil {
			dnsOpts.Tunnel = dns.UpstreamFunc(client.ExchangeDNS)
			opts.DNS = dnsOpts
		}
		opts.KillSwitch, opts.AllowDNS, opts.BlockIPv6 = gp.killSwitch, gp.allowDNS, gp.blockIPv6
		if opts.BlockIPv6 {
			if a, ok := ipv6Endpoint(carrier.Endpoints); ok {
				log.Warn("not blocking IPv6: subtun's own connection may use it", "endpoint", a)
				opts.BlockIPv6, gp.blockIPv6 = false, false
			}
		}
		if gp.on() {
			if opts.Guarded, err = guardPrefixes(final, localPrefixes()); err != nil {
				return err
			}
			if len(opts.Guarded) == 0 {
				log.Warn("kill switch has nothing to guard: every route is a local network")
			}
		}
		opts.Helper, early = early, nil
		if opts.DNS != nil || gp.on() || gp.blockIPv6 {
			// Firewall rules may outlive this process; the next run looks.
			marker.firewall()
		}
		c, err := capture.Start(ctx, final, opts, client, log)
		if err != nil {
			marker.startFailed()
			return startErr(ctx, fmt.Errorf("utun capture: %w", err))
		}
		// Stopped before the tunnel (deferred above): firewall rules and
		// routes go first.
		defer func() {
			leftBehind := c.Stop(deliberate)
			marker.stopped(leftBehind)
			if leftBehind {
				log.Warn("kill switch: blocking rules stay in place; the next subtun run takes them over, or remove them with: subtun cleanup")
			}
		}()
		helperExited = c.HelperExited()
	}

	select {
	case <-ctx.Done():
		deliberate = true
		logShutdown(ctx, log)
		return nil
	case <-client.Done():
		return errors.New("connection to the agent was lost")
	case err := <-errc:
		return fmt.Errorf("SOCKS listener: %w", err)
	case <-helperExited:
		// Ctrl-C reaches the helper too; that's a normal shutdown.
		select {
		case <-ctx.Done():
			deliberate = true
			logShutdown(ctx, log)
			return nil
		case <-time.After(300 * time.Millisecond):
		}
		return errors.New("the root helper exited unexpectedly; its firewall rules may still be in place: the next subtun run takes them over, or remove them with: subtun cleanup")
	}
}

// excludeEndpoints carves the carrier's own addresses (API server, Docker
// daemon) out of the routes, so capture can't cut the tunnel.
func excludeEndpoints(rp *routePlan, endpoints []netip.Addr, log *slog.Logger) ([]netip.Prefix, error) {
	auto := routes.HostPrefixes(endpoints)
	var hit []netip.Prefix
	for _, p := range auto {
		if _, ok := rp.plan.Routed(p.Addr()); ok {
			hit = append(hit, p)
		}
	}
	if len(hit) == 0 {
		return rp.plan.Routes, nil
	}
	final, err := routes.Compute(rp.includes, append(append([]netip.Prefix{}, rp.excludes...), hit...))
	if err != nil {
		return nil, err
	}
	for _, p := range hit {
		log.Info("excluded from routes: subtun's own connection goes there", "addr", p.Addr())
	}
	reserved := make([]routes.Reserved, len(endpoints))
	for i, a := range endpoints {
		reserved[i] = routes.Reserved{Addr: a, What: "subtun's own endpoint"}
	}
	if errs, _ := routes.Check(final, reserved, nil); len(errs) > 0 {
		return nil, errors.New(strings.Join(errs, "; "))
	}
	return final.Routes, nil
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
	level := slog.LevelInfo
	if verbose {
		level = slog.LevelDebug
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: level,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if len(groups) == 0 && a.Key == slog.TimeKey {
				return slog.String(slog.TimeKey, a.Value.Time().Format("15:04:05.000"))
			}
			return a
		},
	}))
}
