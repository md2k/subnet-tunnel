// Package cli is subtun's command line.
package cli

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/md2k/subnet-tunnel/internal/agentbin"
	"github.com/md2k/subnet-tunnel/internal/capture"
	"github.com/md2k/subnet-tunnel/internal/privhelper"
	"github.com/md2k/subnet-tunnel/internal/socks"
	"github.com/md2k/subnet-tunnel/internal/transport"
	"github.com/md2k/subnet-tunnel/internal/transport/docker"
	"github.com/md2k/subnet-tunnel/internal/transport/k8s"
	"github.com/md2k/subnet-tunnel/internal/tunnel"
	"github.com/md2k/subnet-tunnel/internal/version"
)

// Execute runs the CLI and returns the process exit code.
func Execute() int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := newRoot().ExecuteContext(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "subtun:", err)
		return 1
	}
	return 0
}

type globalOpts struct {
	verbose bool
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
	root.AddCommand(newK8sCmd(g), newDockerCmd(g), newVersionCmd(), newHelperCmd())
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

// commonOpts are the flags and arguments every target command shares.
type commonOpts struct {
	socks     string
	agent     string
	agentFile string
	agentDir  string
	cidrs     []netip.Prefix
}

// parseCIDRs turns the positional arguments after the target into routes.
func (o *commonOpts) parseCIDRs(args []string) error {
	for _, a := range args {
		p, err := privhelper.ParseCIDR(a)
		if err != nil {
			return err
		}
		o.cidrs = append(o.cidrs, p)
	}
	return nil
}

func (o *commonOpts) register(cmd *cobra.Command) {
	cmd.Flags().StringVar(&o.socks, "socks", "", "start a SOCKS5 proxy on this address (e.g. 127.0.0.1:1080)")
	cmd.Flags().StringVar(&o.agent, "agent", transport.AgentAuto,
		"agent to run in the target: auto (binary if it can run, else Python), binary, or python (python3 3.6+, writes nothing)")
	cmd.Flags().StringVar(&o.agentDir, "agent-dir", "",
		"directory for the binary agent in the target (default: first usable of ~/.cache/subtun, /tmp/subtun-<uid>, /var/tmp/subtun-<uid>, /dev/shm/subtun-<uid>)")
	cmd.Flags().StringVar(&o.agentFile, "agent-file", "", "upload this agent binary instead of the embedded one (development)")
	_ = cmd.Flags().MarkHidden("agent-file")
}

func (o *commonOpts) transport(g *globalOpts) transport.Options {
	opts := transport.Options{Agent: o.agent, AgentDir: o.agentDir, Version: version.Version}
	if g.verbose {
		opts.AgentArgs = []string{"-v"}
	}
	return opts
}

func newK8sCmd(g *globalOpts) *cobra.Command {
	var t k8s.Target
	var o commonOpts
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
  subtun k8s -n team-a debug-pod --socks 127.0.0.1:1080
  curl --socks5-hostname 127.0.0.1:1080 http://my-svc.team-a.svc.cluster.local`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			t.Pod = strings.TrimPrefix(args[0], "pod/")
			if err := o.parseCIDRs(args[1:]); err != nil {
				return err
			}
			return run(cmd.Context(), g, o, func(ctx context.Context, agents []agentbin.Binary, log *slog.Logger) (*transport.Carrier, error) {
				return k8s.Connect(ctx, t, agents, o.transport(g), log)
			})
		},
	}
	cmd.Flags().StringVarP(&t.Namespace, "namespace", "n", "", "namespace (default: from kubeconfig)")
	cmd.Flags().StringVarP(&t.Container, "container", "c", "", "container (default: kubectl's default container)")
	cmd.Flags().StringVar(&t.Context, "context", "", "kubeconfig context (default: current)")
	cmd.Flags().StringVar(&t.Kubeconfig, "kubeconfig", "", "kubeconfig file (default: $KUBECONFIG or ~/.kube/config)")
	o.register(cmd)
	return cmd
}

func newDockerCmd(g *globalOpts) *cobra.Command {
	var t docker.Target
	var o commonOpts
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
			if err := o.parseCIDRs(args[1:]); err != nil {
				return err
			}
			return run(cmd.Context(), g, o, func(ctx context.Context, agents []agentbin.Binary, log *slog.Logger) (*transport.Carrier, error) {
				return docker.Connect(ctx, t, agents, o.transport(g), log)
			})
		},
	}
	cmd.Flags().StringVarP(&t.Host, "host", "H", "", "Docker daemon address (default: $DOCKER_HOST, then the docker context)")
	cmd.Flags().StringVar(&t.Context, "context", "", "docker context (default: $DOCKER_CONTEXT, then the current context)")
	o.register(cmd)
	return cmd
}

type connectFunc func(ctx context.Context, agents []agentbin.Binary, log *slog.Logger) (*transport.Carrier, error)

func run(ctx context.Context, g *globalOpts, f commonOpts, connect connectFunc) error {
	log := newLogger(g.verbose)
	if f.socks == "" && len(f.cidrs) == 0 {
		return errors.New("nothing to do: give CIDRs to capture, --socks ADDR, or both")
	}
	agents, err := loadAgents(f.agentFile)
	if err != nil {
		return err
	}

	// Listen before connecting, so a busy port fails fast.
	var ln net.Listener
	if f.socks != "" {
		ln, err = net.Listen("tcp", f.socks)
		if err != nil {
			return fmt.Errorf("SOCKS listener: %w", err)
		}
		defer ln.Close()
		if host, _, _ := net.SplitHostPort(f.socks); !isLoopback(host) {
			log.Warn("SOCKS proxy is reachable from other hosts and has no authentication", "addr", ln.Addr())
		}
	}

	start := time.Now()
	carrier, err := connect(ctx, agents, log)
	if err != nil {
		return err
	}
	hctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	client, err := tunnel.NewClient(hctx, carrier, tunnel.Options{ExpectSHA256: carrier.SHA256, Logger: log})
	cancel()
	if err != nil {
		return fmt.Errorf("starting agent in %s: %w", carrier.Desc, err)
	}
	defer func() {
		_ = client.Close()
		_ = carrier.Close()
	}()

	log.Info("tunnel up", "via", carrier.Desc, "agent", client.Agent().Version,
		"took", time.Since(start).Round(time.Millisecond))

	errc := make(chan error, 1)
	if ln != nil {
		srv := &socks.Server{Dialer: client, Logger: log}
		go func() { errc <- srv.Serve(ctx, ln) }()
		log.Info("SOCKS5 proxy ready", "addr", ln.Addr().String())
	}

	if len(f.cidrs) > 0 {
		if err := capture.CheckLoop(f.cidrs, carrier.Endpoints); err != nil {
			return err
		}
		c, err := capture.Start(ctx, f.cidrs, client, log)
		if err != nil {
			return fmt.Errorf("utun capture: %w", err)
		}
		// Closed before the tunnel (deferred above), so routes go first.
		defer c.Close()
	}

	select {
	case <-ctx.Done():
		log.Info("shutting down")
		return nil
	case <-client.Done():
		return errors.New("connection to the agent was lost")
	case err := <-errc:
		return fmt.Errorf("SOCKS listener: %w", err)
	}
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
