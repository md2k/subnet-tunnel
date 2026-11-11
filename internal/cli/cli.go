// Package cli is subtun's command line.
package cli

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/md2k/subnet-tunnel/internal/agentbin"
	"github.com/md2k/subnet-tunnel/internal/socks"
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
	root.AddCommand(newK8sCmd(g), newVersionCmd())
	return root
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

type frontendOpts struct {
	socks     string
	agentFile string
}

func (f *frontendOpts) register(cmd *cobra.Command) {
	cmd.Flags().StringVar(&f.socks, "socks", "", "start a SOCKS5 proxy on this address (e.g. 127.0.0.1:1080)")
	cmd.Flags().StringVar(&f.agentFile, "agent-file", "", "upload this agent binary instead of the embedded one (development)")
	_ = cmd.Flags().MarkHidden("agent-file")
}

func newK8sCmd(g *globalOpts) *cobra.Command {
	var t k8s.Target
	var f frontendOpts
	cmd := &cobra.Command{
		Use:   "k8s POD",
		Short: "Tunnel through a Kubernetes pod, using the exec API",
		Long: `Tunnel through a Kubernetes pod. subtun talks to the API server with your
kubeconfig, uploads its agent into the pod over exec and opens connections
from there. Nothing needs to be installed in the pod beyond sh, uname and cat.`,
		Example: `  subtun k8s -n team-a debug-pod --socks 127.0.0.1:1080
  curl --socks5-hostname 127.0.0.1:1080 http://my-svc.team-a.svc.cluster.local`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			t.Pod = strings.TrimPrefix(args[0], "pod/")
			if g.verbose {
				t.AgentArgs = []string{"-v"}
			}
			return run(cmd.Context(), g, f, func(ctx context.Context, agents []agentbin.Binary, log *slog.Logger) (*k8s.Carrier, error) {
				return k8s.Connect(ctx, t, agents, log)
			})
		},
	}
	cmd.Flags().StringVarP(&t.Namespace, "namespace", "n", "", "namespace (default: from kubeconfig)")
	cmd.Flags().StringVarP(&t.Container, "container", "c", "", "container (default: kubectl's default container)")
	cmd.Flags().StringVar(&t.Context, "context", "", "kubeconfig context (default: current)")
	cmd.Flags().StringVar(&t.Kubeconfig, "kubeconfig", "", "kubeconfig file (default: $KUBECONFIG or ~/.kube/config)")
	cmd.Flags().StringVar(&t.AgentDir, "agent-dir", "/tmp", "writable, executable directory in the container for the agent")
	f.register(cmd)
	return cmd
}

type connectFunc func(ctx context.Context, agents []agentbin.Binary, log *slog.Logger) (*k8s.Carrier, error)

func run(ctx context.Context, g *globalOpts, f frontendOpts, connect connectFunc) error {
	log := newLogger(g.verbose)
	if f.socks == "" {
		return errors.New("nothing to do: pass --socks ADDR (utun capture is not implemented yet)")
	}
	agents, err := loadAgents(f.agentFile)
	if err != nil {
		return err
	}

	// Listen before connecting, so a busy port fails fast.
	ln, err := net.Listen("tcp", f.socks)
	if err != nil {
		return fmt.Errorf("SOCKS listener: %w", err)
	}
	defer ln.Close()
	if host, _, _ := net.SplitHostPort(f.socks); !isLoopback(host) {
		log.Warn("SOCKS proxy is reachable from other hosts and has no authentication", "addr", ln.Addr())
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
		"socks", ln.Addr().String(), "took", time.Since(start).Round(time.Millisecond))

	srv := &socks.Server{Dialer: client, Logger: log}
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ctx, ln) }()

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
