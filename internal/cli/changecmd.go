package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/md2k/subnet-tunnel/internal/control"
	"github.com/md2k/subnet-tunnel/internal/logx"
)

// changeTimeout bounds one change: a reload looks its target's endpoint up.
const changeTimeout = 15 * time.Second

// changeOpts are what every change command takes.
type changeOpts struct {
	profile string
	pid     int
	dryRun  bool
}

func (o *changeOpts) register(cmd *cobra.Command, withProfile bool) {
	if withProfile {
		cmd.Flags().StringVar(&o.profile, "profile", "", "the profile to change (needed when the run has several)")
	}
	cmd.Flags().IntVar(&o.pid, "pid", 0, "the subtun with this process id (needed when several run)")
	cmd.Flags().BoolVar(&o.dryRun, "dry-run", false, "only show what would change")
}

// oneInstance finds the running subtun with pid, or the only one.
func oneInstance(pid int) (control.Instance, error) {
	ins, err := instances(pid)
	if err != nil {
		return control.Instance{}, err
	}
	switch len(ins) {
	case 0:
		return control.Instance{}, errors.New("no subtun running")
	case 1:
		return ins[0], nil
	}
	pids := make([]string, len(ins))
	for i, in := range ins {
		pids[i] = fmt.Sprint(in.PID)
	}
	return control.Instance{}, fmt.Errorf("%d subtuns are running (pids %s): choose one with --pid", len(ins), strings.Join(pids, ", "))
}

// sendChange makes a change to a running subtun and prints what it did.
func sendChange(cmd *cobra.Command, pid int, endpoint string, ch control.Change) error {
	in, err := oneInstance(pid)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(cmd.Context(), changeTimeout)
	defer cancel()
	var res control.Result
	if err := control.NewClient(in.Path).Post(ctx, endpoint, ch, &res); err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return fmt.Errorf("no answer from subtun pid %d within %s; the change may still have been made: see subtun status", in.PID, changeTimeout)
		}
		return err
	}
	writeResult(cmd.OutOrStdout(), cmd.ErrOrStderr(), res)
	return nil
}

func writeResult(out, errOut io.Writer, res control.Result) {
	if res.Profile != "" {
		fmt.Fprintf(out, "profile %s: ", res.Profile)
	}
	fmt.Fprintln(out, res.Message)
	for _, w := range res.Warnings {
		fmt.Fprintf(errOut, "warning: %s\n", w)
	}
}

const changeNote = `
The running subtun needs control: full (--control full, or control: full in
the config file). Changes are planned and checked as at start, and last
until subtun stops. With several running subtuns, choose one with --pid.`

func newRouteCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "route",
		Short: "Add or remove routes of a running subtun",
		Long: `Add or remove routes (CIDRs or single IPs) of a profile in a running subtun:
the utun's routes, the kill switch and which tunnel carries an address
follow at once. With -x the CIDRs are excludes (most specific rule wins).
` + changeNote,
	}
	op := func(name, short, example string) *cobra.Command {
		var o changeOpts
		var exclude bool
		c := &cobra.Command{
			Use:     name + " CIDR...",
			Short:   short,
			Example: example,
			Args:    cobra.MinimumNArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				return sendChange(cmd, o.pid, "/v1/routes", control.Change{Op: name, Profile: o.profile, CIDRs: args, Exclude: exclude, DryRun: o.dryRun})
			},
		}
		c.Flags().BoolVarP(&exclude, "exclude", "x", false, "the CIDRs are excludes: never routed through the tunnel")
		o.register(c, true)
		return c
	}
	cmd.AddCommand(
		op("add", "Route CIDRs through a profile's tunnel", `  subtun route add 10.60.0.0/16
  subtun route add --profile dev 10.70.0.0/16 10.71.0.5
  subtun route add -x 10.60.9.0/24`),
		op("del", "Stop routing CIDRs a profile routes (configured or added)", `  subtun route del 10.60.0.0/16
  subtun route del -x 10.60.9.0/24`),
	)
	return cmd
}

func newDNSCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "dns",
		Short: "Add or remove DNS names of a running subtun",
		Long: `Add or remove the DNS domains and patterns a profile in a running subtun
resolves through its tunnel. A domain matches itself and every name below
it; "." matches all names except local ones; patterns are regular
expressions, as in dns.patterns. The run must capture DNS already (a
profile had DNS names when it started).
` + changeNote,
	}
	op := func(name, short, example string) *cobra.Command {
		var o changeOpts
		var patterns []string
		c := &cobra.Command{
			Use:     name + " [DOMAIN...] [--pattern REGEX]...",
			Short:   short,
			Example: example,
			RunE: func(cmd *cobra.Command, args []string) error {
				if len(args) == 0 && len(patterns) == 0 {
					return errors.New("give a domain or --pattern")
				}
				return sendChange(cmd, o.pid, "/v1/dns", control.Change{Op: name, Profile: o.profile, Domains: args, Patterns: patterns, DryRun: o.dryRun})
			},
		}
		c.Flags().StringArrayVar(&patterns, "pattern", nil, "a regular expression for names (repeatable)")
		o.register(c, true)
		return c
	}
	cmd.AddCommand(
		op("add", "Resolve names through a profile's tunnel", `  subtun dns add corp.example.com
  subtun dns add --profile dev svc.cluster.local --pattern '^db[0-9]+\.'`),
		op("del", "Stop resolving names through a profile's tunnel", `  subtun dns del corp.example.com`),
	)
	return cmd
}

func newProfileCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "profile",
		Short: "Stop, start or reconnect a profile of a running subtun",
		Long: `Stop, start or reconnect one profile of a running subtun; the others go on.
NAME can be left out when the run has one profile.

stop is Ctrl-C for that profile: its routes and DNS names are removed
(kill switch on lifts its blocks; lockdown keeps them, refusing its
traffic). start connects it again with the settings it had, changes made
while running included; with --reload it reads the profile from the config
file again instead, dropping those changes. start of a profile that isn't
part of the run adds it from the config file, checked against the others as
at start. reconnect drops its connection and connects again now.
` + changeNote,
	}
	op := func(name, short string, reload bool) *cobra.Command {
		var o changeOpts
		var doReload bool
		c := &cobra.Command{
			Use:   name + " [NAME]",
			Short: short,
			Args:  cobra.MaximumNArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				ch := control.Change{Op: name, Reload: doReload, DryRun: o.dryRun}
				if len(args) > 0 {
					ch.Profile = args[0]
				}
				return sendChange(cmd, o.pid, "/v1/profiles", ch)
			},
		}
		if reload {
			c.Flags().BoolVar(&doReload, "reload", false, "read the profile from the config file again (the one the run started with)")
		}
		o.register(c, false)
		return c
	}
	cmd.AddCommand(
		op("stop", "Stop a profile: as Ctrl-C, for that profile only", false),
		op("start", "Start a stopped or given-up profile again, or add one from the config file", true),
		op("reconnect", "Drop a profile's connection and connect again now", false),
	)
	return cmd
}

func newLogCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "log",
		Short: "Show or change a running subtun's log levels",
	}
	var o changeOpts
	level := &cobra.Command{
		Use:   "level [SPEC]",
		Short: "Show or change a running subtun's log levels",
		Long: `Show a running subtun's log levels, or change them while it runs. SPEC is as
--log-level: a level (debug, info, warn, error), levels per component
(dns=debug), or both ("info,dns=debug"); it replaces the levels the run has.
The terminal, subtun logs, the terminal UI and the log file all follow.
` + changeNote,
		Example: `  subtun log level                  # show them
  subtun log level info,dns=debug   # every DNS query, the rest at info
  subtun log level info             # back`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				in, err := oneInstance(o.pid)
				if err != nil {
					return err
				}
				ctx, cancel := context.WithTimeout(cmd.Context(), queryTimeout)
				defer cancel()
				var st control.Status
				if err := control.NewClient(in.Path).Get(ctx, "/v1/status", &st); err != nil {
					return err
				}
				fmt.Fprintln(cmd.OutOrStdout(), st.LogLevel)
				return nil
			}
			if _, err := logx.ParseSpec(args[0]); err != nil {
				return err
			}
			return sendChange(cmd, o.pid, "/v1/log", control.Change{Op: "set", Level: args[0], DryRun: o.dryRun})
		},
	}
	o.register(level, false)
	cmd.AddCommand(level)
	return cmd
}
