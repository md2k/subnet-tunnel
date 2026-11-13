package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/md2k/subnet-tunnel/internal/control"
	"github.com/md2k/subnet-tunnel/internal/logring"
)

// queryTimeout bounds one question to a running subtun.
const queryTimeout = 3 * time.Second

// instances finds the running subtuns, or the one with pid (0: all).
func instances(pid int) ([]control.Instance, error) {
	dir, err := control.RunDir()
	if err != nil {
		return nil, err
	}
	all, err := control.Running(dir)
	if err != nil {
		return nil, err
	}
	if pid == 0 {
		return all, nil
	}
	for _, in := range all {
		if in.PID == pid {
			return []control.Instance{in}, nil
		}
	}
	return nil, fmt.Errorf("no running subtun with pid %d (or its control is off)", pid)
}

// instanceStatus is one subtun's status, with its connections if asked.
type instanceStatus struct {
	control.Status
	Connections []control.TunnelConns `json:"connections,omitempty"`
}

func newStatusCmd() *cobra.Command {
	var asJSON, watch, conns bool
	var pid int
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show running subtuns: tunnels, routes, DNS, counters",
		Long: `Show what every running subtun is doing, through its control socket: each
tunnel's state, routes and DNS names, connections and traffic, and the shared
DNS capture and kill switch. Runs with control: off don't show up.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			out := cmd.OutOrStdout()
			collect := func() ([]instanceStatus, error) {
				ins, err := instances(pid)
				if err != nil {
					return nil, err
				}
				var all []instanceStatus
				for _, in := range ins {
					// A suspended or stuck subtun mustn't hold up the others.
					ctx, cancel := context.WithTimeout(cmd.Context(), queryTimeout)
					c := control.NewClient(in.Path)
					var is instanceStatus
					err := c.Get(ctx, "/v1/status", &is.Status)
					if err == nil && conns {
						_ = c.Get(ctx, "/v1/connections", &is.Connections)
					}
					cancel()
					if err != nil {
						fmt.Fprintf(cmd.ErrOrStderr(), "subtun pid %d doesn't answer: %v\n", in.PID, err)
						continue
					}
					all = append(all, is)
				}
				return all, nil
			}
			render := func() error {
				all, err := collect()
				if err != nil {
					return err
				}
				if asJSON {
					enc := json.NewEncoder(out)
					enc.SetIndent("", "  ")
					return enc.Encode(all)
				}
				if len(all) == 0 {
					fmt.Fprintln(out, "no subtun running")
					return nil
				}
				for _, is := range all {
					writeStatus(out, is, time.Now())
				}
				return nil
			}
			if !watch {
				return render()
			}
			t := time.NewTicker(time.Second)
			defer t.Stop()
			for {
				if !asJSON {
					fmt.Fprint(out, "\x1b[H\x1b[2J") // home, clear
				}
				if err := render(); err != nil {
					return err
				}
				select {
				case <-cmd.Context().Done():
					return nil
				case <-t.C:
				}
			}
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print JSON")
	cmd.Flags().BoolVarP(&watch, "watch", "w", false, "refresh every second until Ctrl-C")
	cmd.Flags().BoolVar(&conns, "connections", false, "also list the open connections")
	cmd.Flags().IntVar(&pid, "pid", 0, "only the subtun with this process id")
	return cmd
}

func newLogsCmd() *cobra.Command {
	var follow bool
	var pid int
	cmd := &cobra.Command{
		Use:   "logs",
		Short: "Show a running subtun's recent log lines",
		Long: `Show the recent log lines a running subtun keeps in memory (never on disk),
then, with -f, follow new ones until Ctrl-C.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ins, err := instances(pid)
			if err != nil {
				return err
			}
			switch len(ins) {
			case 0:
				return errors.New("no subtun running")
			case 1:
			default:
				pids := make([]string, len(ins))
				for i, in := range ins {
					pids[i] = fmt.Sprint(in.PID)
				}
				return fmt.Errorf("%d subtuns are running (pids %s): choose one with --pid", len(ins), strings.Join(pids, ", "))
			}
			endpoint := "/v1/logs"
			if follow {
				endpoint += "?follow=1"
			}
			out := cmd.OutOrStdout()
			ctx := cmd.Context()
			if !follow {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, queryTimeout)
				defer cancel()
			}
			return control.NewClient(ins[0].Path).Stream(ctx, endpoint, func(b []byte) error {
				var l logring.Line
				if err := json.Unmarshal(b, &l); err != nil {
					return err
				}
				_, err := fmt.Fprintln(out, l.Text)
				return err
			})
		},
	}
	cmd.Flags().BoolVarP(&follow, "follow", "f", false, "keep printing new lines until Ctrl-C")
	cmd.Flags().IntVar(&pid, "pid", 0, "the subtun with this process id (needed when several run)")
	return cmd
}

// writeStatus prints one subtun's status for people.
func writeStatus(w io.Writer, is instanceStatus, now time.Time) {
	st := is.Status
	fmt.Fprintf(w, "subtun pid %d, %s, up %s", st.PID, st.Version, ago(now, st.Started))
	capturing := st.Utun != ""
	if capturing {
		fmt.Fprintf(w, "; %s (%s), %s root helper", st.Utun, st.TunAddr, st.Helper)
	}
	fmt.Fprintln(w)
	routed := slices.ContainsFunc(st.Tunnels, func(t control.Tunnel) bool { return len(t.Routes) > 0 })
	if routed && !capturing {
		fmt.Fprintln(w, "  capture not started yet (connecting, or sudo is asking)")
	}
	width := 0
	for _, t := range st.Tunnels {
		width = max(width, len(tunnelLabel(t)))
	}
	pad := strings.Repeat(" ", width+4)
	for _, t := range st.Tunnels {
		fmt.Fprintf(w, "  %-*s  %s\n", width, tunnelLabel(t), stateText(t, now))
		var what []string
		if len(t.Routes) > 0 {
			on := "not in use"
			if t.RoutesOn {
				on = "on the utun"
			}
			what = append(what, fmt.Sprintf("routes %s (%s)", summary(t.Routes, 4), on))
		}
		if len(t.Domains) > 0 || t.Patterns > 0 {
			names := t.Domains
			if t.Patterns > 0 {
				names = append(append([]string{}, names...), fmt.Sprintf("%d pattern(s)", t.Patterns))
			}
			what = append(what, "DNS "+strings.Join(names, ", "))
		}
		if t.KillSwitch != "" {
			what = append(what, "kill switch "+t.KillSwitch)
		}
		if t.SOCKS != "" {
			what = append(what, "SOCKS "+t.SOCKS)
		}
		if len(what) > 0 {
			fmt.Fprintf(w, "%s%s\n", pad, strings.Join(what, "; "))
		}
		c := t.Counts
		fmt.Fprintf(w, "%sconnections %d open, %d total, %d failed", pad, c.Open, c.Total, c.Failed)
		if c.ViaSOCKS > 0 {
			fmt.Fprintf(w, " (%d through SOCKS)", c.ViaSOCKS)
		}
		if c.Refused > 0 {
			fmt.Fprintf(w, "; loop guard refused %d", c.Refused)
		}
		fmt.Fprintf(w, "\n%sup %s (%s/s), down %s (%s/s)", pad, bytesText(c.Up), bytesText(c.UpRate), bytesText(c.Down), bytesText(c.DownRate))
		if d := t.DNSCounts; d.Answered+d.Failed > 0 {
			fmt.Fprintf(w, "; DNS %d answered, %d failed", d.Answered, d.Failed)
		}
		fmt.Fprintln(w)
		if t.LastError != "" && t.State != "up" {
			fmt.Fprintf(w, "%slast error: %s\n", pad, t.LastError)
		}
	}
	if d := st.DNS; d != nil && (capturing || d.Development) {
		what, follow := "DNS capture: queries to ", ""
		if d.Development {
			what = "DNS (development listener, nothing captured): other names to "
		}
		if d.Follow {
			follow = ", following the system's"
		}
		if d.Development {
			fmt.Fprintf(w, "  %s%s (%d answered, %d failed)\n", what, strings.Join(d.Fallback, ", "), d.Counts.Answered, d.Counts.Failed)
		} else {
			fmt.Fprintf(w, "  %s%s%s; other names: %s (%d answered, %d failed)\n",
				what, strings.Join(d.Servers, ", "), follow, strings.Join(d.Fallback, ", "), d.Counts.Answered, d.Counts.Failed)
		}
		if len(d.Local) > 0 {
			fmt.Fprintf(w, "    stay local: %s\n", summary(d.Local, 6))
		}
		if len(d.Own) > 0 {
			fmt.Fprintf(w, "    never through a tunnel: %s\n", strings.Join(d.Own, ", "))
		}
	}
	if k := st.KillSwitch; k != nil && capturing {
		fmt.Fprintf(w, "  kill switch %s: %d guarded prefixes (%d stay after Ctrl-C); DNS while holding: %s\n", k.Mode, k.Guarded, k.Lockdown, k.DNS)
	}
	if st.BlockIPv6 {
		fmt.Fprintln(w, "  outgoing IPv6 blocked")
	}
	for _, tc := range is.Connections {
		if len(tc.Conns) == 0 {
			continue
		}
		label := tc.Name
		if label == "" {
			label = "the tunnel"
		}
		fmt.Fprintf(w, "  open connections through %s:\n", label)
		for _, c := range tc.Conns {
			fmt.Fprintf(w, "    %-28s %-5s %8s  up %s, down %s\n", c.Dst, c.Via, ago(now, c.Opened), bytesText(c.Up), bytesText(c.Down))
		}
	}
}

func tunnelLabel(t control.Tunnel) string {
	if t.Name == "" {
		return "tunnel"
	}
	return t.Name
}

func stateText(t control.Tunnel, now time.Time) string {
	s := fmt.Sprintf("%s for %s", t.State, ago(now, t.Since))
	if t.Attempt > 0 {
		s += fmt.Sprintf(" (attempt %d of %d", t.Attempt, t.Attempts)
		if d := t.NextTry.Sub(now); d > 0 {
			s += fmt.Sprintf(", next in %s", d.Round(time.Second))
		}
		s += ")"
	}
	if t.Target != "" {
		s += "; " + t.Target
	}
	return s
}

func ago(now, t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return now.Sub(t).Round(time.Second).String()
}

// summary lists up to n items, then how many more.
func summary(items []string, n int) string {
	if len(items) <= n {
		return strings.Join(items, ", ")
	}
	return fmt.Sprintf("%s and %d more", strings.Join(items[:n], ", "), len(items)-n)
}

// bytesText is a byte count for people (decimal units).
func bytesText(n uint64) string {
	const unit = 1000
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	v, suffix := float64(n), []string{"kB", "MB", "GB", "TB"}
	i := -1
	for v >= unit && i < len(suffix)-1 {
		v /= unit
		i++
	}
	return fmt.Sprintf("%.1f %s", v, suffix[i])
}
