package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/md2k/subnet-tunnel/internal/config"
	"github.com/md2k/subnet-tunnel/internal/tui"
	"github.com/md2k/subnet-tunnel/internal/xdg"
)

func newTUICmd(g *globalOpts) *cobra.Command {
	var pid int
	var layout string
	cmd := &cobra.Command{
		Use:   "tui",
		Short: "Watch and change a running subtun in a terminal UI",
		Long: `Attach a terminal UI to a running subtun, through its control socket: its
profiles with their state, routes, DNS names, kill switch and traffic, and
its log lines. With control: full it also changes the run: stop, start or
reconnect a profile, add or delete routes and DNS names, add a profile from
the config file. Each change shows its dry run first, and lasts until
subtun stops. q quits the TUI; subtun goes on. With several running
subtuns, choose one with --pid.

The dashboard has two layouts, switched with v: table (the profiles above
the logs) and detail (a list, the selected profile's detail, the logs). It
starts with --layout, else the config file's tui.layout, else the one used
last.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := config.ValidLayout(layout); err != nil {
				return fmt.Errorf("--%w", err)
			}
			in, err := oneInstance(pid)
			if err != nil {
				return err
			}
			if layout == "" {
				layout = layoutFromConfig(configPath(g), cmd.ErrOrStderr())
			}
			if layout == "" {
				layout = lastLayout()
			}
			return tui.Run(cmd.Context(), tui.Options{Source: tui.Socket(in.Path), Layout: layout, OnLayout: rememberLayout})
		},
	}
	cmd.Flags().IntVar(&pid, "pid", 0, "the subtun with this process id (needed when several run)")
	cmd.Flags().StringVar(&layout, "layout", "", "the dashboard's layout: table or detail (default: tui.layout, else the one used last)")
	return cmd
}

// layoutFromConfig is the config file's tui.layout; a file that can't be
// read only loses the setting, with a warning.
func layoutFromConfig(path string, warn io.Writer) string {
	f, err := config.Load(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return ""
	case err != nil:
		fmt.Fprintf(warn, "warning: %v; ignoring its tui settings\n", err)
		return ""
	}
	return f.TUI.Layout
}

// tuiState is what the TUI remembers between runs, in the state directory.
type tuiState struct {
	Layout string `json:"layout,omitempty"`
}

func tuiStatePath() (string, error) {
	d, err := xdg.StateDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "tui.json"), nil
}

// lastLayout is the layout used last; "": none remembered.
func lastLayout() string {
	path, err := tuiStatePath()
	if err != nil {
		return ""
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	var s tuiState
	if json.Unmarshal(b, &s) != nil || config.ValidLayout(s.Layout) != nil {
		return ""
	}
	return s.Layout
}

// rememberLayout keeps the layout for the next start (best effort).
func rememberLayout(l string) {
	path, err := tuiStatePath()
	if err != nil {
		return
	}
	if os.MkdirAll(filepath.Dir(path), 0o700) != nil {
		return
	}
	b, _ := json.Marshal(tuiState{Layout: l})
	_ = os.WriteFile(path, b, 0o600)
}
