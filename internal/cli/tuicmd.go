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
	var layout, units, mouse string
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
the logs) and detail (a list, the selected profile's detail, the logs).
Rates show in bytes or bits a second, switched with u. Both start as
--layout / --units say, else the config file's tui.layout / tui.units,
else as used last.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := config.ValidLayout(layout); err != nil {
				return fmt.Errorf("--%w", err)
			}
			if err := config.ValidUnits(units); err != nil {
				return fmt.Errorf("--%w", err)
			}
			if mouse != "" && mouse != "on" && mouse != "off" {
				return fmt.Errorf("--mouse %q: use on or off", mouse)
			}
			in, err := oneInstance(pid)
			if err != nil {
				return err
			}
			fromFile := tuiFromConfig(configPath(g), cmd.ErrOrStderr())
			last := loadTUIState()
			return tui.Run(cmd.Context(), tui.Options{
				Source: tui.Socket(in.Path),
				Layout: firstSet(layout, fromFile.Layout, last.Layout), OnLayout: func(l string) { saveTUIState(func(s *tuiState) { s.Layout = l }) },
				Units: firstSet(units, fromFile.Units, last.Units), OnUnits: func(u string) { saveTUIState(func(s *tuiState) { s.Units = u }) },
				Mouse:       firstSet(mouse, string(fromFile.Mouse), last.Mouse) != "off",
				HiddenPanes: last.Hidden, ConfigTab: last.Tab,
				OnView: func(hidden []string, tab string) {
					saveTUIState(func(s *tuiState) { s.Hidden, s.Tab = hidden, tab })
				},
				OnMouse: func(on bool) {
					saveTUIState(func(s *tuiState) { s.Mouse = map[bool]string{true: "on", false: "off"}[on] })
				},
			})
		},
	}
	cmd.Flags().IntVar(&pid, "pid", 0, "the subtun with this process id (needed when several run)")
	cmd.Flags().StringVar(&layout, "layout", "", "the dashboard's layout: table or detail (default: tui.layout, else the one used last)")
	cmd.Flags().StringVar(&units, "units", "", "rates in bytes or bits a second: bytes or bits (default: tui.units, else the ones used last)")
	cmd.Flags().StringVar(&mouse, "mouse", "", "mouse on or off (default: tui.mouse, else as used last, else on)")
	return cmd
}

func firstSet(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// tuiFromConfig is the config file's tui settings; a file that can't be
// read only loses them, with a warning.
func tuiFromConfig(path string, warn io.Writer) config.TUI {
	f, err := config.Load(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return config.TUI{}
	case err != nil:
		fmt.Fprintf(warn, "warning: %v; ignoring its tui settings\n", err)
		return config.TUI{}
	}
	return f.TUI
}

// tuiState is what the TUI remembers between runs, in the state directory.
type tuiState struct {
	Layout string `json:"layout,omitempty"`
	Units  string `json:"units,omitempty"`
	Mouse  string `json:"mouse,omitempty"`
	// The profile screen's view: the panes hidden, the config tab.
	Hidden []string `json:"hiddenPanes,omitempty"`
	Tab    string   `json:"configTab,omitempty"`
}

func tuiStatePath() (string, error) {
	d, err := xdg.StateDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "tui.json"), nil
}

// loadTUIState is what was remembered; what isn't valid is dropped.
func loadTUIState() tuiState {
	var s tuiState
	path, err := tuiStatePath()
	if err != nil {
		return s
	}
	b, err := os.ReadFile(path)
	if err != nil || json.Unmarshal(b, &s) != nil {
		return tuiState{}
	}
	if config.ValidLayout(s.Layout) != nil {
		s.Layout = ""
	}
	if config.ValidUnits(s.Units) != nil {
		s.Units = ""
	}
	if s.Mouse != "on" && s.Mouse != "off" {
		s.Mouse = ""
	}
	return s
}

// saveTUIState changes what is remembered for the next start (best effort).
func saveTUIState(change func(*tuiState)) {
	path, err := tuiStatePath()
	if err != nil {
		return
	}
	if os.MkdirAll(filepath.Dir(path), 0o700) != nil {
		return
	}
	s := loadTUIState()
	change(&s)
	b, _ := json.Marshal(s)
	_ = os.WriteFile(path, b, 0o600)
}
