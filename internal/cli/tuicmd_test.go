package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/md2k/subnet-tunnel/internal/config"
)

func TestTUICmd(t *testing.T) {
	if _, err := runCLI(t, "tui", "--layout", "grid"); err == nil || err.Error() != `--layout "grid": use table or detail` {
		t.Errorf("bad layout: %v", err)
	}
	if _, err := runCLI(t, "tui", "--units", "furlongs"); err == nil || err.Error() != `--units "furlongs": use bytes or bits` {
		t.Errorf("bad units: %v", err)
	}
	if _, err := runCLI(t, "tui"); err == nil || err.Error() != "no subtun running" {
		t.Errorf("nothing running: %v", err)
	}
}

// The settings come from the config file's tui key (a broken file only
// loses them, with a warning), else from what was remembered.
func TestTUISettings(t *testing.T) {
	dir := t.TempDir()
	profiles := "profiles:\n  p:\n    target: {docker: {container: c}}\n    socks: 127.0.0.1:1080\n"
	write := func(name, content string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	var warn bytes.Buffer
	if c := tuiFromConfig(write("good.yaml", "tui: {layout: detail, units: bits}\n"+profiles), &warn); c.Layout != "detail" || c.Units != "bits" || warn.Len() != 0 {
		t.Errorf("good: %+v %q", c, warn.String())
	}
	if c := tuiFromConfig(filepath.Join(dir, "none.yaml"), &warn); c != (config.TUI{}) || warn.Len() != 0 {
		t.Errorf("missing: %+v %q", c, warn.String())
	}
	if c := tuiFromConfig(write("bad.yaml", "tui: {layout: grid}\n"+profiles), &warn); c != (config.TUI{}) || !strings.Contains(warn.String(), "ignoring its tui settings") {
		t.Errorf("bad: %+v %q", c, warn.String())
	}
	if got := firstSet("", "detail", "table"); got != "detail" {
		t.Errorf("firstSet: %q", got)
	}

	t.Setenv("XDG_STATE_HOME", dir)
	if s := loadTUIState(); s != (tuiState{}) {
		t.Errorf("nothing remembered yet: %+v", s)
	}
	saveTUIState(func(s *tuiState) { s.Layout = "detail" })
	saveTUIState(func(s *tuiState) { s.Units = "bits" })
	if s := loadTUIState(); s.Layout != "detail" || s.Units != "bits" {
		t.Errorf("remembered: %+v", s)
	}
	if fi, err := os.Stat(filepath.Join(dir, "subtun", "tui.json")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("state file: %v %v", fi, err)
	}
}
