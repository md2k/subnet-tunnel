package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTUICmd(t *testing.T) {
	if _, err := runCLI(t, "tui", "--layout", "grid"); err == nil || err.Error() != `--layout "grid": use table or detail` {
		t.Errorf("bad layout: %v", err)
	}
	if _, err := runCLI(t, "tui"); err == nil || err.Error() != "no subtun running" {
		t.Errorf("nothing running: %v", err)
	}
}

// The layout comes from the config file's tui.layout (a broken file only
// loses it, with a warning), else from the one remembered.
func TestTUILayoutSettings(t *testing.T) {
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
	if l := layoutFromConfig(write("good.yaml", "tui: {layout: detail}\n"+profiles), &warn); l != "detail" || warn.Len() != 0 {
		t.Errorf("good: %q %q", l, warn.String())
	}
	if l := layoutFromConfig(filepath.Join(dir, "none.yaml"), &warn); l != "" || warn.Len() != 0 {
		t.Errorf("missing: %q %q", l, warn.String())
	}
	if l := layoutFromConfig(write("bad.yaml", "tui: {layout: grid}\n"+profiles), &warn); l != "" || !strings.Contains(warn.String(), "ignoring its tui settings") {
		t.Errorf("bad: %q %q", l, warn.String())
	}

	t.Setenv("XDG_STATE_HOME", dir)
	if l := lastLayout(); l != "" {
		t.Errorf("nothing remembered yet: %q", l)
	}
	rememberLayout("detail")
	if l := lastLayout(); l != "detail" {
		t.Errorf("remembered: %q", l)
	}
	if fi, err := os.Stat(filepath.Join(dir, "subtun", "tui.json")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("state file: %v %v", fi, err)
	}
}
