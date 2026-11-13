package xdg

import (
	"path/filepath"
	"runtime"
	"testing"
)

func TestDirs(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("nix layout")
	}
	t.Setenv("HOME", "/home/u")
	t.Setenv("XDG_STATE_HOME", "")
	t.Setenv("XDG_RUNTIME_DIR", "")
	check := func(what string, f func() (string, error), want string) {
		t.Helper()
		got, err := f()
		if err != nil || got != want {
			t.Errorf("%s: %q %v, want %q", what, got, err, want)
		}
	}
	check("state", StateDir, "/home/u/.local/state/subtun")
	check("run", RunDir, "/home/u/.local/state/subtun/run")
	check("logs", LogDir, "/home/u/.local/state/subtun/logs")

	t.Setenv("XDG_STATE_HOME", "/s")
	t.Setenv("XDG_RUNTIME_DIR", "/run/user/501")
	check("state", StateDir, "/s/subtun")
	check("run", RunDir, "/run/user/501/subtun")
	check("logs", LogDir, filepath.Join("/s", "subtun", "logs"))

	// Relative values are ignored, as the spec says.
	t.Setenv("XDG_STATE_HOME", "rel")
	t.Setenv("XDG_RUNTIME_DIR", "rel")
	check("state", StateDir, "/home/u/.local/state/subtun")
	check("run", RunDir, "/home/u/.local/state/subtun/run")
}
