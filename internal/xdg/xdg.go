// Package xdg names subtun's directories the nix way (the XDG base
// directory spec), on macOS too: subtun is a command-line tool, not an app
// bundle.
//
//	state  $XDG_STATE_HOME/subtun, else ~/.local/state/subtun (logs)
//	run    $XDG_RUNTIME_DIR/subtun when set (Linux), else <state>/run
//	       (the control sockets, the root helper's socket)
//
// On Windows both live under %LOCALAPPDATA%\subtun. The callers create the
// directories with the permissions they need.
package xdg

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
)

// StateDir is subtun's state directory.
func StateDir() (string, error) {
	if runtime.GOOS == "windows" {
		if d := os.Getenv("LOCALAPPDATA"); d != "" {
			return filepath.Join(d, "subtun"), nil
		}
		return "", errors.New("%LOCALAPPDATA% is not set")
	}
	if d := os.Getenv("XDG_STATE_HOME"); filepath.IsAbs(d) {
		return filepath.Join(d, "subtun"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".local", "state", "subtun"), nil
}

// RunDir is where subtun's sockets go: private to the user.
func RunDir() (string, error) {
	if runtime.GOOS != "windows" {
		if d := os.Getenv("XDG_RUNTIME_DIR"); filepath.IsAbs(d) {
			return filepath.Join(d, "subtun"), nil
		}
	}
	state, err := StateDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(state, "run"), nil
}

// LogDir is where subtun's log files go.
func LogDir() (string, error) {
	state, err := StateDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(state, "logs"), nil
}
