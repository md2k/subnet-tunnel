//go:build unix

// Package syscmd finds the system commands subtun runs (ip, nft, sudo, ...).
// Distributions put them in different places, so it looks through fixed
// system directories, never $PATH: the root helper runs them as root. A file
// is used only if root owns it and its directory and only root can write
// either.
package syscmd

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// Dirs are the directories searched, in order.
var Dirs = []string{"/usr/sbin", "/sbin", "/usr/bin", "/bin", "/usr/local/sbin", "/usr/local/bin"}

// Find returns the path of the system command name (symlinks resolved).
func Find(name string) (string, error) { return find(name, Dirs, 0) }

func find(name string, dirs []string, owner int) (string, error) {
	if name == "" || strings.ContainsRune(name, '/') || name == "." || name == ".." {
		return "", fmt.Errorf("%q is not a command name", name)
	}
	for _, d := range dirs {
		real, err := filepath.EvalSymlinks(filepath.Join(d, name))
		if err != nil {
			continue
		}
		fi, err := os.Stat(real)
		if err != nil || !fi.Mode().IsRegular() || fi.Mode()&0o111 == 0 {
			continue
		}
		// Found: either it's safe or we stop here (a writable binary in a
		// system directory is a problem to report, not to step around).
		for _, p := range []string{real, filepath.Dir(real)} {
			if err := trusted(p, owner); err != nil {
				return "", fmt.Errorf("not running %s: %w", real, err)
			}
		}
		return real, nil
	}
	return "", fmt.Errorf("%s not found in %s", name, strings.Join(dirs, ", "))
}

func trusted(path string, owner int) error {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("no owner information")
	}
	if int(st.Uid) != owner {
		return fmt.Errorf("%s is owned by uid %d, want %d", path, st.Uid, owner)
	}
	if fi.Mode().Perm()&(fs.ModePerm&0o022) != 0 {
		return fmt.Errorf("%s is writable by group or others", path)
	}
	return nil
}
