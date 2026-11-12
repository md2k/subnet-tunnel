//go:build !windows

package privhelper

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/md2k/subnet-tunnel/internal/platform"
)

// state records who holds subtun's firewall rules, so that rules left
// behind (kill switch, or a helper that was killed) can be told apart from
// a running session's, taken over by the next session, or cleaned up, and
// pf's enable reference released.
type state struct {
	Owner   int             `json:"owner"`             // pid of the helper that holds the rules
	Token   string          `json:"token,omitempty"`   // pf enable reference
	Persist *platform.Rules `json:"persist,omitempty"` // what stays if the tunnel goes away
}

type stateStore interface {
	load() (*state, error) // nil, nil when there is none
	save(*state) error
	remove() error
}

// fileState keeps the state in a root-only directory. /var/run is cleared
// at boot on macOS, like pf's rules; a stale file is harmless either way
// (an empty anchor means nothing is left behind).
type fileState struct{ dir string }

func (f fileState) path() string { return filepath.Join(f.dir, "state.json") }

func (f fileState) load() (*state, error) {
	b, err := os.ReadFile(f.path())
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var st state
	if err := json.Unmarshal(b, &st); err != nil {
		return nil, fmt.Errorf("%s: %w", f.path(), err)
	}
	return &st, nil
}

func (f fileState) save(st *state) error {
	if err := os.MkdirAll(f.dir, 0o700); err != nil {
		return err
	}
	if err := checkPrivate(f.dir, 0); err != nil {
		return err
	}
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	tmp := f.path() + ".new"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, f.path())
}

func (f fileState) remove() error {
	err := os.Remove(f.path())
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

// processAlive reports whether pid is a running subtun process (the helper
// that recorded it). A recycled pid running something else counts as gone.
func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	if err := syscall.Kill(pid, 0); err != nil && !errors.Is(err, syscall.EPERM) {
		return false
	}
	out, err := exec.Command("/bin/ps", "-p", strconv.Itoa(pid), "-o", "comm=").Output()
	if err != nil {
		return false
	}
	return strings.HasPrefix(filepath.Base(strings.TrimSpace(string(out))), "subtun")
}

// checkPrivate verifies that path is owned by uid and not accessible to
// group or others.
func checkPrivate(path string, uid int) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%s: can't read owner", path)
	}
	if int(st.Uid) != uid {
		return fmt.Errorf("%s is owned by uid %d, not %d", path, st.Uid, uid)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s is accessible to other users (%v)", path, fi.Mode().Perm())
	}
	return nil
}
