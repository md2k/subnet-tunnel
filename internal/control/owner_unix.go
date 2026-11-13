//go:build !windows

package control

import (
	"fmt"
	"os"
	"syscall"
)

// ownedByMe refuses a directory that isn't this user's alone.
func ownedByMe(dir string) error {
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || !fi.IsDir() || int(st.Uid) != os.Getuid() || fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s must be a directory owned by you with mode 0700", dir)
	}
	return nil
}
