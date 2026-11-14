//go:build unix

package cli

import (
	"bufio"
	"log/slog"
	"os"
	"runtime/debug"

	"golang.org/x/sys/unix"
)

// captureFd2 points fd 2 at a pipe whose lines go to log, and returns the
// terminal's standard error (a copy of the old fd 2) and restore. A crash
// meanwhile still reaches the terminal.
func captureFd2(log *slog.Logger) (*os.File, func(), error) {
	saved, err := unix.Dup(2)
	if err != nil {
		return nil, nil, err
	}
	unix.CloseOnExec(saved)
	r, w, err := os.Pipe()
	if err != nil {
		_ = unix.Close(saved)
		return nil, nil, err
	}
	if err := unix.Dup2(int(w.Fd()), 2); err != nil { // fd 2 itself is inherited by children
		_ = unix.Close(saved)
		_ = r.Close()
		_ = w.Close()
		return nil, nil, err
	}
	_ = w.Close()
	term := os.NewFile(uintptr(saved), "/dev/stderr")
	_ = debug.SetCrashOutput(term, debug.CrashOptions{})
	go func() {
		sc := bufio.NewScanner(r)
		for sc.Scan() {
			log.Info("stderr: " + sc.Text())
		}
		_ = r.Close()
	}()
	return term, func() {
		_ = debug.SetCrashOutput(nil, debug.CrashOptions{})
		_ = unix.Dup2(saved, 2) // the reader ends once the pipe's last writer (a child, maybe) has gone
		_ = term.Close()
	}, nil
}
