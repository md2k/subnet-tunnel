//go:build linux

package linux

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/md2k/subnet-tunnel/internal/syscmd"
)

// run runs a system command (found by syscmd, fixed arguments, no shell).
func run(name string, args ...string) error {
	_, err := output(name, args...)
	return err
}

// output runs a system command and returns its standard output.
func output(name string, args ...string) ([]byte, error) {
	path, err := syscmd.Find(name)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return out, fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}
