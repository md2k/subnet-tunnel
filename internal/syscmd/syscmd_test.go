//go:build unix

package syscmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFind(t *testing.T) {
	uid := os.Getuid()
	var a, b string
	for _, d := range []*string{&a, &b} {
		real, err := filepath.EvalSymlinks(t.TempDir()) // macOS: /var is /private/var
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(real, 0o755); err != nil {
			t.Fatal(err)
		}
		*d = real
	}
	write := func(dir, name string, mode os.FileMode) string {
		t.Helper()
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("#!/bin/sh\n"), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	ip := write(b, "ip", 0o755)
	write(a, "plain", 0o644) // not executable: skipped
	write(b, "plain", 0o755)
	if err := os.Symlink(ip, filepath.Join(a, "iplink")); err != nil {
		t.Fatal(err)
	}

	for _, c := range []struct {
		name, want, err string
	}{
		{"ip", ip, ""},                           // found in the second directory
		{"plain", filepath.Join(b, "plain"), ""}, // the first one isn't executable
		{"iplink", ip, ""},                       // a symlink: the real file
		{"nothing", "", "not found"},
		{"../ip", "", "a command name"},
	} {
		got, err := find(c.name, []string{a, b}, uid)
		if c.err != "" {
			if err == nil || !strings.Contains(err.Error(), c.err) {
				t.Errorf("%s: got %q, %v; want an error with %q", c.name, got, err, c.err)
			}
			continue
		}
		if err != nil || got != c.want {
			t.Errorf("%s: got %q, %v; want %q", c.name, got, err, c.want)
		}
	}

	// Found, but not safe to run as root: an error, not the next directory.
	if _, err := find("ip", []string{b}, uid+1); err == nil || !strings.Contains(err.Error(), "owned by") {
		t.Errorf("another owner: %v", err)
	}
	write(a, "loose", 0o775)
	if _, err := find("loose", []string{a, b}, uid); err == nil || !strings.Contains(err.Error(), "writable") {
		t.Errorf("group-writable file: %v", err)
	}
	if err := os.Chmod(b, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := find("ip", []string{b}, uid); err == nil || !strings.Contains(err.Error(), "writable") {
		t.Errorf("world-writable directory: %v", err)
	}
}
