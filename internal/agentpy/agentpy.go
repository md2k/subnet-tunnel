// Package agentpy is the Python edition of the agent, for targets that have
// python3 but can't take the Go binary (no shell, no writable or executable
// directory). Like sshuttle's server it is sent as source over the exec
// session and run from memory with `python3 -c`, so nothing is written to the
// target. It speaks the same protocol as cmd/subtun-agent.
package agentpy

import (
	_ "embed"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

//go:embed agent.py
var source string

// Minimum Python version the agent supports.
const (
	MinMajor = 3
	MinMinor = 6
)

var safeVersion = regexp.MustCompile(`^[A-Za-z0-9._+-]+$`)

// Source returns the agent source with the subtun version filled in.
func Source(version string) []byte {
	if !safeVersion.MatchString(version) {
		version = "dev"
	}
	return []byte(strings.Replace(source, "__SUBTUN_VERSION__", version, 1))
}

// Command returns the argv that runs src: python reads exactly len(src)
// bytes of source from stdin, runs it, and the rest of stdin becomes the
// carrier. The source sees itself as _src, for the checksum in its hello.
func Command(python string, src []byte, args []string) []string {
	loader := fmt.Sprintf("import sys;_src=sys.stdin.buffer.read(%d);"+
		"exec(compile(_src,'subtun-agent.py','exec'),{'__name__':'__main__','_src':_src})", len(src))
	return append([]string{python, "-c", loader}, args...)
}

// VersionProbe is a python snippet that prints "MAJOR.MINOR".
const VersionProbe = `import sys;print("%d.%d"%sys.version_info[:2])`

// Supported reports whether a "MAJOR.MINOR" version can run the agent.
func Supported(v string) bool {
	major, minor, ok := strings.Cut(strings.TrimSpace(v), ".")
	if !ok {
		return false
	}
	ma, err1 := strconv.Atoi(major)
	mi, err2 := strconv.Atoi(minor)
	if err1 != nil || err2 != nil {
		return false
	}
	return ma > MinMajor || (ma == MinMajor && mi >= MinMinor)
}
