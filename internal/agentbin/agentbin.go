// Package agentbin holds the Linux agent binaries that subtun uploads into
// targets. `make agents` builds them into dist/ and they are embedded at
// build time. A plain `go build` without them still works, but then the agent
// has to come from --agent-file.
package agentbin

import (
	"bytes"
	"crypto/sha256"
	"debug/elf"
	"embed"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"sort"
	"strings"
)

//go:embed all:dist
var dist embed.FS

const prefix = "subtun-agent-linux-"

// Binary is one agent executable for one architecture.
type Binary struct {
	Arch   string // GOARCH: amd64, arm64
	Data   []byte
	SHA256 string // hex
}

var machines = map[string]elf.Machine{
	"amd64": elf.EM_X86_64,
	"arm64": elf.EM_AARCH64,
}

// Embedded returns every agent built into this subtun, sorted by arch.
func Embedded() ([]Binary, error) {
	entries, err := fs.ReadDir(dist, "dist")
	if err != nil {
		return nil, err
	}
	var out []Binary
	for _, e := range entries {
		arch, ok := strings.CutPrefix(e.Name(), prefix)
		if !ok {
			continue
		}
		data, err := dist.ReadFile("dist/" + e.Name())
		if err != nil {
			return nil, err
		}
		b, err := newBinary(arch, data)
		if err != nil {
			return nil, fmt.Errorf("embedded agent %s: %w", e.Name(), err)
		}
		out = append(out, b)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Arch < out[j].Arch })
	return out, nil
}

// FromFile loads an agent from disk. The architecture is read from the ELF
// header, so the file has to be a Linux build of cmd/subtun-agent.
func FromFile(path string) (Binary, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Binary{}, err
	}
	f, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		return Binary{}, fmt.Errorf("%s: not a Linux ELF executable: %w", path, err)
	}
	for arch, m := range machines {
		if f.Machine == m {
			return newBinary(arch, data)
		}
	}
	return Binary{}, fmt.Errorf("%s: unsupported ELF machine %v", path, f.Machine)
}

func newBinary(arch string, data []byte) (Binary, error) {
	want, ok := machines[arch]
	if !ok {
		return Binary{}, fmt.Errorf("unsupported arch %q", arch)
	}
	f, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		return Binary{}, fmt.Errorf("not an ELF executable: %w", err)
	}
	if f.OSABI != elf.ELFOSABI_NONE && f.OSABI != elf.ELFOSABI_LINUX {
		return Binary{}, fmt.Errorf("not a Linux executable (OSABI %v)", f.OSABI)
	}
	if f.Machine != want {
		return Binary{}, fmt.Errorf("ELF machine is %v, want %v for %s", f.Machine, want, arch)
	}
	sum := sha256.Sum256(data)
	return Binary{Arch: arch, Data: data, SHA256: hex.EncodeToString(sum[:])}, nil
}

// ArchFromUname maps `uname -m` output to a GOARCH.
func ArchFromUname(m string) (string, bool) {
	switch strings.TrimSpace(m) {
	case "x86_64", "amd64":
		return "amd64", true
	case "aarch64", "arm64", "armv8l":
		return "arm64", true
	default:
		return "", false
	}
}
