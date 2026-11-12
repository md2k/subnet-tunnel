// Package config reads subtun's YAML config file: named profiles, each with
// a target and the same settings the command line accepts. Command-line
// flags override a profile's values; routes and excludes given on the
// command line are added to the profile's.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"sigs.k8s.io/yaml"

	"github.com/md2k/subnet-tunnel/internal/dns"
	"github.com/md2k/subnet-tunnel/internal/routes"
)

// File is the whole config file.
type File struct {
	Profiles map[string]Profile `json:"profiles"`
}

// Profile is one named setup, run with `subtun up NAME`.
type Profile struct {
	Target   Target   `json:"target"`
	Routes   []string `json:"routes,omitempty"`
	Exclude  []string `json:"exclude,omitempty"`
	Socks    string   `json:"socks,omitempty"`
	Agent    string   `json:"agent,omitempty"`
	AgentDir string   `json:"agentDir,omitempty"`
	Tun      Tun      `json:"tun,omitempty"`
	DNS      DNS      `json:"dns,omitempty"`
}

// Target is where the agent runs: exactly one of K8s or Docker.
type Target struct {
	K8s    *K8sTarget    `json:"k8s,omitempty"`
	Docker *DockerTarget `json:"docker,omitempty"`
}

// K8sTarget selects a pod.
type K8sTarget struct {
	Kubeconfig string `json:"kubeconfig,omitempty"`
	Context    string `json:"context,omitempty"`
	Namespace  string `json:"namespace,omitempty"`
	Pod        string `json:"pod"`
	Container  string `json:"container,omitempty"`
}

// DockerTarget selects a container.
type DockerTarget struct {
	Host      string `json:"host,omitempty"`
	Context   string `json:"context,omitempty"`
	Container string `json:"container"`
}

// Tun configures subtun's own interface.
type Tun struct {
	Address string `json:"address,omitempty"` // default 198.18.249.1
	MTU     int    `json:"mtu,omitempty"`     // default 9000
}

// DNS configures DNS capture: queries the system sends to its DNS servers
// are answered by subtun, through the tunnel for matching names.
type DNS struct {
	Capture  string     `json:"capture,omitempty"`  // firewall (default) or off
	Servers  ServerList `json:"servers,omitempty"`  // auto (default) or IPv4 addresses
	Domains  []string   `json:"domains,omitempty"`  // suffixes resolved through the tunnel; "." = all
	Patterns []string   `json:"patterns,omitempty"` // regular expressions, also through the tunnel
	Fallback string     `json:"fallback,omitempty"` // system (default) or ip[:port] for everything else
}

// ServerList is "auto" or a list of addresses; in YAML either
// `servers: auto` or `servers: [192.168.1.1]`.
type ServerList []string

// UnmarshalJSON accepts a string or a list of strings.
func (l *ServerList) UnmarshalJSON(b []byte) error {
	var one string
	if err := json.Unmarshal(b, &one); err == nil {
		*l = ServerList{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return errors.New("dns.servers: use auto or a list of addresses")
	}
	*l = many
	return nil
}

var profileName = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)

// DefaultPath is $SUBTUN_CONFIG, else $XDG_CONFIG_HOME/subtun/config.yaml,
// else ~/.config/subtun/config.yaml.
func DefaultPath() string {
	if p := os.Getenv("SUBTUN_CONFIG"); p != "" {
		return p
	}
	dir := os.Getenv("XDG_CONFIG_HOME")
	if dir == "" {
		home, _ := os.UserHomeDir()
		dir = filepath.Join(home, ".config")
	}
	return filepath.Join(dir, "subtun", "config.yaml")
}

// Load reads and validates a config file. Unknown keys are errors, so a
// typo doesn't silently drop a setting.
func Load(path string) (*File, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(data, path)
}

// Parse validates config bytes; name is used in error messages.
func Parse(data []byte, name string) (*File, error) {
	var f File
	if err := yaml.UnmarshalStrict(data, &f); err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	if len(f.Profiles) == 0 {
		return nil, fmt.Errorf("%s: no profiles", name)
	}
	for n, p := range f.Profiles {
		if err := p.validate(n); err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
	}
	return &f, nil
}

// Profile returns the named profile, or an error listing the known ones.
func (f *File) Profile(name string) (Profile, error) {
	p, ok := f.Profiles[name]
	if !ok {
		return Profile{}, fmt.Errorf("no profile %q (have: %s)", name, strings.Join(f.Names(), ", "))
	}
	return p, nil
}

// Names lists the profiles, sorted.
func (f *File) Names() []string {
	names := make([]string, 0, len(f.Profiles))
	for n := range f.Profiles {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

func (p Profile) validate(name string) error {
	if !profileName.MatchString(name) {
		return fmt.Errorf("profile %q: names are lowercase letters, digits, '.', '_' and '-'", name)
	}
	fail := func(err error) error { return fmt.Errorf("profile %s: %w", name, err) }
	switch {
	case p.Target.K8s != nil && p.Target.Docker != nil:
		return fail(errors.New("target: set either k8s or docker, not both"))
	case p.Target.K8s != nil:
		if p.Target.K8s.Pod == "" {
			return fail(errors.New("target.k8s.pod is required"))
		}
	case p.Target.Docker != nil:
		if p.Target.Docker.Container == "" {
			return fail(errors.New("target.docker.container is required"))
		}
	default:
		return fail(errors.New("target: set k8s or docker"))
	}
	if _, err := routes.ParseAll(p.Routes, routes.ParseRoute); err != nil {
		return fail(fmt.Errorf("routes: %w", err))
	}
	if _, err := routes.ParseAll(p.Exclude, routes.ParsePrefix); err != nil {
		return fail(fmt.Errorf("exclude: %w", err))
	}
	switch p.Agent {
	case "", "auto", "binary", "python":
	default:
		return fail(fmt.Errorf("agent %q: use auto, binary or python", p.Agent))
	}
	if len(p.Routes) == 0 && p.Socks == "" {
		return fail(errors.New("nothing to do: set routes, socks, or both"))
	}
	switch p.DNS.Capture {
	case "", "firewall", "off":
	default:
		return fail(fmt.Errorf("dns.capture %q: use firewall or off", p.DNS.Capture))
	}
	if _, err := dns.NewMatcher(p.DNS.Domains, p.DNS.Patterns); err != nil {
		return fail(err)
	}
	return nil
}

// ExpandHome turns a leading ~/ into the home directory (for kubeconfig paths).
func ExpandHome(p string) string {
	if rest, ok := strings.CutPrefix(p, "~/"); ok {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, rest)
		}
	}
	return p
}
