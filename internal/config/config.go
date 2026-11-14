// Package config reads subtun's YAML config file: named profiles, each with
// a target and the same settings the command line accepts, plus optional
// defaults for every profile. A profile's own value wins over the default;
// lists (routes, excludes, DNS domains and patterns) add up. Command-line
// flags override both, and lists given on the command line are added.
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
	"time"

	"sigs.k8s.io/yaml"

	"github.com/md2k/subnet-tunnel/internal/dns"
	"github.com/md2k/subnet-tunnel/internal/logx"
	"github.com/md2k/subnet-tunnel/internal/routes"
)

// File is the whole config file.
type File struct {
	// Control is the control socket for every run (status, full, off):
	// global, never per profile.
	Control Word `json:"control,omitempty"`
	Log     Log  `json:"log,omitempty"` // global too
	TUI     TUI  `json:"tui,omitempty"` // subtun tui

	Defaults Profile            `json:"defaults,omitempty"` // every key except target
	Profiles map[string]Profile `json:"profiles"`
}

// Log is how a run logs (global, never per profile).
type Log struct {
	File     Word              `json:"file,omitempty"`     // on (default), off
	Dir      string            `json:"dir,omitempty"`      // default ~/.local/state/subtun/logs
	Format   string            `json:"format,omitempty"`   // json (default), text
	Level    string            `json:"level,omitempty"`    // info (default), or "info,dns=debug"
	Levels   map[string]string `json:"levels,omitempty"`   // per component: dns: debug
	MaxSize  string            `json:"maxSize,omitempty"`  // 20MB
	MaxAge   string            `json:"maxAge,omitempty"`   // 3d
	MaxTotal string            `json:"maxTotal,omitempty"` // 500MB
	Mask     []string          `json:"mask,omitempty"`     // dns, destinations
}

// Validate checks the log settings.
func (l Log) Validate() error {
	switch l.File {
	case "", "on", "off":
	default:
		return fmt.Errorf("log.file %q: use on or off", l.File)
	}
	switch l.Format {
	case "", "json", "text":
	default:
		return fmt.Errorf("log.format %q: use json or text", l.Format)
	}
	spec, err := logx.ParseSpec(l.Level)
	if err != nil {
		return fmt.Errorf("log.level: %w", err)
	}
	for c, lvl := range l.Levels {
		if err := spec.Set(c, lvl); err != nil {
			return fmt.Errorf("log.levels: %w", err)
		}
	}
	for key, v := range map[string]string{"maxSize": l.MaxSize, "maxTotal": l.MaxTotal} {
		if _, err := logx.ParseSize(v); v != "" && err != nil {
			return fmt.Errorf("log.%s: %w", key, err)
		}
	}
	if _, err := logx.ParseAge(l.MaxAge); l.MaxAge != "" && err != nil {
		return fmt.Errorf("log.maxAge: %w", err)
	}
	for _, m := range l.Mask {
		if m != "dns" && m != "destinations" {
			return fmt.Errorf("log.mask %q: use dns or destinations", m)
		}
	}
	return nil
}

// TUI is the terminal UI's settings (subtun tui).
type TUI struct {
	// Layout is the dashboard it starts with: table (the profiles above the
	// logs) or detail (a list, and the selected profile's detail); unset:
	// the one used last.
	Layout string `json:"layout,omitempty"`
	// Units are the rates' units: bytes (MB/s) or bits (Mb/s); unset: the
	// ones used last.
	Units string `json:"units,omitempty"`
	// Mouse: on (clicks, double-click opens, the wheel scrolls) or off (the
	// terminal selects text); unset: as used last, else on.
	Mouse Word `json:"mouse,omitempty"`
}

// Layouts of the terminal UI's dashboard, and its units for rates.
const (
	LayoutTable  = "table"
	LayoutDetail = "detail"
	UnitsBytes   = "bytes"
	UnitsBits    = "bits"
)

// ValidUnits checks the TUI's units (the setting and --units).
func ValidUnits(v string) error {
	switch v {
	case "", UnitsBytes, UnitsBits:
		return nil
	}
	return fmt.Errorf("units %q: use bytes or bits", v)
}

// ValidLayout checks a TUI layout (the setting and --layout).
func ValidLayout(v string) error {
	switch v {
	case "", LayoutTable, LayoutDetail:
		return nil
	}
	return fmt.Errorf("layout %q: use table or detail", v)
}

// ValidControl checks a control mode (the setting and --control).
func ValidControl(v string) error {
	switch v {
	case "", "status", "full", "off":
		return nil
	}
	return fmt.Errorf("control %q: use status, full or off", v)
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

	KillSwitch KillSwitch `json:"killSwitch,omitempty"`
	BlockIPv6  Toggle     `json:"blockIPv6,omitempty"` // auto (default: in a full tunnel), true, false
	Reconnect  Reconnect  `json:"reconnect,omitempty"`
}

// KillSwitch keeps traffic for the routed CIDRs from leaving any other way
// when the tunnel is gone.
type KillSwitch struct {
	// Mode: off (default); on: blocks stay after a crash or a lost tunnel;
	// lockdown: they also stay after a deliberate stop (Ctrl-C).
	Mode Mode `json:"mode,omitempty"`
	// DNS while the blocks stay, with DNS capture: block (default) or allow.
	DNS string `json:"dns,omitempty"`
}

// Mode is a kill switch mode. YAML 1.1 reads bare on/off/yes/no as
// booleans (and the YAML library hands them to string fields as "true" /
// "false"), so those are mapped back.
type Mode string

// UnmarshalJSON accepts off, on, lockdown, and booleans.
func (m *Mode) UnmarshalJSON(b []byte) error {
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	switch t := v.(type) {
	case bool:
		*m = "off"
		if t {
			*m = "on"
		}
	case string:
		switch t {
		case "true":
			t = "on"
		case "false":
			t = "off"
		}
		*m = Mode(t)
	default:
		return errors.New("killSwitch.mode: use off, on or lockdown")
	}
	return nil
}

// Reconnect is what subtun does when the connection to the agent is lost.
type Reconnect struct {
	Attempts *int   `json:"attempts,omitempty"` // per outage (default 10); 0: exit instead
	Delay    string `json:"delay,omitempty"`    // before the first attempt (default 1s), doubling
	MaxDelay string `json:"maxDelay,omitempty"` // longest wait (default 1m)
}

// Word is a setting with words for values (dns.capture: firewall, off).
// Bare on/off/yes/no reach string fields as "true"/"false" (see Mode), so
// those, and real booleans, are mapped back to on/off.
type Word string

// UnmarshalJSON accepts a string or a boolean.
func (w *Word) UnmarshalJSON(b []byte) error {
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	switch x := v.(type) {
	case bool:
		*w = "off"
		if x {
			*w = "on"
		}
	case string:
		switch x {
		case "true":
			x = "on"
		case "false":
			x = "off"
		}
		*w = Word(x)
	default:
		return errors.New("use a word")
	}
	return nil
}

// Toggle is auto, true or false; YAML booleans and strings both work.
type Toggle string

// UnmarshalJSON accepts true, false or a string.
func (t *Toggle) UnmarshalJSON(b []byte) error {
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	switch x := v.(type) {
	case bool:
		*t = "false"
		if x {
			*t = "true"
		}
	case string:
		*t = Toggle(x)
	default:
		return errors.New("use auto, true or false")
	}
	return nil
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
	Capture  Word       `json:"capture,omitempty"`  // firewall (default) or off
	Servers  ServerList `json:"servers,omitempty"`  // auto (default) or IPv4 addresses
	Domains  []string   `json:"domains,omitempty"`  // suffixes resolved through the tunnel; "." = all
	Patterns []string   `json:"patterns,omitempty"` // regular expressions, also through the tunnel
	Fallback string     `json:"fallback,omitempty"` // system (default) or ip[:port] for everything else
	Unrouted string     `json:"unrouted,omitempty"` // warn (default), fallback or block: tunnel answers outside the routes
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

// ValidProfileName reports whether name can name a profile.
func ValidProfileName(name string) bool { return profileName.MatchString(name) }

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
	if err := ValidControl(string(f.Control)); err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	if err := f.Log.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	if err := ValidLayout(f.TUI.Layout); err != nil {
		return nil, fmt.Errorf("%s: tui.%w", name, err)
	}
	if err := ValidUnits(f.TUI.Units); err != nil {
		return nil, fmt.Errorf("%s: tui.%w", name, err)
	}
	if m := f.TUI.Mouse; m != "" && m != "on" && m != "off" {
		return nil, fmt.Errorf("%s: tui.mouse %q: use on or off", name, m)
	}
	if f.Defaults.Target.K8s != nil || f.Defaults.Target.Docker != nil {
		return nil, fmt.Errorf("%s: defaults: target can only be set in a profile", name)
	}
	if err := f.Defaults.validateSettings(); err != nil {
		return nil, fmt.Errorf("%s: defaults: %w", name, err)
	}
	for n, p := range f.Profiles {
		if err := merge(f.Defaults, p).validate(n); err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
	}
	return &f, nil
}

// merge applies defaults d to profile p: p's own values win, lists add up.
func merge(d, p Profile) Profile {
	pick := func(own, def string) string {
		if own != "" {
			return own
		}
		return def
	}
	cat := func(def, own []string) []string {
		if len(def) == 0 {
			return own
		}
		return append(append([]string{}, def...), own...)
	}
	out := p
	out.Routes = cat(d.Routes, p.Routes)
	out.Exclude = cat(d.Exclude, p.Exclude)
	out.Socks = pick(p.Socks, d.Socks)
	out.Agent = pick(p.Agent, d.Agent)
	out.AgentDir = pick(p.AgentDir, d.AgentDir)
	out.Tun.Address = pick(p.Tun.Address, d.Tun.Address)
	if out.Tun.MTU == 0 {
		out.Tun.MTU = d.Tun.MTU
	}
	out.DNS.Capture = Word(pick(string(p.DNS.Capture), string(d.DNS.Capture)))
	out.DNS.Fallback = pick(p.DNS.Fallback, d.DNS.Fallback)
	out.DNS.Unrouted = pick(p.DNS.Unrouted, d.DNS.Unrouted)
	if out.Reconnect.Attempts == nil {
		out.Reconnect.Attempts = d.Reconnect.Attempts
	}
	out.Reconnect.Delay = pick(p.Reconnect.Delay, d.Reconnect.Delay)
	out.Reconnect.MaxDelay = pick(p.Reconnect.MaxDelay, d.Reconnect.MaxDelay)
	if len(out.DNS.Servers) == 0 {
		out.DNS.Servers = d.DNS.Servers
	}
	out.DNS.Domains = cat(d.DNS.Domains, p.DNS.Domains)
	out.DNS.Patterns = cat(d.DNS.Patterns, p.DNS.Patterns)
	out.KillSwitch.Mode = Mode(pick(string(p.KillSwitch.Mode), string(d.KillSwitch.Mode)))
	out.KillSwitch.DNS = pick(p.KillSwitch.DNS, d.KillSwitch.DNS)
	out.BlockIPv6 = Toggle(pick(string(p.BlockIPv6), string(d.BlockIPv6)))
	return out
}

// Profile returns the named profile with the defaults applied, or an error
// listing the known ones.
func (f *File) Profile(name string) (Profile, error) {
	p, ok := f.Profiles[name]
	if !ok {
		return Profile{}, fmt.Errorf("no profile %q (have: %s)", name, strings.Join(f.Names(), ", "))
	}
	return merge(f.Defaults, p), nil
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
	if err := p.validateSettings(); err != nil {
		return fail(err)
	}
	if len(p.Routes) == 0 && p.Socks == "" {
		return fail(errors.New("nothing to do: set routes, socks, or both"))
	}
	return nil
}

// validateSettings checks everything but the target; used for defaults too.
func (p Profile) validateSettings() error {
	if _, err := routes.ParseAll(p.Routes, routes.ParseRoute); err != nil {
		return fmt.Errorf("routes: %w", err)
	}
	if _, err := routes.ParseAll(p.Exclude, routes.ParsePrefix); err != nil {
		return fmt.Errorf("exclude: %w", err)
	}
	switch p.Agent {
	case "", "auto", "binary", "python":
	default:
		return fmt.Errorf("agent %q: use auto, binary or python", p.Agent)
	}
	switch p.DNS.Capture {
	case "", "firewall", "off":
	default:
		return fmt.Errorf("dns.capture %q: use firewall or off", p.DNS.Capture)
	}
	if _, err := dns.NewMatcher(p.DNS.Domains, p.DNS.Patterns); err != nil {
		return err
	}
	switch p.KillSwitch.Mode {
	case "", "off", "on", "lockdown":
	default:
		return fmt.Errorf("killSwitch.mode %q: use off, on or lockdown", p.KillSwitch.Mode)
	}
	if a := p.Reconnect.Attempts; a != nil && *a < 0 {
		return fmt.Errorf("reconnect.attempts %d: 0 or more (0: no reconnect)", *a)
	}
	for key, v := range map[string]string{"reconnect.delay": p.Reconnect.Delay, "reconnect.maxDelay": p.Reconnect.MaxDelay} {
		if v == "" {
			continue
		}
		if d, err := time.ParseDuration(v); err != nil || d <= 0 {
			return fmt.Errorf("%s %q: a positive duration, like 1s or 2m", key, v)
		}
	}
	switch p.KillSwitch.DNS {
	case "", "block", "allow":
	default:
		return fmt.Errorf("killSwitch.dns %q: use block or allow", p.KillSwitch.DNS)
	}
	switch p.BlockIPv6 {
	case "", "auto", "true", "false":
	default:
		return fmt.Errorf("blockIPv6 %q: use auto, true or false", p.BlockIPv6)
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
