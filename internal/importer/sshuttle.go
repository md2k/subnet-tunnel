// Package importer turns other tools' settings into subtun profiles.
package importer

import (
	"bufio"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"slices"
	"strings"

	"github.com/md2k/subnet-tunnel/internal/dns"
	"github.com/md2k/subnet-tunnel/internal/routes"
)

// Profile is what an import produced, plus what it couldn't carry over.
type Profile struct {
	Routes   []string
	Exclude  []string
	Domains  []string
	Patterns []string
	Servers  []string // DNS servers to capture (--ns-hosts)
	Fallback string   // --dns-to
	Notes    []string // options and values not carried over, or changed
	Dropped  []string // redundant routes and excludes, and covered domains
}

// sshuttle options that take a value, by every name they have.
var sshuttleValue = map[string]string{
	"-l": "--listen", "--listen": "--listen",
	"--dns-domains": "--dns-domains", "--dns-to": "--dns-to",
	"--ns-hosts": "--ns-hosts", "--to-ns": "--to-ns",
	"--method": "--method", "--python": "--python",
	"-r": "--remote", "--remote": "--remote",
	"-x": "--exclude", "--exclude": "--exclude",
	"-X": "--exclude-from", "--exclude-from": "--exclude-from",
	"-e": "--ssh-cmd", "--ssh-cmd": "--ssh-cmd",
	"--remote-shell": "--remote-shell", "--seed-hosts": "--seed-hosts",
	"--latency-buffer-size": "--latency-buffer-size", "--wrap": "--wrap",
	"-s": "--subnets", "--subnets": "--subnets",
	"--pidfile": "--pidfile", "--user": "--user", "--group": "--group",
	"--sudoers-user": "--sudoers-user", "-t": "--tmark", "--tmark": "--tmark",
}

// sshuttle options without a value.
var sshuttleFlag = map[string]string{
	"-H": "--auto-hosts", "--auto-hosts": "--auto-hosts",
	"-N": "--auto-nets", "--auto-nets": "--auto-nets",
	"--dns": "--dns", "-v": "--verbose", "--verbose": "--verbose",
	"-V": "--version", "--version": "--version",
	"--no-cmd-delimiter": "--no-cmd-delimiter", "--no-latency-control": "--no-latency-control",
	"--disable-ipv6": "--disable-ipv6", "-D": "--daemon", "--daemon": "--daemon",
	"--syslog": "--syslog", "--firewall": "--firewall", "--hostwatch": "--hostwatch",
	"--sudoers-no-modify": "--sudoers-no-modify", "--no-sudo-pythonpath": "--no-sudo-pythonpath",
}

// Not needed or no equivalent in subtun; reported together.
var sshuttleIgnored = map[string]string{
	"--listen":              "subtun captures with a utun interface, no local listener",
	"--method":              "subtun captures with a utun interface, not pf/nft",
	"--python":              "subtun's agent picks Python by itself (--agent)",
	"--ssh-cmd":             "no SSH transport yet",
	"--remote-shell":        "no SSH transport yet",
	"--no-cmd-delimiter":    "no SSH transport yet",
	"--no-latency-control":  "subtun has no latency control to turn off",
	"--latency-buffer-size": "subtun has no latency control",
	"--wrap":                "not needed",
	"--verbose":             "use -v on subtun",
	"--version":             "not a setting",
	"--daemon":              "run subtun in the background yourself",
	"--syslog":              "subtun logs to stderr",
	"--pidfile":             "not needed",
	"--user":                "subtun runs as you; only the helper uses sudo",
	"--group":               "subtun runs as you; only the helper uses sudo",
	"--firewall":            "internal sshuttle option",
	"--hostwatch":           "internal sshuttle option",
	"--sudoers-no-modify":   "subtun uses plain sudo",
	"--sudoers-user":        "subtun uses plain sudo",
	"--no-sudo-pythonpath":  "subtun uses plain sudo",
	"--tmark":               "not needed",
	"--auto-hosts":          "not supported",
	"--auto-nets":           "not supported",
	"--seed-hosts":          "not supported",
	"--to-ns":               "subtun resolves through the target's own resolver",
}

// SSHuttle reads an sshuttle options file (the @file format: one argument
// per line, # comments; whole command lines work too) and builds a profile.
// readFile opens files named by -s/--subnets and -X/--exclude-from.
func SSHuttle(r io.Reader, readFile func(string) ([]byte, error)) (*Profile, error) {
	args, err := sshuttleArgs(r)
	if err != nil {
		return nil, err
	}
	return fromArgs(args, readFile)
}

// sshuttleArgs splits an options file into arguments like sshuttle does:
// one argument per line, surrounding quotes removed. A line holding a short
// option and its value ("-x 10.1.0.0/16") becomes both, which sshuttle reads
// the same way.
func sshuttleArgs(r io.Reader) ([]string, error) {
	var args []string
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if len(line) >= 2 && (line[0] == '\'' || line[0] == '"') && line[len(line)-1] == line[0] {
			line = line[1 : len(line)-1]
		}
		args = append(args, line)
	}
	return args, sc.Err()
}

type collector struct {
	p        Profile
	includes []string
	excludes []string
	patterns []string
	dns      bool
	ignored  map[string]bool
	readFile func(string) ([]byte, error)
}

func fromArgs(args []string, readFile func(string) ([]byte, error)) (*Profile, error) {
	c := &collector{ignored: map[string]bool{}, readFile: readFile}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "-") || a == "-" {
			c.subnet(a, false)
			continue
		}
		name, val, hasVal := a, "", false
		if strings.HasPrefix(a, "--") {
			if n, v, ok := strings.Cut(a, "="); ok {
				name, val, hasVal = n, v, true
			} else if n, v, ok := strings.Cut(a, " "); ok { // "--dns-to 1.2.3.4:53" on one line
				name, val, hasVal = n, strings.TrimSpace(v), true
			}
		} else if len(a) > 2 {
			name, val, hasVal = a[:2], strings.TrimSpace(strings.TrimPrefix(a[2:], "=")), true
		}
		if canon, ok := sshuttleFlag[name]; ok {
			c.flag(canon)
			continue
		}
		canon, ok := sshuttleValue[name]
		if !ok {
			c.note("%s: unknown sshuttle option, left out", name)
			continue
		}
		if !hasVal {
			if i+1 >= len(args) {
				return nil, fmt.Errorf("%s needs a value", name)
			}
			i++
			val = args[i]
		}
		if err := c.option(canon, val); err != nil {
			return nil, err
		}
	}
	return c.finish()
}

func (c *collector) note(format string, args ...any) {
	c.p.Notes = append(c.p.Notes, fmt.Sprintf(format, args...))
}

func (c *collector) flag(name string) {
	switch name {
	case "--dns":
		c.dns = true
	case "--disable-ipv6":
		c.note("--disable-ipv6: subtun captures IPv4 only; to block IPv6 set blockIPv6 (default auto: blocked in a full tunnel)")
	default:
		c.ignore(name)
	}
}

func (c *collector) ignore(name string) {
	if !c.ignored[name] {
		c.ignored[name] = true
		c.note("%s: left out (%s)", name, sshuttleIgnored[name])
	}
}

func (c *collector) option(name, val string) error {
	switch name {
	case "--exclude":
		c.subnet(val, true)
	case "--subnets", "--exclude-from":
		data, err := c.readFile(val)
		if err != nil {
			return fmt.Errorf("%s %s: %w", name, val, err)
		}
		for _, line := range strings.Split(string(data), "\n") {
			if line = strings.TrimSpace(line); line != "" && !strings.HasPrefix(line, "#") {
				c.subnet(line, name == "--exclude-from")
			}
		}
	case "--dns-domains":
		c.patterns = append(c.patterns, splitList(val)...)
	case "--dns-to":
		ap, err := resolverAddr(val)
		if err != nil {
			c.note("--dns-to %s: %v; left out", val, err)
			return nil
		}
		c.p.Fallback = ap
	case "--ns-hosts":
		for _, s := range splitList(val) {
			a, err := netip.ParseAddr(s)
			if err != nil || !a.Is4() {
				c.note("--ns-hosts %s: subtun captures IPv4 DNS servers only; left out", s)
				continue
			}
			c.p.Servers = append(c.p.Servers, a.String())
		}
	case "--remote":
		c.note("--remote %s: SSH targets aren't supported yet; set the target to a pod or container", val)
	default:
		c.ignore(name)
	}
	return nil
}

func splitList(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\n' })
}

func resolverAddr(s string) (string, error) {
	if ap, err := netip.ParseAddrPort(s); err == nil {
		if !ap.Addr().Is4() {
			return "", fmt.Errorf("IPv4 only")
		}
		if ap.Port() == 53 {
			return ap.Addr().String(), nil
		}
		return ap.String(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil || !a.Is4() {
		return "", fmt.Errorf("want an IPv4 address with an optional port")
	}
	return a.String(), nil
}

// subnet converts one sshuttle subnet ([IP or name][/width][:port[-port]]).
func (c *collector) subnet(s string, exclude bool) {
	what := "route"
	if exclude {
		what = "exclude"
	}
	orig := s
	if strings.Count(s, ":") == 1 { // IPv4 or name with a port range
		host, port, _ := strings.Cut(s, ":")
		c.note("%s %s: port ranges aren't supported; the whole address is used (port %s dropped)", what, orig, port)
		s = host
	}
	if s == "0/0" || s == "0.0.0.0/0" {
		if exclude {
			c.note("exclude %s: excluding everything makes no sense; left out", orig)
			return
		}
		c.note("route %s: written as 0.0.0.0/1 and 128.0.0.0/1 (a full tunnel that leaves the real default route alone)", orig)
		c.includes = append(c.includes, "0.0.0.0/1", "128.0.0.0/1")
		return
	}
	var p netip.Prefix
	if a, err := netip.ParseAddr(s); err == nil {
		p = netip.PrefixFrom(a, a.BitLen())
	} else if p, err = netip.ParsePrefix(s); err != nil {
		c.note("%s %s: only IP addresses and CIDRs can be imported (names and short forms aren't); left out", what, orig)
		return
	}
	if !p.Addr().Is4() {
		c.note("%s %s: subtun captures IPv4 only; left out", what, orig)
		return
	}
	if p.Masked() != p {
		c.note("%s %s: written as %s (host bits cleared, as sshuttle does)", what, orig, p.Masked())
		p = p.Masked()
	}
	if exclude {
		c.excludes = append(c.excludes, p.String())
	} else {
		c.includes = append(c.includes, p.String())
	}
}

// suffixPattern matches sshuttle's ".*.company.com" / ".*\.company\.com".
var suffixPattern = regexp.MustCompile(`^\.\*\\?\.((?:[a-zA-Z0-9_-]+\\?\.)*[a-zA-Z0-9_-]+)\.?$`)

func (c *collector) finish() (*Profile, error) {
	if err := c.routes(); err != nil {
		return nil, err
	}
	c.dnsSettings()
	slices.Sort(c.p.Notes)
	c.p.Notes = slices.Compact(c.p.Notes)
	return &c.p, nil
}

// routes drops what the route planner finds redundant (duplicates, routes
// covered by a broader one, excludes that match nothing), keeping order.
func (c *collector) routes() error {
	inc, err := routes.ParseAll(c.includes, routes.ParsePrefix)
	if err != nil {
		return err
	}
	exc, err := routes.ParseAll(c.excludes, routes.ParsePrefix)
	if err != nil {
		return err
	}
	if len(inc) == 0 {
		c.p.Exclude = c.excludes
		return nil
	}
	plan, err := routes.Compute(inc, exc)
	if err != nil {
		return err
	}
	drop := map[string]int{} // "route 10.1.0.0/16" -> how many copies to drop
	for _, n := range plan.Redundant {
		kind := "route"
		if n.Exclude {
			kind = "exclude"
		}
		drop[kind+" "+n.Prefix.String()]++
		c.p.Dropped = append(c.p.Dropped, n.String())
	}
	keep := func(kind string, list []string) []string {
		var out []string
		for _, s := range list {
			if k := kind + " " + s; drop[k] > 0 {
				drop[k]--
				continue
			}
			out = append(out, s)
		}
		return out
	}
	c.p.Routes = keep("route", c.includes)
	c.p.Exclude = keep("exclude", c.excludes)
	return nil
}

func (c *collector) dnsSettings() {
	if !c.dns {
		if len(c.patterns) > 0 {
			c.note("--dns-domains without --dns had no effect in sshuttle; imported anyway (subtun captures DNS whenever domains or patterns are set)")
		}
		if c.p.Fallback != "" || len(c.p.Servers) > 0 {
			c.note("--dns-to / --ns-hosts without --dns: imported, but they only matter with DNS domains or patterns")
		}
	}
	if c.dns && len(c.patterns) == 0 {
		// Plain --dns: every query goes through the tunnel.
		c.p.Domains = []string{"."}
		return
	}
	suffixes := 0
	for _, pat := range c.patterns {
		if m := suffixPattern.FindStringSubmatch(pat); m != nil {
			d, err := dns.NormalizeDomain(strings.ReplaceAll(m[1], `\.`, "."))
			if err == nil {
				c.p.Domains = append(c.p.Domains, d)
				suffixes++
				continue
			}
		}
		re := pat
		if !strings.HasPrefix(re, "^") {
			re = "^" + re // sshuttle matched with re.match: anchored at the start
		}
		if _, err := regexp.Compile(re); err != nil {
			c.note("--dns-domains %s: not valid as a Go regular expression (%v); left out", pat, err)
			continue
		}
		c.p.Patterns = append(c.p.Patterns, re)
	}
	if suffixes > 0 {
		c.note("--dns-domains: %d pattern(s) of the form .*.suffix became domain suffixes (they now also match the bare domain itself, and only on label boundaries)", suffixes)
	}
	if len(c.p.Patterns) > 0 {
		c.note("--dns-domains: other patterns became regular expressions anchored with ^ (sshuttle matched with Python's re.match); check them")
	}
	c.p.Domains = c.coveredDomains(c.p.Domains)
}

// coveredDomains drops duplicates and domains under another listed one.
func (c *collector) coveredDomains(in []string) []string {
	var out []string
	for i, d := range in {
		cover := ""
		for j, e := range in {
			if (e == d && j < i) || strings.HasSuffix(d, "."+e) {
				cover = e
				break
			}
		}
		if cover == d {
			c.p.Dropped = append(c.p.Dropped, fmt.Sprintf("domain %s: listed twice", d))
			continue
		}
		if cover != "" {
			c.p.Dropped = append(c.p.Dropped, fmt.Sprintf("domain %s: already covered by %s", d, cover))
			continue
		}
		out = append(out, d)
	}
	return out
}
