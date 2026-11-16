package ssh

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// hostConfig is how OpenSSH would connect to a host: ~/.ssh/config (with
// Include, Match, Host patterns) applied by ssh -G, under what the target
// sets. Without an ssh binary, OpenSSH's defaults.
type hostConfig struct {
	alias       string // the host as given
	hostname    string
	user        string
	port        int
	identities  []string // tried in order; missing files are skipped
	certs       []string
	jump        string // ProxyJump; "" or "none": none
	proxyCmd    string // ProxyCommand; "" or "none": none
	userKnown   []string
	globalKnown []string
	strict      string // StrictHostKeyChecking: ask, yes, no, accept-new
	hashKnown   bool
	idOnly      bool
	agent       string // IdentityAgent; "": $SSH_AUTH_SOCK
	timeout     time.Duration
	alive       time.Duration // ServerAliveInterval; 0: off
	aliveMax    int
}

// sshBinary is the OpenSSH client asked for the config (tests replace it).
var sshBinary = "ssh"

// resolve asks ssh -G for host's settings, the target's own ones given as
// ssh's flags so they win over ~/.ssh/config the same way.
func resolve(ctx context.Context, host, user string, port int, identity, jump string) (*hostConfig, error) {
	args := []string{"-G"}
	if user != "" {
		args = append(args, "-l", user)
	}
	if port != 0 {
		args = append(args, "-p", strconv.Itoa(port))
	}
	if identity != "" {
		args = append(args, "-i", identity)
	}
	if jump != "" {
		args = append(args, "-J", jump)
	}
	args = append(args, "--", host)
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, sshBinary, args...)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if errors.Is(err, exec.ErrNotFound) {
		return defaults(host, user, port, identity, jump), nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading the SSH config for %s (ssh -G): %v: %s", host, err, strings.TrimSpace(stderr.String()))
	}
	return parseConfig(host, string(out))
}

// parseConfig reads ssh -G's output: "key value" lines, keys lowercase;
// some keys repeat, some list values separated by spaces.
func parseConfig(alias, out string) (*hostConfig, error) {
	c := &hostConfig{alias: alias, strict: "ask", port: 22, aliveMax: 3}
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		key, val, _ := strings.Cut(strings.TrimSpace(sc.Text()), " ")
		val = strings.TrimSpace(val)
		switch key {
		case "hostname":
			c.hostname = val
		case "user":
			c.user = val
		case "port":
			n, err := strconv.Atoi(val)
			if err != nil {
				return nil, fmt.Errorf("ssh -G %s: port %q", alias, val)
			}
			c.port = n
		case "identityfile":
			c.identities = append(c.identities, val)
		case "certificatefile":
			c.certs = append(c.certs, val)
		case "proxyjump":
			c.jump = val
		case "proxycommand":
			c.proxyCmd = val
		case "userknownhostsfile":
			c.userKnown = append(c.userKnown, strings.Fields(val)...)
		case "globalknownhostsfile":
			c.globalKnown = append(c.globalKnown, strings.Fields(val)...)
		case "stricthostkeychecking":
			c.strict = strictWord(val)
		case "hashknownhosts":
			c.hashKnown = val == "yes"
		case "identitiesonly":
			c.idOnly = val == "yes"
		case "identityagent":
			c.agent = val
		case "connecttimeout":
			if n, err := strconv.Atoi(val); err == nil {
				c.timeout = time.Duration(n) * time.Second
			}
		case "serveraliveinterval":
			if n, err := strconv.Atoi(val); err == nil {
				c.alive = time.Duration(n) * time.Second
			}
		case "serveralivecountmax":
			if n, err := strconv.Atoi(val); err == nil && n > 0 {
				c.aliveMax = n
			}
		}
	}
	if c.hostname == "" {
		c.hostname = alias
	}
	if c.user == "" {
		c.user = localUser()
	}
	c.expand()
	return c, nil
}

// strictWord maps StrictHostKeyChecking's spellings to ask, yes, no,
// accept-new.
func strictWord(v string) string {
	switch strings.ToLower(v) {
	case "yes", "true":
		return "yes"
	case "no", "off", "false":
		return "no"
	case "accept-new":
		return "accept-new"
	}
	return "ask"
}

// defaults is OpenSSH's own settings, for when there is no ssh binary to
// read ~/.ssh/config with.
func defaults(host, user string, port int, identity, jump string) *hostConfig {
	c := &hostConfig{alias: host, hostname: host, user: user, port: port, jump: jump, strict: "ask", aliveMax: 3}
	if c.user == "" {
		c.user = localUser()
	}
	if c.port == 0 {
		c.port = 22
	}
	if identity != "" {
		c.identities = append(c.identities, identity)
	}
	for _, k := range []string{"id_rsa", "id_ecdsa", "id_ecdsa_sk", "id_ed25519", "id_ed25519_sk"} {
		c.identities = append(c.identities, "~/.ssh/"+k)
	}
	c.userKnown = []string{"~/.ssh/known_hosts", "~/.ssh/known_hosts2"}
	c.globalKnown = []string{"/etc/ssh/ssh_known_hosts", "/etc/ssh/ssh_known_hosts2"}
	c.expand()
	return c
}

// expand replaces ~ and the % tokens OpenSSH allows in file names.
func (c *hostConfig) expand() {
	home, _ := os.UserHomeDir()
	r := strings.NewReplacer("%%", "%", "%d", home, "%u", localUser(), "%h", c.hostname, "%r", c.user,
		"%p", strconv.Itoa(c.port), "%n", c.alias)
	exp := func(list []string) []string {
		out := make([]string, 0, len(list))
		for _, p := range list {
			if p == "none" {
				continue
			}
			p = r.Replace(p)
			if p == "~" || strings.HasPrefix(p, "~/") {
				p = filepath.Join(home, p[1:])
			}
			out = append(out, p)
		}
		return out
	}
	c.identities, c.certs = exp(c.identities), exp(c.certs)
	c.userKnown, c.globalKnown = exp(c.userKnown), exp(c.globalKnown)
	if c.agent != "" && c.agent != "none" {
		if a := exp([]string{c.agent}); len(a) == 1 {
			c.agent = a[0]
		}
	}
}

// addr is host:port to dial.
func (c *hostConfig) addr() string { return joinHostPort(c.hostname, c.port) }

func joinHostPort(host string, port int) string { return net.JoinHostPort(host, strconv.Itoa(port)) }

func localUser() string {
	if u, err := user.Current(); err == nil {
		return u.Username
	}
	return os.Getenv("USER")
}
