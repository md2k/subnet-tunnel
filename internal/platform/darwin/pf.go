//go:build darwin

package darwin

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/md2k/subnet-tunnel/internal/platform"
)

// Anchor holds subtun's pf rules. macOS's /etc/pf.conf evaluates every
// anchor under com.apple/ (nat, rdr and filter), so subtun never has to
// touch the main ruleset.
const Anchor = "com.apple/subtun"

// PF is the macOS firewall driver.
//
// Rules live only in subtun's anchor and are all "quick", so a VPN client's
// anchor evaluated later can't override them (the sshuttle 2.0 lesson).
// pf is enabled with a reference token (pfctl -E) and the token released on
// Flush, so pf ends up exactly as enabled or disabled as it was. Flushing
// clears only the anchor's rules and tables: "pfctl -a ... -F all" would also
// clear pf's global state table.
type PF struct {
	// Run executes pfctl with stdin and returns its combined output; nil
	// runs /sbin/pfctl. Tests replace it.
	Run func(stdin string, args ...string) (string, error)
	Log *slog.Logger

	checked bool
	token   string
}

var pfToken = regexp.MustCompile(`Token : ([0-9]+)`)

// Apply replaces subtun's anchor with r and enables pf if needed.
func (p *PF) Apply(r platform.Rules) error {
	text, err := pfRules(r)
	if err != nil {
		return err
	}
	if !p.checked {
		if err := p.check(); err != nil {
			return err
		}
		p.checked = true
	}
	if _, err := p.run(text, "-a", Anchor, "-f", "/dev/stdin"); err != nil {
		return err
	}
	if p.token == "" {
		out, err := p.run("", "-E")
		if err != nil {
			return err
		}
		m := pfToken.FindStringSubmatch(out)
		if m == nil {
			return fmt.Errorf("pfctl -E: no token in %q", strings.TrimSpace(out))
		}
		p.token = m[1]
	}
	return nil
}

// Flush empties subtun's anchor and releases the enable token.
func (p *PF) Flush() error {
	var errs []error
	for _, what := range []string{"rules", "nat", "Tables"} {
		if _, err := p.run("", "-a", Anchor, "-F", what); err != nil {
			errs = append(errs, err)
		}
	}
	if p.token != "" {
		if _, err := p.run("", "-X", p.token); err != nil {
			errs = append(errs, err)
		}
		p.token = ""
	}
	return errors.Join(errs...)
}

// check makes sure the main ruleset evaluates com.apple/* anchors, that our
// anchor is free and that pf doesn't skip lo0, where the redirect happens.
// It reports other software's anchors, whose rules could interfere.
func (p *PF) check() error {
	rules, err := p.run("", "-s", "rules")
	if err != nil {
		return err
	}
	nat, err := p.run("", "-s", "nat")
	if err != nil {
		return err
	}
	if !strings.Contains(rules, `anchor "com.apple/*"`) || !strings.Contains(nat, `rdr-anchor "com.apple/*"`) {
		return errors.New(`pf's main ruleset doesn't evaluate the com.apple/* anchors (see /etc/pf.conf); DNS capture can't add its rules`)
	}
	// Someone else's rules in our anchor: another subtun with DNS capture,
	// or leftovers from a helper that was killed. Replacing them would
	// silently break the other one.
	if mine, err := p.run("", "-a", Anchor, "-s", "nat"); err == nil && strings.Contains(mine, "rdr ") {
		return fmt.Errorf("pf anchor %s already has rules: another subtun with DNS capture is running, or one was killed without cleaning up; if none is running, remove them with: sudo pfctl -a %s -F nat && sudo pfctl -a %s -F rules", Anchor, Anchor, Anchor)
	}
	lo, err := p.run("", "-s", "Interfaces", "-i", "lo0", "-v")
	if err != nil {
		return err
	}
	if strings.Contains(lo, "skip") {
		return errors.New("pf is set to skip lo0 (set skip on lo0); DNS capture redirects through lo0 and can't work")
	}
	if anchors, err := p.run("", "-s", "Anchors"); err == nil {
		var other []string
		for _, line := range strings.Split(anchors, "\n") {
			a := strings.TrimSpace(line)
			if a == "" || strings.Contains(a, "ALTQ") || strings.Contains(a, " ") || a == "com.apple" || strings.HasPrefix(a, "com.apple/") {
				continue // pfctl's ALTQ notices, our own namespace
			}
			other = append(other, a)
		}
		if len(other) > 0 && p.Log != nil {
			p.Log.Warn("other software has pf rules; if DNS capture misbehaves, check them", "anchors", strings.Join(other, " "))
		}
	}
	return nil
}

// pfRules renders the intent as pf rules for subtun's anchor.
func pfRules(r platform.Rules) (string, error) {
	var b strings.Builder
	if d := r.DNS; d != nil {
		if len(d.Servers) == 0 || d.ListenPort == 0 || d.BypassPort == 0 || d.ListenPort == d.BypassPort {
			return "", errors.New("DNS redirect needs servers and two different ports")
		}
		servers := make([]string, len(d.Servers))
		for i, a := range d.Servers {
			if !a.Is4() || a.IsLoopback() || a.IsUnspecified() || a.IsMulticast() {
				return "", fmt.Errorf("DNS server %s: need a unicast IPv4 address", a)
			}
			servers[i] = a.String()
		}
		// A query to a DNS server leaves via lo0 (route-to), where rdr hands
		// it to subtun's listener. subtun's own fallback queries come from
		// the bypass port and pass first.
		fmt.Fprintf(&b, "table <subtun_dns> const { %s }\n", strings.Join(servers, " "))
		fmt.Fprintf(&b, "rdr pass on lo0 inet proto { udp tcp } from any to <subtun_dns> port 53 -> 127.0.0.1 port %d\n", d.ListenPort)
		fmt.Fprintf(&b, "pass out quick inet proto { udp tcp } from any port %d to <subtun_dns> port 53 keep state\n", d.BypassPort)
		b.WriteString("pass out quick route-to lo0 inet proto { udp tcp } from any to <subtun_dns> port 53 keep state\n")
	}
	return b.String(), nil
}

func (p *PF) run(stdin string, args ...string) (string, error) {
	if p.Run != nil {
		return p.Run(stdin, args...)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/sbin/pfctl", args...)
	cmd.Stdin = strings.NewReader(stdin)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("pfctl %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}
