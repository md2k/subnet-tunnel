//go:build darwin

package darwin

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
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
// Rules live only in subtun's anchor and filter rules are all "quick", so a
// VPN client's anchor evaluated later can't override them (the sshuttle 2.0
// lesson).
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
	adopted bool            // token taken over: verify pf is still enabled
	tables  map[string]bool // the tables the rules loaded last define
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
	// pf keeps a table the new rules no longer mention (pfctl -t ... -T
	// test still finds it, though nothing refers to it): remove it.
	now := map[string]bool{"subtun_dns": r.DNS != nil || len(r.DNSBlock) > 0, "subtun_guard": r.KillSwitch != nil}
	for _, name := range []string{"subtun_dns", "subtun_guard"} {
		if !now[name] && (p.tables[name] || p.adopted) {
			_, _ = p.run("", "-a", Anchor, "-t", name, "-T", "kill") // gone already is fine
		}
	}
	p.tables = now
	if p.adopted {
		// The reference came from an earlier session; if pf was disabled
		// since (pfctl -d), it no longer holds pf enabled.
		p.adopted = false
		if info, err := p.run("", "-s", "info"); err == nil && !strings.Contains(info, "Status: Enabled") {
			p.token = ""
		}
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

// Busy reports whether subtun's anchor holds rules. pfctl fails for an
// anchor that was never loaded, which counts as empty.
func (p *PF) Busy() (bool, error) {
	for _, what := range []string{"nat", "rules"} {
		out, err := p.run("", "-a", Anchor, "-s", what)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(out, "\n") {
			if f := strings.Fields(line); len(f) > 0 && (f[0] == "rdr" || f[0] == "pass" || f[0] == "block") {
				return true, nil
			}
		}
	}
	return false, nil
}

// Token is the pf enable reference held for subtun.
func (p *PF) Token() string { return p.token }

// Adopt takes over an enable reference left by an earlier session.
func (p *PF) Adopt(token string) { p.token, p.adopted = token, token != "" }

// Flush empties subtun's anchor and releases the enable token.
func (p *PF) Flush() error {
	p.tables = nil
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

// check makes sure the main ruleset evaluates com.apple/* anchors and that
// pf doesn't skip lo0, where the DNS redirect happens. It reports other
// software's anchors, whose rules could interfere.
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
		return errors.New(`pf's main ruleset doesn't evaluate the com.apple/* anchors (see /etc/pf.conf); subtun can't add its rules`)
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

// pfRules renders the intent as pf rules for subtun's anchor: tables
// first, then the redirect, then filter rules (pf requires that order).
// DNS rules come before the kill switch, so a captured DNS server inside
// the routed CIDRs is still captured.
func pfRules(r platform.Rules) (string, error) {
	var tables, rdr, filter strings.Builder
	if r.DNS != nil && len(r.DNSBlock) > 0 {
		return "", errors.New("DNS redirect and DNS block are exclusive")
	}
	if d := r.DNS; d != nil {
		if d.ListenPort == 0 || d.BypassPort == 0 || d.ListenPort == d.BypassPort {
			return "", errors.New("DNS redirect needs two different ports")
		}
		list, err := dnsServers(d.Servers)
		if err != nil {
			return "", err
		}
		// A query to a DNS server leaves via lo0 (route-to), where rdr hands
		// it to subtun's listener. subtun's own fallback queries come from
		// the bypass port and pass first.
		fmt.Fprintf(&tables, "table <subtun_dns> const { %s }\n", list)
		fmt.Fprintf(&rdr, "rdr pass on lo0 inet proto { udp tcp } from any to <subtun_dns> port 53 -> 127.0.0.1 port %d\n", d.ListenPort)
		fmt.Fprintf(&filter, "pass out quick inet proto { udp tcp } from any port %d to <subtun_dns> port 53 keep state\n", d.BypassPort)
		filter.WriteString("pass out quick route-to lo0 inet proto { udp tcp } from any to <subtun_dns> port 53 keep state\n")
	}
	if len(r.DNSBlock) > 0 {
		list, err := dnsServers(r.DNSBlock)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(&tables, "table <subtun_dns> const { %s }\n", list)
		filter.WriteString("block return out quick inet proto { udp tcp } from any to <subtun_dns> port 53\n")
	}
	if k := r.KillSwitch; k != nil {
		if len(k.Prefixes) == 0 {
			return "", errors.New("kill switch without prefixes")
		}
		list := make([]string, len(k.Prefixes))
		for i, p := range k.Prefixes {
			if !p.IsValid() || !p.Addr().Is4() || p.Masked() != p || p.Bits() == 0 {
				return "", fmt.Errorf("kill switch prefix %s: need IPv4 with host bits zero, not the default route", p)
			}
			list[i] = p.String()
		}
		if k.TunIface != "" && !utunName.MatchString(k.TunIface) {
			return "", fmt.Errorf("kill switch interface %q is not a utun", k.TunIface)
		}
		fmt.Fprintf(&tables, "table <subtun_guard> const { %s }\n", strings.Join(list, " "))
		if k.TunIface != "" {
			fmt.Fprintf(&filter, "pass out quick on %s inet from any to <subtun_guard>\n", k.TunIface)
		}
		filter.WriteString("block return out quick inet from any to <subtun_guard>\n")
	}
	if r.BlockIPv6 {
		filter.WriteString("pass out quick on lo0 inet6 all\n")
		filter.WriteString("pass out quick inet6 from any to { fe80::/10, ff00::/8 }\n")
		filter.WriteString("block return out quick inet6 all\n")
	}
	return tables.String() + rdr.String() + filter.String(), nil
}

func dnsServers(servers []netip.Addr) (string, error) {
	if len(servers) == 0 {
		return "", errors.New("DNS rules need servers")
	}
	list := make([]string, len(servers))
	for i, a := range servers {
		if !a.Is4() || a.IsLoopback() || a.IsUnspecified() || a.IsMulticast() {
			return "", fmt.Errorf("DNS server %s: need a unicast IPv4 address", a)
		}
		list[i] = a.String()
	}
	return strings.Join(list, " "), nil
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
