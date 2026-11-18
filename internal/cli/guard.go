package cli

import (
	"fmt"
	"io"
	"net/netip"
	"slices"

	"github.com/spf13/cobra"

	"github.com/md2k/subnet-tunnel/internal/privhelper"
	"github.com/md2k/subnet-tunnel/internal/routes"
	"github.com/md2k/subnet-tunnel/internal/transport"
)

// guardPlan is the validated kill switch and IPv6 setup.
type guardPlan struct {
	killSwitch string // off, on, lockdown
	allowDNS   bool   // DNS allowed while the kill switch holds
	blockIPv6  bool
	ipv6Why    string
}

func (g *guardPlan) on() bool { return g.killSwitch == "on" || g.killSwitch == "lockdown" }

// planGuard checks the kill switch and IPv6 settings before anything
// connects or asks for sudo. Without routes they're ignored, with a note: a
// profile without routes may inherit them from defaults.
func planGuard(s settings, rp *routePlan) (*guardPlan, []string, error) {
	g := &guardPlan{killSwitch: s.killSwitch}
	switch g.killSwitch {
	case "":
		g.killSwitch = "off"
	case "off", "on", "lockdown":
	default:
		return nil, nil, fmt.Errorf("kill switch %q: use off, on or lockdown", s.killSwitch)
	}
	switch s.killSwitchDNS {
	case "", "block":
	case "allow":
		g.allowDNS = true
	default:
		return nil, nil, fmt.Errorf("kill switch DNS %q: use block or allow", s.killSwitchDNS)
	}
	switch s.blockIPv6 {
	case "", "auto":
		if rp != nil && rp.fullTunnel() {
			g.blockIPv6, g.ipv6Why = true, "full tunnel"
		}
	case "true":
		g.blockIPv6, g.ipv6Why = true, "asked for"
	case "false":
	default:
		return nil, nil, fmt.Errorf("block IPv6 %q: use auto, true or false", s.blockIPv6)
	}
	if rp == nil {
		var notes []string
		if g.on() {
			notes = append(notes, "kill switch ignored: it guards routed CIDRs, and there are no routes")
		}
		if s.blockIPv6 == "true" {
			notes = append(notes, "IPv6 blocking ignored: it works together with the route capture, and there are no routes")
		}
		return nil, notes, nil
	}
	return g, nil, nil
}

// fullTunnel reports whether the routes cover all of IPv4 (before
// excludes): 0.0.0.0/1 and 128.0.0.0/1.
func (rp *routePlan) fullTunnel() bool {
	all, err := routes.Compute(rp.includes, nil)
	return err == nil && slices.Equal(all.Routes, []netip.Prefix{netip.MustParsePrefix("0.0.0.0/1"), netip.MustParsePrefix("128.0.0.0/1")})
}

// guardPrefixes is what the kill switch blocks outside the tunnel: the
// routes, minus local networks more specific than them (your LAN inside a
// full tunnel stays reachable, as it does through the routing table).
// Routes more specific than a local network (CGNAT /24s inside a VPN
// client's /16) stay guarded, since they would fall back to that network.
func guardPrefixes(final, locals []netip.Prefix) ([]netip.Prefix, error) {
	p, err := routes.Compute(final, locals)
	if err != nil {
		return nil, err
	}
	return p.Routes, nil
}

func localPrefixes() []netip.Prefix {
	var out []netip.Prefix
	for _, l := range localNetworks() {
		out = append(out, l.Network)
	}
	return out
}

func printGuardPlan(w io.Writer, g *guardPlan, guarded int, dnsCapture bool) {
	switch g.killSwitch {
	case "on":
		fmt.Fprintf(w, "kill switch: on: traffic for %d guarded prefixes can only leave through the tunnel; if subtun dies or the tunnel is lost the blocks stay (until the next run or subtun cleanup), Ctrl-C removes them\n", guarded)
	case "lockdown":
		fmt.Fprintf(w, "kill switch: lockdown: traffic for %d guarded prefixes can only leave through the tunnel; the blocks stay after subtun stops for any reason, until the next run or subtun cleanup\n", guarded)
	}
	if g.on() && dnsCapture {
		if g.allowDNS {
			fmt.Fprintln(w, "  DNS stays allowed while the kill switch holds")
		} else {
			fmt.Fprintln(w, "  DNS to the captured servers is blocked too while it holds")
		}
	}
	if g.blockIPv6 {
		fmt.Fprintf(w, "IPv6: outgoing IPv6 blocked (%s); link-local, multicast and loopback still allowed\n", g.ipv6Why)
	}
}

func newCleanupCmd(g *globalOpts) *cobra.Command {
	return &cobra.Command{
		Use:   "cleanup",
		Short: "Remove firewall rules an earlier session left behind (kill switch)",
		Long: `Remove the firewall rules an earlier subtun session left in place: the kill
switch's blocks after a crash, a lost tunnel or a lockdown stop, or rules of
a root helper that was killed. Asks for sudo. Refuses while a subtun
session is running; stop that one instead. The next subtun session takes
over leftovers by itself, so this is only needed to get back to normal
without starting one.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			log := newLogger(g.verbose)
			h, err := privhelper.Start(cmd.Context(), &transport.LineLog{Log: log, Prefix: "helper: "}, log, nil)
			if err != nil {
				return err
			}
			msg, err := h.Cleanup()
			if err != nil {
				return err
			}
			privhelper.ClearLeftovers()
			fmt.Fprintln(cmd.OutOrStdout(), msg)
			return nil
		},
	}
}

// leftovers decides about the marker that tells the next run firewall rules
// may outlive this one. Runs share it, so only a run that loaded firewall
// rules itself, or took over the rules it was set for, may remove it; a run
// that only adds routes must leave another session's marker alone.
type leftovers struct {
	mark  func() error
	clear func()

	ours     bool // set for our rules, or for rules we took over
	tookOver bool // an earlier session's blocking rules were taken over
	running  bool // it belongs to a session that is running
}

// adopted records what the helper found before connecting.
func (l *leftovers) adopted(r privhelper.AdoptResult) {
	switch {
	case r.Running:
		l.running = true
	case r.Kept:
		l.ours, l.tookOver = true, true
	default:
		l.clear() // nothing was left, or it didn't block anything and is gone
	}
}

// firewall is called before this run loads firewall rules.
func (l *leftovers) firewall() {
	if l.running {
		return // another session's rules: this run will be refused
	}
	_ = l.mark()
	l.ours = true
}

// startFailed: rules taken over were put back by the helper; fresh ones
// were removed.
func (l *leftovers) startFailed() {
	if l.ours && !l.tookOver {
		l.clear()
	}
}

// stopped: leftBehind reports whether blocking rules stayed.
func (l *leftovers) stopped(leftBehind bool) {
	if l.ours && !leftBehind {
		l.clear()
	}
}
