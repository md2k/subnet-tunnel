// Package routes turns the CIDRs a user asks to capture, and the ones they
// exclude, into the set of routes subtun installs on its utun.
//
// Semantics, as in sshuttle: for any address the most specific matching rule
// decides, include or exclude. "10.0.0.0/8, exclude 10.205.0.0/16, include
// 10.205.188.50/32" routes the /8 except that /16, but still the /32 inside
// it. Excludes are not installed as routes via the normal gateway; they are
// carved out of the includes, so every installed route stays on the utun and
// disappears with it.
package routes

import (
	"fmt"
	"net/netip"
	"sort"
)

// Plan is the result of combining includes and excludes.
type Plan struct {
	Routes    []netip.Prefix // routes to install, sorted, minimal
	Redundant []Note         // rules that changed nothing
}

// Note explains why a rule was dropped.
type Note struct {
	Prefix  netip.Prefix
	Exclude bool
	Reason  string
}

func (n Note) String() string {
	kind := "route"
	if n.Exclude {
		kind = "exclude"
	}
	return fmt.Sprintf("%s %s: %s", kind, n.Prefix, n.Reason)
}

type rule struct {
	p       netip.Prefix
	include bool
}

// Compute builds the route plan. Inputs must be masked IPv4 prefixes. A
// prefix listed as both include and exclude is excluded.
func Compute(includes, excludes []netip.Prefix) (Plan, error) {
	rules := map[netip.Prefix]bool{} // prefix -> include
	var plan Plan
	for _, p := range includes {
		if err := check(p); err != nil {
			return Plan{}, err
		}
		if _, dup := rules[p]; dup {
			plan.Redundant = append(plan.Redundant, Note{Prefix: p, Reason: "listed twice"})
			continue
		}
		rules[p] = true
	}
	for _, p := range excludes {
		if err := check(p); err != nil {
			return Plan{}, err
		}
		if inc, dup := rules[p]; dup {
			if inc {
				plan.Redundant = append(plan.Redundant, Note{Prefix: p, Reason: "both routed and excluded; excluded"})
			} else {
				plan.Redundant = append(plan.Redundant, Note{Prefix: p, Exclude: true, Reason: "listed twice"})
				continue
			}
		}
		rules[p] = false
	}

	// Drop rules that don't change the decision they inherit from the most
	// specific enclosing rule (default: not routed). Broad rules first, so a
	// rule's enclosers are settled before it.
	sorted := make([]rule, 0, len(rules))
	for p, inc := range rules {
		sorted = append(sorted, rule{p, inc})
	}
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].p.Bits() != sorted[j].p.Bits() {
			return sorted[i].p.Bits() < sorted[j].p.Bits()
		}
		return sorted[i].p.Addr().Less(sorted[j].p.Addr())
	})
	var kept []rule
	for _, r := range sorted {
		inherited, by := false, netip.Prefix{}
		for _, k := range kept { // kept is broad-to-specific: last match is the most specific
			if k.p.Bits() < r.p.Bits() && k.p.Contains(r.p.Addr()) {
				inherited, by = k.include, k.p
			}
		}
		if inherited == r.include {
			reason := "outside every route, nothing to exclude"
			if by.IsValid() {
				reason = "already covered by " + by.String()
				if !r.include {
					reason = "already excluded by " + by.String()
				}
			}
			plan.Redundant = append(plan.Redundant, Note{Prefix: r.p, Exclude: !r.include, Reason: reason})
			continue
		}
		kept = append(kept, r)
	}

	walk(netip.MustParsePrefix("0.0.0.0/0"), false, kept, &plan.Routes)
	plan.Routes = merge(plan.Routes)
	sort.Slice(plan.Redundant, func(i, j int) bool { return plan.Redundant[i].Prefix.Addr().Less(plan.Redundant[j].Prefix.Addr()) })
	return plan, nil
}

// walk emits the largest prefixes under p whose addresses are all routed.
// It only splits p on the path towards rules inside it, so the work is
// bounded by rules × 32.
func walk(p netip.Prefix, routed bool, rules []rule, out *[]netip.Prefix) {
	inner := false
	for _, r := range rules {
		if r.p == p {
			routed = r.include
		} else if r.p.Bits() > p.Bits() && p.Contains(r.p.Addr()) {
			inner = true
		}
	}
	if !inner {
		if routed {
			*out = append(*out, p)
		}
		return
	}
	lo, hi := halves(p)
	walk(lo, routed, rules, out)
	walk(hi, routed, rules, out)
}

// merge joins sibling prefixes (two halves of one parent) until none are
// left, e.g. two routed /25s become their /24. Input must not overlap.
func merge(ps []netip.Prefix) []netip.Prefix {
	set := make(map[netip.Prefix]bool, len(ps))
	for _, p := range ps {
		set[p] = true
	}
	for changed := true; changed; {
		changed = false
		for p := range set {
			if p.Bits() == 0 || !set[p] {
				continue
			}
			parent := netip.PrefixFrom(p.Addr(), p.Bits()-1).Masked()
			lo, hi := halves(parent)
			if set[lo] && set[hi] {
				delete(set, lo)
				delete(set, hi)
				set[parent] = true
				changed = true
			}
		}
	}
	out := make([]netip.Prefix, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Addr().Less(out[j].Addr()) })
	return out
}

func halves(p netip.Prefix) (netip.Prefix, netip.Prefix) {
	bits := p.Bits() + 1
	lo := netip.PrefixFrom(p.Addr(), bits)
	a := p.Addr().As4()
	idx := p.Bits() / 8
	a[idx] |= 0x80 >> (p.Bits() % 8)
	hi := netip.PrefixFrom(netip.AddrFrom4(a), bits)
	return lo, hi
}

func check(p netip.Prefix) error {
	if !p.IsValid() || !p.Addr().Is4() {
		return fmt.Errorf("%s: only IPv4 prefixes are supported", p)
	}
	if p.Masked() != p {
		return fmt.Errorf("%s has host bits set; did you mean %s?", p, p.Masked())
	}
	return nil
}

// Routed reports whether addr is covered by the plan's routes.
func (pl Plan) Routed(addr netip.Addr) (netip.Prefix, bool) {
	for _, r := range pl.Routes {
		if r.Contains(addr) {
			return r, true
		}
	}
	return netip.Prefix{}, false
}
