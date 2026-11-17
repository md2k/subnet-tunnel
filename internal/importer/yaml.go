package importer

import (
	"fmt"
	"strings"
)

// YAML renders the profile as a config file with one profile, named name.
// target is the profile's target in YAML flow style (e.g. `{docker:
// {container: app}}`); empty leaves a placeholder that must be filled in
// (subtun refuses a profile without a target). Notes and dropped rules go
// into comments.
func (p *Profile) YAML(name, target, source string) []byte {
	return []byte("profiles:\n" + p.Entry(name, target, source, "  "))
}

// Entry renders just the profile (comments, name and settings) for a
// profiles: mapping whose entries are indented by indent.
func (p *Profile) Entry(name, target, source, indent string) string {
	var b strings.Builder
	c := func(format string, args ...any) { fmt.Fprintf(&b, indent+"# "+format+"\n", args...) }
	c("Imported from sshuttle options (%s) by subtun import sshuttle.", source)
	if len(p.Notes) > 0 {
		c("Not carried over, or changed:")
		for _, n := range p.Notes {
			c("  - %s", n)
		}
	}
	if len(p.Dropped) > 0 {
		c("Dropped as redundant:")
		for _, d := range p.Dropped {
			c("  - %s", d)
		}
	}
	in1, in2 := indent+"  ", indent+"    "
	fmt.Fprintf(&b, "%s%s:\n", indent, name)
	if target == "" {
		fmt.Fprintf(&b, "%starget: {}  # set one: {k8s: {context: ..., namespace: ...}} (subtun creates the pod), {docker: {network: ...}} or {ssh: {host: user@host}}; an existing pod or container: create: false, name: ...\n", in1)
	} else {
		fmt.Fprintf(&b, "%starget: %s\n", in1, target)
	}
	list := func(ind, key string, items []string, quote bool) {
		if len(items) == 0 {
			return
		}
		fmt.Fprintf(&b, "%s%s:\n", ind, key)
		for _, it := range items {
			if quote {
				it = yamlQuote(it)
			}
			fmt.Fprintf(&b, "%s  - %s\n", ind, it)
		}
	}
	list(in1, "routes", p.Routes, false)
	list(in1, "exclude", p.Exclude, false)
	if len(p.Domains)+len(p.Patterns)+len(p.Servers) > 0 || p.Fallback != "" {
		fmt.Fprintf(&b, "%sdns:\n", in1)
		list(in2, "domains", p.Domains, true)
		list(in2, "patterns", p.Patterns, true)
		list(in2, "servers", p.Servers, false)
		if p.Fallback != "" {
			fmt.Fprintf(&b, "%sfallback: %s\n", in2, yamlQuote(p.Fallback))
		}
	}
	return b.String()
}

// AddProfile inserts a profile entry into an existing config file's text,
// right below its top-level "profiles:" line, so comments and everything
// else stay as they are. entry renders the profile for a given indentation;
// the existing profiles' indentation is used. Without a profiles key, one
// is appended. The caller validates the result.
func AddProfile(existing []byte, entry func(indent string) string) ([]byte, error) {
	lines := strings.SplitAfter(string(existing), "\n")
	at, indent := -1, "  "
	for i, l := range lines {
		t := strings.TrimRight(l, "\r\n")
		if strings.HasPrefix(t, "profiles:") {
			rest := strings.TrimSpace(strings.TrimPrefix(t, "profiles:"))
			if rest != "" && !strings.HasPrefix(rest, "#") {
				return nil, fmt.Errorf("profiles is written inline (%q); add the profile by hand", rest)
			}
			at = i
			for _, next := range lines[i+1:] {
				nt := strings.TrimRight(next, "\r\n")
				if strings.TrimSpace(nt) == "" || strings.HasPrefix(strings.TrimSpace(nt), "#") {
					continue
				}
				if n := len(nt) - len(strings.TrimLeft(nt, " ")); n > 0 {
					indent = nt[:n]
				}
				break
			}
			break
		}
	}
	if at < 0 {
		out := string(existing)
		if out != "" && !strings.HasSuffix(out, "\n") {
			out += "\n"
		}
		return []byte(out + "profiles:\n" + entry("  ")), nil
	}
	var b strings.Builder
	for i, l := range lines {
		b.WriteString(l)
		if i == at {
			if !strings.HasSuffix(l, "\n") {
				b.WriteString("\n")
			}
			b.WriteString(entry(indent))
		}
	}
	return []byte(b.String()), nil
}

// yamlQuote writes s as a single-quoted YAML scalar (only ' needs escaping).
func yamlQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}
