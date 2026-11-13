// Package logx is subtun's logging: levels per component, masking of DNS
// names and destinations, and log files that rotate by size and age.
//
// A logger's component is its "component" attribute (log.With("component",
// "dns")); the filter drops records below that component's level.
package logx

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"strings"
)

// Components are the parts of subtun with their own level.
var Components = []string{
	"tunnel",    // connecting, reconnecting, changes while running
	"dns",       // every DNS query (debug), unrouted answers
	"conn",      // every captured connection (debug)
	"capture",   // the utun, routes, the firewall, the kill switch
	"helper",    // the root helper's lines
	"control",   // the control socket
	"socks",     // the SOCKS proxy, every connection through it (debug)
	"transport", // reaching the target (Kubernetes, Docker), the agent
}

// ComponentKey is the attribute naming a logger's component.
const ComponentKey = "component"

// Spec is a default level and levels per component.
type Spec struct {
	Default slog.Level
	By      map[string]slog.Level
}

// ParseLevel reads debug, info, warn or error.
func ParseLevel(s string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug, nil
	case "info", "":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	}
	return 0, fmt.Errorf("log level %q: use debug, info, warn or error", s)
}

// ParseSpec reads "info", "info,dns=debug" or "dns=debug" (default info).
func ParseSpec(s string) (Spec, error) {
	sp := Spec{Default: slog.LevelInfo, By: map[string]slog.Level{}}
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		comp, lvl, ok := strings.Cut(part, "=")
		if !ok {
			l, err := ParseLevel(part)
			if err != nil {
				return Spec{}, err
			}
			sp.Default = l
			continue
		}
		if err := sp.Set(comp, lvl); err != nil {
			return Spec{}, err
		}
	}
	return sp, nil
}

// Set gives a component its level.
func (s *Spec) Set(comp, level string) error {
	comp = strings.TrimSpace(comp)
	if !slices.Contains(Components, comp) {
		return fmt.Errorf("log component %q: use one of %s", comp, strings.Join(Components, ", "))
	}
	l, err := ParseLevel(level)
	if err != nil {
		return err
	}
	if s.By == nil {
		s.By = map[string]slog.Level{}
	}
	s.By[comp] = l
	return nil
}

// Level is the level for a component ("": none).
func (s Spec) Level(comp string) slog.Level {
	if l, ok := s.By[comp]; ok {
		return l
	}
	return s.Default
}

// Min is the lowest level any component logs at: the handlers behind the
// filter must let it through.
func (s Spec) Min() slog.Level {
	m := s.Default
	for _, l := range s.By {
		m = min(m, l)
	}
	return m
}

// String is the spec as ParseSpec reads it.
func (s Spec) String() string {
	parts := []string{strings.ToLower(s.Default.String())}
	for _, c := range Components {
		if l, ok := s.By[c]; ok {
			parts = append(parts, c+"="+strings.ToLower(l.String()))
		}
	}
	return strings.Join(parts, ",")
}

// Filter drops records below their component's level; h gets the rest.
func Filter(h slog.Handler, spec Spec) slog.Handler { return filter{h: h, spec: spec} }

type filter struct {
	h    slog.Handler
	spec Spec
	comp string
}

func (f filter) Enabled(ctx context.Context, l slog.Level) bool {
	return l >= f.spec.Level(f.comp) && f.h.Enabled(ctx, l)
}

// Handle adds the component once, last (nested With calls would repeat
// the key otherwise).
func (f filter) Handle(ctx context.Context, r slog.Record) error {
	if f.comp != "" {
		r = r.Clone()
		r.AddAttrs(slog.String(ComponentKey, f.comp))
	}
	return f.h.Handle(ctx, r)
}

func (f filter) WithAttrs(as []slog.Attr) slog.Handler {
	comp := f.comp
	rest := make([]slog.Attr, 0, len(as))
	for _, a := range as {
		if a.Key == ComponentKey {
			comp = a.Value.String()
			continue
		}
		rest = append(rest, a)
	}
	return filter{h: f.h.WithAttrs(rest), spec: f.spec, comp: comp}
}

func (f filter) WithGroup(name string) slog.Handler {
	return filter{h: f.h.WithGroup(name), spec: f.spec, comp: f.comp}
}
