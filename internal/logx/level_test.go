package logx

import (
	"log/slog"
	"strings"
	"testing"
)

// Levels change while running: the filter and the handlers' minimum follow.
func TestLevelsChange(t *testing.T) {
	var b strings.Builder
	lv := NewLevels(Spec{Default: slog.LevelInfo})
	log := slog.New(FilterLevels(slog.NewTextHandler(&b, &slog.HandlerOptions{Level: lv.Min()}), lv)).With(ComponentKey, "dns")
	log.Debug("before")
	dns, _ := ParseSpec("info,dns=debug")
	lv.Set(dns)
	log.Debug("after")
	if strings.Contains(b.String(), "before") || !strings.Contains(b.String(), "after") {
		t.Fatalf("log: %q", b.String())
	}
	if lv.Min().Level() != slog.LevelDebug || lv.Get().String() != "info,dns=debug" {
		t.Fatalf("min %v, spec %q", lv.Min().Level(), lv.Get().String())
	}
}
