package logx

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseSpec(t *testing.T) {
	sp, err := ParseSpec("warn, dns=debug ,conn=info")
	if err != nil {
		t.Fatal(err)
	}
	if sp.Default != slog.LevelWarn || sp.Level("dns") != slog.LevelDebug || sp.Level("conn") != slog.LevelInfo ||
		sp.Level("capture") != slog.LevelWarn || sp.Min() != slog.LevelDebug || sp.String() != "warn,dns=debug,conn=info" {
		t.Errorf("spec: %+v %s", sp, sp)
	}
	if sp, err := ParseSpec("dns=debug"); err != nil || sp.Default != slog.LevelInfo {
		t.Errorf("component only: %+v %v", sp, err)
	}
	for _, bad := range []string{"loud", "dns=loud", "disk=debug"} {
		if _, err := ParseSpec(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

// Each component logs at its own level.
func TestFilter(t *testing.T) {
	var b bytes.Buffer
	sp, _ := ParseSpec("info,dns=debug,conn=warn")
	log := slog.New(Filter(slog.NewTextHandler(&b, &slog.HandlerOptions{Level: sp.Min()}), sp))
	log.Debug("general debug")
	log.Info("general info")
	log.With(ComponentKey, "dns").Debug("dns debug")
	conn := log.With(ComponentKey, "conn")
	conn.Info("conn info")
	conn.Warn("conn warn")
	conn.With(ComponentKey, "dns").Debug("a later component wins")
	out := b.String()
	for _, want := range []string{"general info", "dns debug", "conn warn", "a later component wins"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
	for _, not := range []string{"general debug", "conn info"} {
		if strings.Contains(out, not) {
			t.Errorf("%q logged", not)
		}
	}
}

func TestMask(t *testing.T) {
	m := NewMasker(true, true, func() []string { return []string{"corp.example", ".", "svc.corp.example"} })
	n1, n2 := m.Name("DB1.svc.corp.example."), m.Name("db1.svc.corp.example")
	if n1 != n2 || !strings.HasPrefix(n1, "h") || !strings.HasSuffix(n1, ".svc.corp.example") || strings.Contains(n1, "db1") {
		t.Errorf("name: %q %q", n1, n2)
	}
	if got := m.Name("www.github.com"); !strings.HasSuffix(got, ".github.com") || strings.Contains(got, "www") {
		t.Errorf("unconfigured: %q", got)
	}
	if got := m.Name("corp.example"); got != "corp.example" {
		t.Errorf("a configured domain itself: %q", got)
	}
	if got := m.Addr("10.0.4.17:5432"); !strings.HasPrefix(got, "ip-") || !strings.HasSuffix(got, ":5432") || strings.Contains(got, "10.0.4.17") {
		t.Errorf("addr: %q", got)
	}
	if other := NewMasker(true, true, nil); other.Addr("10.0.4.17") == m.Addr("10.0.4.17") {
		t.Error("two runs give the same hash")
	}

	var b bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&b, &slog.HandlerOptions{ReplaceAttr: m.Replace}))
	log.Info("dns", "name", "api.svc.corp.example", "addrs", []netip.Addr{netip.MustParseAddr("10.9.9.9")}, "via", "tunnel")
	log.Info("connected", "dst", "140.82.112.3:443")
	out := b.String()
	for _, secret := range []string{"api.svc", "10.9.9.9", "140.82.112.3"} {
		if strings.Contains(out, secret) {
			t.Errorf("%q not masked:\n%s", secret, out)
		}
	}
	if !strings.Contains(out, `"via":"tunnel"`) || !strings.Contains(out, ":443") {
		t.Errorf("too much masked:\n%s", out)
	}
	off := &Masker{}
	if a := off.Replace(nil, slog.String("name", "x.example")); a.Value.String() != "x.example" {
		t.Error("an inactive masker masked")
	}
}

// One file per run; parts as it grows; old files and those over the total
// go, never the current one.
func TestFile(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	old := filepath.Join(dir, "subtun-20200101-000000-1.json")
	recent := filepath.Join(dir, "subtun-20200102-000000-2.json")
	other := filepath.Join(dir, "notes.txt")
	for _, p := range []string{old, recent, other} {
		if err := os.WriteFile(p, []byte(strings.Repeat("x", 100)), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	_ = os.Chtimes(old, now.Add(-100*time.Hour), now.Add(-100*time.Hour))
	_ = os.Chtimes(recent, now.Add(-time.Hour), now.Add(-time.Hour))

	f, err := OpenFile(FileOptions{Dir: dir, MaxSize: 64, MaxTotal: 250}, now)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Error("a file older than max age is kept")
	}
	if _, err := os.Stat(recent); err != nil {
		t.Error("a recent file was removed")
	}
	if _, err := os.Stat(other); err != nil {
		t.Error("a file not subtun's was removed")
	}
	first := f.Path()
	if info, err := os.Stat(first); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("log file: %v %v", info, err)
	}
	log := slog.New(slog.NewJSONHandler(f, nil))
	for range 6 {
		log.Info("a record long enough to fill a part")
	}
	if f.Path() == first || !strings.HasSuffix(f.Path(), "-3.json") && !strings.HasSuffix(f.Path(), "-4.json") &&
		!strings.HasSuffix(f.Path(), "-5.json") && !strings.HasSuffix(f.Path(), "-6.json") {
		t.Errorf("parts: now %s", f.Path())
	}
	// Every part holds whole JSON records.
	parts, _ := filepath.Glob(filepath.Join(dir, "subtun-*-*.json"))
	for _, p := range parts {
		data, _ := os.ReadFile(p)
		for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
			if line == "" || p == recent {
				continue
			}
			var v map[string]any
			if err := json.Unmarshal([]byte(line), &v); err != nil {
				t.Errorf("%s: %q: %v", p, line, err)
			}
		}
	}
	// The total cap took the oldest files (the recent one first).
	if _, err := os.Stat(recent); !os.IsNotExist(err) {
		t.Error("the total cap kept the oldest file")
	}
	if _, err := os.Stat(f.Path()); err != nil {
		t.Error("the current part was removed")
	}
	_ = f.Close()
	if _, err := f.Write([]byte("x")); err == nil {
		t.Error("write after close")
	}
}
