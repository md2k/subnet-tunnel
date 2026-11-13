package logx

import (
	"bytes"
	"encoding/json"
	"fmt"
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
	if n := strings.Count(out, "component=dns"); n != 2 || strings.Count(out, "component=") != 3 {
		t.Errorf("one component per line, the latest:\n%s", out)
	}
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
	// Errors repeat destinations; SOCKS destinations can be names.
	b.Reset()
	log.Info("connect failed", "dst", "db.svc.corp.example:5432", "err", "tunnel: dial 10.9.9.9:443: connect: connection refused; lookup api.github.com: no such host")
	if out := b.String(); strings.Contains(out, "10.9.9.9") || strings.Contains(out, "api.github.com") || strings.Contains(out, `"dst":"db.`) ||
		!strings.Contains(out, ".svc.corp.example:5432") || !strings.Contains(out, "connection refused") {
		t.Errorf("errors and SOCKS names:\n%s", out)
	}
	dnsOnly := NewMasker(true, false, nil)
	if got := dnsOnly.Replace(nil, slog.String("dst", "db.corp.example:5432")).Value.String(); strings.Contains(got, "db.") {
		t.Errorf("a SOCKS name with dns masking: %q", got)
	}
	if got := dnsOnly.Replace(nil, slog.String("dst", "10.1.2.3:443")).Value.String(); got != "10.1.2.3:443" {
		t.Errorf("an address with dns masking only: %q", got)
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
	old := filepath.Join(dir, "subtun-20200101-000000-7777777.json") // no such process
	recent := filepath.Join(dir, "subtun-20200102-000000-7777778.json")
	other := filepath.Join(dir, "notes.txt")
	for _, p := range []string{old, recent, other} {
		if err := os.WriteFile(p, []byte(strings.Repeat("x", 100)), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	_ = os.Chtimes(old, now.Add(-100*time.Hour), now.Add(-100*time.Hour))
	_ = os.Chtimes(recent, now.Add(-time.Hour), now.Add(-time.Hour))

	// Another running subtun's file (this test's own pid stands in for it,
	// under another start time) and files not subtun's stay.
	live := filepath.Join(dir, fmt.Sprintf("subtun-20200103-000000-%d.json", os.Getpid()))
	mine := filepath.Join(dir, "subtun-notes.json")
	for _, p := range []string{live, mine} {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		_ = os.Chtimes(p, now.Add(-100*time.Hour), now.Add(-100*time.Hour))
	}
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
	if _, err := os.Stat(mine); err != nil {
		t.Error("a file named like subtun's, not one, was removed")
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

func TestParseSizeAndAge(t *testing.T) {
	for in, want := range map[string]int64{"20MB": 20 << 20, "500kb": 500 << 10, "1GB": 1 << 30, "4096": 4096, "10 MB": 10 << 20} {
		if got, err := ParseSize(in); err != nil || got != want {
			t.Errorf("size %q: %d %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "0MB", "-1MB", "20TB", "lots"} {
		if _, err := ParseSize(bad); err == nil {
			t.Errorf("size %q accepted", bad)
		}
	}
	for in, want := range map[string]time.Duration{"3d": 72 * time.Hour, "12h": 12 * time.Hour, "90m": 90 * time.Minute} {
		if got, err := ParseAge(in); err != nil || got != want {
			t.Errorf("age %q: %v %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "0d", "-3d", "3w", "soon"} {
		if _, err := ParseAge(bad); err == nil {
			t.Errorf("age %q accepted", bad)
		}
	}
}
