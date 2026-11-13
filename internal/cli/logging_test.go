package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/md2k/subnet-tunnel/internal/config"
	"github.com/md2k/subnet-tunnel/internal/logx"
)

// The run's log: the terminal (text, no component), the ring and a JSON
// file (with the component); levels per component; masking everywhere.
func TestRunLog(t *testing.T) {
	dir := t.TempDir()
	var term bytes.Buffer
	lc := config.Log{Dir: dir, Level: "info,dns=debug", Mask: []string{"dns", "destinations"}}
	rl, warn := newRunLog(false, lc, func() []string { return []string{"corp.example"} }, &term)
	if warn != "" || rl.file == nil {
		t.Fatalf("no file: %q", warn)
	}
	dnsLog := rl.log.With(logx.ComponentKey, "dns")
	connLog := rl.log.With(logx.ComponentKey, "conn")
	dnsLog.Debug("dns", "name", "db1.corp.example", "via", "tunnel")
	connLog.Debug("connected", "dst", "10.0.4.17:5432") // conn is at info: dropped
	connLog.Info("connect failed", "dst", "10.0.4.17:5432", "err", "refused")
	rl.log.Debug("general debug") // dropped
	path := rl.file.Path()
	rl.close()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var recs []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		var r map[string]any
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatalf("%q: %v", line, err)
		}
		recs = append(recs, r)
	}
	if len(recs) != 2 || recs[0]["component"] != "dns" || recs[1]["component"] != "conn" || recs[1]["msg"] != "connect failed" {
		t.Fatalf("file records: %v", recs)
	}
	for _, out := range []string{term.String(), string(data), strings.Join(lines(rl), "\n")} {
		if strings.Contains(out, "db1") || strings.Contains(out, "10.0.4.17") {
			t.Errorf("not masked:\n%s", out)
		}
		if strings.Contains(out, "general debug") || strings.Contains(out, `"msg":"connected"`) || strings.Contains(out, "msg=connected") {
			t.Errorf("below its level:\n%s", out)
		}
	}
	if strings.Contains(term.String(), "component=") || !strings.Contains(term.String(), ".corp.example") || !strings.Contains(term.String(), ":5432") {
		t.Errorf("terminal:\n%s", term.String())
	}

	// -v: everything at debug; text files; files off.
	term.Reset()
	rl, _ = newRunLog(true, config.Log{Dir: dir, Format: "text", Level: "warn"}, nil, &term)
	rl.log.With(logx.ComponentKey, "conn").Debug("connected", "dst", "10.0.4.17:5432")
	if p := rl.file.Path(); !strings.HasSuffix(p, ".log") {
		t.Errorf("text file: %s", p)
	}
	text, _ := os.ReadFile(rl.file.Path())
	rl.close()
	if !strings.Contains(term.String(), "dst=10.0.4.17:5432") || !strings.Contains(string(text), "component=conn") {
		t.Errorf("-v: terminal %q, file %q", term.String(), text)
	}
	rl, warn = newRunLog(false, config.Log{File: "off"}, nil, &term)
	if rl.file != nil || warn != "" {
		t.Errorf("file off: %v %q", rl.file, warn)
	}
}

func lines(rl *runLog) []string {
	var out []string
	for _, l := range rl.ring.Lines() {
		out = append(out, l.Text)
	}
	return out
}

// Log flags are global for the run: several profiles take them; bad values
// are refused before anything runs.
func TestLogFlags(t *testing.T) {
	if _, err := runCLI(t, "--config", "testdata/multi.yaml", "up", "--profile", "work,dev", "--dry-run", "--log-level", "info,dns=debug", "--log-file", "off", "--log-mask", "dns"); err != nil {
		t.Errorf("several profiles with log flags: %v", err)
	}
	for _, args := range [][]string{
		{"--log-level", "loud"}, {"--log-level", "disk=debug"}, {"--log-file", "maybe"}, {"--log-mask", "everything"}, {"--log-max-age", "3w"},
	} {
		all := append([]string{"--config", "testdata/multi.yaml", "up", "dev", "--dry-run"}, args...)
		if _, err := runCLI(t, all...); err == nil {
			t.Errorf("%v accepted", args)
		}
	}
}
