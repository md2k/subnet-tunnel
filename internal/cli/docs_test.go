package cli

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/spf13/pflag"

	"github.com/md2k/subnet-tunnel/internal/capture"
	"github.com/md2k/subnet-tunnel/internal/config"
	"github.com/md2k/subnet-tunnel/internal/transport"
)

// Every profile in the docs' complete config examples must also plan
// cleanly (routes, DNS, kill switch), not just parse: a setting that loads
// can still be refused at run time.
func TestDocExamplesPlan(t *testing.T) {
	fakeSystemDNS(t)
	block := regexp.MustCompile("(?s)```yaml\n(.*?)```")
	n := 0
	for _, doc := range []string{"../../README.md", "../../docs/config.md"} {
		data, err := os.ReadFile(doc)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range block.FindAllStringSubmatch(string(data), -1) {
			if !strings.Contains(m[1], "profiles:") {
				continue
			}
			f, err := config.Parse([]byte(m[1]), doc)
			if err != nil {
				t.Errorf("%s: %v", doc, err)
				continue
			}
			var specs []*tunnelSpec
			for _, name := range f.Names() {
				p, err := f.Profile(name)
				if err != nil {
					t.Errorf("%s: %s: %v", doc, name, err)
					continue
				}
				n++
				s := settings{tunAddr: capture.DefaultTunAddr, mtu: capture.DefaultMTU, agent: transport.AgentAuto,
					reconnectAttempts: defaultReconnectAttempts, reconnectDelay: defaultReconnectDelay, reconnectMaxDelay: defaultReconnectMaxDelay}
				s.applyProfile(p, pflag.NewFlagSet("none", pflag.ContinueOnError))
				specs = append(specs, &tunnelSpec{name: name, s: s, cfg: p, endpoint: func() (string, error) { return "", nil }})
				rp, _, err := planRoutes(s)
				if err == nil {
					_, _, err = planDNS(s, rp)
				}
				if err == nil {
					_, _, err = planGuard(s, rp)
				}
				if err != nil {
					t.Errorf("%s: profile %s doesn't plan: %v", doc, name, err)
				}
			}
			// An example with several profiles must also run as a set.
			if len(specs) > 1 {
				if _, err := planMulti(specs); err != nil {
					t.Errorf("%s: profiles %v don't plan together: %v", doc, f.Names(), err)
				}
				t.Logf("%s: planned %v together", doc, f.Names())
			}
		}
	}
	if n < 6 {
		t.Fatalf("planned only %d profiles; did the docs move?", n)
	}
}
