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
			for _, name := range f.Names() {
				p, err := f.Profile(name)
				if err != nil {
					t.Errorf("%s: %s: %v", doc, name, err)
					continue
				}
				n++
				s := settings{tunAddr: capture.DefaultTunAddr, mtu: capture.DefaultMTU, agent: transport.AgentAuto}
				s.applyProfile(p, pflag.NewFlagSet("none", pflag.ContinueOnError))
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
		}
	}
	if n < 6 {
		t.Fatalf("planned only %d profiles; did the docs move?", n)
	}
}
