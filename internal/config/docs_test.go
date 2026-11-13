package config

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// Every complete config example in the docs (a YAML block with profiles:)
// must load, so the docs can't drift from the parser.
func TestDocExamplesLoad(t *testing.T) {
	block := regexp.MustCompile("(?s)```yaml\n(.*?)```")
	n := 0
	for _, doc := range []string{"../../README.md", "../../docs/config.md"} {
		data, err := os.ReadFile(doc)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range block.FindAllStringSubmatch(string(data), -1) {
			if !strings.Contains(m[1], "profiles:") {
				continue // a fragment
			}
			n++
			f, err := Parse([]byte(m[1]), doc)
			if err != nil {
				t.Errorf("%s: example doesn't load: %v\n%s", doc, err, m[1])
				continue
			}
			for _, name := range f.Names() {
				if _, err := f.Profile(name); err != nil {
					t.Errorf("%s: profile %s: %v", doc, name, err)
				}
			}
		}
	}
	if n < 5 {
		t.Fatalf("found only %d examples; did the docs move?", n)
	}
}
