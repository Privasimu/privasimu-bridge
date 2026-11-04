package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestReferenceExampleIsValid keeps examples/bridge.example.yaml in step with the code.
func TestReferenceExampleIsValid(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "examples", "bridge.example.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	c, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	// The example uses Unix paths; on Windows only the checks of absolute paths differ.
	if err := c.Validate(); err != nil {
		ve, ok := err.(*ValidationError)
		if !ok || filepath.Separator != '\\' {
			t.Fatal(err)
		}
		for _, p := range ve.Problems {
			if !strings.Contains(p, ".path") && !strings.Contains(p, ".exclude[") {
				t.Fatal(err)
			}
		}
	}
	if err := c.ValidateServer(); err != nil {
		t.Fatal(err)
	}
	if err := c.ValidateAgent(); err != nil {
		t.Fatal(err)
	}
	if len(c.Sources) != 7 || c.Sources[1].Engine != "mysql" || c.Sources[0].Match.Host != "corebank" ||
		c.Sources[5].Port != 5439 || c.Sources[6].Port != ClickHouseTLSPort {
		t.Fatalf("%+v", c.Sources)
	}
	if len(c.Packages.Targets) != 3 || c.Packages.Tools.Matcher != MatcherGrype || c.Packages.Targets[2].Kind != PackageImageArchive {
		t.Fatalf("%+v", c.Packages)
	}
}
