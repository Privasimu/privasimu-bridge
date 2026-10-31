package config

import (
	"os"
	"path/filepath"
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
	// The example uses a Unix path for the file root; on Windows only the root check differs.
	if err := c.Validate(); err != nil {
		if ve, ok := err.(*ValidationError); !ok || len(ve.Problems) != 1 || filepath.Separator != '\\' {
			t.Fatal(err)
		}
	}
	if err := c.ValidateServer(); err != nil {
		t.Fatal(err)
	}
	if err := c.ValidateAgent(); err != nil {
		t.Fatal(err)
	}
	if len(c.Sources) != 5 || c.Sources[1].Engine != "mysql" || c.Sources[0].Match.Host != "corebank" {
		t.Fatalf("%+v", c.Sources)
	}
}
