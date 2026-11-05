package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidationRejectsAmbiguousCoverage(t *testing.T) {
	app := filepath.Join(t.TempDir(), "probe.exe")
	if err := os.WriteFile(app, []byte("test"), 0600); err != nil {
		t.Fatal(err)
	}
	c := Config{SchemaVersion: 1, Applications: []string{app}, VPNInterface: Interface{GUID: "05b44401-f55a-1be5-94c3-7fa54bb2d33e"}}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	c.Applications = []string{app, app}
	if err := c.Validate(); err == nil {
		t.Fatal("duplicate application accepted")
	}
	c.Applications = []string{`C:\path\*.exe`}
	if err := c.Validate(); err == nil {
		t.Fatal("wildcard accepted")
	}
	c.Applications = []string{app}
	c.SchemaVersion = 2
	if err := c.Validate(); err == nil {
		t.Fatal("unknown schema accepted")
	}
}
