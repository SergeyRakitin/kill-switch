package config

import (
	"os"
	"path/filepath"
	"strings"
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
	missing := filepath.Join(filepath.Dir(app), "old-version", "probe.exe")
	c.Applications = []string{missing}
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), `"`+missing+`"`) || strings.Contains(err.Error(), `\\`) {
		t.Fatalf("missing application error must show the path with single backslashes: %v", err)
	}
	c.Applications = []string{app}
	c.SchemaVersion = 2
	if err := c.Validate(); err == nil {
		t.Fatal("unknown schema accepted")
	}
}

func TestPackageFamilyValidation(t *testing.T) {
	c := Config{SchemaVersion: 1, PackageFamilies: []string{"Claude_pzs8sxrjxfjjc", "OpenAI.Codex_2p2nqsd0c76g0"}, VPNInterface: Interface{GUID: "05b44401-f55a-1be5-94c3-7fa54bb2d33e"}}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []string{"", "Claude", "Claude_*", `C:\Program Files\WindowsApps\Claude_`, "two_families_here"} {
		c.PackageFamilies = []string{invalid}
		if err := c.Validate(); err == nil {
			t.Fatalf("invalid package family accepted: %q", invalid)
		}
	}
	c.PackageFamilies = []string{"Claude_pzs8sxrjxfjjc", "claude_pzs8sxrjxfjjc"}
	if err := c.Validate(); err == nil {
		t.Fatal("duplicate package family accepted")
	}
}

func TestFileNameValidation(t *testing.T) {
	c := Config{SchemaVersion: 1, FileNames: []string{"claude.exe", "cowork-svc.exe", "Claude Helper (1).EXE"}, VPNInterface: Interface{GUID: "05b44401-f55a-1be5-94c3-7fa54bb2d33e"}}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []string{
		"", ".exe", "...exe", "claude", "claude.dll", `C:\Apps\claude.exe`, `app\claude.exe`, "app/claude.exe",
		"*.exe", "cl?ude.exe", " claude.exe", "claude.exe ", "клод.exe", "claude\x00.exe", `cla"ude.exe`,
	} {
		c.FileNames = []string{invalid}
		if err := c.Validate(); err == nil {
			t.Fatalf("invalid file name accepted: %q", invalid)
		}
	}
	c.FileNames = []string{"claude.exe", "CLAUDE.EXE"}
	if err := c.Validate(); err == nil {
		t.Fatal("duplicate file name accepted")
	}
}
