package ui

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestPortableSettingsAndSafety(t *testing.T) {
	dir := t.TempDir()
	s, err := LoadOrCreateSettings(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, SettingsFile)); err != nil {
		t.Fatal(err)
	}
	if !s.Target("probe").Enabled || s.Target("claude").Enabled || s.Target("codex").Enabled {
		t.Fatalf("unsafe defaults: %+v", s.Targets)
	}
	if s.Target("probe").Path != "guard-probe.exe" {
		t.Fatalf("probe path: %s", s.Target("probe").Path)
	}
	s.Targets = append(s.Targets, Target{ID: "custom-1", Path: `C:\Lab\other.exe`, Enabled: true})
	if paths, err := s.ActivePaths(dir); err != nil || len(paths) != 2 {
		t.Fatalf("active paths: %v, %v", paths, err)
	}
	s.Target("custom-1").Enabled = false
	if paths, err := s.ActivePaths(dir); err != nil || len(paths) != 1 || paths[0] != filepath.Join(dir, "guard-probe.exe") {
		t.Fatalf("paths=%v err=%v", paths, err)
	}
	path := filepath.Join(dir, SettingsFile)
	if err := SaveSettings(path, s); err != nil {
		t.Fatal(err)
	}
	reloaded, err := LoadOrCreateSettings(dir)
	if err != nil || len(reloaded.Targets) != 4 {
		t.Fatalf("reload: %+v, %v", reloaded, err)
	}
}

func TestMigrationPreservesGUIDAndUserPaths(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, SettingsFile)
	s := DefaultSettings(dir)
	s.VPNInterfaceGUID = "{05B44401-F55A-1BE5-94C3-7FA54BB2D33E}"
	s.Target("claude").Path = `C:\Apps\Claude.exe`
	s.Target("codex").Path = ""
	s.NetworkAdapterTypes = nil
	s.Targets = append(s.Targets, Target{ID: "custom-42", Path: `D:\Other\tool.exe`, Enabled: false})
	b, _ := json.Marshal(s)
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	got, err := LoadOrCreateSettings(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got.VPNInterfaceGUID != s.VPNInterfaceGUID || got.Target("claude").Path != s.Target("claude").Path || got.Target("codex").Path != "Z" || got.Target("custom-42").Path != s.Target("custom-42").Path {
		t.Fatalf("migration lost data: %+v", got)
	}
	if !reflect.DeepEqual(got.NetworkAdapterTypes, DefaultNetworkAdapterTypes()) {
		t.Fatalf("adapter defaults not migrated: %+v", got.NetworkAdapterTypes)
	}
	got2, err := LoadOrCreateSettings(dir)
	if err != nil || got2.Target("codex").Path != "Z" {
		t.Fatalf("second load: %+v %v", got2, err)
	}
}

func TestTrailingJSONRejected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, SettingsFile)
	if err := os.WriteFile(path, []byte(`{"schemaVersion":1,"vpnInterfaceName":"AmneziaVPN","targets":[]} {}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateSettings(dir); err == nil {
		t.Fatal("trailing JSON accepted")
	}
}

func TestCodexAndClaudeCanBeEnabledThroughJSON(t *testing.T) {
	for _, id := range []string{"codex", "claude"} {
		s := DefaultSettings(t.TempDir())
		s.Target(id).Enabled = true
		if err := s.Validate(); err != nil {
			t.Fatalf("%s: %v", id, err)
		}
	}
}
