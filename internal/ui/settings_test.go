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
	if len(s.Targets) != 1 || !s.Target("probe").Enabled || s.Target("claude") != nil || s.Target("codex") != nil {
		t.Fatalf("unexpected defaults: %+v", s.Targets)
	}
	if s.Target("probe").Path != "guard-probe.exe" {
		t.Fatalf("probe path: %s", s.Target("probe").Path)
	}
	s.Targets = append(s.Targets,
		Target{ID: "custom-claude-cli", Path: `C:\Lab\claude.exe`, Enabled: true},
		Target{ID: "custom-claude-desktop", Path: `C:\Lab\Desktop\claude.exe`, Enabled: true},
	)
	if paths, err := s.ActivePaths(dir); err != nil || len(paths) != 3 {
		t.Fatalf("active paths: %v, %v", paths, err)
	}
	s.Target("custom-claude-cli").Enabled = false
	s.Target("custom-claude-desktop").Enabled = false
	if paths, err := s.ActivePaths(dir); err != nil || len(paths) != 1 || paths[0] != filepath.Join(dir, "guard-probe.exe") {
		t.Fatalf("paths=%v err=%v", paths, err)
	}
	path := filepath.Join(dir, SettingsFile)
	if err := SaveSettings(path, s); err != nil {
		t.Fatal(err)
	}
	reloaded, err := LoadOrCreateSettings(dir)
	if err != nil || len(reloaded.Targets) != 3 {
		t.Fatalf("reload: %+v, %v", reloaded, err)
	}
}

func TestMigrationPreservesRealPathsAndRemovesPlaceholders(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, SettingsFile)
	s := DefaultSettings(dir)
	s.VPNInterfaceGUID = "{05B44401-F55A-1BE5-94C3-7FA54BB2D33E}"
	s.Targets = append(s.Targets,
		Target{ID: "claude", Path: `C:\Apps\Claude.exe`, Enabled: false},
		Target{ID: "codex", Path: "Z", Enabled: false},
		Target{ID: "custom-42", Path: `D:\Other\tool.exe`, Enabled: false},
	)
	s.NetworkAdapterTypes = nil
	b, _ := json.Marshal(s)
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	got, err := LoadOrCreateSettings(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got.VPNInterfaceGUID != s.VPNInterfaceGUID || got.Target("claude") == nil || got.Target("claude").Path != `C:\Apps\Claude.exe` || got.Target("custom-42") == nil {
		t.Fatalf("migration lost data: %+v", got)
	}
	if got.Target("codex") != nil || len(got.Targets) != 3 {
		t.Fatalf("placeholder was not removed: %+v", got.Targets)
	}
	if !reflect.DeepEqual(got.NetworkAdapterTypes, DefaultNetworkAdapterTypes()) {
		t.Fatalf("adapter defaults not migrated: %+v", got.NetworkAdapterTypes)
	}
	got2, err := LoadOrCreateSettings(dir)
	if err != nil || got2.Target("codex") != nil {
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
	for _, id := range []string{"custom-codex-cli", "custom-claude-cli", "custom-claude-desktop"} {
		s := DefaultSettings(t.TempDir())
		s.Targets = append(s.Targets, Target{ID: id, Path: `C:\Apps\app.exe`, Enabled: true})
		if err := s.Validate(); err != nil {
			t.Fatalf("%s: %v", id, err)
		}
	}
}

func TestMSIXTargetsRemainBackwardCompatible(t *testing.T) {
	dir := t.TempDir()
	s := DefaultSettings(dir)
	s.Targets = append(s.Targets,
		Target{ID: "custom-claude-msix", Type: TargetTypeMSIX, Path: "Claude_pzs8sxrjxfjjc", Enabled: true},
		Target{ID: "custom-codex-msix", Type: TargetTypeMSIX, Path: "OpenAI.Codex_2p2nqsd0c76g0", Enabled: true},
	)
	set, err := s.ActiveTargets(dir)
	if err != nil || len(set.Apps) != 1 || len(set.PackageFamilies) != 2 || len(set.FileNames) != 0 {
		t.Fatalf("targets=%+v error=%v", set, err)
	}
	if set.PackageFamilies[0] != "Claude_pzs8sxrjxfjjc" || set.PackageFamilies[1] != "OpenAI.Codex_2p2nqsd0c76g0" {
		t.Fatalf("packages=%v", set.PackageFamilies)
	}
	if err := SaveSettings(filepath.Join(dir, SettingsFile), s); err != nil {
		t.Fatal(err)
	}
	reloaded, err := LoadOrCreateSettings(dir)
	if err != nil || reloaded.Target("custom-claude-msix").Kind() != TargetTypeMSIX || reloaded.Target("probe").Kind() != TargetTypeEXE {
		t.Fatalf("reload=%+v error=%v", reloaded.Targets, err)
	}
	s.Target("custom-claude-msix").Path = `C:\Program Files\WindowsApps\Claude_`
	if err := s.Validate(); err == nil {
		t.Fatal("folder path accepted as package family")
	}
}

func TestNameTargets(t *testing.T) {
	dir := t.TempDir()
	s := DefaultSettings(dir)
	s.Targets = append(s.Targets,
		Target{ID: "custom-name-claude", Type: TargetTypeName, Path: "claude.exe", Enabled: true},
		Target{ID: "custom-name-cowork", Type: TargetTypeName, Path: "cowork-svc.exe", Enabled: true},
		Target{ID: "custom-name-off", Type: TargetTypeName, Path: "codex.exe", Enabled: false},
	)
	set, err := s.ActiveTargets(dir)
	if err != nil || len(set.Apps) != 1 || len(set.PackageFamilies) != 0 || !reflect.DeepEqual(set.FileNames, []string{"claude.exe", "cowork-svc.exe"}) {
		t.Fatalf("targets=%+v error=%v", set, err)
	}
	if got := set.Display(); !reflect.DeepEqual(got, []string{filepath.Join(dir, "guard-probe.exe"), "name:claude.exe", "name:cowork-svc.exe"}) {
		t.Fatalf("display=%v", got)
	}
	if set.Count() != 3 || !set.Equal(set.Clone()) {
		t.Fatalf("count=%d", set.Count())
	}
	if err := SaveSettings(filepath.Join(dir, SettingsFile), s); err != nil {
		t.Fatal(err)
	}
	reloaded, err := LoadOrCreateSettings(dir)
	if err != nil || reloaded.Target("custom-name-claude").Kind() != TargetTypeName {
		t.Fatalf("reload=%+v error=%v", reloaded.Targets, err)
	}
	s.Target("custom-name-cowork").Path = "CLAUDE.EXE"
	if _, err := s.ActiveTargets(dir); err == nil {
		t.Fatal("duplicate file name accepted")
	}
	for _, invalid := range []string{`C:\Apps\claude.exe`, "*.exe", "claude"} {
		s.Target("custom-name-cowork").Path = invalid
		if err := s.Validate(); err == nil {
			t.Fatalf("invalid file name accepted: %q", invalid)
		}
	}
}
