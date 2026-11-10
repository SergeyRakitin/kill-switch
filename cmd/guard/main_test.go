package main

import (
	"os"
	"strings"
	"testing"
)

func TestInstallConfigDirectPath(t *testing.T) {
	app, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	guid := "ab5f47c1-3f3e-4ac3-83c0-c2ff7bb68cd8"
	c, err := installConfig("", []string{app}, []string{"Claude_pzs8sxrjxfjjc"}, []string{"claude.exe"}, guid)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Applications) != 1 || c.Applications[0] != app || len(c.PackageFamilies) != 1 || c.PackageFamilies[0] != "Claude_pzs8sxrjxfjjc" || len(c.FileNames) != 1 || c.FileNames[0] != "claude.exe" || c.VPNInterface.GUID != guid || c.LoopbackPolicy != "deny" {
		t.Fatalf("unexpected direct config: %+v", c)
	}
	if _, err := installConfig("", nil, nil, []string{`C:\Apps\claude.exe`}, guid); err == nil {
		t.Fatal("path accepted as file name")
	}
	if _, err := installConfig("x.json", nil, nil, []string{"claude.exe"}, ""); err == nil || !strings.Contains(err.Error(), "--file-name") {
		t.Fatalf("file name mixed with --config: %v", err)
	}
}

func TestInstallConfigRequiresOneCompleteSource(t *testing.T) {
	for _, tc := range []struct{ file, app, guid string }{
		{},
		{app: `C:\\Lab\\guard-probe.exe`},
		{file: "x.json", app: `C:\\Lab\\guard-probe.exe`, guid: "ab5f47c1-3f3e-4ac3-83c0-c2ff7bb68cd8"},
	} {
		var apps []string
		if tc.app != "" {
			apps = []string{tc.app}
		}
		_, err := installConfig(tc.file, apps, nil, nil, tc.guid)
		if err == nil || (!strings.Contains(err.Error(), "--vpn-guid") && !strings.Contains(err.Error(), "--config")) {
			t.Fatalf("expected source error for %+v; got %v", tc, err)
		}
	}
}
