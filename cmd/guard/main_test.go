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
	c, err := installConfig("", []string{app}, guid)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Applications) != 1 || c.Applications[0] != app || c.VPNInterface.GUID != guid || c.LoopbackPolicy != "deny" {
		t.Fatalf("unexpected direct config: %+v", c)
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
		_, err := installConfig(tc.file, apps, tc.guid)
		if err == nil || (!strings.Contains(err.Error(), "--vpn-guid") && !strings.Contains(err.Error(), "--config")) {
			t.Fatalf("expected source error for %+v; got %v", tc, err)
		}
	}
}
