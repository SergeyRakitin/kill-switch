package desktop

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"kill-switch/internal/policy"
	"kill-switch/internal/ui"
	"kill-switch/internal/wfp"
)

const testGUID = "5d9bfb35-0e98-4b08-a233-e8cd2219514f"
const emptyStatus = `{"state":"disabled","wfp":{"provider":{"present":false},"sublayer":{"present":false},"filters":[]}}`

func newTestService(t *testing.T, run func(context.Context, ...string) ([]byte, error)) *Service {
	t.Helper()
	service, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	service.view.Settings.VPNInterfaceGUID = testGUID
	service.client = ui.Client{RunContext: run, Warnings: make(chan string, 8)}
	return service
}

func TestServiceRequiresConfirmationAndCurrentPreview(t *testing.T) {
	var calls [][]string
	service := newTestService(t, func(_ context.Context, args ...string) ([]byte, error) {
		calls = append(calls, args)
		if args[0] == "install" && slices.Contains(args, "--dry-run") {
			return previewJSON("preview", "digest"), nil
		}
		t.Fatalf("unexpected guard call: %v", args)
		return nil, nil
	})
	for _, request := range []func() (View, error){
		func() (View, error) { return service.Apply("preview", false) },
		func() (View, error) { return service.Apply("preview", true) },
		func() (View, error) { return service.Remove(false) },
		func() (View, error) { return service.Canary(false) },
		func() (View, error) { return service.SetTarget("probe", false, false) },
		func() (View, error) { return service.RemoveTarget("probe", true) },
	} {
		if _, err := request(); err == nil {
			t.Fatal("unexpected authorization")
		}
	}
	if len(calls) != 0 || !service.Snapshot().Settings.Targets[0].Enabled {
		t.Fatalf("request changed state: %v", calls)
	}
	preview, err := service.Preview()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.SetTarget("probe", false, true); err != nil {
		t.Fatal(err)
	}
	if _, err := service.SetTarget("probe", true, false); err != nil {
		t.Fatal(err)
	}
	view, err := service.Apply(preview.Fingerprint, true)
	if err == nil || !strings.Contains(err.Error(), "устарел") || len(calls) != 1 || !view.ConfigDirty {
		t.Fatalf("stale plan after reverted settings: calls=%v dirty=%v error=%v", calls, view.ConfigDirty, err)
	}
}

func TestServiceKeepsSnapshotResponsiveAndSerializesOperations(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	service := newTestService(t, func(_ context.Context, args ...string) ([]byte, error) {
		switch args[0] {
		case "uninstall":
			close(entered)
			<-release
			return nil, nil
		case "status":
			return []byte(emptyStatus), nil
		case "diagnose":
			return []byte(`{"adapters":[]}`), nil
		default:
			t.Errorf("unexpected guard call: %v", args)
			return nil, errors.New("unexpected command")
		}
	})
	done := make(chan error, 1)
	go func() {
		_, err := service.Remove(true)
		done <- err
	}()
	defer func() {
		close(release)
		if err := <-done; err != nil {
			t.Errorf("remove: %v", err)
		}
		if service.IsMutating() || service.Snapshot().Busy {
			t.Error("busy or mutating remained set")
		}
		if !BeginShutdown(service) || !BeginShutdown(service) {
			t.Error("idle shutdown was not accepted")
		}
		if _, err := service.Remove(true); err == nil {
			t.Error("mutation accepted after shutdown began")
		}
	}()
	<-entered

	if !service.IsMutating() || !service.Snapshot().Busy {
		t.Fatal("in-progress mutation missing")
	}
	if BeginShutdown(service) {
		t.Fatal("shutdown accepted during mutation")
	}
	if _, err := service.Refresh(); err == nil {
		t.Fatal("concurrent operation accepted")
	}
	if _, err := service.SetTarget("probe", false, true); err == nil {
		t.Fatal("concurrent settings change accepted")
	}
}

func TestServiceDistinguishesCommandFailureFromReadFailure(t *testing.T) {
	for _, tc := range []struct {
		name, statusJSON, wantStatus, wantError string
		statusErr, commandErr                   error
	}{
		{"command failure", emptyStatus, "disabled", "command stderr", nil, errors.New("command stderr")},
		{"read failure", `{"state":"unknown"}`, "error", "read stderr", errors.New("read stderr"), nil},
		{"malformed status", `{"state":"disabled"}`, "error", "не вернула полный снимок", nil, nil},
		{"truncated snapshot", `{"state":"disabled","wfp":{}}`, "error", "не вернула полный снимок", nil, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			service := newTestService(t, func(_ context.Context, args ...string) ([]byte, error) {
				switch args[0] {
				case "uninstall":
					return nil, tc.commandErr
				case "status":
					return []byte(tc.statusJSON), tc.statusErr
				case "diagnose":
					return []byte(`{"adapters":[]}`), nil
				}
				t.Fatalf("unexpected guard call: %v", args)
				return nil, nil
			})
			view, err := service.Remove(true)
			if err == nil || !strings.Contains(err.Error(), tc.wantError) || view.Status != tc.wantStatus {
				t.Fatalf("status=%q error=%v", view.Status, err)
			}
			if !strings.Contains(view.Diagnostic, tc.wantError) || len(view.VerifiedPaths) != 0 {
				t.Fatalf("diagnostics=%q paths=%v", view.Diagnostic, view.VerifiedPaths)
			}
		})
	}
}

func TestServiceRefreshRejectsChangedSnapshot(t *testing.T) {
	snapshot := wfp.Snapshot{Filters: []wfp.FilterState{{Key: "installed-filter"}}}
	raw, err := json.Marshal(map[string]any{"state": "unknown", "wfp": snapshot})
	if err != nil {
		t.Fatal(err)
	}
	service := newTestService(t, func(_ context.Context, args ...string) ([]byte, error) {
		switch args[0] {
		case "status":
			return raw, nil
		case "diagnose":
			return []byte(`{"adapters":[{"interfaceGuid":"` + testGUID + `","status":"Up","luid":18446744073709551615}]}`), nil
		case "install":
			if slices.Contains(args, "--dry-run") {
				return previewJSON("preview", "changed"), nil
			}
		}
		t.Fatalf("unexpected guard call: %v", args)
		return nil, nil
	})
	view, err := service.Refresh()
	if err != nil || view.Status != "unknown" || len(view.VerifiedPaths) != 0 || !view.ObjectsPresent ||
		!strings.Contains(view.Diagnostic, "изменилось между чтением") {
		t.Fatalf("view=%+v error=%v", view, err)
	}
	if view.VPNStatus != "connected" || len(view.Adapters) != 1 || view.Adapters[0].LUID != "0xFFFFFFFFFFFFFFFF" {
		t.Fatalf("adapter state or LUID lost: %+v", view.Adapters)
	}
}

func previewJSON(fingerprint, digest string) []byte {
	plan := ui.Plan{
		Kind: "UNVERIFIED_DRY_RUN", ExistingWFPState: "READ",
		ProviderGUID: policy.ProviderGUID, SublayerGUID: policy.SublayerGUID,
		Fingerprint: fingerprint, SnapshotDigest: digest,
	}
	raw, _ := json.Marshal(plan)
	return raw
}

func TestServiceRefreshExplainsAccessDenied(t *testing.T) {
	service := newTestService(t, func(_ context.Context, args ...string) ([]byte, error) {
		switch args[0] {
		case "status":
			return []byte(`{"state":"unknown"}`), errors.New("guard.exe: FwpmFilterCreateEnumHandle0: 0x00000005 (ERROR_ACCESS_DENIED)")
		case "diagnose":
			return []byte(`{"adapters":[]}`), nil
		default:
			t.Fatalf("unexpected guard call: %v", args)
			return nil, nil
		}
	})
	view, err := service.Refresh()
	if err == nil || !strings.Contains(view.Reason, "от имени администратора") || !strings.Contains(view.Diagnostic, "ERROR_ACCESS_DENIED") {
		t.Fatalf("view=%+v err=%v", view, err)
	}
}

func TestServiceRefreshFiltersAdapters(t *testing.T) {
	service := newTestService(t, func(_ context.Context, args ...string) ([]byte, error) {
		switch args[0] {
		case "status":
			return []byte(emptyStatus), nil
		case "diagnose":
			return []byte(`{"adapters":[
				{"name":"VPN Miniport","interfaceDescription":"WAN Miniport (IKEv2)","interfaceGuid":"miniport","status":"Up"},
				{"name":"Wi-Fi","interfaceDescription":"Intel(R) Wi-Fi","interfaceGuid":"wifi","status":"Up","hardwareInterface":true},
				{"name":"AmneziaVPN","interfaceDescription":"WireGuard Tunnel","interfaceGuid":"amnezia","status":"Up"}
			]}`), nil
		default:
			t.Fatalf("unexpected guard call: %v", args)
			return nil, nil
		}
	})
	view, err := service.Refresh()
	if err != nil || len(view.Adapters) != 2 || view.Adapters[0].GUID != "amnezia" || view.Adapters[1].GUID != "wifi" {
		t.Fatalf("adapters=%+v err=%v", view.Adapters, err)
	}
}

func TestServiceRemovesLegacyAndCustomTargets(t *testing.T) {
	service := newTestService(t, nil)
	service.view.Settings.Targets = append(service.view.Settings.Targets,
		ui.Target{ID: "claude", Path: `C:\Apps\Claude.exe`, Enabled: false},
		ui.Target{ID: "custom-codex-cli", Path: `C:\Apps\codex.exe`, Enabled: false},
	)
	for _, id := range []string{"claude", "custom-codex-cli"} {
		view, err := service.RemoveTarget(id, true)
		if err != nil || view.Settings.Target(id) != nil {
			t.Fatalf("remove %s: view=%+v err=%v", id, view.Settings.Targets, err)
		}
	}
	settings := service.Snapshot().Settings
	if len(settings.Targets) != 1 || settings.Target("probe") == nil {
		t.Fatalf("probe was removed: %+v", settings.Targets)
	}
}

func TestServiceReportsInstalledApplicationsAfterSettingsChange(t *testing.T) {
	snapshot := wfp.Snapshot{
		Provider: wfp.ObjectState{Present: true},
		Sublayer: wfp.ObjectState{Present: true},
		Filters: []wfp.FilterState{
			{Application: `C:\Apps\one.exe`},
			{Application: `C:\Apps\one.exe`},
			{Application: `D:\Apps\two.exe`},
		},
	}
	raw, err := json.Marshal(map[string]any{"state": "unknown", "wfp": snapshot})
	if err != nil {
		t.Fatal(err)
	}
	service := newTestService(t, func(_ context.Context, args ...string) ([]byte, error) {
		switch args[0] {
		case "status":
			return raw, nil
		case "diagnose":
			return []byte(`{"adapters":[]}`), nil
		case "install":
			return nil, errors.New("installed rules differ")
		default:
			t.Fatalf("unexpected guard call: %v", args)
			return nil, nil
		}
	})
	view, err := service.Refresh()
	want := []string{`C:\Apps\one.exe`, `D:\Apps\two.exe`}
	if err != nil || !slices.Equal(view.InstalledPaths, want) {
		t.Fatalf("installed paths=%v error=%v", view.InstalledPaths, err)
	}
	view, err = service.SetTarget("probe", false, true)
	if err != nil || !view.ConfigDirty || !slices.Equal(view.InstalledPaths, want) {
		t.Fatalf("dirty=%v installed paths=%v error=%v", view.ConfigDirty, view.InstalledPaths, err)
	}
}

func TestServiceAddsMSIXTarget(t *testing.T) {
	service := newTestService(t, nil)
	view, err := service.AddPackageTarget("Claude_pzs8sxrjxfjjc")
	if err != nil {
		t.Fatal(err)
	}
	var target *ui.Target
	for i := range view.Settings.Targets {
		if view.Settings.Targets[i].Kind() == ui.TargetTypeMSIX {
			target = &view.Settings.Targets[i]
		}
	}
	if target == nil || target.Path != "Claude_pzs8sxrjxfjjc" || !target.Enabled || !view.ConfigDirty {
		t.Fatalf("targets=%+v dirty=%v", view.Settings.Targets, view.ConfigDirty)
	}
	if _, err := service.AddPackageTarget("claude_pzs8sxrjxfjjc"); err == nil {
		t.Fatal("duplicate package family accepted")
	}
	if _, err := service.AddPackageTarget(`C:\Program Files\WindowsApps\Claude_`); err == nil {
		t.Fatal("folder accepted as package family")
	}
}

func TestServiceAddsNameTarget(t *testing.T) {
	service := newTestService(t, nil)
	view, err := service.AddNameTarget("  claude.exe ")
	if err != nil {
		t.Fatal(err)
	}
	var target *ui.Target
	for i := range view.Settings.Targets {
		if view.Settings.Targets[i].Kind() == ui.TargetTypeName {
			target = &view.Settings.Targets[i]
		}
	}
	if target == nil || target.Path != "claude.exe" || !target.Enabled || !strings.HasPrefix(target.ID, "custom-name-") || !view.ConfigDirty {
		t.Fatalf("targets=%+v dirty=%v", view.Settings.Targets, view.ConfigDirty)
	}
	if _, err := service.AddNameTarget("CLAUDE.EXE"); err == nil {
		t.Fatal("duplicate file name accepted")
	}
	for _, invalid := range []string{`C:\Users\me\AppData\Roaming\Claude\claude-code\2.1.321\claude.exe`, "*.exe", "claude"} {
		if _, err := service.AddNameTarget(invalid); err == nil {
			t.Fatalf("invalid file name accepted: %q", invalid)
		}
	}
	if _, err := service.BrowseTarget(target.ID); err == nil || !strings.Contains(err.Error(), "именем файла") {
		t.Fatalf("file picker allowed for name target: %v", err)
	}
}

func TestServicePreviewPassesNameTargets(t *testing.T) {
	var preview []string
	service := newTestService(t, func(_ context.Context, args ...string) ([]byte, error) {
		if args[0] == "install" && slices.Contains(args, "--dry-run") {
			preview = args
			return previewJSON("preview", "digest"), nil
		}
		t.Fatalf("unexpected guard call: %v", args)
		return nil, nil
	})
	if _, err := service.AddNameTarget("claude.exe"); err != nil {
		t.Fatal(err)
	}
	result, err := service.Preview()
	if err != nil {
		t.Fatal(err)
	}
	index := slices.Index(preview, "--file-name")
	if index < 0 || index+1 >= len(preview) || preview[index+1] != "claude.exe" || !slices.Contains(result.Apps, "name:claude.exe") {
		t.Fatalf("preview args=%v apps=%v", preview, result.Apps)
	}
}
