package ui

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"kill-switch/internal/policy"
)

func TestPreviewAndApplyMultipleApps(t *testing.T) {
	p := Plan{Kind: "UNVERIFIED_DRY_RUN", ExistingWFPState: "READ", ProviderGUID: policy.ProviderGUID, SublayerGUID: policy.SublayerGUID, Fingerprint: "hash"}
	b, _ := json.Marshal(p)
	var calls [][]string
	c := Client{RunContext: func(ctx context.Context, args ...string) ([]byte, error) {
		calls = append(calls, append([]string(nil), args...))
		if len(args) > 1 && args[1] == "--dry-run" {
			return b, nil
		}
		return nil, nil
	}}
	apps := []string{`C:\Lab\Claude.exe`, `C:\Lab\Codex.exe`}
	got, _, err := c.PreviewApps(context.Background(), apps, "guid")
	if err != nil || got.Fingerprint != "hash" {
		t.Fatalf("preview: %+v %v", got, err)
	}
	_, err = c.ApplyPlan(context.Background(), apps, "guid", got.Fingerprint, "op-1")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"install", "--vpn-guid", "guid", "--app", apps[0], "--app", apps[1], "--plan-fingerprint", "hash", "--yes", "--operation-id", "op-1"}
	if !reflect.DeepEqual(calls[1], want) {
		t.Fatalf("apply args: %v", calls[1])
	}
}

func TestEmptyAppsPreviewAndCancellation(t *testing.T) {
	p := Plan{Kind: "UNVERIFIED_DRY_RUN", ExistingWFPState: "READ", ProviderGUID: policy.ProviderGUID, SublayerGUID: policy.SublayerGUID, Fingerprint: "empty"}
	b, _ := json.Marshal(p)
	var calls [][]string
	c := Client{RunContext: func(ctx context.Context, args ...string) ([]byte, error) {
		calls = append(calls, append([]string(nil), args...))
		return b, nil
	}}
	if _, _, err := c.PreviewApps(context.Background(), nil, "guid"); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(calls[0], []string{"install", "--dry-run", "--vpn-guid", "guid"}) {
		t.Fatalf("zero apps: %v", calls[0])
	}
	c.RunContext = func(ctx context.Context, args ...string) ([]byte, error) { <-ctx.Done(); return nil, ctx.Err() }
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, err := c.PreviewApps(ctx, nil, "guid")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel: %v", err)
	}
}

func TestDelayedRunnerDoesNotBlockCaller(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	c := Client{RunContext: func(ctx context.Context, args ...string) ([]byte, error) {
		close(started)
		select {
		case <-release:
			return nil, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}}
	done := make(chan error, 1)
	go func() { _, err := c.StatusAsync(context.Background()); done <- err }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("runner did not start")
	}
	select {
	case <-done:
		t.Fatal("runner finished before release")
	default:
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestPreviewReportsUnreadableWFP(t *testing.T) {
	warning := "Existing WFP state could not be read: FwpmFilterCreateEnumHandle0: 0x00000005 (ERROR_ACCESS_DENIED)"
	p := Plan{
		Kind: "UNVERIFIED_DRY_RUN", ExistingWFPState: "UNKNOWN",
		ProviderGUID: policy.ProviderGUID, SublayerGUID: policy.SublayerGUID,
		Warnings: []string{warning},
	}
	b, _ := json.Marshal(p)
	c := Client{RunContext: func(context.Context, ...string) ([]byte, error) { return b, nil }}
	_, raw, err := c.PreviewApps(context.Background(), nil, "guid")
	if err == nil || !strings.Contains(err.Error(), warning) || !strings.Contains(err.Error(), "от имени администратора") {
		t.Fatalf("unhelpful preview error: %v", err)
	}
	if !strings.Contains(raw, "UNKNOWN") {
		t.Fatalf("raw plan lost: %s", raw)
	}
}

func TestWFPAdminGuidance(t *testing.T) {
	denied := errors.New("guard: FwpmTransactionBegin0: 0x00000005 (ERROR_ACCESS_DENIED)")
	err := WFPAdminGuidance(denied)
	if !errors.Is(err, denied) || !strings.Contains(err.Error(), "от имени администратора") {
		t.Fatalf("access guidance: %v", err)
	}
	if got := WFPAdminGuidance(err); got != err {
		t.Fatal("guidance appended twice")
	}
	other := errors.New("invalid argument")
	if got := WFPAdminGuidance(other); got != other {
		t.Fatalf("unrelated error changed: %v", got)
	}
}

func TestAdaptersAsyncReadsHardwareFlag(t *testing.T) {
	c := Client{RunContext: func(context.Context, ...string) ([]byte, error) {
		return []byte(`{"adapters":[{"name":"Wi-Fi","interfaceDescription":"Intel","interfaceGuid":"guid","status":"Up","hardwareInterface":true,"luid":42}]}`), nil
	}}
	adapters, err := c.AdaptersAsync(context.Background())
	if err != nil || len(adapters) != 1 || !adapters[0].HardwareInterface || adapters[0].LUID != 42 {
		t.Fatalf("adapters=%+v err=%v", adapters, err)
	}
}
