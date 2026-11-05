package runlog

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestJSONLAndClose(t *testing.T) {
	dir := t.TempDir()
	l, err := New("guard", dir, "info", "op-123", "run-123")
	if err != nil {
		t.Fatal(err)
	}
	l.Event("phase", "ok", time.Millisecond, "count", 2)
	l.Close("not_applied", time.Second)
	files, err := filepath.Glob(filepath.Join(dir, "guard-*.done.jsonl"))
	if err != nil || len(files) != 1 {
		t.Fatalf("files=%v err=%v", files, err)
	}
	f, err := os.Open(files[0])
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	count := 0
	for s.Scan() {
		var record map[string]any
		if err := json.Unmarshal(s.Bytes(), &record); err != nil {
			t.Fatal(err)
		}
		if record["runId"] != "run-123" || record["operationId"] != "op-123" {
			t.Fatalf("correlation: %v", record)
		}
		if stamp, ok := record["time"].(string); !ok || !strings.HasSuffix(stamp, "Z") {
			t.Fatalf("time is not UTC: %v", record["time"])
		}
		count++
	}
	if err := s.Err(); err != nil {
		t.Fatal(err)
	}
	if count != 3 {
		t.Fatalf("records=%d", count)
	}
}

func TestRotationAndActiveLogs(t *testing.T) {
	dir := t.TempDir()
	a, err := New("guard", dir, "info", "", "a")
	if err != nil {
		t.Fatal(err)
	}
	b, err := New("guard", dir, "info", "", "b")
	if err != nil {
		t.Fatal(err)
	}
	a.maxFile = 1
	a.Event("rotate", "ok", 0)
	active, err := filepath.Glob(filepath.Join(dir, "guard-*.jsonl"))
	if err != nil || len(active) < 2 {
		t.Fatalf("active files=%v err=%v", active, err)
	}
	a.Close("completed", 0)
	b.Event("still_active", "ok", 0)
	b.Close("completed", 0)
	done, _ := filepath.Glob(filepath.Join(dir, "guard-*.done.jsonl"))
	if len(done) < 3 {
		t.Fatalf("done files=%v", done)
	}
}

func TestFallbackAndBudget(t *testing.T) {
	root := t.TempDir()
	t.Setenv("LOCALAPPDATA", root)
	blocked := filepath.Join(root, "blocked")
	if err := os.WriteFile(blocked, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	l, err := New("guard", blocked, "info", "", "fallback")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(l.Path(), "KillSwitch") {
		t.Fatalf("fallback=%s", l.Path())
	}
	l.maxBudget = 1
	l.Event("exhausted", "ok", 0)
	if !l.failed {
		t.Fatal("budget did not stop logging")
	}
	l.Close("completed", 0)
}

func TestWriteFailureDoesNotPanicOrRetry(t *testing.T) {
	l, err := New("guard", t.TempDir(), "info", "op", "write-failure")
	if err != nil {
		t.Fatal(err)
	}
	if err := l.file.Close(); err != nil {
		t.Fatal(err)
	}
	l.Event("phase", "error", 0)
	if !l.failed {
		t.Fatal("write failure was not recorded")
	}
	l.Event("retry", "error", 0)
	l.Close("error", 0)
}

func TestExamples(t *testing.T) {
	dir := os.Getenv("KS_LOG_EXAMPLE_DIR")
	if dir == "" {
		t.Skip("set KS_LOG_EXAMPLE_DIR to write examples")
	}
	for _, tc := range []struct {
		component, runID, operationID, event, outcome string
		attrs                                         []any
	}{
		{"guard", "example-guard-ok", "ui-example-1", "wfp_verify_plan", "applied_verified", []any{"rules", 5}},
		{"guard", "example-guard-error", "ui-example-2", "wfp_begin", "error", []any{"error", map[string]any{"function": "FwpmTransactionBegin0", "code": "0x8032001C", "name": "FWP_E_NULL_POINTER", "message": "example only"}}},
		{"guard-probe", "example-probe-ok", "", "probe_attempt", "response", []any{"seq", 1, "status", 200, "bytes", 12}},
		{"guard-probe", "example-probe-error", "", "probe_attempt", "error", []any{"seq", 2, "error", map[string]any{"kind": "timeout", "message": "example only"}}},
	} {
		l, err := New(tc.component, dir, "info", tc.operationID, tc.runID)
		if err != nil {
			t.Fatal(err)
		}
		l.Event(tc.event, tc.outcome, 5*time.Millisecond, tc.attrs...)
		l.Close(tc.outcome, 10*time.Millisecond)
	}
}
