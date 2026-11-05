package wfp

import (
	"runtime"
	"testing"
	"unsafe"

	"kill-switch/internal/policy"
)

func TestPreviewFingerprintChangesWithWFPAndApplication(t *testing.T) {
	p := policy.Plan{Kind: "UNVERIFIED_DRY_RUN", ProviderGUID: policy.ProviderGUID, SublayerGUID: policy.SublayerGUID, Add: []policy.Rule{{Key: "rule-1", Application: `C:\Lab\probe.exe`}}}
	s := Snapshot{Filters: []FilterState{{Key: "rule-0"}}}
	AttachSnapshot(&p, s)
	if p.ExistingWFPState != "READ" || len(p.Delete) != 1 || p.Fingerprint == "" || p.Digest() != p.Fingerprint {
		t.Fatalf("plan binding: %+v", p)
	}
	other := p
	other.Add = append([]policy.Rule(nil), p.Add...)
	other.Add[0].Application = `C:\Lab\claude.exe`
	if other.Digest() == p.Fingerprint {
		t.Fatal("application change left fingerprint unchanged")
	}
	other = p
	other.Interface.LUID = 123
	if other.Digest() == p.Fingerprint {
		t.Fatal("LUID change left fingerprint unchanged")
	}
	other = p
	AttachSnapshot(&other, Snapshot{Filters: []FilterState{{Key: "rule-2"}}})
	if other.Fingerprint == p.Fingerprint {
		t.Fatal("WFP change left fingerprint unchanged")
	}
}

func TestValueUnionPointerAndScalar(t *testing.T) {
	n := new(uint64)
	*n = 0x12345678abcdef00
	var pin runtime.Pinner
	pin.Pin(n)
	defer pin.Unpin()
	v := value{Type: uint64Type, Value: uintptr(unsafe.Pointer(n))}
	if got := *(*uint64)(v.pointer()); got != *n {
		t.Fatalf("pointer-valued union: %x", got)
	}
	v = value{Type: uint32Type, Value: loopbackFlag}
	if uint32(v.Value) != loopbackFlag {
		t.Fatalf("scalar-valued union: %x", v.Value)
	}
	runtime.KeepAlive(n)
}
