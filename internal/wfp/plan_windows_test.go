package wfp

import (
	"runtime"
	"syscall"
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

func TestVerifyPackageFamilyRule(t *testing.T) {
	family := "Claude_pzs8sxrjxfjjc"
	sid, err := packageSIDString(family)
	if err != nil {
		t.Fatal(err)
	}
	rule := policy.Rule{
		Key: "rule-msix", PackageFamily: family, Layer: "FWPM_LAYER_ALE_AUTH_CONNECT_V4", Action: "BLOCK", Weight: 100, Persistent: true,
		Conditions: []policy.Condition{{Field: "FWPM_CONDITION_ALE_PACKAGE_ID", Operator: "EQUAL", Value: family}},
	}
	actual := Snapshot{
		Provider: ObjectState{Present: true, Persistent: true},
		Sublayer: ObjectState{Present: true, Persistent: true},
		Filters: []FilterState{{
			Key: rule.Key, PackageFamily: family, Flags: persistent, Layer: rule.Layer, Action: actionBlock, Weight: 100, Persistent: true, ConditionCount: 1,
			Conditions: []ConditionState{{Field: "FWPM_CONDITION_ALE_PACKAGE_ID", Match: matchEqual, Type: sidType, Value: sid}},
		}},
	}
	if err := Verify(policy.Plan{Add: []policy.Rule{rule}}, actual); err != nil {
		t.Fatal(err)
	}
	actual.Filters[0].Conditions[0].Type = byteBlobType
	if err := Verify(policy.Plan{Add: []policy.Rule{rule}}, actual); err == nil {
		t.Fatal("PACKAGE_ID type mismatch accepted")
	}
}

func TestVerifyFileNameRule(t *testing.T) {
	rule := policy.Rule{
		Key: "rule-name", FileName: "Claude.exe", Layer: "FWPM_LAYER_ALE_AUTH_CONNECT_V4", Action: "BLOCK", Weight: 100, Persistent: true,
		Conditions: []policy.Condition{{Field: "FWPM_CONDITION_ALE_APP_ID", Operator: "SUFFIX", Value: `\claude.exe`}},
	}
	actual := Snapshot{
		Provider: ObjectState{Present: true, Persistent: true},
		Sublayer: ObjectState{Present: true, Persistent: true},
		Filters: []FilterState{{
			Key: rule.Key, FileName: "claude.exe", Flags: persistent, Layer: rule.Layer, Action: actionBlock, Weight: 100, Persistent: true, ConditionCount: 1,
			Conditions: []ConditionState{{Field: "FWPM_CONDITION_ALE_APP_ID", Match: matchSuffix, Type: byteBlobType, Value: `\claude.exe`}},
		}},
	}
	plan := policy.Plan{Add: []policy.Rule{rule}}
	if err := Verify(plan, actual); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*ConditionState){
		"exact match":  func(c *ConditionState) { c.Match = matchEqual },
		"other suffix": func(c *ConditionState) { c.Value = `\codex.exe` },
		"wrong type":   func(c *ConditionState) { c.Type = sidType },
	} {
		changed := actual
		changed.Filters = []FilterState{actual.Filters[0]}
		changed.Filters[0].Conditions = []ConditionState{actual.Filters[0].Conditions[0]}
		change(&changed.Filters[0].Conditions[0])
		if err := Verify(plan, changed); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	rule.Conditions[0].Value = `\codex.exe`
	if err := Verify(policy.Plan{Add: []policy.Rule{rule}}, actual); err == nil {
		t.Fatal("plan condition that differs from the file name accepted")
	}
}

func TestFileNameSuffixData(t *testing.T) {
	data, err := fileNameSuffixData("Claude.EXE")
	if err != nil {
		t.Fatal(err)
	}
	if data[len(data)-1] != 0 || syscall.UTF16ToString(data) != `\claude.exe` {
		t.Fatalf("suffix=%q data=%v", syscall.UTF16ToString(data), data)
	}
	blob := byteBlob{Size: uint32(len(data) * 2), Data: (*byte)(unsafe.Pointer(&data[0]))}
	if got, err := appIDSuffix(&blob); err != nil || got != `\claude.exe` {
		t.Fatalf("round trip=%q error=%v", got, err)
	}
	for _, invalid := range []string{`C:\Apps\claude.exe`, "*.exe", ""} {
		if _, err := fileNameSuffixData(invalid); err == nil {
			t.Fatalf("invalid file name accepted: %q", invalid)
		}
	}
	unterminated := byteBlob{Size: uint32((len(data) - 1) * 2), Data: (*byte)(unsafe.Pointer(&data[0]))}
	if _, err := appIDSuffix(&unterminated); err == nil {
		t.Fatal("suffix without NUL accepted")
	}
	runtime.KeepAlive(data)
}

func TestOwnedFilterWithSuffixCondition(t *testing.T) {
	data, err := fileNameSuffixData("claude.exe")
	if err != nil {
		t.Fatal(err)
	}
	blob := &byteBlob{Size: uint32(len(data) * 2), Data: (*byte)(unsafe.Pointer(&data[0]))}
	var pin runtime.Pinner
	pin.Pin(&data[0])
	pin.Pin(blob)
	defer pin.Unpin()
	conditions := []condition{{Field: fieldAppID, Match: matchSuffix, Value: value{Type: byteBlobType, Value: uintptr(unsafe.Pointer(blob))}}}
	f := &filter{Layer: layerConnect4, Flags: persistent, Action: action{Type: actionBlock}, ConditionCount: 1, Conditions: &conditions[0]}
	if !validOwnedFilter(f) {
		t.Fatal("suffix identity rejected")
	}
	observed, err := readConditions(f)
	if err != nil || len(observed) != 1 || observed[0].Match != matchSuffix || observed[0].Value != `\claude.exe` {
		t.Fatalf("observed=%+v error=%v", observed, err)
	}
	conditions[0].Match = matchFlagsNoneSet
	if validOwnedFilter(f) {
		t.Fatal("AppID condition with unexpected match type accepted as identity")
	}
	runtime.KeepAlive(conditions)
	runtime.KeepAlive(blob)
}

func TestSplitTarget(t *testing.T) {
	for target, want := range map[string][3]string{
		`C:\Lab\probe.exe`:          {`C:\Lab\probe.exe`, "", ""},
		"msix:Claude_pzs8sxrjxfjjc": {"", "Claude_pzs8sxrjxfjjc", ""},
		"name:claude.exe":           {"", "", "claude.exe"},
	} {
		application, family, name := splitTarget(target)
		if [3]string{application, family, name} != want {
			t.Fatalf("%s: %q %q %q", target, application, family, name)
		}
	}
}
