package wfp

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"kill-switch/internal/policy"
)

var ErrCommitUnknown = errors.New("WFP commit result is unknown; re-read status before any cleanup")
var ErrAppliedVerification = errors.New("WFP committed, but verification failed")
var Observe func(name string, started time.Time, err error, attrs ...any)

func observed(name string, started time.Time, err error, attrs ...any) {
	if Observe != nil {
		Observe(name, started, err, attrs...)
	}
}

func SnapshotDigest(s Snapshot) string {
	sort.Slice(s.Filters, func(i, j int) bool { return s.Filters[i].Key < s.Filters[j].Key })
	b, _ := json.Marshal(s)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func AttachSnapshot(p *policy.Plan, s Snapshot) {
	p.ExistingWFPState = "READ"
	p.Delete = p.Delete[:0]
	for _, f := range s.Filters {
		p.Delete = append(p.Delete, f.Key)
	}
	sort.Strings(p.Delete)
	p.SnapshotDigest = SnapshotDigest(s)
	p.Fingerprint = p.Digest()
}

func Current() (Snapshot, error) {
	started := time.Now()
	e, err := Open()
	observed("wfp_open", started, err)
	if err != nil {
		return Snapshot{}, err
	}
	defer e.Close()
	started = time.Now()
	s, err := e.Snapshot()
	observed("wfp_read", started, err, "filters", len(s.Filters))
	return s, err
}

// PrepareCanary creates only the owned provider and sublayer, with no filters.
// It is for checking emergency removal on the approved bench before policy installation.
func PrepareCanary() error {
	started := time.Now()
	e, err := Open()
	observed("wfp_open", started, err)
	if err != nil {
		return err
	}
	defer e.Close()
	started = time.Now()
	if err := e.Begin(); err != nil {
		observed("wfp_begin", started, err)
		return err
	}
	observed("wfp_begin", started, nil)
	inTxn := true
	defer func() {
		if inTxn {
			started := time.Now()
			err := e.Abort()
			observed("wfp_abort", started, err)
		}
	}()
	started = time.Now()
	before, err := e.Snapshot()
	observed("wfp_read_in_transaction", started, err, "filters", len(before.Filters))
	if err != nil {
		return err
	}
	if before.Provider.Present || before.Sublayer.Present || len(before.Filters) > 0 {
		return errors.New("canary refused: owned WFP objects already exist")
	}
	if err := e.addProvider(); err != nil {
		return err
	}
	if err := e.addSublayer(); err != nil {
		return err
	}
	started = time.Now()
	err = e.Commit()
	observed("wfp_commit", started, err)
	inTxn = false
	if err != nil {
		return fmt.Errorf("%w: %v", ErrCommitUnknown, err)
	}
	started = time.Now()
	after, err := e.Snapshot()
	observed("wfp_verify_read", started, err, "filters", len(after.Filters))
	if err != nil {
		return fmt.Errorf("%w: %v", ErrAppliedVerification, err)
	}
	if !after.Provider.Present || !after.Sublayer.Present || len(after.Filters) > 0 {
		return fmt.Errorf("%w: recovery test objects differ", ErrAppliedVerification)
	}
	return nil
}

func Install(plan policy.Plan) error {
	if plan.Kind != "UNVERIFIED_DRY_RUN" || plan.ProviderGUID != policy.ProviderGUID || plan.SublayerGUID != policy.SublayerGUID || plan.ExistingWFPState != "READ" || plan.Fingerprint == "" || plan.Fingerprint != plan.Digest() {
		return errors.New("invalid policy plan")
	}
	started := time.Now()
	e, err := Open()
	observed("wfp_open", started, err)
	if err != nil {
		return err
	}
	defer e.Close()
	started = time.Now()
	if err := e.Begin(); err != nil {
		observed("wfp_begin", started, err)
		return err
	}
	observed("wfp_begin", started, nil)
	inTxn := true
	defer func() {
		if inTxn {
			started := time.Now()
			err := e.Abort()
			observed("wfp_abort", started, err)
		}
	}()
	started = time.Now()
	old, err := e.Snapshot()
	observed("wfp_read_in_transaction", started, err, "filters", len(old.Filters))
	if err != nil {
		return err
	}
	if plan.Interface.LUID != 0 {
		luid, luidErr := currentLUID(plan.Interface.GUID)
		if luidErr != nil {
			return fmt.Errorf("verify VPN LUID: %w", luidErr)
		}
		if luid != plan.Interface.LUID {
			return errors.New("VPN LUID changed after preview; create a new preview")
		}
	}
	if SnapshotDigest(old) != plan.SnapshotDigest {
		return errors.New("WFP state changed after preview; create a new preview")
	}
	if len(old.Filters) != len(plan.Delete) {
		return errors.New("WFP delete set changed after preview")
	}
	for i, f := range old.Filters {
		if f.Key != plan.Delete[i] {
			return errors.New("WFP delete set changed after preview")
		}
	}
	if len(plan.Add) == 0 {
		for _, f := range old.Filters {
			if err := e.deleteFilter(f.Key); err != nil {
				return err
			}
		}
		started = time.Now()
		err = e.Commit()
		observed("wfp_commit", started, err)
		inTxn = false
		if err != nil {
			return fmt.Errorf("%w: %v", ErrCommitUnknown, err)
		}
		started = time.Now()
		after, readErr := e.Snapshot()
		observed("wfp_verify_read", started, readErr, "filters", len(after.Filters))
		if readErr != nil {
			return fmt.Errorf("%w: %v", ErrAppliedVerification, readErr)
		}
		if len(after.Filters) != 0 {
			return fmt.Errorf("%w: %d filters remain", ErrAppliedVerification, len(after.Filters))
		}
		return nil
	}
	if old.Provider.Disabled || old.Sublayer.Disabled || old.Provider.ServiceName != "" {
		return errors.New("owned WFP objects are disabled or service-bound")
	}
	if !old.Provider.Present {
		if err := e.addProvider(); err != nil {
			return err
		}
	}
	if !old.Sublayer.Present {
		if err := e.addSublayer(); err != nil {
			return err
		}
	}
	for _, f := range old.Filters {
		if err := e.deleteFilter(f.Key); err != nil {
			return err
		}
	}
	for _, r := range plan.Add {
		if err := e.addRule(r); err != nil {
			return err
		}
	}
	started = time.Now()
	err = e.Commit()
	observed("wfp_commit", started, err)
	inTxn = false
	if err != nil {
		return fmt.Errorf("%w: %v", ErrCommitUnknown, err)
	}
	started = time.Now()
	actual, err := e.Snapshot()
	observed("wfp_verify_read", started, err, "filters", len(actual.Filters))
	if err != nil {
		return fmt.Errorf("%w: %v", ErrAppliedVerification, err)
	}
	started = time.Now()
	if err := Verify(plan, actual); err != nil {
		observed("wfp_verify_plan", started, err)
		return fmt.Errorf("%w: %v", ErrAppliedVerification, err)
	}
	observed("wfp_verify_plan", started, nil)
	return nil
}

func Remove(all bool) error {
	started := time.Now()
	e, err := Open()
	observed("wfp_open", started, err)
	if err != nil {
		return err
	}
	defer e.Close()
	started = time.Now()
	if err := e.Begin(); err != nil {
		observed("wfp_begin", started, err)
		return err
	}
	observed("wfp_begin", started, nil)
	inTxn := true
	defer func() {
		if inTxn {
			started := time.Now()
			err := e.Abort()
			observed("wfp_abort", started, err)
		}
	}()
	started = time.Now()
	old, err := e.Snapshot()
	observed("wfp_read_in_transaction", started, err, "filters", len(old.Filters))
	if err != nil {
		return err
	}
	if len(old.Filters) == 0 && (!all || (!old.Provider.Present && !old.Sublayer.Present)) {
		after, readErr := e.Snapshot()
		if readErr != nil {
			return fmt.Errorf("remove verification: %w", readErr)
		}
		if len(after.Filters) != 0 {
			return errors.New("owned WFP filters appeared during removal")
		}
		return nil
	}
	for _, f := range old.Filters {
		if err := e.deleteFilter(f.Key); err != nil {
			return err
		}
	}
	if all {
		if old.Sublayer.Present {
			if err := invoke(sublayerDelete, e.handle, uintptr(unsafe.Pointer(&sublayerKey))); err != nil {
				return err
			}
		}
		if old.Provider.Present {
			if err := invoke(providerDelete, e.handle, uintptr(unsafe.Pointer(&providerKey))); err != nil {
				return err
			}
		}
	}
	started = time.Now()
	err = e.Commit()
	observed("wfp_commit", started, err)
	inTxn = false
	if err != nil {
		return fmt.Errorf("%w: %v", ErrCommitUnknown, err)
	}
	started = time.Now()
	after, err := e.Snapshot()
	observed("wfp_verify_read", started, err, "filters", len(after.Filters))
	if err != nil {
		return fmt.Errorf("%w: %v", ErrAppliedVerification, err)
	}
	if len(after.Filters) != 0 || (all && (after.Provider.Present || after.Sublayer.Present)) {
		return fmt.Errorf("%w: owned WFP objects remain after removal", ErrAppliedVerification)
	}
	return nil
}

func Verify(plan policy.Plan, actual Snapshot) error {
	if !actual.Provider.Present || !actual.Provider.Persistent || actual.Provider.Disabled || actual.Provider.ServiceName != "" || !actual.Sublayer.Present || !actual.Sublayer.Persistent {
		return errors.New("provider or sublayer not active and persistent")
	}
	if len(actual.Filters) != len(plan.Add) {
		return fmt.Errorf("filter count: want %d got %d", len(plan.Add), len(actual.Filters))
	}
	byKey := map[string]FilterState{}
	for _, f := range actual.Filters {
		byKey[f.Key] = f
	}
	for _, r := range plan.Add {
		f, ok := byKey[strings.ToLower(r.Key)]
		if !ok {
			return fmt.Errorf("filter %s missing", r.Key)
		}
		action := uint32(actionBlock)
		if r.Action == "PERMIT_SOFT" {
			action = actionPermit
		}
		if f.Layer != r.Layer || f.Action != action || f.Weight != r.Weight || f.Disabled || !f.Persistent || f.Flags&(persistent|2|8|16) != persistent || f.ConditionCount != uint32(len(r.Conditions)) {
			return fmt.Errorf("filter %s differs from plan", r.Key)
		}
		appHash, err := appIDHash(r.Application)
		if err != nil {
			return err
		}
		for i, c := range r.Conditions {
			if i >= len(f.Conditions) {
				return fmt.Errorf("filter %s missing condition", r.Key)
			}
			observed := f.Conditions[i]
			if observed.Field != c.Field {
				return fmt.Errorf("filter %s condition field differs", r.Key)
			}
			wantMatch := uint32(matchEqual)
			wantType := uint32(byteBlobType)
			wantValue := appHash
			switch c.Field {
			case "FWPM_CONDITION_IP_NEXTHOP_INTERFACE":
				wantType = uint64Type
				wantValue = c.Value
			case "FWPM_CONDITION_FLAGS":
				wantType = uint32Type
				wantMatch = matchFlagsNoneSet
				wantValue = "0x00000001"
			case "FWPM_CONDITION_ALE_APP_ID":
			default:
				return fmt.Errorf("unexpected plan condition %s", c.Field)
			}
			if observed.Match != wantMatch || observed.Type != wantType || observed.Value != wantValue {
				return fmt.Errorf("filter %s condition differs", r.Key)
			}
		}
	}
	return nil
}

func appIDHash(path string) (string, error) {
	w, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return "", err
	}
	var ptr *byteBlob
	if err := invoke(getAppID, uintptr(unsafe.Pointer(w)), uintptr(unsafe.Pointer(&ptr))); err != nil {
		return "", err
	}
	defer free(&ptr)
	if ptr == nil {
		return "", errors.New("nil AppID")
	}
	b := ptr
	if b.Size == 0 || b.Size > 8192 || b.Data == nil {
		return "", errors.New("invalid AppID blob")
	}
	sum := sha256.Sum256(unsafe.Slice(b.Data, b.Size))
	runtime.KeepAlive(w)
	return hex.EncodeToString(sum[:]), nil
}

func (e *Engine) addProvider() error {
	started := time.Now()
	name, _ := syscall.UTF16PtrFromString("KS guard v1 provider")
	p := provider{Key: providerKey, Display: displayData{Name: name}, Flags: persistent}
	var pin runtime.Pinner
	pin.Pin(name)
	pin.Pin(&p)
	defer pin.Unpin()
	err := invoke(providerAdd, e.handle, uintptr(unsafe.Pointer(&p)), 0)
	observed("wfp_add_provider", started, err, "key", providerKey.String())
	runtime.KeepAlive(name)
	runtime.KeepAlive(p)
	return err
}
func (e *Engine) addSublayer() error {
	started := time.Now()
	name, _ := syscall.UTF16PtrFromString("KS guard v1 sublayer")
	s := sublayer{Key: sublayerKey, Display: displayData{Name: name}, Flags: persistent, ProviderKey: &providerKey, Weight: policy.SublayerWeight}
	var pin runtime.Pinner
	pin.Pin(name)
	pin.Pin(&s)
	defer pin.Unpin()
	err := invoke(sublayerAdd, e.handle, uintptr(unsafe.Pointer(&s)), 0)
	observed("wfp_add_sublayer", started, err, "key", sublayerKey.String())
	runtime.KeepAlive(name)
	runtime.KeepAlive(s)
	return err
}
func (e *Engine) deleteFilter(key string) error {
	started := time.Now()
	g, err := parseGUID(key)
	if err != nil {
		return err
	}
	err = invoke(filterDelete, e.handle, uintptr(unsafe.Pointer(&g)))
	observed("wfp_delete_filter", started, err, "key", key)
	return err
}

func (e *Engine) addRule(r policy.Rule) error {
	started := time.Now()
	key, err := parseGUID(r.Key)
	if err != nil {
		return err
	}
	var layer guid
	switch r.Layer {
	case "FWPM_LAYER_ALE_AUTH_CONNECT_V4":
		layer = layerConnect4
	case "FWPM_LAYER_ALE_AUTH_CONNECT_V6":
		layer = layerConnect6
	case "FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4":
		layer = layerRecv4
	case "FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6":
		layer = layerRecv6
	default:
		return fmt.Errorf("unsupported layer %s", r.Layer)
	}
	name, err := syscall.UTF16PtrFromString("KS guard v1 " + r.Action + " " + r.Application)
	if err != nil {
		return err
	}
	appPath, err := syscall.UTF16PtrFromString(r.Application)
	if err != nil {
		return err
	}
	var appPtr *byteBlob
	if err := invoke(getAppID, uintptr(unsafe.Pointer(appPath)), uintptr(unsafe.Pointer(&appPtr))); err != nil {
		return err
	}
	defer free(&appPtr)
	if appPtr == nil {
		return errors.New("FwpmGetAppIdFromFileName0 returned nil")
	}
	blob := appPtr
	weight := new(uint64)
	*weight = r.Weight
	conditions := make([]condition, 0, 3)
	luid := new(uint64)
	for _, c := range r.Conditions {
		switch c.Field {
		case "FWPM_CONDITION_ALE_APP_ID":
			if c.Operator != "EQUAL" {
				return errors.New("invalid AppID match")
			}
			conditions = append(conditions, condition{Field: fieldAppID, Match: matchEqual, Value: value{Type: byteBlobType, Value: uintptr(unsafe.Pointer(blob))}})
		case "FWPM_CONDITION_IP_NEXTHOP_INTERFACE":
			if c.Operator != "EQUAL" {
				return errors.New("invalid next-hop match")
			}
			*luid, err = strconv.ParseUint(strings.TrimPrefix(c.Value, "0x"), 16, 64)
			if err != nil {
				return err
			}
			conditions = append(conditions, condition{Field: fieldNextHop, Match: matchEqual, Value: value{Type: uint64Type, Value: uintptr(unsafe.Pointer(luid))}})
		case "FWPM_CONDITION_FLAGS":
			if c.Operator != "FLAGS_NONE_SET" || c.Value != "FWP_CONDITION_FLAG_IS_LOOPBACK" {
				return errors.New("invalid flag constraint")
			}
			conditions = append(conditions, condition{Field: fieldFlags, Match: matchFlagsNoneSet, Value: value{Type: uint32Type, Value: loopbackFlag}})
		default:
			return fmt.Errorf("unsupported condition %s", c.Field)
		}
	}
	if len(conditions) == 0 || conditions[0].Field != fieldAppID {
		return errors.New("rule without AppID")
	}
	if r.Action == "PERMIT_SOFT" && (len(conditions) != 3 || *luid == 0 || layer == layerRecv4 || layer == layerRecv6) {
		return errors.New("broad permit refused")
	}
	act := uint32(actionBlock)
	if r.Action == "PERMIT_SOFT" {
		act = actionPermit
	} else if r.Action != "BLOCK" {
		return errors.New("unknown action")
	}
	f := filter{Key: key, Display: displayData{Name: name}, Flags: persistent, ProviderKey: &providerKey, Layer: layer, Sublayer: sublayerKey, Weight: value{Type: uint64Type, Value: uintptr(unsafe.Pointer(weight))}, ConditionCount: uint32(len(conditions)), Conditions: &conditions[0], Action: action{Type: act}}
	var pin runtime.Pinner
	pin.Pin(weight)
	pin.Pin(luid)
	pin.Pin(&conditions[0])
	pin.Pin(&f)
	pin.Pin(name)
	pin.Pin(appPath)
	defer pin.Unpin()
	var id uint64
	err = invoke(filterAdd, e.handle, uintptr(unsafe.Pointer(&f)), 0, uintptr(unsafe.Pointer(&id)))
	observed("wfp_add_filter", started, err, "key", r.Key, "application", r.Application)
	runtime.KeepAlive(name)
	runtime.KeepAlive(appPath)
	runtime.KeepAlive(blob)
	runtime.KeepAlive(weight)
	runtime.KeepAlive(luid)
	runtime.KeepAlive(conditions)
	runtime.KeepAlive(f)
	return err
}

func currentLUID(raw string) (uint64, error) {
	g, err := parseGUID(raw)
	if err != nil {
		return 0, err
	}
	var luid uint64
	p := syscall.NewLazyDLL("iphlpapi.dll").NewProc("ConvertInterfaceGuidToLuid")
	rc, _, _ := p.Call(uintptr(unsafe.Pointer(&g)), uintptr(unsafe.Pointer(&luid)))
	runtime.KeepAlive(g)
	if rc != 0 {
		return 0, fmt.Errorf("ConvertInterfaceGuidToLuid: 0x%08X", uint32(rc))
	}
	return luid, nil
}
