package wfp

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"runtime"
	"strings"
	"syscall"
	"unsafe"
)

const (
	errFilterNotFound   = 0x80320003
	errProviderNotFound = 0x80320005
	errSublayerNotFound = 0x80320007
)

var dll = syscall.NewLazyDLL("fwpuclnt.dll")
var (
	engineOpen        = dll.NewProc("FwpmEngineOpen0")
	engineClose       = dll.NewProc("FwpmEngineClose0")
	txnBegin          = dll.NewProc("FwpmTransactionBegin0")
	txnCommit         = dll.NewProc("FwpmTransactionCommit0")
	txnAbort          = dll.NewProc("FwpmTransactionAbort0")
	providerGet       = dll.NewProc("FwpmProviderGetByKey0")
	providerAdd       = dll.NewProc("FwpmProviderAdd0")
	providerDelete    = dll.NewProc("FwpmProviderDeleteByKey0")
	sublayerGet       = dll.NewProc("FwpmSubLayerGetByKey0")
	sublayerAdd       = dll.NewProc("FwpmSubLayerAdd0")
	sublayerDelete    = dll.NewProc("FwpmSubLayerDeleteByKey0")
	filterAdd         = dll.NewProc("FwpmFilterAdd0")
	filterDelete      = dll.NewProc("FwpmFilterDeleteByKey0")
	filterCreateEnum  = dll.NewProc("FwpmFilterCreateEnumHandle0")
	filterEnum        = dll.NewProc("FwpmFilterEnum0")
	filterDestroyEnum = dll.NewProc("FwpmFilterDestroyEnumHandle0")
	getAppID          = dll.NewProc("FwpmGetAppIdFromFileName0")
	freeMemory        = dll.NewProc("FwpmFreeMemory0")
)

// Preserve pointer arguments across stack growth in this syscall wrapper.
//
//go:uintptrescapes
func invoke(p *syscall.LazyProc, args ...uintptr) error {
	rc, _, _ := p.Call(args...)
	if uint32(rc) != 0 {
		return APIError{Function: p.Name, Code: uint32(rc)}
	}
	return nil
}

type APIError struct {
	Function string
	Code     uint32
}

func (e APIError) Error() string {
	return fmt.Sprintf("%s: 0x%08X (%s)", e.Function, e.Code, errorName(e.Code))
}
func (e APIError) Name() string { return errorName(e.Code) }

func errorName(code uint32) string {
	switch code {
	case 5:
		return "ERROR_ACCESS_DENIED"
	case 0x80320001:
		return "FWP_E_CALLOUT_NOT_FOUND"
	case 0x80320003:
		return "FWP_E_FILTER_NOT_FOUND"
	case 0x80320005:
		return "FWP_E_PROVIDER_NOT_FOUND"
	case 0x80320007:
		return "FWP_E_SUBLAYER_NOT_FOUND"
	case 0x8032001C:
		return "FWP_E_NULL_POINTER"
	default:
		return "UNKNOWN"
	}
}

type Engine struct{ handle uintptr }

func Open() (*Engine, error) {
	if err := checkABI(); err != nil {
		return nil, err
	}
	var h uintptr
	if err := invoke(engineOpen, 0, 10, 0, 0, uintptr(unsafe.Pointer(&h))); err != nil {
		return nil, err
	}
	if h == 0 {
		return nil, fmt.Errorf("FwpmEngineOpen0 succeeded with a null engine handle")
	}
	return &Engine{handle: h}, nil
}
func (e *Engine) Close() error {
	if e.handle == 0 {
		return nil
	}
	h := e.handle
	e.handle = 0
	return invoke(engineClose, h)
}
func (e *Engine) Begin() error  { return invoke(txnBegin, e.handle, 0) }
func (e *Engine) Commit() error { return invoke(txnCommit, e.handle) }
func (e *Engine) Abort() error  { return invoke(txnAbort, e.handle) }

//go:uintptrescapes
func free[T any](p **T) {
	if *p != nil {
		freeMemory.Call(uintptr(unsafe.Pointer(p)))
	}
}

type ObjectState struct {
	Present     bool   `json:"present"`
	Persistent  bool   `json:"persistent"`
	Disabled    bool   `json:"disabled"`
	ServiceName string `json:"serviceName,omitempty"`
}
type FilterState struct {
	Key            string           `json:"key"`
	Application    string           `json:"application,omitempty"`
	Flags          uint32           `json:"flags"`
	Layer          string           `json:"layer"`
	Action         uint32           `json:"action"`
	Weight         uint64           `json:"weight"`
	Persistent     bool             `json:"persistent"`
	Disabled       bool             `json:"disabled"`
	ConditionCount uint32           `json:"conditionCount"`
	Conditions     []ConditionState `json:"conditions"`
}
type ConditionState struct {
	Field string `json:"field"`
	Match uint32 `json:"match"`
	Type  uint32 `json:"type"`
	Value string `json:"value"`
}
type Snapshot struct {
	Provider ObjectState   `json:"provider"`
	Sublayer ObjectState   `json:"sublayer"`
	Filters  []FilterState `json:"filters"`
}

func (e *Engine) Snapshot() (Snapshot, error) {
	out := Snapshot{Filters: []FilterState{}}
	var providerPtr *provider
	rc, _, _ := providerGet.Call(e.handle, uintptr(unsafe.Pointer(&providerKey)), uintptr(unsafe.Pointer(&providerPtr)))
	switch uint32(rc) {
	case 0:
		p := providerPtr
		if p == nil {
			return out, fmt.Errorf("FwpmProviderGetByKey0 succeeded with a nil provider")
		}
		out.Provider = ObjectState{Present: true, Persistent: p.Flags&persistent != 0, Disabled: p.Flags&providerDisabled != 0}
		if p.ServiceName != nil {
			out.Provider.ServiceName = "<service-bound>"
		}
		if p.Key != providerKey || !strings.HasPrefix(utf16String(p.Display.Name), "KS guard v1") {
			free(&providerPtr)
			return out, fmt.Errorf("provider key collision or foreign owner")
		}
		free(&providerPtr)
	case errProviderNotFound:
	default:
		return out, APIError{Function: "FwpmProviderGetByKey0", Code: uint32(rc)}
	}
	var sublayerPtr *sublayer
	rc, _, _ = sublayerGet.Call(e.handle, uintptr(unsafe.Pointer(&sublayerKey)), uintptr(unsafe.Pointer(&sublayerPtr)))
	switch uint32(rc) {
	case 0:
		s := sublayerPtr
		if s == nil {
			return out, fmt.Errorf("FwpmSubLayerGetByKey0 succeeded with a nil sublayer")
		}
		out.Sublayer = ObjectState{Present: true, Persistent: s.Flags&persistent != 0}
		if s.Key != sublayerKey || s.ProviderKey == nil || *s.ProviderKey != providerKey || !strings.HasPrefix(utf16String(s.Display.Name), "KS guard v1") {
			free(&sublayerPtr)
			return out, fmt.Errorf("sublayer key collision or foreign owner")
		}
		free(&sublayerPtr)
	case errSublayerNotFound:
	default:
		return out, APIError{Function: "FwpmSubLayerGetByKey0", Code: uint32(rc)}
	}
	filters, err := e.listOwnFilters()
	if err != nil {
		return out, err
	}
	out.Filters = filters
	if len(filters) > 0 && (!out.Provider.Present || !out.Sublayer.Present) {
		return out, fmt.Errorf("owned filters exist without owner objects")
	}
	return out, nil
}

func (e *Engine) listOwnFilters() ([]FilterState, error) {
	var enum uintptr
	if err := invoke(filterCreateEnum, e.handle, 0, uintptr(unsafe.Pointer(&enum))); err != nil {
		return nil, err
	}
	defer filterDestroyEnum.Call(e.handle, enum)
	result := []FilterState{}
	for {
		var array **filter
		var count uint32
		if err := invoke(filterEnum, e.handle, enum, 100, uintptr(unsafe.Pointer(&array)), uintptr(unsafe.Pointer(&count))); err != nil {
			return nil, err
		}
		if count == 0 {
			free(&array)
			break
		}
		if array == nil || count > 100 {
			free(&array)
			return nil, fmt.Errorf("invalid WFP filter page")
		}
		entries := unsafe.Slice(array, count)
		for _, f := range entries {
			if f == nil {
				free(&array)
				return nil, fmt.Errorf("nil WFP filter")
			}
			providerMatch := f.ProviderKey != nil && *f.ProviderKey == providerKey
			subMatch := f.Sublayer == sublayerKey
			if !providerMatch && !subMatch {
				continue
			}
			name := utf16String(f.Display.Name)
			application, applicationOK := filterApplication(name, f.Action.Type)
			if !providerMatch || !subMatch || !strings.HasPrefix(name, "KS guard v1") || !applicationOK || !validOwnedFilter(f) {
				free(&array)
				return nil, fmt.Errorf("foreign or malformed filter in owned namespace: %s", f.Key.String())
			}
			var weight uint64
			if f.Weight.Type == uint64Type && f.Weight.Value != 0 {
				weight = *(*uint64)(f.Weight.pointer())
			} else {
				free(&array)
				return nil, fmt.Errorf("unexpected WFP weight on %s", f.Key.String())
			}
			observed, err := readConditions(f)
			if err != nil {
				free(&array)
				return nil, err
			}
			result = append(result, FilterState{Key: f.Key.String(), Application: application, Flags: f.Flags, Layer: layerName(f.Layer), Action: f.Action.Type, Weight: weight, Persistent: f.Flags&persistent != 0, Disabled: f.Flags&disabled != 0, ConditionCount: f.ConditionCount, Conditions: observed})
		}
		free(&array)
		if count < 100 {
			break
		}
	}
	runtime.KeepAlive(e)
	return result, nil
}

func filterApplication(name string, actionType uint32) (string, bool) {
	prefix := "KS guard v1 "
	switch actionType {
	case actionBlock:
		prefix += "BLOCK "
	case actionPermit:
		prefix += "PERMIT_SOFT "
	default:
		return "", false
	}
	application, ok := strings.CutPrefix(name, prefix)
	if !ok || application == "" {
		return "", false
	}
	return application, true
}

func validOwnedFilter(f *filter) bool {
	if f.Layer != layerConnect4 && f.Layer != layerConnect6 && f.Layer != layerRecv4 && f.Layer != layerRecv6 {
		return false
	}
	if f.Action.Type != actionBlock && f.Action.Type != actionPermit {
		return false
	}
	if f.Flags&persistent == 0 || f.ConditionCount < 1 || f.ConditionCount > 3 || f.Conditions == nil {
		return false
	}
	conditions := unsafe.Slice(f.Conditions, f.ConditionCount)
	app := false
	for _, c := range conditions {
		if c.Field == fieldAppID && c.Match == matchEqual && c.Value.Type == byteBlobType {
			app = true
		}
	}
	return app
}

func readConditions(f *filter) ([]ConditionState, error) {
	result := make([]ConditionState, 0, f.ConditionCount)
	for _, c := range unsafe.Slice(f.Conditions, f.ConditionCount) {
		obs := ConditionState{Match: c.Match, Type: c.Value.Type}
		switch c.Field {
		case fieldAppID:
			obs.Field = "FWPM_CONDITION_ALE_APP_ID"
			if c.Value.Type != byteBlobType || c.Value.Value == 0 {
				return nil, fmt.Errorf("invalid AppID condition")
			}
			blob := (*byteBlob)(c.Value.pointer())
			if blob.Size == 0 || blob.Size > 8192 || blob.Data == nil {
				return nil, fmt.Errorf("invalid AppID blob")
			}
			sum := sha256.Sum256(unsafe.Slice(blob.Data, blob.Size))
			obs.Value = hex.EncodeToString(sum[:])
		case fieldNextHop:
			obs.Field = "FWPM_CONDITION_IP_NEXTHOP_INTERFACE"
			if c.Value.Type != uint64Type || c.Value.Value == 0 {
				return nil, fmt.Errorf("invalid next-hop condition")
			}
			obs.Value = fmt.Sprintf("0x%016X", *(*uint64)(c.Value.pointer()))
		case fieldFlags:
			obs.Field = "FWPM_CONDITION_FLAGS"
			if c.Value.Type != uint32Type {
				return nil, fmt.Errorf("invalid flags condition")
			}
			obs.Value = fmt.Sprintf("0x%08X", uint32(c.Value.Value))
		default:
			return nil, fmt.Errorf("unexpected condition field %s", c.Field.String())
		}
		result = append(result, obs)
	}
	return result, nil
}

func layerName(g guid) string {
	switch g {
	case layerConnect4:
		return "FWPM_LAYER_ALE_AUTH_CONNECT_V4"
	case layerConnect6:
		return "FWPM_LAYER_ALE_AUTH_CONNECT_V6"
	case layerRecv4:
		return "FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4"
	case layerRecv6:
		return "FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6"
	default:
		return g.String()
	}
}

func utf16String(p *uint16) string {
	if p == nil {
		return ""
	}
	length, _, _ := syscall.NewLazyDLL("kernel32.dll").NewProc("lstrlenW").Call(uintptr(unsafe.Pointer(p)))
	if length > 2048 {
		return ""
	}
	return syscall.UTF16ToString(unsafe.Slice(p, length))
}
