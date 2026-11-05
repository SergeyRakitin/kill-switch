package wfp

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"unsafe"
)

// These layouts mirror the Windows SDK x64 FWPM/FWP structures. Do not use on 32-bit builds.
type guid struct {
	D1 uint32
	D2 uint16
	D3 uint16
	D4 [8]byte
}
type displayData struct {
	Name        *uint16
	Description *uint16
}
type byteBlob struct {
	Size uint32
	Data *byte
}
type provider struct {
	Key         guid
	Display     displayData
	Flags       uint32
	Data        byteBlob
	ServiceName *uint16
}
type sublayer struct {
	Key         guid
	Display     displayData
	Flags       uint32
	ProviderKey *guid
	Data        byteBlob
	Weight      uint16
}
type value struct {
	Type  uint32
	Value uintptr
}

// FWP_VALUE0 stores either a scalar or a pointer in the same native slot.
// Keep the slot numeric for FWP_UINT32, and view it as a pointer only for
// pointer-valued types after checking Type.
func (v *value) pointer() unsafe.Pointer {
	return *(*unsafe.Pointer)(unsafe.Pointer(&v.Value))
}

type condition struct {
	Field guid
	Match uint32
	Value value
}
type action struct {
	Type    uint32
	Callout guid
}
type filter struct {
	Key             guid
	Display         displayData
	Flags           uint32
	ProviderKey     *guid
	Data            byteBlob
	Layer           guid
	Sublayer        guid
	Weight          value
	ConditionCount  uint32
	Conditions      *condition
	Action          action
	Context         [16]byte
	Reserved        *guid
	ID              uint64
	EffectiveWeight value
}

const (
	persistent        = 1
	disabled          = 0x20
	providerDisabled  = 0x10
	uint32Type        = 3
	uint64Type        = 4
	byteBlobType      = 12
	matchEqual        = 0
	matchFlagsNoneSet = 8
	actionBlock       = 0x1001
	actionPermit      = 0x1002
	loopbackFlag      = 1
)

var (
	providerKey   = mustGUID("ab5f47c1-3f3e-4ac3-83c0-c2ff7bb68cd8")
	sublayerKey   = mustGUID("6a927b7c-36aa-4cf6-8b37-d29052998638")
	fieldAppID    = mustGUID("d78e1e87-8644-4ea5-9437-d809ecefc971")
	fieldNextHop  = mustGUID("93ae8f5b-7f6f-4719-98c8-14e97429ef04")
	fieldFlags    = mustGUID("632ce23b-5167-435c-86d7-e903684aa80c")
	layerConnect4 = mustGUID("c38d57d1-05a7-4c33-904f-7fbceee60e82")
	layerConnect6 = mustGUID("4a72393b-319f-44bc-84c3-ba54dcb3b6b4")
	layerRecv4    = mustGUID("e1cd9fe7-f4b5-4273-96c0-592e487b8650")
	layerRecv6    = mustGUID("a3b42c97-9f04-4672-b87e-cee9c483257f")
)

func parseGUID(raw string) (guid, error) {
	p := strings.Split(strings.Trim(raw, "{}"), "-")
	if len(p) != 5 || len(p[0]) != 8 || len(p[1]) != 4 || len(p[2]) != 4 || len(p[3]) != 4 || len(p[4]) != 12 {
		return guid{}, fmt.Errorf("invalid GUID: %q", raw)
	}
	a, e1 := strconv.ParseUint(p[0], 16, 32)
	b, e2 := strconv.ParseUint(p[1], 16, 16)
	c, e3 := strconv.ParseUint(p[2], 16, 16)
	d, e4 := hex.DecodeString(p[3] + p[4])
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil || len(d) != 8 {
		return guid{}, fmt.Errorf("invalid GUID: %q", raw)
	}
	g := guid{D1: uint32(a), D2: uint16(b), D3: uint16(c)}
	copy(g.D4[:], d)
	return g, nil
}
func mustGUID(s string) guid {
	g, e := parseGUID(s)
	if e != nil {
		panic(e)
	}
	return g
}
func (g guid) String() string {
	return fmt.Sprintf("%08x-%04x-%04x-%02x%02x-%x", g.D1, g.D2, g.D3, g.D4[0], g.D4[1], g.D4[2:])
}

func checkABI() error {
	if unsafe.Sizeof(uintptr(0)) != 8 || unsafe.Sizeof(provider{}) != 64 || unsafe.Sizeof(sublayer{}) != 72 || unsafe.Sizeof(filter{}) != 200 || unsafe.Sizeof(condition{}) != 40 || unsafe.Offsetof(filter{}.Action) != 128 || unsafe.Offsetof(filter{}.Conditions) != 120 {
		return fmt.Errorf("unexpected WFP ABI layout")
	}
	return nil
}
