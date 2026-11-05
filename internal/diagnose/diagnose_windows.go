package diagnose

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"kill-switch/internal/policy"
)

type Snapshot struct {
	OS struct {
		Caption        string
		Version        string
		BuildNumber    string
		OSArchitecture string
	} `json:"os"`
	Adapters []Adapter `json:"adapters"`
	Routes   []Route   `json:"routes"`
	DNS      []struct {
		InterfaceAlias  string
		AddressFamily   int
		ServerAddresses []string
	} `json:"dns"`
	Services []struct {
		Name   string
		Status int
	} `json:"services"`
}

type Adapter struct {
	Name                 string `json:"name"`
	InterfaceDescription string `json:"interfaceDescription"`
	InterfaceGuid        string `json:"interfaceGuid"`
	IfIndex              int    `json:"ifIndex"`
	Status               string `json:"status"`
	HardwareInterface    bool   `json:"hardwareInterface"`
	LUID                 uint64 `json:"luid"`
}

type Route struct {
	InterfaceAlias    string `json:"interfaceAlias"`
	DestinationPrefix string `json:"destinationPrefix"`
	NextHop           string `json:"nextHop"`
	RouteMetric       int    `json:"routeMetric"`
}

const inventoryScript = `[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false);
$ErrorActionPreference='Stop';
$x=[pscustomobject]@{
 os=(Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber,OSArchitecture);
 adapters=@(Get-NetAdapter -IncludeHidden | Select-Object Name,InterfaceDescription,InterfaceGuid,ifIndex,Status,HardwareInterface);
 routes=@(Get-NetRoute | Select-Object InterfaceAlias,DestinationPrefix,NextHop,RouteMetric);
 dns=@(Get-DnsClientServerAddress | Select-Object InterfaceAlias,AddressFamily,ServerAddresses);
 services=@(Get-Service BFE,MpsSvc | Select-Object Name,Status)
}; $x | ConvertTo-Json -Depth 6 -Compress`

func Read() (Snapshot, error) {
	var s Snapshot
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", inventoryScript)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000} // CREATE_NO_WINDOW
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	output, err := cmd.Output()
	if err != nil {
		return s, fmt.Errorf("read-only Windows inventory: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	if err := json.Unmarshal(output, &s); err != nil {
		return s, fmt.Errorf("Windows inventory JSON: %w", err)
	}
	for i := range s.Adapters {
		luid, err := guidToLUID(s.Adapters[i].InterfaceGuid)
		if err == nil {
			s.Adapters[i].LUID = luid
		}
	}
	return s, nil
}

func (s Snapshot) Resolve(guid string) *policy.InterfaceState {
	for _, a := range s.Adapters {
		if !strings.EqualFold(strings.Trim(a.InterfaceGuid, "{}"), strings.Trim(guid, "{}")) {
			continue
		}
		state := &policy.InterfaceState{GUID: a.InterfaceGuid, Description: a.InterfaceDescription, LUID: a.LUID}
		if !strings.EqualFold(a.Status, "Up") {
			return state
		}
		for _, r := range s.Routes {
			if r.InterfaceAlias != a.Name {
				continue
			}
			p, err := netip.ParsePrefix(r.DestinationPrefix)
			if err != nil {
				continue
			}
			addr := p.Addr()
			if addr.Is4() && (p.Bits() == 0 || (addr.IsGlobalUnicast() && !addr.IsMulticast())) {
				state.IPv4Route = true
			}
			if addr.Is6() && (p.Bits() == 0 || (addr.IsGlobalUnicast() && (addr.As16()[0]&0xe0) == 0x20)) {
				state.IPv6Route = true
			}
		}
		return state
	}
	return nil
}

type nativeGUID struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

func guidToLUID(raw string) (uint64, error) {
	parts := strings.Split(strings.Trim(raw, "{}"), "-")
	if len(parts) != 5 || len(parts[3]) != 4 || len(parts[4]) != 12 {
		return 0, fmt.Errorf("invalid GUID %q", raw)
	}
	a, e1 := strconv.ParseUint(parts[0], 16, 32)
	b, e2 := strconv.ParseUint(parts[1], 16, 16)
	c, e3 := strconv.ParseUint(parts[2], 16, 16)
	d, e4 := hex.DecodeString(parts[3] + parts[4])
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil || len(d) != 8 {
		return 0, fmt.Errorf("invalid GUID %q", raw)
	}
	g := nativeGUID{Data1: uint32(a), Data2: uint16(b), Data3: uint16(c)}
	copy(g.Data4[:], d)
	proc := syscall.NewLazyDLL("iphlpapi.dll").NewProc("ConvertInterfaceGuidToLuid")
	var luid uint64
	rc, _, _ := proc.Call(uintptr(unsafe.Pointer(&g)), uintptr(unsafe.Pointer(&luid)))
	if rc != 0 {
		return 0, fmt.Errorf("ConvertInterfaceGuidToLuid: %d", rc)
	}
	return luid, nil
}
