package ui

import (
	"fmt"
	"strings"
)

const (
	NetworkAdapterAmnezia  = "amnezia-vpn"
	NetworkAdapterPhysical = "physical"
	NetworkAdapterOtherVPN = "other-vpn"
)

func DefaultNetworkAdapterTypes() []string {
	return []string{NetworkAdapterAmnezia, NetworkAdapterPhysical, NetworkAdapterOtherVPN}
}

func ValidateNetworkAdapterTypes(types []string) error {
	seen := map[string]bool{}
	for _, kind := range types {
		switch kind {
		case NetworkAdapterAmnezia, NetworkAdapterPhysical, NetworkAdapterOtherVPN:
		default:
			return fmt.Errorf("неизвестная категория сетевого адаптера %q", kind)
		}
		if seen[kind] {
			return fmt.Errorf("повторяющаяся категория сетевого адаптера %q", kind)
		}
		seen[kind] = true
	}
	return nil
}

func FilterAdapters(adapters []Adapter, types []string, selectedGUID string) []Adapter {
	if types == nil {
		types = DefaultNetworkAdapterTypes()
	}
	enabled := make(map[string]bool, len(types))
	for _, kind := range types {
		enabled[kind] = true
	}
	result := []Adapter{}
	for _, kind := range DefaultNetworkAdapterTypes() {
		if !enabled[kind] {
			continue
		}
		for _, adapter := range adapters {
			if networkAdapterCategory(adapter) == kind && !adapterListed(result, adapter.GUID) {
				result = append(result, adapter)
			}
		}
	}
	if selectedGUID != "" && !adapterListed(result, selectedGUID) {
		for _, adapter := range adapters {
			if equalAdapterGUID(adapter.GUID, selectedGUID) {
				result = append(result, adapter)
				break
			}
		}
	}
	return result
}

func networkAdapterCategory(adapter Adapter) string {
	text := strings.ToLower(adapter.Name + " " + adapter.Description)
	if strings.Contains(text, "amnezia") {
		return NetworkAdapterAmnezia
	}
	for _, excluded := range []string{
		"bluetooth", "wi-fi direct", "wifi direct", "wan miniport", "teredo", "ip-https",
		"6to4", "kernel debug", "loopback", "hyper-v", "vmware", "virtualbox", "virtual switch",
	} {
		if strings.Contains(text, excluded) {
			return ""
		}
	}
	if adapter.HardwareInterface || physicalAdapterDescription(text) {
		return NetworkAdapterPhysical
	}
	for _, vpn := range []string{
		"vpn", "wireguard", "tailscale", "zerotier", "tap-windows", "wintun", "openconnect",
		"anyconnect", "softether", "globalprotect", "fortissl", "nordlynx", "mullvad", "proton", "outline",
	} {
		if strings.Contains(text, vpn) {
			return NetworkAdapterOtherVPN
		}
	}
	return ""
}

func physicalAdapterDescription(text string) bool {
	for _, marker := range []string{
		"wi-fi", "wifi", "wireless", "802.11", "ethernet", "intel(r)", "realtek", "broadcom",
		"qualcomm atheros", "mediatek",
	} {
		if strings.Contains(text, marker) {
			return true
		}
	}
	return false
}

func adapterListed(adapters []Adapter, guid string) bool {
	for _, adapter := range adapters {
		if equalAdapterGUID(adapter.GUID, guid) {
			return true
		}
	}
	return false
}

func equalAdapterGUID(a, b string) bool {
	return a != "" && b != "" && strings.EqualFold(strings.Trim(a, "{}"), strings.Trim(b, "{}"))
}
