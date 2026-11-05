package ui

import (
	"reflect"
	"testing"
)

func TestFilterAdaptersDefaults(t *testing.T) {
	adapters := []Adapter{
		{Name: "Bluetooth", Description: "Bluetooth Device (Personal Area Network)"},
		{Name: "Wi-Fi", Description: "Intel(R) Wi-Fi 6E AX211 160MHz", GUID: "wifi", HardwareInterface: true},
		{Name: "Wi-Fi Direct", Description: "Microsoft Wi-Fi Direct Virtual Adapter"},
		{Name: "TAP", Description: "TAP-Windows Adapter V9", GUID: "tap"},
		{Name: "Tailscale", Description: "Tailscale Tunnel", GUID: "tailscale"},
		{Name: "AmneziaVPN", Description: "WireGuard Tunnel", GUID: "amnezia"},
		{Name: "VPN Miniport", Description: "WAN Miniport (IKEv2)", GUID: "miniport"},
		{Name: "Virtual", Description: "Hyper-V Virtual Ethernet Adapter", GUID: "virtual"},
	}
	got := FilterAdapters(adapters, nil, "")
	want := []string{"amnezia", "wifi", "tap", "tailscale"}
	if names := adapterGUIDs(got); !reflect.DeepEqual(names, want) {
		t.Fatalf("visible adapters: got %v, want %v", names, want)
	}
}

func TestFilterAdaptersHonorsConfigAndKeepsSelected(t *testing.T) {
	adapters := []Adapter{
		{Name: "AmneziaVPN", Description: "WireGuard Tunnel", GUID: "{AA}"},
		{Name: "Wi-Fi", Description: "Intel(R) Wireless", GUID: "wifi", HardwareInterface: true},
		{Name: "Tailscale", Description: "Tailscale Tunnel", GUID: "tailscale"},
	}
	got := FilterAdapters(adapters, []string{NetworkAdapterAmnezia}, "{aa}")
	if names := adapterGUIDs(got); !reflect.DeepEqual(names, []string{"{AA}"}) {
		t.Fatalf("configured adapters: %v", names)
	}
	got = FilterAdapters(adapters, []string{}, "tailscale")
	if names := adapterGUIDs(got); !reflect.DeepEqual(names, []string{"tailscale"}) {
		t.Fatalf("selected hidden category: %v", names)
	}
	got = FilterAdapters(adapters, []string{}, "")
	if len(got) != 0 {
		t.Fatalf("all categories disabled: %+v", got)
	}
}

func TestFilterAdaptersSupportsOlderGuardInventory(t *testing.T) {
	adapters := []Adapter{{Name: "Wi-Fi", Description: "Intel(R) Wi-Fi 6E AX211", GUID: "wifi"}}
	got := FilterAdapters(adapters, []string{NetworkAdapterPhysical}, "")
	if len(got) != 1 || got[0].GUID != "wifi" {
		t.Fatalf("physical fallback: %+v", got)
	}
}

func TestValidateNetworkAdapterTypes(t *testing.T) {
	if err := ValidateNetworkAdapterTypes(nil); err != nil {
		t.Fatal(err)
	}
	if err := ValidateNetworkAdapterTypes([]string{NetworkAdapterOtherVPN}); err != nil {
		t.Fatal(err)
	}
	if err := ValidateNetworkAdapterTypes([]string{"all"}); err == nil {
		t.Fatal("unknown category accepted")
	}
	if err := ValidateNetworkAdapterTypes([]string{NetworkAdapterPhysical, NetworkAdapterPhysical}); err == nil {
		t.Fatal("duplicate category accepted")
	}
}

func adapterGUIDs(adapters []Adapter) []string {
	result := make([]string, 0, len(adapters))
	for _, adapter := range adapters {
		result = append(result, adapter.GUID)
	}
	return result
}
