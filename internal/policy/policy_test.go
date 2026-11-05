package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"kill-switch/internal/config"
)

func testConfig(t *testing.T) config.Config {
	t.Helper()
	app := filepath.Join(t.TempDir(), "guard-probe.exe")
	if err := os.WriteFile(app, []byte("probe fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	return config.Config{SchemaVersion: 1, Applications: []string{app}, VPNInterface: config.Interface{GUID: "05b44401-f55a-1be5-94c3-7fa54bb2d33e", ExpectedDescription: "WireGuard Tunnel"}, TrustedVPNServerIPs: []string{"203.0.113.5"}}
}

func TestUnknownInterfaceHasOnlyAppScopedBlocks(t *testing.T) {
	c := testConfig(t)
	p, err := Build(c, nil)
	if err != nil {
		t.Fatal(err)
	}
	if p.Verified || p.Kind != "UNVERIFIED_DRY_RUN" {
		t.Fatal("dry-run misrepresented as verified")
	}
	if len(p.Add) != 4 {
		t.Fatalf("want four scoped blocks, got %d", len(p.Add))
	}
	for _, r := range p.Add {
		if r.Action != "BLOCK" || !r.Persistent || len(r.Conditions) != 1 || r.Conditions[0].Field != "FWPM_CONDITION_ALE_APP_ID" {
			t.Fatalf("unsafe rule: %+v", r)
		}
		if r.Application != c.Applications[0] {
			t.Fatalf("unexpected application: %s", r.Application)
		}
	}
}

func TestPermitIsNarrowAndServerIPDoesNotGrantAccess(t *testing.T) {
	c := testConfig(t)
	iface := &InterfaceState{GUID: c.VPNInterface.GUID, Description: c.VPNInterface.ExpectedDescription, LUID: 42, IPv4Route: true, IPv6Route: false}
	p, err := Build(c, iface)
	if err != nil {
		t.Fatal(err)
	}
	permits := 0
	keys := map[string]bool{}
	for _, r := range p.Add {
		if keys[r.Key] {
			t.Fatalf("duplicate key %s", r.Key)
		}
		keys[r.Key] = true
		if r.Action != "PERMIT_SOFT" {
			continue
		}
		permits++
		if r.Layer != "FWPM_LAYER_ALE_AUTH_CONNECT_V4" || r.Weight <= 100 || len(r.Conditions) != 3 {
			t.Fatalf("broad permit: %+v", r)
		}
		var app, ifaceCondition, loopback bool
		for _, cond := range r.Conditions {
			if strings.Contains(cond.Value, "203.0.113.5") {
				t.Fatal("VPN server IP became application destination")
			}
			switch cond.Field {
			case "FWPM_CONDITION_ALE_APP_ID":
				app = true
			case "FWPM_CONDITION_IP_NEXTHOP_INTERFACE":
				ifaceCondition = cond.Value == "0x000000000000002A"
			case "FWPM_CONDITION_FLAGS":
				loopback = cond.Operator == "FLAGS_NONE_SET" && cond.Value == "FWP_CONDITION_FLAG_IS_LOOPBACK"
			}
		}
		if !app || !ifaceCondition || !loopback {
			t.Fatalf("permit missing constraint: %+v", r)
		}
	}
	if permits != 1 {
		t.Fatalf("want one v4 permit and v6 deny, got %d", permits)
	}
	again, err := Build(c, iface)
	if err != nil {
		t.Fatal(err)
	}
	for i := range p.Add {
		if p.Add[i].Key != again.Add[i].Key {
			t.Fatal("rule keys are not deterministic")
		}
	}
}

func TestDescriptionMismatchSuppressesPermits(t *testing.T) {
	c := testConfig(t)
	p, err := Build(c, &InterfaceState{GUID: c.VPNInterface.GUID, Description: "Other VPN", LUID: 42, IPv4Route: true, IPv6Route: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range p.Add {
		if r.Action != "BLOCK" {
			t.Fatal("permitted unrecognized interface")
		}
	}
}
