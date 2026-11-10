package wfp

import "testing"

func TestWindowsABISizes(t *testing.T) {
	if err := checkABI(); err != nil {
		t.Fatal(err)
	}
}
func TestGUIDRoundTrip(t *testing.T) {
	for _, raw := range []string{"ab5f47c1-3f3e-4ac3-83c0-c2ff7bb68cd8", "c38d57d1-05a7-4c33-904f-7fbceee60e82"} {
		g, err := parseGUID(raw)
		if err != nil {
			t.Fatal(err)
		}
		if g.String() != raw {
			t.Fatalf("GUID round trip %s -> %s", raw, g.String())
		}
	}
}

func TestPackageSIDString(t *testing.T) {
	for family, want := range map[string]string{
		"Claude_pzs8sxrjxfjjc":       "S-1-15-2-3557520199-3666692283-3112367039-3524159787-2791857073-3163583606-3692855932",
		"OpenAI.Codex_2p2nqsd0c76g0": "S-1-15-2-2968813833-811790644-2202111208-3784096404-1081847329-2708967783-1438471679",
	} {
		got, err := packageSIDString(family)
		if err != nil || got != want {
			t.Fatalf("%s: SID=%q error=%v, want %q", family, got, err, want)
		}
	}
}
