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
