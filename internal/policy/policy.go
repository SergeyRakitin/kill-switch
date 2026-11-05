// Package policy builds a reviewable candidate. It does not touch WFP.
package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"kill-switch/internal/config"
)

const (
	ProviderGUID   = "ab5f47c1-3f3e-4ac3-83c0-c2ff7bb68cd8"
	SublayerGUID   = "6a927b7c-36aa-4cf6-8b37-d29052998638"
	SublayerWeight = 0x8000
)

type InterfaceState struct {
	GUID        string `json:"guid"`
	Description string `json:"description"`
	LUID        uint64 `json:"luid"`
	IPv4Route   bool   `json:"ipv4Route"`
	IPv6Route   bool   `json:"ipv6Route"`
}

type Condition struct {
	Field    string `json:"field"`
	Operator string `json:"operator"`
	Value    string `json:"value"`
}

type Rule struct {
	Key         string      `json:"key"`
	Application string      `json:"application"`
	Layer       string      `json:"layer"`
	Action      string      `json:"action"`
	Weight      uint64      `json:"weight"`
	Persistent  bool        `json:"persistent"`
	Conditions  []Condition `json:"conditions"`
}

type Plan struct {
	Kind             string         `json:"kind"`
	Verified         bool           `json:"verified"`
	ExistingWFPState string         `json:"existingWfpState"`
	ProviderGUID     string         `json:"providerGuid"`
	SublayerGUID     string         `json:"sublayerGuid"`
	SublayerWeight   uint16         `json:"sublayerWeight"`
	Interface        InterfaceState `json:"interface"`
	Add              []Rule         `json:"add"`
	Delete           []string       `json:"delete"`
	Warnings         []string       `json:"warnings"`
	SnapshotDigest   string         `json:"snapshotDigest,omitempty"`
	Fingerprint      string         `json:"fingerprint,omitempty"`
}

func (p Plan) Digest() string {
	p.Fingerprint = ""
	b, _ := json.Marshal(p)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func Build(c config.Config, found *InterfaceState) (Plan, error) {
	if err := c.Validate(); err != nil {
		return Plan{}, err
	}
	p := Plan{Kind: "UNVERIFIED_DRY_RUN", ExistingWFPState: "UNKNOWN", ProviderGUID: ProviderGUID, SublayerGUID: SublayerGUID, SublayerWeight: SublayerWeight, Add: []Rule{}, Delete: []string{}, Warnings: []string{
		"Candidate only: network behavior, open flows, reboot, DNS and proxy have not been verified.",
		"CONNECTED VPN state and trustedVpnServerIPs do not grant application destinations.",
	}}
	trusted := found != nil && strings.EqualFold(strings.Trim(found.GUID, "{}"), strings.Trim(c.VPNInterface.GUID, "{}")) && found.LUID != 0
	if trusted && c.VPNInterface.ExpectedDescription != "" && !strings.EqualFold(c.VPNInterface.ExpectedDescription, found.Description) {
		trusted = false
	}
	if trusted {
		p.Interface = *found
	} else {
		p.Warnings = append(p.Warnings, "VPN interface identity is not resolved: only BLOCK rules are planned.")
	}
	for _, app := range c.Applications {
		for _, family := range []string{"V4", "V6"} {
			layer := "FWPM_LAYER_ALE_AUTH_CONNECT_" + family
			route := found != nil && ((family == "V4" && found.IPv4Route) || (family == "V6" && found.IPv6Route))
			if trusted && route {
				p.Add = append(p.Add, Rule{
					Key: key(app, layer, "permit"), Application: app, Layer: layer, Action: "PERMIT_SOFT", Weight: 200, Persistent: true,
					Conditions: []Condition{
						{Field: "FWPM_CONDITION_ALE_APP_ID", Operator: "EQUAL", Value: "FwpmGetAppIdFromFileName0(" + app + ")"},
						{Field: "FWPM_CONDITION_IP_NEXTHOP_INTERFACE", Operator: "EQUAL", Value: fmt.Sprintf("0x%016X", found.LUID)},
						{Field: "FWPM_CONDITION_FLAGS", Operator: "FLAGS_NONE_SET", Value: "FWP_CONDITION_FLAG_IS_LOOPBACK"},
					},
				})
			} else {
				p.Warnings = append(p.Warnings, fmt.Sprintf("%s %s: no matching interface route was observed; BLOCK only", app, family))
			}
			p.Add = append(p.Add, block(app, layer))
			// Inbound-originated flows can send replies; deny until lab evidence supports a narrower rule.
			p.Add = append(p.Add, block(app, "FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_"+family))
		}
	}
	return p, nil
}

func block(app, layer string) Rule {
	return Rule{Key: key(app, layer, "block"), Application: app, Layer: layer, Action: "BLOCK", Weight: 100, Persistent: true,
		Conditions: []Condition{{Field: "FWPM_CONDITION_ALE_APP_ID", Operator: "EQUAL", Value: "FwpmGetAppIdFromFileName0(" + app + ")"}}}
}

func key(app, layer, action string) string {
	sum := sha256.Sum256([]byte("kill-switch/v1\x00" + strings.ToLower(app) + "\x00" + layer + "\x00" + action))
	b := sum[:16]
	b[6] = (b[6] & 0x0f) | 0x50
	b[8] = (b[8] & 0x3f) | 0x80
	h := hex.EncodeToString(b)
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}
