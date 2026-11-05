package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
)

type Config struct {
	SchemaVersion       int       `json:"schemaVersion"`
	Applications        []string  `json:"applications"`
	VPNInterface        Interface `json:"vpnInterface"`
	LoopbackPolicy      string    `json:"loopbackPolicy"`
	TrustedVPNServerIPs []string  `json:"trustedVpnServerIPs,omitempty"`
}

type Interface struct {
	GUID                string `json:"guid"`
	ExpectedDescription string `json:"expectedDescription,omitempty"`
}

func Load(file string) (Config, error) {
	var c Config
	f, err := os.Open(file)
	if err != nil {
		return c, err
	}
	defer f.Close()
	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return c, fmt.Errorf("config JSON: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return c, errors.New("config JSON has trailing data")
		}
		return c, fmt.Errorf("config JSON trailing data: %w", err)
	}
	return c, c.Validate()
}

func (c Config) Validate() error {
	if c.SchemaVersion != 1 {
		return fmt.Errorf("schemaVersion must be 1, got %d", c.SchemaVersion)
	}
	if !validGUID(c.VPNInterface.GUID) {
		return errors.New("vpnInterface.guid must be a GUID")
	}
	if c.LoopbackPolicy == "" {
		c.LoopbackPolicy = "deny"
	}
	if c.LoopbackPolicy != "deny" {
		return errors.New("only loopbackPolicy=deny is supported")
	}
	seen := map[string]bool{}
	for _, app := range c.Applications {
		if !windowsAbsoluteEXE(app) {
			return fmt.Errorf("application must be an absolute local .exe path: %q", app)
		}
		normalized := strings.ToLower(filepath.Clean(app))
		if seen[normalized] {
			return fmt.Errorf("duplicate application: %q", app)
		}
		seen[normalized] = true
		fi, err := os.Lstat(app)
		if err != nil {
			return fmt.Errorf("application %q: %w", app, err)
		}
		if !fi.Mode().IsRegular() || fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("application is not a regular file: %q", app)
		}
		real, err := filepath.EvalSymlinks(app)
		if err != nil || !strings.EqualFold(filepath.Clean(real), filepath.Clean(app)) {
			return fmt.Errorf("application uses a reparse/ambiguous path: %q", app)
		}
	}
	for _, raw := range c.TrustedVPNServerIPs {
		ip, err := netip.ParseAddr(raw)
		if err != nil || ip.Zone() != "" {
			return fmt.Errorf("invalid trustedVpnServerIPs entry: %q", raw)
		}
	}
	return nil
}

func windowsAbsoluteEXE(path string) bool {
	if len(path) < 4 || path[1] != ':' || (path[2] != '\\' && path[2] != '/') {
		return false
	}
	if !((path[0] >= 'A' && path[0] <= 'Z') || (path[0] >= 'a' && path[0] <= 'z')) {
		return false
	}
	return strings.EqualFold(filepath.Ext(path), ".exe") && !strings.Contains(path, "*")
}

func validGUID(s string) bool {
	s = strings.Trim(s, "{}")
	if len(s) != 36 {
		return false
	}
	for i, r := range s {
		switch i {
		case 8, 13, 18, 23:
			if r != '-' {
				return false
			}
		default:
			if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
				return false
			}
		}
	}
	return true
}
