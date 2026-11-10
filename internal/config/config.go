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
	PackageFamilies     []string  `json:"packageFamilies,omitempty"`
	FileNames           []string  `json:"fileNames,omitempty"`
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
			return c, errors.New("config JSON has trailing content")
		}
		return c, fmt.Errorf("config JSON trailing content: %w", err)
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
			return fmt.Errorf("application must be an absolute local .exe path: \"%s\"", app)
		}
		normalized := strings.ToLower(filepath.Clean(app))
		if seen[normalized] {
			return fmt.Errorf("duplicate application: \"%s\"", app)
		}
		seen[normalized] = true
		fi, err := os.Lstat(app)
		if err != nil {
			return fmt.Errorf("application \"%s\": %w", app, err)
		}
		if !fi.Mode().IsRegular() || fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("application is not a regular file: \"%s\"", app)
		}
		real, err := canonicalPath(app)
		if err != nil || !strings.EqualFold(filepath.Clean(real), filepath.Clean(app)) {
			return fmt.Errorf("application uses a reparse/ambiguous path: \"%s\"", app)
		}
	}
	packages := map[string]bool{}
	for _, family := range c.PackageFamilies {
		if !ValidPackageFamily(family) {
			return fmt.Errorf("invalid MSIX package family: \"%s\"", family)
		}
		normalized := strings.ToLower(family)
		if packages[normalized] {
			return fmt.Errorf("duplicate MSIX package family: \"%s\"", family)
		}
		packages[normalized] = true
	}
	names := map[string]bool{}
	for _, name := range c.FileNames {
		if !ValidFileName(name) {
			return fmt.Errorf("file name must be a plain ASCII .exe name without folders or wildcards: \"%s\"", name)
		}
		normalized := strings.ToLower(name)
		if names[normalized] {
			return fmt.Errorf("duplicate file name: \"%s\"", name)
		}
		names[normalized] = true
	}
	for _, raw := range c.TrustedVPNServerIPs {
		ip, err := netip.ParseAddr(raw)
		if err != nil || ip.Zone() != "" {
			return fmt.Errorf("invalid trustedVpnServerIPs entry: \"%s\"", raw)
		}
	}
	return nil
}

func ValidPackageFamily(raw string) bool {
	if raw == "" || len(raw) > 128 || strings.Count(raw, "_") != 1 {
		return false
	}
	parts := strings.SplitN(raw, "_", 2)
	if parts[0] == "" || parts[1] == "" {
		return false
	}
	for _, r := range raw {
		if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' || r == '-' || r == '_' {
			continue
		}
		return false
	}
	return true
}

// ValidFileName принимает только имя EXE без каталога: правило по имени
// совпадает с файлом в любой папке, поэтому разделители путей и маски запрещены.
// Допускается лишь печатный ASCII: WFP сравнивает путь в нижнем регистре,
// а приведение регистра не-ASCII символов в Go и в ядре Windows может разойтись,
// и тогда правило молча перестанет совпадать.
func ValidFileName(raw string) bool {
	if len(raw) > 255 || raw != strings.TrimSpace(raw) || !strings.EqualFold(filepath.Ext(raw), ".exe") {
		return false
	}
	if strings.Trim(raw[:len(raw)-len(".exe")], ". ") == "" {
		return false
	}
	for _, r := range raw {
		if r < 0x20 || r > 0x7e || strings.ContainsRune(`<>:"/\|?*`, r) {
			return false
		}
	}
	return true
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
