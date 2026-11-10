package ui

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const SettingsFile = "guard-ui.json"

type Target struct {
	ID      string `json:"id"`
	Path    string `json:"path"`
	Enabled bool   `json:"enabled"`
}

type Settings struct {
	SchemaVersion       int      `json:"schemaVersion"`
	VPNInterfaceName    string   `json:"vpnInterfaceName"`
	VPNInterfaceGUID    string   `json:"vpnInterfaceGuid,omitempty"`
	NetworkAdapterTypes []string `json:"networkAdapterTypes"`
	Targets             []Target `json:"targets"`
}

func DefaultSettings(exeDir string) Settings {
	return Settings{
		SchemaVersion:       1,
		VPNInterfaceName:    "AmneziaVPN",
		NetworkAdapterTypes: DefaultNetworkAdapterTypes(),
		Targets: []Target{
			{ID: "probe", Path: "guard-probe.exe", Enabled: true},
		},
	}
}

func LoadOrCreateSettings(exeDir string) (Settings, error) {
	path := filepath.Join(exeDir, SettingsFile)
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		s := DefaultSettings(exeDir)
		return s, SaveSettings(path, s)
	}
	if err != nil {
		return Settings{}, err
	}
	var s Settings
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return Settings{}, fmt.Errorf("%s: %w", SettingsFile, err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return Settings{}, fmt.Errorf("%s: trailing JSON data", SettingsFile)
	}
	changed := false
	if s.NetworkAdapterTypes == nil {
		s.NetworkAdapterTypes = DefaultNetworkAdapterTypes()
		changed = true
	}
	for i := len(s.Targets) - 1; i >= 0; i-- {
		target := s.Targets[i]
		if (target.ID == "claude" || target.ID == "codex") && !target.Enabled && (target.Path == "" || target.Path == "Z") {
			s.Targets = append(s.Targets[:i], s.Targets[i+1:]...)
			changed = true
		}
	}
	if err := s.Validate(); err != nil {
		return Settings{}, fmt.Errorf("%s: %w", SettingsFile, err)
	}
	if changed {
		if err := SaveSettings(path, s); err != nil {
			return Settings{}, err
		}
	}
	return s, nil
}

func (s Settings) Validate() error {
	if s.SchemaVersion != 1 || s.VPNInterfaceName == "" {
		return errors.New("неподдерживаемая версия или пустое имя VPN-интерфейса")
	}
	if err := ValidateNetworkAdapterTypes(s.NetworkAdapterTypes); err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, t := range s.Targets {
		if t.ID == "" || seen[t.ID] {
			return fmt.Errorf("неверный или повторяющийся id приложения %q", t.ID)
		}
		seen[t.ID] = true
		if t.ID != "probe" && t.ID != "claude" && t.ID != "codex" && !strings.HasPrefix(t.ID, "custom-") {
			return fmt.Errorf("неизвестный тип приложения %q", t.ID)
		}
	}
	if !seen["probe"] {
		return errors.New("отсутствует служебная запись probe")
	}
	return nil
}

func SaveSettings(path string, s Settings) error {
	if err := s.Validate(); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".guard-ui-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return replaceSettingsFile(f.Name(), path)
}

func (s *Settings) Target(id string) *Target {
	for i := range s.Targets {
		if s.Targets[i].ID == id {
			return &s.Targets[i]
		}
	}
	return nil
}

// ActivePaths resolves all desired applications without treating disabled placeholders as executables.
func (s Settings) ActivePaths(exeDir string) ([]string, error) {
	paths := []string{}
	seen := map[string]bool{}
	for _, t := range s.Targets {
		if !t.Enabled {
			continue
		}
		if t.Path == "" || t.Path == "Z" {
			return nil, fmt.Errorf("%s: укажите существующий EXE", t.ID)
		}
		p := t.Path
		if !filepath.IsAbs(p) {
			p = filepath.Join(exeDir, p)
		}
		key := strings.ToLower(filepath.Clean(p))
		if seen[key] {
			return nil, fmt.Errorf("повторный путь EXE: %s", p)
		}
		seen[key] = true
		paths = append(paths, p)
	}
	return paths, nil
}
