package ui

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"kill-switch/internal/config"
)

const SettingsFile = "guard-ui.json"

const (
	TargetTypeEXE  = "exe"
	TargetTypeMSIX = "msix"
	// TargetTypeName — цель по имени EXE: совпадает с файлом в любой папке,
	// поэтому переживает обновления, которые кладут новую версию в новый каталог.
	TargetTypeName = "name"
)

type Target struct {
	ID      string `json:"id"`
	Type    string `json:"type,omitempty"`
	Path    string `json:"path"`
	Enabled bool   `json:"enabled"`
}

func (t Target) Kind() string {
	if t.Type == "" {
		return TargetTypeEXE
	}
	return t.Type
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
		if err == nil {
			return Settings{}, fmt.Errorf("%s: trailing content", SettingsFile)
		}
		return Settings{}, fmt.Errorf("%s: trailing content: %w", SettingsFile, err)
	}
	changed := false
	if s.NetworkAdapterTypes == nil {
		s.NetworkAdapterTypes = DefaultNetworkAdapterTypes()
		changed = true
	}
	for i := len(s.Targets) - 1; i >= 0; i-- {
		t := s.Targets[i]
		if (t.ID == "claude" || t.ID == "codex") && !t.Enabled && (t.Path == "" || t.Path == "Z") {
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
		switch t.Kind() {
		case TargetTypeEXE:
		case TargetTypeMSIX:
			if !config.ValidPackageFamily(t.Path) {
				return fmt.Errorf("неверное семейство MSIX-пакета %q", t.Path)
			}
		case TargetTypeName:
			if !config.ValidFileName(t.Path) {
				return fmt.Errorf("неверное имя EXE %q: нужно только имя файла латиницей, без папки и масок", t.Path)
			}
		default:
			return fmt.Errorf("неизвестный тип цели %q", t.Type)
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

func (s Settings) ActivePaths(exeDir string) ([]string, error) {
	set, err := s.ActiveTargets(exeDir)
	return set.Apps, err
}

// TargetSet — включённые цели, разложенные по способу сопоставления в WFP.
type TargetSet struct {
	Apps            []string // полные пути EXE
	PackageFamilies []string // семейства MSIX-пакетов
	FileNames       []string // имена EXE без каталога
}

func (t TargetSet) Count() int {
	return len(t.Apps) + len(t.PackageFamilies) + len(t.FileNames)
}

func (t TargetSet) Equal(other TargetSet) bool {
	return slices.Equal(t.Apps, other.Apps) && slices.Equal(t.PackageFamilies, other.PackageFamilies) && slices.Equal(t.FileNames, other.FileNames)
}

func (t TargetSet) Clone() TargetSet {
	return TargetSet{Apps: slices.Clone(t.Apps), PackageFamilies: slices.Clone(t.PackageFamilies), FileNames: slices.Clone(t.FileNames)}
}

// Display возвращает цели в виде для показа: путь EXE, msix:семейство, name:имя.
func (t TargetSet) Display() []string {
	result := slices.Clone(t.Apps)
	for _, family := range t.PackageFamilies {
		result = append(result, "msix:"+family)
	}
	for _, name := range t.FileNames {
		result = append(result, "name:"+name)
	}
	return result
}

// MissingApps возвращает пути EXE из набора, которых нет на диске.
// Так бывает после обновления, которое переносит приложение в новый каталог.
func (t TargetSet) MissingApps() []string {
	missing := []string{}
	for _, app := range t.Apps {
		if _, err := os.Stat(app); errors.Is(err, fs.ErrNotExist) {
			missing = append(missing, app)
		}
	}
	return missing
}

// MissingTargetIDs возвращает id записей «по точному пути», файла которых нет на диске,
// включая выключенные: GUI помечает их, чтобы запись удалили или выбрали EXE заново.
func (s Settings) MissingTargetIDs(exeDir string) []string {
	ids := []string{}
	for _, t := range s.Targets {
		if t.Kind() != TargetTypeEXE || t.Path == "" || t.Path == "Z" {
			continue
		}
		p := t.Path
		if !filepath.IsAbs(p) {
			p = filepath.Join(exeDir, p)
		}
		if _, err := os.Stat(p); errors.Is(err, fs.ErrNotExist) {
			ids = append(ids, t.ID)
		}
	}
	return ids
}

func (s Settings) ActiveTargets(exeDir string) (TargetSet, error) {
	set := TargetSet{Apps: []string{}, PackageFamilies: []string{}, FileNames: []string{}}
	seen := map[string]bool{}
	for _, t := range s.Targets {
		if !t.Enabled {
			continue
		}
		if t.Path == "" || t.Path == "Z" {
			return TargetSet{}, fmt.Errorf("%s: укажите существующий EXE, семейство MSIX или имя EXE", t.ID)
		}
		kind := t.Kind()
		p := t.Path
		switch kind {
		case TargetTypeEXE:
			if !filepath.IsAbs(p) {
				p = filepath.Join(exeDir, p)
			}
		case TargetTypeMSIX:
			if !config.ValidPackageFamily(p) {
				return TargetSet{}, fmt.Errorf("%s: неверное семейство MSIX-пакета %q", t.ID, p)
			}
		case TargetTypeName:
			if !config.ValidFileName(p) {
				return TargetSet{}, fmt.Errorf("%s: неверное имя EXE %q", t.ID, p)
			}
		default:
			return TargetSet{}, fmt.Errorf("%s: неизвестный тип цели %q", t.ID, t.Type)
		}
		key := kind + "\x00" + strings.ToLower(filepath.Clean(p))
		if seen[key] {
			return TargetSet{}, fmt.Errorf("повторная цель: %s", p)
		}
		seen[key] = true
		switch kind {
		case TargetTypeMSIX:
			set.PackageFamilies = append(set.PackageFamilies, p)
		case TargetTypeName:
			set.FileNames = append(set.FileNames, p)
		default:
			set.Apps = append(set.Apps, p)
		}
	}
	return set, nil
}
