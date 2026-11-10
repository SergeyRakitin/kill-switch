package desktop

import (
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"kill-switch/internal/config"
	"kill-switch/internal/ui"
)

func (s *Service) SetTarget(id string, enabled, confirmed bool) (View, error) {
	return s.withView(func() error {
		next := s.Snapshot().Settings
		target := next.Target(id)
		if target == nil {
			return errors.New("Приложение не найдено.")
		}
		if target.Enabled == enabled {
			return nil
		}
		if !enabled && !confirmed {
			return errors.New("Подтвердите исключение приложения.")
		}
		target.Enabled = enabled
		if enabled {
			if _, err := next.ActiveTargets(s.exeDir); err != nil {
				return err
			}
		}
		return s.saveSettings(next)
	})
}

func (s *Service) BrowseTarget(id string) (View, error) {
	return s.withView(func() error {
		next := s.Snapshot().Settings
		target := next.Target(id)
		if id != "" && target == nil {
			return errors.New("Приложение не найдено.")
		}
		if target != nil && target.Kind() == ui.TargetTypeMSIX {
			return errors.New("MSIX-цель изменяется через семейство пакета, а не выбор EXE.")
		}
		if target != nil && target.Kind() == ui.TargetTypeName {
			return errors.New("Цель по имени задаётся именем файла, а не выбором EXE.")
		}
		s.mu.Lock()
		picker := s.picker
		s.mu.Unlock()
		if picker == nil {
			return errors.New("Диалог выбора EXE недоступен.")
		}
		path, err := picker()
		if err != nil || path == "" {
			return err
		}
		if !filepath.IsAbs(path) || !strings.EqualFold(filepath.Ext(path), ".exe") {
			return errors.New("Выберите файл EXE.")
		}
		path = filepath.Clean(path)
		if target == nil {
			next.Targets = append(next.Targets, ui.Target{
				ID: fmt.Sprintf("custom-%d", time.Now().UnixNano()), Type: ui.TargetTypeEXE, Path: path, Enabled: true,
			})
		} else {
			target.Path = path
		}
		return s.saveSettings(next)
	})
}

func (s *Service) AddPackageTarget(family string) (View, error) {
	return s.withView(func() error {
		family = strings.TrimSpace(family)
		if !config.ValidPackageFamily(family) {
			return errors.New("Укажите семейство MSIX в формате Name_PublisherId, например Claude_pzs8sxrjxfjjc.")
		}
		next := s.Snapshot().Settings
		for _, target := range next.Targets {
			if target.Kind() == ui.TargetTypeMSIX && strings.EqualFold(target.Path, family) {
				return errors.New("Это семейство MSIX уже есть в списке.")
			}
		}
		next.Targets = append(next.Targets, ui.Target{
			ID: fmt.Sprintf("custom-msix-%d", time.Now().UnixNano()), Type: ui.TargetTypeMSIX, Path: family, Enabled: true,
		})
		if _, err := next.ActiveTargets(s.exeDir); err != nil {
			return err
		}
		return s.saveSettings(next)
	})
}

// AddNameTarget добавляет цель по имени EXE: правило совпадёт с этим файлом в любой папке.
func (s *Service) AddNameTarget(name string) (View, error) {
	return s.withView(func() error {
		name = strings.TrimSpace(name)
		if !config.ValidFileName(name) {
			return errors.New("Укажите только имя EXE латиницей, без папки и масок, например claude.exe.")
		}
		next := s.Snapshot().Settings
		for _, target := range next.Targets {
			if target.Kind() == ui.TargetTypeName && strings.EqualFold(target.Path, name) {
				return errors.New("Это имя EXE уже есть в списке.")
			}
		}
		next.Targets = append(next.Targets, ui.Target{
			ID: fmt.Sprintf("custom-name-%d", time.Now().UnixNano()), Type: ui.TargetTypeName, Path: name, Enabled: true,
		})
		if _, err := next.ActiveTargets(s.exeDir); err != nil {
			return err
		}
		return s.saveSettings(next)
	})
}

func (s *Service) RemoveTarget(id string, confirmed bool) (View, error) {
	return s.withView(func() error {
		if !confirmed {
			return errors.New("Подтвердите удаление приложения.")
		}
		next := s.Snapshot().Settings
		if id == "probe" {
			return errors.New("Служебную запись probe удалить нельзя.")
		}
		index := slices.IndexFunc(next.Targets, func(target ui.Target) bool { return target.ID == id })
		if index < 0 {
			return errors.New("Приложение не найдено.")
		}
		next.Targets = slices.Delete(next.Targets, index, index+1)
		return s.saveSettings(next)
	})
}

func (s *Service) SelectAdapter(guid string) (View, error) {
	return s.withView(func() error {
		view := s.Snapshot()
		for _, adapter := range view.Adapters {
			if sameGUID(adapter.GUID, guid) {
				view.Settings.VPNInterfaceGUID = adapter.GUID
				view.Settings.VPNInterfaceName = adapter.Name
				return s.saveSettings(view.Settings)
			}
		}
		return errors.New("Выберите обнаруженный VPN-интерфейс.")
	})
}

func (s *Service) saveSettings(next ui.Settings) error {
	current := s.Snapshot().Settings
	if next.VPNInterfaceGUID == current.VPNInterfaceGUID &&
		next.VPNInterfaceName == current.VPNInterfaceName &&
		slices.Equal(next.NetworkAdapterTypes, current.NetworkAdapterTypes) &&
		slices.Equal(next.Targets, current.Targets) {
		return nil
	}
	if err := ui.SaveSettings(filepath.Join(s.exeDir, ui.SettingsFile), next); err != nil {
		return fmt.Errorf("Не удалось сохранить настройки: %w", err)
	}
	missing := next.MissingTargetIDs(s.exeDir)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.view.Settings = next
	s.view.MissingTargetIDs = missing
	s.revision++
	s.reviewed = reviewedPlan{}
	s.view.ConfigDirty = true
	s.view.VerifiedPaths = []string{}
	s.view.VerifiedTargetIDs = []string{}
	s.view.VPNStatus = vpnStatus(next.VPNInterfaceGUID, s.view.Adapters)
	if s.view.Status == "active" {
		s.view.Status = "unknown"
		s.view.Reason = "Настройки изменились. Проверьте и примените новый план."
	}
	s.addEventLocked("info", "Настройки сохранены. Правила WFP ещё не изменены.")
	return nil
}
