package desktop

import (
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"time"

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
			if _, err := next.ActivePaths(s.exeDir); err != nil {
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
				ID: fmt.Sprintf("custom-%d", time.Now().UnixNano()), Path: path, Enabled: true,
			})
		} else {
			target.Path = path
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
		if !strings.HasPrefix(id, "custom-") {
			return errors.New("Встроенную запись удалить нельзя.")
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
	s.mu.Lock()
	defer s.mu.Unlock()
	s.view.Settings = next
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
