package desktop

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"kill-switch/internal/policy"
	"kill-switch/internal/ui"
	"kill-switch/internal/wfp"
)

func (s *Service) Refresh() (View, error) {
	return s.withView(func() error { return s.refresh(context.Background(), "") })
}

const missingTargetsReason = "Файлы некоторых записей «EXE по точному пути» не найдены. Удалите или выключите эти записи либо выберите EXE заново, затем установите правила."

// hasEnabledMissing сообщает, есть ли среди включённых записей та, чьего файла нет на диске.
func hasEnabledMissing(settings ui.Settings, missing []string) bool {
	for _, target := range settings.Targets {
		if target.Enabled && slices.Contains(missing, target.ID) {
			return true
		}
	}
	return false
}

func (s *Service) refresh(ctx context.Context, operationID string) error {
	settings := s.Snapshot().Settings
	missing := settings.MissingTargetIDs(s.exeDir)
	raw, readErr := s.client.StatusAsync(ctx, operationID)
	var observed struct {
		State string `json:"state"`
		WFP   *struct {
			Provider *wfp.ObjectState  `json:"provider"`
			Sublayer *wfp.ObjectState  `json:"sublayer"`
			Filters  []wfp.FilterState `json:"filters"`
		} `json:"wfp"`
	}
	if readErr == nil {
		if err := json.Unmarshal([]byte(raw), &observed); err != nil {
			readErr = fmt.Errorf("JSON состояния WFP: %w", err)
		} else if observed.WFP == nil || observed.WFP.Provider == nil || observed.WFP.Sublayer == nil || observed.WFP.Filters == nil {
			readErr = errors.New("Команда status не вернула полный снимок WFP.")
		} else if observed.State != "disabled" && observed.State != "unknown" && observed.State != "degraded" {
			readErr = fmt.Errorf("Команда status вернула неизвестное состояние WFP %q.", observed.State)
		}
	}

	adapters, adapterErr := s.client.AdaptersAsync(ctx)
	adapters = ui.FilterAdapters(adapters, settings.NetworkAdapterTypes, settings.VPNInterfaceGUID)
	status, reason := "unknown", "Обнаруженные правила не подтверждены."
	paths := []string{}
	installedPaths := []string{}
	var count int
	var present bool
	var verifyErr error
	if readErr != nil {
		status, reason = "error", "Не удалось прочитать состояние WFP."
		if ui.WFPAccessDenied(readErr.Error()) {
			reason = "Windows отклонила доступ к WFP. Закройте приложение и запустите guard-desktop.exe от имени администратора. Перезапуск не меняет VPN или правила."
		}
	} else {
		snapshot := wfp.Snapshot{
			Provider: *observed.WFP.Provider,
			Sublayer: *observed.WFP.Sublayer,
			Filters:  observed.WFP.Filters,
		}
		count = len(snapshot.Filters)
		present = count > 0 || snapshot.Provider.Present || snapshot.Sublayer.Present
		seenInstalled := map[string]bool{}
		for _, filter := range snapshot.Filters {
			target := filter.Application
			if filter.PackageFamily != "" {
				target = "msix:" + filter.PackageFamily
			}
			if filter.FileName != "" {
				target = "name:" + filter.FileName
			}
			key := strings.ToLower(target)
			if key != "" && !seenInstalled[key] {
				seenInstalled[key] = true
				installedPaths = append(installedPaths, target)
			}
		}
		switch {
		case snapshot.Provider.Disabled || snapshot.Sublayer.Disabled:
			reason = "Провайдер или подслой WFP отключён."
		case count == 0 && observed.State == "disabled":
			status, reason = "disabled", "Собственные фильтры не установлены."
		case count > 0 && hasEnabledMissing(settings, missing):
			// План для таких настроек не строится; без сверки обходимся без предупреждения в журнале на каждом обновлении.
			reason = missingTargetsReason
		case count > 0:
			paths, verifyErr = s.verifyPaths(ctx, settings, snapshot)
			if verifyErr == nil {
				status, reason = "active", "Фильтры WFP соответствуют выбранным приложениям и VPN."
			} else {
				reason = "Не удалось подтвердить соответствие правил настройкам."
			}
		}
	}
	warnings := s.warnings()

	s.mu.Lock()
	defer s.mu.Unlock()
	s.view.RawStatus = raw
	s.view.Status, s.view.Reason = status, reason
	s.view.FilterCount, s.view.ObjectsPresent = count, present
	s.view.VerifiedPaths = paths
	s.view.InstalledPaths = installedPaths
	s.view.MissingTargetIDs = missing
	s.view.VerifiedTargetIDs = []string{}
	if status == "active" {
		s.view.ConfigDirty = false
		// The verified plan covers every enabled target in these settings.
		for _, target := range settings.Targets {
			if target.Enabled {
				s.view.VerifiedTargetIDs = append(s.view.VerifiedTargetIDs, target.ID)
			}
		}
	}
	s.view.Adapters = make([]Adapter, 0, len(adapters))
	for _, adapter := range adapters {
		s.view.Adapters = append(s.view.Adapters, Adapter{
			Name: adapter.Name, Description: adapter.Description,
			GUID: adapter.GUID, Status: adapter.Status, LUID: fmt.Sprintf("0x%016X", adapter.LUID),
		})
	}
	s.view.VPNStatus = vpnStatus(settings.VPNInterfaceGUID, s.view.Adapters)
	details := []string{"Чтение состояния WFP", raw}
	if readErr != nil {
		details = append(details, readErr.Error())
	}
	if adapterErr != nil {
		warnings = append(warnings, "Обнаружение интерфейсов: "+adapterErr.Error())
	}
	if verifyErr != nil {
		warnings = append(warnings, "Сопоставление фильтров: "+verifyErr.Error())
	}
	if len(warnings) > 0 {
		details = append(details, strings.Join(warnings, "\n"))
	}
	s.recordWarningsLocked(warnings)
	s.appendDiagnosticLocked(strings.Join(details, "\n"))
	if readErr != nil {
		return fmt.Errorf("Чтение состояния WFP: %w", readErr)
	}
	if operationID == "" {
		s.addEventLocked("info", "Состояние WFP перечитано. "+reason)
	}
	return nil
}

func (s *Service) verifyPaths(ctx context.Context, settings ui.Settings, snapshot wfp.Snapshot) ([]string, error) {
	empty := []string{}
	targets, err := settings.ActiveTargets(s.exeDir)
	if err != nil {
		return empty, err
	}
	if err := missingAppsError(targets); err != nil {
		return empty, err
	}
	_, raw, err := s.client.PreviewTargets(ctx, targets, settings.VPNInterfaceGUID)
	if err != nil {
		return empty, err
	}
	var plan policy.Plan
	if err = json.Unmarshal([]byte(raw), &plan); err != nil {
		return empty, err
	}
	if plan.SnapshotDigest == "" || plan.SnapshotDigest != wfp.SnapshotDigest(snapshot) {
		return empty, errors.New("Состояние WFP изменилось между чтением и проверкой плана.")
	}
	if err := wfp.Verify(plan, snapshot); err != nil {
		return empty, err
	}
	return targets.Display(), nil
}

func sameGUID(a, b string) bool {
	return a != "" && b != "" && strings.EqualFold(strings.Trim(a, "{}"), strings.Trim(b, "{}"))
}

func vpnStatus(guid string, adapters []Adapter) string {
	for _, adapter := range adapters {
		if !sameGUID(adapter.GUID, guid) {
			continue
		}
		switch strings.ToLower(adapter.Status) {
		case "up", "connected":
			return "connected"
		case "down", "disconnected":
			return "disconnected"
		}
	}
	return "unknown"
}
