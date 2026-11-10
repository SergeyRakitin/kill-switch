package desktop

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"kill-switch/internal/ui"
)

type Adapter struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	GUID        string `json:"guid"`
	Status      string `json:"status"`
	LUID        string `json:"luid"`
}

type Event struct {
	Time    string `json:"time"`
	Level   string `json:"level"`
	Message string `json:"message"`
}

type View struct {
	Settings          ui.Settings `json:"settings"`
	Adapters          []Adapter   `json:"adapters"`
	Status            string      `json:"status"`
	Reason            string      `json:"reason"`
	VPNStatus         string      `json:"vpnStatus"`
	VerifiedPaths     []string    `json:"verifiedPaths"`
	VerifiedTargetIDs []string    `json:"verifiedTargetIds"`
	InstalledPaths    []string    `json:"installedPaths"`
	FilterCount       int         `json:"filterCount"`
	ObjectsPresent    bool        `json:"objectsPresent"`
	ConfigDirty       bool        `json:"configDirty"`
	RawStatus         string      `json:"rawStatus"`
	Diagnostic        string      `json:"diagnostic"`
	Events            []Event     `json:"events"`
	Busy              bool        `json:"busy"`
	Error             string      `json:"error"`
}

type PreviewResult struct {
	Fingerprint string   `json:"fingerprint"`
	Apps        []string `json:"apps"`
	AddCount    int      `json:"addCount"`
	DeleteCount int      `json:"deleteCount"`
	Raw         string   `json:"raw"`
	Warnings    []string `json:"warnings"`
}

type reviewedPlan struct {
	fingerprint string
	revision    uint64
	targets     ui.TargetSet
}

type Service struct {
	exeDir string
	client ui.Client

	mu       sync.Mutex
	view     View
	mutating bool
	closing  bool
	revision uint64
	reviewed reviewedPlan
	picker   func() (string, error)
}

func New(exeDir string) (*Service, error) {
	settings, err := ui.LoadOrCreateSettings(exeDir)
	if err != nil {
		return nil, err
	}
	return &Service{
		exeDir: exeDir,
		client: ui.New(filepath.Join(exeDir, "guard.exe")),
		view: View{
			Settings: settings, Adapters: []Adapter{}, VerifiedPaths: []string{}, VerifiedTargetIDs: []string{}, InstalledPaths: []string{}, Events: []Event{},
			Status: "unknown", Reason: "Состояние WFP ещё не прочитано.", VPNStatus: "unknown",
		},
	}, nil
}

func SetFilePicker(s *Service, picker func() (string, error)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.picker = picker
}

// BeginShutdown reserves the idle service for shutdown before the window closes.
func BeginShutdown(s *Service) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.view.Busy {
		return false
	}
	s.closing = true
	return true
}

func (s *Service) IsMutating() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.mutating
}

func (s *Service) Snapshot() View {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.snapshotLocked()
}

func (s *Service) snapshotLocked() View {
	view := s.view
	view.Settings.Targets = slices.Clone(view.Settings.Targets)
	view.Settings.NetworkAdapterTypes = slices.Clone(view.Settings.NetworkAdapterTypes)
	view.Adapters = slices.Clone(view.Adapters)
	view.VerifiedPaths = slices.Clone(view.VerifiedPaths)
	view.VerifiedTargetIDs = slices.Clone(view.VerifiedTargetIDs)
	view.InstalledPaths = slices.Clone(view.InstalledPaths)
	view.Events = slices.Clone(view.Events)
	return view
}

func (s *Service) ClearEvents() View {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.view.Events = []Event{}
	return s.snapshotLocked()
}

func (s *Service) begin() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closing {
		return errors.New("Приложение закрывается.")
	}
	if s.view.Busy {
		return errors.New("Дождитесь завершения текущей операции.")
	}
	s.view.Busy = true
	s.view.Error = ""
	return nil
}

func (s *Service) end(err error) View {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.view.Busy = false
	s.mutating = false
	if err != nil {
		s.view.Error = err.Error()
		s.addEventLocked("error", err.Error())
	}
	return s.snapshotLocked()
}

func (s *Service) withView(action func() error) (View, error) {
	if err := s.begin(); err != nil {
		return s.Snapshot(), err
	}
	err := action()
	return s.end(err), err
}

func (s *Service) addEventLocked(level, message string) {
	const limit = 150
	if len(s.view.Events) == limit {
		copy(s.view.Events, s.view.Events[1:])
		s.view.Events = s.view.Events[:limit-1]
	}
	s.view.Events = append(s.view.Events, Event{Time: time.Now().Format(time.RFC3339), Level: level, Message: message})
}

func (s *Service) appendDiagnosticLocked(section string) {
	if section == "" {
		return
	}
	const limit = 512 * 1024
	if len(s.view.Diagnostic)+len(section) > limit {
		s.view.Diagnostic = ""
	}
	if s.view.Diagnostic != "" {
		s.view.Diagnostic += "\n\n"
	}
	s.view.Diagnostic += time.Now().Format(time.RFC3339) + "\n" + section
}

func (s *Service) warnings() []string {
	warnings := []string{}
	for {
		select {
		case warning := <-s.client.Warnings:
			warnings = append(warnings, warning)
		default:
			return warnings
		}
	}
}

func (s *Service) recordWarningsLocked(warnings []string) {
	for _, warning := range warnings {
		s.addEventLocked("warning", warning)
	}
}

func (s *Service) Preview() (result PreviewResult, err error) {
	if err = s.begin(); err != nil {
		return result, err
	}
	defer func() { s.end(err) }()
	s.mu.Lock()
	s.reviewed = reviewedPlan{}
	settings := s.view.Settings
	revision := s.revision
	s.mu.Unlock()

	targets, err := settings.ActiveTargets(s.exeDir)
	if err != nil {
		return result, err
	}
	plan, raw, err := s.client.PreviewTargets(context.Background(), targets, settings.VPNInterfaceGUID)
	warnings := append(s.warnings(), plan.Warnings...)

	s.mu.Lock()
	defer s.mu.Unlock()
	details := []string{"Предпросмотр WFP", raw, strings.Join(warnings, "\n")}
	if err != nil {
		details = append(details, err.Error())
	}
	s.appendDiagnosticLocked(strings.Join(details, "\n"))
	s.recordWarningsLocked(warnings)
	if err != nil {
		return result, err
	}
	s.reviewed = reviewedPlan{fingerprint: plan.Fingerprint, revision: revision, targets: targets.Clone()}
	s.addEventLocked("info", fmt.Sprintf("План подготовлен: %d EXE, %d MSIX и %d по имени, добавление %d и удаление %d фильтров.", len(targets.Apps), len(targets.PackageFamilies), len(targets.FileNames), len(plan.Add), len(plan.Delete)))
	return PreviewResult{
		Fingerprint: plan.Fingerprint, Apps: targets.Display(), AddCount: len(plan.Add),
		DeleteCount: len(plan.Delete), Raw: raw, Warnings: warnings,
	}, nil
}

func (s *Service) Apply(fingerprint string, confirmed bool) (View, error) {
	return s.withView(func() error {
		if !confirmed {
			return errors.New("Подтвердите применение плана.")
		}
		view := s.Snapshot()
		targets, err := view.Settings.ActiveTargets(s.exeDir)
		if err != nil {
			return err
		}
		if fingerprint == "" || fingerprint != s.reviewed.fingerprint || s.revision != s.reviewed.revision || !targets.Equal(s.reviewed.targets) {
			return errors.New("План устарел. Постройте и проверьте новый план.")
		}
		return s.mutate("Применение правил", func(ctx context.Context, operationID string) (string, error) {
			return s.client.ApplyTargets(ctx, targets, view.Settings.VPNInterfaceGUID, fingerprint, operationID)
		}, func(view View) bool {
			if targets.Count() == 0 {
				return view.Status == "disabled"
			}
			return view.Status == "active"
		}, true)
	})
}

func (s *Service) Remove(confirmed bool) (View, error) {
	return s.withView(func() error {
		if !confirmed {
			return errors.New("Подтвердите снятие правил WFP.")
		}
		return s.mutate("Снятие правил", s.client.RemoveAsync, allObjectsAbsent, false)
	})
}

func (s *Service) Canary(confirmed bool) (View, error) {
	return s.withView(func() error {
		if !confirmed {
			return errors.New("Подтвердите проверку записи в WFP.")
		}
		return s.mutate("Проверка записи WFP", func(ctx context.Context, operationID string) (string, error) {
			raw, err := s.client.CanaryAsync(ctx, operationID)
			if err != nil {
				return raw, err
			}
			removal, err := s.client.RemoveAsync(ctx, operationID)
			return raw + "\nУдаление: " + removal, err
		}, allObjectsAbsent, false)
	})
}

func allObjectsAbsent(view View) bool {
	return view.Status == "disabled" && !view.ObjectsPresent
}

func (s *Service) mutate(label string, command func(context.Context, string) (string, error), verified func(View) bool, appliesSettings bool) error {
	s.mu.Lock()
	s.mutating = true
	s.reviewed = reviewedPlan{}
	s.view.Status = "unknown"
	s.view.Reason = "Выполняется изменение WFP. Ожидайте проверки результата."
	s.view.VerifiedPaths = []string{}
	s.view.VerifiedTargetIDs = []string{}
	s.mu.Unlock()

	ctx := context.Background()
	operationID := fmt.Sprintf("ui-%d", time.Now().UnixNano())
	raw, commandErr := command(ctx, operationID)
	warnings := s.warnings()
	s.mu.Lock()
	details := []string{label + " · " + operationID, raw, strings.Join(warnings, "\n")}
	if commandErr != nil {
		details = append(details, "Ошибка команды: "+commandErr.Error())
	}
	s.appendDiagnosticLocked(strings.Join(details, "\n"))
	s.recordWarningsLocked(warnings)
	s.mu.Unlock()

	readErr := s.refresh(ctx, operationID)
	if commandErr != nil {
		commandErr = fmt.Errorf("%s: %w", label, commandErr)
	}
	if err := errors.Join(commandErr, readErr); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !verified(s.view) {
		return fmt.Errorf("%s: проверка результата не подтвердила ожидаемое состояние WFP", label)
	}
	if appliesSettings {
		s.view.ConfigDirty = false
	}
	s.addEventLocked("success", label+": результат проверен.")
	return nil
}
