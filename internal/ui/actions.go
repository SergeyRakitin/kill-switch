package ui

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"kill-switch/internal/policy"
)

type Plan struct {
	Kind             string `json:"kind"`
	Verified         bool   `json:"verified"`
	ExistingWFPState string `json:"existingWfpState"`
	ProviderGUID     string `json:"providerGuid"`
	SublayerGUID     string `json:"sublayerGuid"`
	Fingerprint      string `json:"fingerprint"`
	SnapshotDigest   string `json:"snapshotDigest"`
	Interface        struct {
		GUID string `json:"guid"`
		LUID uint64 `json:"luid"`
	} `json:"interface"`
	Add []struct {
		Key         string `json:"key"`
		Application string `json:"application"`
		Layer       string `json:"layer"`
		Action      string `json:"action"`
	} `json:"add"`
	Delete   []string `json:"delete"`
	Warnings []string `json:"warnings"`
}

type Client struct {
	Binary     string
	RunContext func(context.Context, ...string) ([]byte, error)
	Warnings   chan string
}

const wfpAdminGuidance = "Обычно ERROR_ACCESS_DENIED означает запуск без прав администратора. Закройте GUI и выберите «Запуск от имени администратора» (CLI запускайте из повышенного терминала). Перезапуск сам по себе не меняет VPN или правила WFP."

func WFPAccessDenied(text string) bool {
	return strings.Contains(text, "ERROR_ACCESS_DENIED") || strings.Contains(text, "0x00000005")
}

func WFPAdminGuidance(err error) error {
	if err == nil || !WFPAccessDenied(err.Error()) || strings.Contains(err.Error(), wfpAdminGuidance) {
		return err
	}
	return fmt.Errorf("%w\n%s", err, wfpAdminGuidance)
}

func New(binary string) Client {
	c := Client{Binary: binary, Warnings: make(chan string, 8)}
	c.RunContext = func(ctx context.Context, args ...string) ([]byte, error) {
		cmd := exec.CommandContext(ctx, binary, args...)
		configureCommand(cmd)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		if err != nil {
			return out, WFPAdminGuidance(fmt.Errorf("guard.exe: %w: %s", err, strings.TrimSpace(stderr.String())))
		}
		if stderr.Len() > 0 {
			select {
			case c.Warnings <- strings.TrimSpace(stderr.String()):
			default:
			}
		}
		return out, nil
	}
	return c
}

func (c Client) execute(ctx context.Context, args ...string) ([]byte, error) {
	if c.RunContext == nil {
		return nil, errors.New("guard runner unavailable")
	}
	return c.RunContext(ctx, args...)
}

func (c Client) PreviewApps(ctx context.Context, apps []string, guid string) (Plan, string, error) {
	return c.PreviewTargets(ctx, TargetSet{Apps: apps}, guid)
}

// targetArgs переводит набор целей в аргументы guard.exe install.
func targetArgs(targets TargetSet) []string {
	args := []string{}
	for _, app := range targets.Apps {
		args = append(args, "--app", app)
	}
	for _, family := range targets.PackageFamilies {
		args = append(args, "--package-family", family)
	}
	for _, name := range targets.FileNames {
		args = append(args, "--file-name", name)
	}
	return args
}

func (c Client) PreviewTargets(ctx context.Context, targets TargetSet, guid string) (Plan, string, error) {
	var p Plan
	if strings.TrimSpace(guid) == "" {
		return p, "", errors.New("GUID VPN не задан в JSON")
	}
	args := append([]string{"install", "--dry-run", "--vpn-guid", guid}, targetArgs(targets)...)
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	out, err := c.execute(ctx, args...)
	if err != nil {
		return p, string(out), err
	}
	if err := json.Unmarshal(out, &p); err != nil {
		return p, string(out), fmt.Errorf("dry-run JSON: %w", err)
	}
	if p.Kind != "UNVERIFIED_DRY_RUN" || p.Verified || p.ProviderGUID != policy.ProviderGUID || p.SublayerGUID != policy.SublayerGUID {
		return p, string(out), errors.New("некорректный dry-run: не совпали тип или идентификаторы WFP")
	}
	if p.ExistingWFPState != "READ" {
		detail := "причина не возвращена"
		if len(p.Warnings) > 0 {
			detail = p.Warnings[len(p.Warnings)-1]
		}
		return p, string(out), WFPAdminGuidance(fmt.Errorf("план не подтверждён чтением WFP (%s): %s", p.ExistingWFPState, detail))
	}
	if p.Fingerprint == "" {
		return p, string(out), errors.New("некорректный dry-run: пустой отпечаток плана")
	}
	return p, string(out), nil
}

func (c Client) ApplyPlan(ctx context.Context, apps []string, guid, fingerprint, operationID string) (string, error) {
	return c.ApplyTargets(ctx, TargetSet{Apps: apps}, guid, fingerprint, operationID)
}

func (c Client) ApplyTargets(ctx context.Context, targets TargetSet, guid, fingerprint, operationID string) (string, error) {
	args := append([]string{"install", "--vpn-guid", guid}, targetArgs(targets)...)
	args = append(args, "--plan-fingerprint", fingerprint, "--yes", "--operation-id", operationID)
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	out, err := c.execute(ctx, args...)
	return string(out), err
}
func (c Client) RemoveAsync(ctx context.Context, operationID string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	out, err := c.execute(ctx, "uninstall", "--emergency", "--yes", "--operation-id", operationID)
	return string(out), err
}
func (c Client) StatusAsync(ctx context.Context, operationID ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	args := []string{"status"}
	if len(operationID) > 0 && operationID[0] != "" {
		args = append(args, "--operation-id", operationID[0])
	}
	out, err := c.execute(ctx, args...)
	return string(out), err
}
func (c Client) CanaryAsync(ctx context.Context, operationID string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	out, err := c.execute(ctx, "lab-canary", "--yes", "--operation-id", operationID)
	return string(out), err
}

type Adapter struct {
	Name, Description, GUID, Status string
	HardwareInterface               bool
	LUID                            uint64
}

type Package struct {
	Name              string `json:"name"`
	PackageFamilyName string `json:"packageFamilyName"`
	Version           string `json:"version"`
	InstallLocation   string `json:"installLocation"`
}

func (c Client) PackagesAsync(ctx context.Context) ([]Package, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	out, err := c.execute(ctx, "packages", "--json")
	if err != nil {
		return nil, err
	}
	var packages []Package
	if err := json.Unmarshal(out, &packages); err != nil {
		return nil, fmt.Errorf("MSIX package JSON: %w", err)
	}
	return packages, nil
}

func (c Client) AdaptersAsync(ctx context.Context) ([]Adapter, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	out, err := c.execute(ctx, "diagnose", "--json")
	if err != nil {
		return nil, err
	}
	var snapshot struct {
		Adapters []struct {
			Name                 string `json:"name"`
			InterfaceDescription string `json:"interfaceDescription"`
			InterfaceGuid        string `json:"interfaceGuid"`
			Status               string `json:"status"`
			HardwareInterface    bool   `json:"hardwareInterface"`
			LUID                 uint64 `json:"luid"`
		} `json:"adapters"`
	}
	if err := json.Unmarshal(out, &snapshot); err != nil {
		return nil, fmt.Errorf("adapter JSON: %w", err)
	}
	result := make([]Adapter, 0, len(snapshot.Adapters))
	for _, a := range snapshot.Adapters {
		result = append(result, Adapter{
			Name: a.Name, Description: a.InterfaceDescription, GUID: a.InterfaceGuid, Status: a.Status,
			HardwareInterface: a.HardwareInterface, LUID: a.LUID,
		})
	}
	return result, nil
}
