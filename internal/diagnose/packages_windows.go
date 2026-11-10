package diagnose

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"syscall"
)

type Package struct {
	Name              string `json:"name"`
	PackageFamilyName string `json:"packageFamilyName"`
	Version           string `json:"version"`
	InstallLocation   string `json:"installLocation"`
}

const packageScript = `[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false); $ErrorActionPreference='Stop'; @(Get-AppxPackage -PackageTypeFilter Main | Sort-Object Name | Select-Object Name,PackageFamilyName,Version,InstallLocation) | ConvertTo-Json -Depth 3 -Compress`

func ReadPackages() ([]Package, error) {
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", packageScript)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("read-only MSIX inventory: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	var packages []Package
	if err := json.Unmarshal(output, &packages); err != nil {
		return nil, fmt.Errorf("MSIX inventory JSON: %w", err)
	}
	return packages, nil
}
