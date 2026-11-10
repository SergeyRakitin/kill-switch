package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"kill-switch/internal/config"
	"kill-switch/internal/diagnose"
	"kill-switch/internal/policy"
	"kill-switch/internal/runlog"
	"kill-switch/internal/wfp"
)

var journal *runlog.Log
var logStartupError string

func main() {
	args, dir, level, operationID, optErr := globalOptions(os.Args[1:])
	if optErr != nil {
		fmt.Fprintln(os.Stderr, "guard:", optErr)
		os.Exit(2)
	}
	var logErr error
	journal, logErr = runlog.New("guard", dir, level, operationID, "")
	wfp.Observe = func(name string, started time.Time, phaseErr error, attrs ...any) {
		outcome := "ok"
		if phaseErr != nil {
			outcome = "error"
			attrs = append(attrs, "error", phaseErr)
		}
		event(name, outcome, started, attrs...)
	}
	if logErr != nil {
		logStartupError = logErr.Error()
		fmt.Fprintln(os.Stderr, "guard log:", logErr)
	}
	start := time.Now()
	err := run(args)
	outcome := "not_applied"
	if err == nil {
		outcome = "not_applied"
		if len(args) > 0 && (args[0] == "uninstall" || args[0] == "disable" || args[0] == "lab-canary" || (args[0] == "install" && !strings.Contains(strings.Join(args, " "), "--dry-run"))) {
			outcome = "applied_verified"
		}
	}
	if errors.Is(err, wfp.ErrCommitUnknown) {
		outcome = "commit_unknown"
	}
	if errors.Is(err, wfp.ErrAppliedVerification) {
		outcome = "applied_verification_failed"
	}
	journal.Close(outcome, time.Since(start))
	if err != nil {
		fmt.Fprintln(os.Stderr, "guard:", err)
		os.Exit(1)
	}
}

func globalOptions(args []string) ([]string, string, string, string, error) {
	out := make([]string, 0, len(args))
	dir, level, op := "", "info", ""
	for i := 0; i < len(args); i++ {
		v := args[i]
		value := ""
		for _, key := range []string{"--log-dir", "--log-level", "--operation-id"} {
			if v == key {
				if i+1 >= len(args) {
					return nil, "", "", "", fmt.Errorf("%s requires a value", key)
				}
				i++
				value = args[i]
			} else if strings.HasPrefix(v, key+"=") {
				value = strings.TrimPrefix(v, key+"=")
			} else {
				continue
			}
			switch key {
			case "--log-dir":
				dir = value
			case "--log-level":
				level = value
			case "--operation-id":
				op = value
			}
			v = ""
			break
		}
		if v != "" {
			out = append(out, v)
		}
	}
	if level != "info" && level != "debug" {
		return nil, "", "", "", errors.New("log level must be info or debug")
	}
	return out, dir, level, op, nil
}

func event(name, outcome string, started time.Time, attrs ...any) {
	for i := 0; i+1 < len(attrs); i += 2 {
		if attrs[i] != "error" {
			continue
		}
		if e, ok := attrs[i+1].(error); ok {
			data := map[string]any{"message": e.Error()}
			var api wfp.APIError
			if errors.As(e, &api) {
				data["function"] = api.Function
				data["code"] = fmt.Sprintf("0x%08X", api.Code)
				data["name"] = api.Name()
			}
			attrs[i+1] = data
		}
	}
	journal.Event(name, outcome, time.Since(started), attrs...)
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: guard diagnose [--json] | install --dry-run --config FILE | status | test | disable --yes | uninstall --emergency --yes")
	}
	switch args[0] {
	case "diagnose":
		fs := flag.NewFlagSet("diagnose", flag.ContinueOnError)
		asJSON := fs.Bool("json", false, "machine-readable read-only snapshot")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 0 {
			return errors.New("unexpected diagnose argument")
		}
		started := time.Now()
		s, err := diagnose.Read()
		if err != nil {
			event("diagnose", "error", started, "error", err)
		} else {
			event("diagnose", "ok", started)
		}
		if err != nil {
			return err
		}
		if *asJSON {
			return emit(s)
		}
		fmt.Printf("%s %s build %s\n", s.OS.Caption, s.OS.Version, s.OS.BuildNumber)
		for _, a := range s.Adapters {
			if a.Status == "Up" {
				fmt.Printf("%s | %s | %s | ifIndex %d | LUID 0x%016X\n", a.Name, a.InterfaceDescription, a.InterfaceGuid, a.IfIndex, a.LUID)
			}
		}
		fmt.Printf("routes: %d; DNS interface records: %d; read-only, no WFP changes\n", len(s.Routes), len(s.DNS))
		return nil
	case "packages":
		fs := flag.NewFlagSet("packages", flag.ContinueOnError)
		asJSON := fs.Bool("json", false, "machine-readable read-only package list")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 0 {
			return errors.New("unexpected packages argument")
		}
		packages, err := diagnose.ReadPackages()
		if err != nil {
			return err
		}
		if *asJSON {
			return emit(packages)
		}
		for _, p := range packages {
			fmt.Printf("%s | %s | %s\n", p.Name, p.PackageFamilyName, p.Version)
		}
		return nil
	case "install":
		fs := flag.NewFlagSet("install", flag.ContinueOnError)
		dry := fs.Bool("dry-run", false, "plan only; no system changes")
		file := fs.String("config", "", "JSON configuration")
		var apps appList
		fs.Var(&apps, "app", "absolute path to an EXE; repeat for multiple applications")
		var packageFamilies appList
		fs.Var(&packageFamilies, "package-family", "MSIX package family name; repeat for multiple packages")
		var fileNames appList
		fs.Var(&fileNames, "file-name", "EXE file name without folder, e.g. claude.exe; matches that name in any folder; repeat for multiple names")
		vpnGUID := fs.String("vpn-guid", "", "VPN interface GUID")
		fingerprint := fs.String("plan-fingerprint", "", "fingerprint from reviewed dry-run")
		yes := fs.Bool("yes", false, "confirm real WFP mutation")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 0 {
			return errors.New("unexpected install argument")
		}
		c, err := installConfig(*file, apps, packageFamilies, fileNames, *vpnGUID)
		started := time.Now()
		if err != nil {
			event("validation", "error", started, "error", err)
		} else {
			event("validation", "ok", started, "apps", len(c.Applications), "packageFamilies", len(c.PackageFamilies), "fileNames", len(c.FileNames), "guid", c.VPNInterface.GUID)
		}
		if err != nil {
			return err
		}
		started = time.Now()
		s, err := diagnose.Read()
		if err != nil {
			event("diagnose", "error", started, "error", err)
		} else {
			event("diagnose", "ok", started)
		}
		if err != nil {
			return err
		}
		started = time.Now()
		p, err := policy.Build(c, s.Resolve(c.VPNInterface.GUID))
		if err != nil {
			event("plan", "error", started, "error", err)
		} else {
			event("plan", "ok", started, "rules", len(p.Add))
		}
		if err != nil {
			return err
		}
		started = time.Now()
		old, err := wfp.Current()
		if err != nil {
			event("wfp_read", "error", started, "error", err)
		} else {
			event("wfp_read", "ok", started, "filters", len(old.Filters))
		}
		if err != nil {
			if !*dry {
				return fmt.Errorf("WFP read failed; installation refused: %w", err)
			}
			p.Warnings = append(p.Warnings, "Existing WFP state could not be read; delete list is UNKNOWN (not empty): "+err.Error())
		} else {
			wfp.AttachSnapshot(&p, old)
		}
		if *dry {
			event("preview", "ok", time.Now(), "fingerprint", p.Fingerprint)
			return emit(p)
		}
		if !*yes || *fingerprint == "" {
			return errors.New("installation requires --yes and --plan-fingerprint from a reviewed preview")
		}
		if p.Fingerprint != *fingerprint {
			return errors.New("preview changed; review a new plan before applying")
		}
		if len(p.Add) > 0 && p.Interface.LUID == 0 {
			return errors.New("VPN interface unresolved; install refused")
		}
		started = time.Now()
		err = wfp.Install(p)
		if err != nil {
			event("install", "error", started, "error", err, "fingerprint", p.Fingerprint)
		} else {
			event("install", "applied_verified", started, "fingerprint", p.Fingerprint, "rules", len(p.Add))
		}
		return err
	case "lab-canary":
		fs := flag.NewFlagSet("lab-canary", flag.ContinueOnError)
		yes := fs.Bool("yes", false, "confirm provider/sublayer creation without filters")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 0 {
			return errors.New("unexpected argument")
		}
		if !*yes {
			return errors.New("test recovery requires --yes")
		}
		started := time.Now()
		err := wfp.PrepareCanary()
		if err != nil {
			event("recovery_test", "error", started, "error", err)
		} else {
			event("recovery_test", "applied_verified", started)
		}
		return err
	case "status", "test":
		if len(args) != 1 {
			return errors.New("unexpected argument")
		}
		s, err := wfp.Current()
		if err != nil {
			_ = emit(struct {
				State    string `json:"state"`
				Error    string `json:"error"`
				LogDir   string `json:"logDir"`
				LogError string `json:"logError,omitempty"`
			}{"unknown", err.Error(), journal.Path(), logStartupError})
			return fmt.Errorf("status unknown: %w", err)
		}
		state := "unknown"
		if len(s.Filters) == 0 {
			state = "disabled"
		}
		if s.Provider.Disabled || s.Sublayer.Disabled {
			state = "degraded"
		}
		return emit(struct {
			State           string       `json:"state"`
			PolicyInstalled bool         `json:"policyInstalled"`
			Verified        bool         `json:"verified"`
			WFP             wfp.Snapshot `json:"wfp"`
			LogDir          string       `json:"logDir"`
			LogError        string       `json:"logError,omitempty"`
		}{State: state, PolicyInstalled: len(s.Filters) > 0, Verified: false, WFP: s, LogDir: journal.Path(), LogError: logStartupError})
	case "disable", "uninstall":
		fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
		yes := fs.Bool("yes", false, "confirm removal of own WFP filters")
		emergency := fs.Bool("emergency", false, "remove own objects without JSON")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 0 {
			return errors.New("unexpected argument")
		}
		if !*yes {
			return errors.New("removal requires --yes; no system changes made")
		}
		if args[0] == "disable" && *emergency {
			return errors.New("--emergency only applies to uninstall")
		}
		started := time.Now()
		err := wfp.Remove(args[0] == "uninstall")
		if err != nil {
			event("remove", "error", started, "error", err)
		} else {
			event("remove", "applied_verified", started)
		}
		return err
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

type appList []string

func (a *appList) String() string     { return strings.Join(*a, ",") }
func (a *appList) Set(v string) error { *a = append(*a, v); return nil }

func installConfig(file string, apps, packageFamilies, fileNames []string, vpnGUID string) (config.Config, error) {
	if file != "" {
		if len(apps) != 0 || len(packageFamilies) != 0 || len(fileNames) != 0 || vpnGUID != "" {
			return config.Config{}, errors.New("use either --config or --app/--package-family/--file-name with --vpn-guid")
		}
		return config.Load(file)
	}
	if vpnGUID == "" {
		return config.Config{}, errors.New("specify --vpn-guid, or --config")
	}
	c := config.Config{
		SchemaVersion:   1,
		Applications:    apps,
		PackageFamilies: packageFamilies,
		FileNames:       fileNames,
		VPNInterface:    config.Interface{GUID: vpnGUID},
		LoopbackPolicy:  "deny",
	}
	return c, c.Validate()
}

func emit(value any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(value)
}
