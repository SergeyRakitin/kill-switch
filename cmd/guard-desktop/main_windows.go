package main

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"time"
	"unsafe"

	"github.com/wailsapp/wails/v3/pkg/application"
	"github.com/wailsapp/wails/v3/pkg/events"
	"kill-switch/frontend"
	"kill-switch/internal/desktop"
)

func main() {
	executable, err := os.Executable()
	if err != nil {
		fatal(err)
		return
	}
	service, err := desktop.New(filepath.Dir(executable))
	if err != nil {
		fatal(err)
		return
	}
	assets, err := fs.Sub(frontend.Assets, "dist")
	if err != nil {
		fatal(err)
		return
	}
	stopped := make(chan struct{})
	var window *application.WebviewWindow
	app := application.New(application.Options{
		Name:        "VPN Kill Switch",
		Description: "Защита сетевых подключений",
		Icon:        shieldIcon(56, 139, 253),
		Services:    []application.Service{application.NewService(service)},
		Assets:      application.AssetOptions{Handler: application.BundledAssetFileServer(assets)},
		ShouldQuit:  func() bool { return desktop.BeginShutdown(service) },
		SingleInstance: &application.SingleInstanceOptions{UniqueID: "local.kill-switch.desktop", OnSecondInstanceLaunch: func(application.SecondInstanceData) {
			if window != nil {
				window.Show()
				window.Focus()
			}
		}},
		OnShutdown: func() { close(stopped) },
	})
	window = app.Window.NewWithOptions(application.WebviewWindowOptions{
		Name: "main", Title: "VPN Kill Switch", URL: "/",
		Width: 1000, Height: 680, MinWidth: 720, MinHeight: 500,
		BackgroundColour:           application.NewRGB(8, 18, 27),
		DefaultContextMenuDisabled: true,
		Windows:                    application.WindowsWindow{Theme: application.Dark},
	})
	desktop.SetFilePicker(service, func() (string, error) {
		return app.Dialog.OpenFile().CanChooseFiles(true).AddFilter("Приложения Windows", "*.exe").AttachToWindow(window).PromptForSingleSelection()
	})
	window.RegisterHook(events.Common.WindowClosing, func(e *application.WindowEvent) {
		if !desktop.BeginShutdown(service) {
			e.Cancel()
			window.Show()
			window.Focus()
		}
	})
	tray := app.SystemTray.New()
	tray.SetIcon(shieldIcon(245, 185, 66))
	tray.SetTooltip("VPN Kill Switch · Состояние не подтверждено")
	menu := app.NewMenu()
	menu.Add("Открыть окно").OnClick(func(*application.Context) { window.Show(); window.Focus() })
	menu.Add("Проверить состояние").OnClick(func(*application.Context) { go func() { _, _ = service.Refresh() }() })
	menu.AddSeparator()
	menu.Add("Выход").OnClick(func(*application.Context) { app.Quit() })
	tray.SetMenu(menu)
	tray.OnClick(func() { window.Show(); window.Focus() })
	// Observe the cached result only; the tray never issues mutations or reads WFP on its own.
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		last := ""
		for {
			select {
			case <-stopped:
				return
			case <-ticker.C:
				view := service.Snapshot()
				state := view.Status + "/" + view.VPNStatus
				if state == last {
					continue
				}
				last = state
				r, g, b := byte(245), byte(185), byte(66)
				if view.Status == "active" && view.VPNStatus == "connected" {
					r, g, b = 40, 215, 123
				}
				if view.Status == "error" || view.Status == "disabled" {
					r, g, b = 240, 82, 101
				}
				tray.SetIcon(shieldIcon(r, g, b))
				tray.SetTooltip("VPN Kill Switch · " + view.Reason)
			}
		}
	}()
	if err = app.Run(); err != nil {
		fatal(err)
	}
}

func fatal(err error) {
	text, _ := syscall.UTF16PtrFromString(fmt.Sprintf("Не удалось открыть VPN Kill Switch:\n%v", err))
	title, _ := syscall.UTF16PtrFromString("VPN Kill Switch")
	syscall.NewLazyDLL("user32.dll").NewProc("MessageBoxW").Call(0, uintptr(unsafe.Pointer(text)), uintptr(unsafe.Pointer(title)), 0x10)
}
