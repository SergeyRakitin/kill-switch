//go:build !windows

package ui

import "os"

func replaceSettingsFile(source, target string) error { return os.Rename(source, target) }
