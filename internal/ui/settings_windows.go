package ui

import "os"

// os.Rename uses a same-volume replacement on Windows.
func replaceSettingsFile(source, target string) error { return os.Rename(source, target) }
