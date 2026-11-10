//go:build !windows

package config

import "path/filepath"

func canonicalPath(path string) (string, error) {
	return filepath.EvalSymlinks(path)
}
