package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCanonicalPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "probe.exe")
	if err := os.WriteFile(path, []byte("probe"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := canonicalPath(path)
	if err != nil || !strings.EqualFold(filepath.Clean(got), filepath.Clean(path)) {
		t.Fatalf("path=%q error=%v, want %q", got, err, path)
	}
	if _, err := canonicalPath(path + ".missing"); err == nil {
		t.Fatal("missing file accepted")
	}
}
