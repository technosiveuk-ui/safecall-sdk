//go:build !windows

package fileutil

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCheckFilePermissions_Valid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret.yaml")
	if err := os.WriteFile(path, []byte("test"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := CheckFilePermissions(path); err != nil {
		t.Errorf("expected no error for 0600 file, got: %v", err)
	}
}

func TestCheckFilePermissions_TooPermissive(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret.yaml")
	if err := os.WriteFile(path, []byte("test"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := CheckFilePermissions(path); err == nil {
		t.Error("expected error for 0644 file, got nil")
	}
}

func TestCheckFilePermissions_MissingFile(t *testing.T) {
	if err := CheckFilePermissions("/nonexistent/file.yaml"); err == nil {
		t.Error("expected error for missing file, got nil")
	}
}
