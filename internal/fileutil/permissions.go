//go:build !windows

// Package fileutil provides file-system security helpers.
package fileutil

import (
	"fmt"
	"os"
)

// CheckFilePermissions verifies that the file at path is not group- or
// world-readable. On Unix-like systems this means the mode must be 0600.
// Returns an error describing the violation if the check fails.
func CheckFilePermissions(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("safecall: cannot stat %q: %w", path, err)
	}

	mode := info.Mode().Perm()
	if mode&0o077 != 0 {
		return fmt.Errorf(
			"safecall: file %q has mode %04o; expected 0600 (no group/world access). "+
				"Fix with: chmod 600 %s",
			path, mode, path,
		)
	}
	return nil
}
