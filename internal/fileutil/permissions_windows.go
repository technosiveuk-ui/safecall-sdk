//go:build windows

package fileutil

// CheckFilePermissions on Windows is a documentation-only stub.
// POSIX permission bits are not meaningful on Windows; the SDK documents
// that users should restrict the file to the executing user via Windows ACLs.
func CheckFilePermissions(_ string) error {
	// No-op on Windows. See PRD §NFR5 for rationale.
	return nil
}
