//go:build !windows

package ui

// enableVTInput is a no-op on POSIX — terminals deliver ESC sequences natively.
func enableVTInput() {}
