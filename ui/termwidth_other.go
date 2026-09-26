//go:build !windows

package ui

// termWidthCrash — вне Windows ширину не спрашиваем.
func termWidthCrash() int { return 0 }
