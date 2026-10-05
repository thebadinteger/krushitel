//go:build windows

package ui

import "golang.org/x/sys/windows"

func waitKey() {
	h, err := windows.GetStdHandle(windows.STD_INPUT_HANDLE)
	if err != nil {
		return
	}
	var mode uint32
	if err := windows.GetConsoleMode(h, &mode); err != nil {
		return
	}
	_ = windows.FlushConsoleInputBuffer(h)
	_, _ = windows.WaitForSingleObject(h, windows.INFINITE)
}
