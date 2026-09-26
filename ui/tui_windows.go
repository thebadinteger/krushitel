//go:build windows

package ui

import (
	"os"

	"golang.org/x/sys/windows"
)

const enableVirtualTerminalProcessing = 0x0004

// enableVT turns on ANSI escape processing in conhost (Win10 1607+/21H2,
// Windows Terminal enables it by default). No-op if already enabled or
// stdout is redirected.
func enableVT() {
	h := windows.Handle(os.Stdout.Fd())
	var mode uint32
	if err := windows.GetConsoleMode(h, &mode); err != nil {
		return
	}
	_ = windows.SetConsoleMode(h, mode|enableVirtualTerminalProcessing)
}
