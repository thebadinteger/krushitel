//go:build windows

package ui

import (
	"os"

	"golang.org/x/sys/windows"
)

const enableVirtualTerminalProcessing = 0x0004

func enableVT() {
	h := windows.Handle(os.Stdout.Fd())
	var mode uint32
	if err := windows.GetConsoleMode(h, &mode); err != nil {
		return
	}
	_ = windows.SetConsoleMode(h, mode|enableVirtualTerminalProcessing)
}
