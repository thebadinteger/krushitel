//go:build windows

package ui

import (
	"os"

	"golang.org/x/sys/windows"
)

const enableVirtualTerminalInput = 0x0200

func enableVTInput() {
	h := windows.Handle(os.Stdin.Fd())
	var mode uint32
	if err := windows.GetConsoleMode(h, &mode); err != nil {
		return
	}
	_ = windows.SetConsoleMode(h, mode|enableVirtualTerminalInput)
}
