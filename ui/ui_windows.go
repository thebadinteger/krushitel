//go:build windows

package ui

import (
	"os"

	"golang.org/x/sys/windows"
)

const enableVirtualTerminalInput = 0x0200

// enableVTInput turns on VT input mode so arrow keys arrive as ESC[A..D
// sequences (conhost 21H2+; Windows Terminal does this by default).
// Must be called while stdin is in raw mode.
func enableVTInput() {
	h := windows.Handle(os.Stdin.Fd())
	var mode uint32
	if err := windows.GetConsoleMode(h, &mode); err != nil {
		return
	}
	_ = windows.SetConsoleMode(h, mode|enableVirtualTerminalInput)
}
