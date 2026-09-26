//go:build windows

package ui

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

// discordDial — коннект к discord-ipc-0..9 через именованный пайп.
// Синхронный хендл → *os.File (нам хватает Write+Close), без дедовых либ.
// Пайпа нет (дискорд не запущен) — CreateFile падает сразу, без виса.
func discordDial() (discordConn, error) {
	var lastErr error
	for i := 0; i < 10; i++ {
		name := fmt.Sprintf(`\\.\pipe\discord-ipc-%d`, i)
		p, err := windows.UTF16PtrFromString(name)
		if err != nil {
			lastErr = err
			continue
		}
		h, err := windows.CreateFile(p,
			windows.GENERIC_READ|windows.GENERIC_WRITE,
			0, nil, windows.OPEN_EXISTING, 0, 0)
		if err != nil {
			lastErr = err
			continue
		}
		return os.NewFile(uintptr(h), name), nil
	}
	if lastErr == nil {
		lastErr = os.ErrNotExist
	}
	return nil, lastErr
}
