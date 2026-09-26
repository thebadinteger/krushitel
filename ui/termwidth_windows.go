//go:build windows

package ui

import "golang.org/x/sys/windows"

// termWidthCrash — ширина окна консоли в колонках, 0 если неизвестно
// (вывод не в консоль). Хендл берём из ОС, а не из os.Stdout: TUI подменяет
// переменную на DevNull, системный хендл при этом живой.
func termWidthCrash() int {
	h, err := windows.GetStdHandle(windows.STD_OUTPUT_HANDLE)
	if err != nil {
		return 0
	}
	var info windows.ConsoleScreenBufferInfo
	if err := windows.GetConsoleScreenBufferInfo(h, &info); err != nil {
		return 0
	}
	w := int(info.Window.Right-info.Window.Left) + 1
	if w < 20 {
		return 0
	}
	return w
}
