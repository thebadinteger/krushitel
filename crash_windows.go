//go:build windows

package main

import (
	"os"

	"golang.org/x/sys/windows"
)

func redirectToCrashLog(lf *os.File) {
	_ = windows.SetStdHandle(windows.STD_ERROR_HANDLE, windows.Handle(lf.Fd()))
}
