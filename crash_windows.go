//go:build windows

package main

import (
	"os"

	"golang.org/x/sys/windows"
)

// redirectToCrashLog дублирует системный хендл stderr в файл: рантайм пишет
// туда стек паники из любой горутины (переменная os.Stderr тут не поможет).
func redirectToCrashLog(lf *os.File) {
	_ = windows.SetStdHandle(windows.STD_ERROR_HANDLE, windows.Handle(lf.Fd()))
}
