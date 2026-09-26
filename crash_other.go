//go:build !windows

package main

import "os"

// redirectToCrashLog — заглушка для не-Windows: нечего дублировать.
func redirectToCrashLog(lf *os.File) {}
