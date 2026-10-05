//go:build !windows

package main

import "os"

func redirectToCrashLog(lf *os.File) {}
