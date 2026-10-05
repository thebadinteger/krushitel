//go:build !windows

package update

import (
	"os"
	"syscall"
)

func restart() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	return syscall.Exec(exe, os.Args, os.Environ())
}
