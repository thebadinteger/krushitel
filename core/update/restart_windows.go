//go:build windows

package update

import (
	"os"
	"os/exec"
)

func restart() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	c := exec.Command(exe, os.Args[1:]...)
	c.Stdin = os.Stdin
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	err = c.Run()
	if c.ProcessState != nil {
		os.Exit(c.ProcessState.ExitCode())
	}
	return err
}
