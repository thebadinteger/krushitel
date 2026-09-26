//go:build !windows

package ui

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"
)

// discordDial — коннект к discord-ipc-0..9 через unix-сокеты.
// Порядок как у десктопных клиентов: XDG_RUNTIME_DIR, TMPDIR, /tmp, /run.
func discordDial() (net.Conn, error) {
	dirs := []string{os.Getenv("XDG_RUNTIME_DIR"), os.Getenv("TMPDIR"), "/tmp", "/run", "/var/run"}
	var lastErr error
	for _, dir := range dirs {
		if dir == "" {
			continue
		}
		for i := 0; i < 10; i++ {
			conn, err := net.DialTimeout("unix",
				filepath.Join(dir, fmt.Sprintf("discord-ipc-%d", i)), 2*time.Second)
			if err != nil {
				lastErr = err
				continue
			}
			return conn, nil
		}
	}
	if lastErr == nil {
		lastErr = os.ErrNotExist
	}
	return nil, lastErr
}
