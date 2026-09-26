//go:build !windows

package ui

import "os"

// waitKey — ждём enter, если stdin — терминал. Пайп/перенаправление —
// сразу дальше, не висим.
func waitKey() {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return
	}
	if fi.Mode()&os.ModeCharDevice == 0 {
		return
	}
	var b [1]byte
	_, _ = os.Stdin.Read(b[:])
}
