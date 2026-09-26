//go:build !windows

package syslimits

import (
	"os"
	"strconv"
	"strings"
)

// freeRAMBytes — свободная RAM из /proc/meminfo (MemAvailable, фолбэк MemFree).
// Нет /proc (не-линукс) — возвращаем 0, окно посчитается минимальным.
func freeRAMBytes() uint64 {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0
	}
	var memFree uint64
	for _, ln := range strings.Split(string(data), "\n") {
		f := strings.Fields(ln)
		if len(f) < 2 {
			continue
		}
		v, err := strconv.ParseUint(f[1], 10, 64)
		if err != nil {
			continue
		}
		switch f[0] {
		case "MemAvailable:":
			return v * 1024
		case "MemFree:":
			memFree = v * 1024
		}
	}
	return memFree
}
