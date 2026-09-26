//go:build windows

package syslimits

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// memoryStatusEx — MEMORYSTATUSEX из kernel32 (своя, чтобы не зависеть
// от наличия готовых биндингов в вендорном x/sys).
type memoryStatusEx struct {
	Length               uint32
	MemoryLoad           uint32
	TotalPhys            uint64
	AvailPhys            uint64
	TotalPageFile        uint64
	AvailPageFile        uint64
	TotalVirtual         uint64
	AvailVirtual         uint64
	AvailExtendedVirtual uint64
}

var (
	modkernel32                = windows.NewLazySystemDLL("kernel32.dll")
	procGlobalMemoryStatusEx   = modkernel32.NewProc("GlobalMemoryStatusEx")
)

// freeRAMBytes — свободная RAM (AvailPhys) через GlobalMemoryStatusEx.
func freeRAMBytes() uint64 {
	var st memoryStatusEx
	st.Length = uint32(unsafe.Sizeof(st))
	r1, _, _ := syscall.Syscall(procGlobalMemoryStatusEx.Addr(), 1,
		uintptr(unsafe.Pointer(&st)), 0, 0)
	if r1 == 0 {
		return 0
	}
	return st.AvailPhys
}
