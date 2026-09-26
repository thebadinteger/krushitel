//go:build !windows

package syslimits

import "syscall"

// Ensure — проверить мягкий лимит fd и поднять до WantFD (в пределах
// hard-лимита — без рута). Возвращает отчёт для лога и клампа воркеров.
func Ensure() Report {
	var rl syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rl); err != nil {
		return Report{MaxWorkers: 1024 - ReserveFD, ManualFix: SocketHint()}
	}
	before := rl.Cur
	raised := false
	if before < WantFD {
		want := uint64(WantFD)
		if want > rl.Max {
			want = rl.Max
		}
		if want > before {
			rl.Cur = want
			if syscall.Setrlimit(syscall.RLIMIT_NOFILE, &rl) == nil {
				raised = true
			}
		}
	}
	after := before
	if raised {
		after = rl.Cur
	}
	// Cur может быть RLIM_INFINITY — в int не лезет, режем потолком.
	maxW := WorkerCeil
	if after < uint64(WorkerCeil+ReserveFD) {
		maxW = int(after) - ReserveFD
		if maxW < 1 {
			maxW = 1
		}
	}
	rep := Report{FDBefore: before, FDAfter: after, Raised: raised, MaxWorkers: maxW}
	if after < WantFD {
		rep.ManualFix = SocketHint()
	}
	return rep
}

// SocketHint — готовая команда на случай ошибок создания сокетов.
func SocketHint() string { return "ulimit -n 32768" }
