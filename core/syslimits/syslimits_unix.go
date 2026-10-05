//go:build !windows

package syslimits

import "syscall"

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

func SocketHint() string { return "ulimit -n 32768" }
