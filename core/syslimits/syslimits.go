package syslimits

const (
	WantFD         = 32768
	ReserveFD      = 256
	WorkerCeil     = 2048
	WindowsWorkers = 512
)

type Report struct {
	FDBefore   uint64
	FDAfter    uint64
	Raised     bool
	MaxWorkers int
	ManualFix  string
}

func (r Report) ClampWorkers(want int) int {
	if want <= 0 || want > r.MaxWorkers {
		return r.MaxWorkers
	}
	return want
}
