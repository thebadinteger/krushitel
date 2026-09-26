// Package syslimits — автонастройка ОС-лимитов под скан, чтобы юзер не парился.
//
// Linux: мягкий лимит fd поднимаем сами через Setrlimit (в пределах hard-лимита
// рут не нужен); если не вышло — отдаём готовую команду вместо падения.
// Windows: поднять лимиты из процесса нельзя (там netsh + админ), поэтому только
// безопасный кап воркеров (сокеты переиспользуются из пула — эфемерные порты
// на пробу не тратим) и готовая подсказка на случай ошибок создания сокетов.
package syslimits

const (
	// WantFD — сколько fd хотим иметь (сокеты воркеров + файлы + запас).
	WantFD = 32768
	// ReserveFD — запас fd, который не отдаём под воркеры.
	ReserveFD = 256
	// WorkerCeil — потолок воркеров: больше облако всё равно душит governor'ом,
	// а планировщик и RAM страдают. Кап поверх расчёта из лимитов.
	WorkerCeil = 2048
	// WindowsWorkers — кап воркеров на Windows.
	WindowsWorkers = 512
)

// Report — итог автонастройки лимитов.
type Report struct {
	FDBefore   uint64 // мягкий лимит fd до настройки (0 на windows — неприменимо)
	FDAfter    uint64 // мягкий лимит fd после настройки (0 на windows)
	Raised     bool   // лимит подняли сами
	MaxWorkers int    // кап воркеров под эти лимиты
	ManualFix  string // "" = автофикс ок; иначе готовая команда юзеру (не локализуется — команда)
}

// ClampWorkers — втискивает want в [1, MaxWorkers]; want <= 0 = взять максимум.
func (r Report) ClampWorkers(want int) int {
	if want <= 0 || want > r.MaxWorkers {
		return r.MaxWorkers
	}
	return want
}
