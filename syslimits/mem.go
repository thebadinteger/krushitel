// Окно префиксов: сколько префиксов держать в одном окне генерации.
// Считаем от свободной RAM, чтобы юзер не парился: окно = префиксы, чьи
// серийники влезают в долю свободной памяти. Остальное — скан-пайплайну,
// сокетам и системе.
package syslimits

const (
	// SerialMemEstimate — оценка RAM на один сгенерированный серийник в окне:
	// строка 15 символов + заголовок ≈ 32 байта с округлением аллокатора.
	SerialMemEstimate = 32
	// SuffixCombos — 00000..FFFFF вариантов суффикса на префикс.
	SuffixCombos = 1 << 20
	// WindowRAMShare — какую долю свободной RAM отдаём под окно (1/N).
	WindowRAMShare = 4
	// WindowCap — потолок префиксов в окне: 64M серийников ≈ 2 ГБ —
	// дальше окно жуётся вечность, а резюм мельче не становится лучше.
	WindowCap = 64
)

// FreeRAM — свободной оперативной памяти в байтах (0 = не смогли узнать;
// тогда едем осторожно — по одному префиксу).
func FreeRAM() uint64 { return freeRAMBytes() }

// WindowPrefixes — сколько префиксов брать в окно под freeRAM свободной
// памяти. Минимум 1 (на крохах — медленно, но едет).
// Пример: 8 ГБ свободных → 64 (кап), 2 ГБ → 16, 512 МБ → 4.
func WindowPrefixes(freeRAM uint64) int {
	if freeRAM == 0 {
		return 1
	}
	n := freeRAM / WindowRAMShare / SerialMemEstimate / SuffixCombos
	if n < 1 {
		n = 1
	}
	if n > WindowCap {
		n = WindowCap
	}
	return int(n)
}
