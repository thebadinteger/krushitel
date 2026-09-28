// prefixmem.go — скан префиксов с результатами В ОПЕРАТИВНОЙ ПАМЯТИ.
// Серийники генерируются ПО ОДНОМУ на лету (O(1) RAM на генерацию — никаких
// развернутых окон), живые уходят в колбэк движка двухфазного режима.
// Промежуточных файлов нет: ни alive-файла, ни чекпоинта по окнам —
// чекпоинт на краш/прерывание пишет сам движок (crashscan.json/txt),
// отсюда наружу только телеметрия в ScanStats (Fed/PrefixDone/LastSerial).
package scanner

import (
	"context"
	"fmt"
	"sync/atomic"

	"krushitel/i18n"
)

// SuffixCombos — 00000..FFFFF вариантов суффикса на префикс (16^5 = 1М).
// Экспорт: движок двухфазного режима и UI считают ScanTotal по нему.
const SuffixCombos = 1 << 20

// hexChars — алфавит суффикса.
const hexChars = "0123456789ABCDEF"

// resumeSkipMargin — сколько серийников перед позицией чекпоинта
// пересканируется при resume: они были скормлены в jobs, но вердикт не
// успел (буфер канала + окно в полёте + кладбище ретраев). Перескорм
// безвреден (дедуп живых у движка), недоскорм теряет серийники.
func resumeSkipMargin(workers int) int64 {
	return int64(workers)*10 + 4096
}

// ResumeSkip — позиция старта resume по счётчикам чекпоинта. checked —
// абсолютный индекс добитых вердиктов (с учётом seed прошлых resume),
// emitted — абсолютный индекс скормленных. Берём checked с запасом:
// непомеченные in-flight серийники пересканируются, помеченные после
// границы — повторно пробуются (безвредно).
func ResumeSkip(emitted, checked int64, workers int) int64 {
	skip := checked - resumeSkipMargin(workers)
	if skip < 0 {
		skip = 0
	}
	if emitted > 0 && skip > emitted {
		skip = emitted
	}
	return skip
}

// streamSerialsMem — детерминированный поток серийников по префиксам
// (префиксы в порядке списка, суффикс 000000..FFFFF): первые skip штук
// перепрыгиваются (resume), остальные отдаются в emit. emit => false —
// стоп потока (отмена ctx): недоеденные серийники НЕ должны попасть в
// счётчик Fed, иначе чекпоинт соврёт про позицию. Выделений почти нет —
// один буфер на весь поток. Возвращает число отданных серийников.
func streamSerialsMem(prefixes []string, skip int64, emit func(string) bool) int64 {
	var fed, out int64
	var buf [15]byte
	for _, p := range prefixes {
		copy(buf[:10], p)
		for i := 0; i < SuffixCombos; i++ {
			if fed < skip {
				fed++
				continue
			}
			buf[10] = hexChars[(i>>16)&0xF]
			buf[11] = hexChars[(i>>12)&0xF]
			buf[12] = hexChars[(i>>8)&0xF]
			buf[13] = hexChars[(i>>4)&0xF]
			buf[14] = hexChars[i&0xF]
			out++
			if !emit(string(buf[:])) {
				return out
			}
			fed++
		}
	}
	return out
}

// RunPrefixesMem — скан списка префиксов без промежуточных файлов.
// skip — сколько серийников детерминированного потока перепрыгнуть
// (resume после краша). onAlive получает каждого живого ровно один раз
// на прогон (дедуп в runPipe; сквозной дедуп между прогонами — забота
// колбэка). Возвращает текст ошибки ("" = ок).
func RunPrefixesMem(ctx context.Context, prefixes []string, skip int64, workers int, stats *ScanStats, events chan<- string, onAlive func(string)) string {
	if len(prefixes) == 0 {
		return i18n.Tr("список префиксов пуст")
	}
	total := int64(len(prefixes)) * SuffixCombos
	atomic.StoreInt64(&stats.Total, total)
	atomic.StoreInt64(&stats.PrefixTotal, int64(len(prefixes)))
	if skip > 0 {
		// бар честный: resume продолжает с позиции, а не с нуля
		atomic.StoreInt64(&stats.Checked, skip)
		emitEvent(events, "[SYS] "+fmt.Sprintf(i18n.Tr("resume: пропускаю %d уже отскормленных серийников"), skip))
	}

	feed := func(jobs chan string) {
		defer close(jobs)
		// Fed считает серийники, УШЕДШИЕ в jobs (не заблокированные на
		// отправке) — «где остановились» в чекпоинте должно быть честным.
		// Прогресс по префиксам — арифметика от Fed: поток детерминирован,
		// префикс добит, когда отданы все его суффиксы.
		emit := func(s string) bool {
			select {
			case <-ctx.Done():
				return false
			case jobs <- s:
			}
			fed := atomic.AddInt64(&stats.Fed, 1)
			if fed&4095 == 0 {
				stats.LastSerial.Store(s) // чекпоинту нужен «где остановились»
			}
			atomic.StoreInt64(&stats.PrefixDone, (skip+fed)/SuffixCombos)
			return true
		}
		streamSerialsMem(prefixes, skip, emit)
	}
	return runPipe(ctx, stats, events, onAlive, workers, feed, nil)
}
