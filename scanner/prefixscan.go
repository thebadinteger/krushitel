// prefixscan.go — скан префиксов без промежуточных файлов: префиксы из
// файла разворачиваются в 00000..FFFFF на лету и льются straight в пайплайн.
//
// Окна по свободной RAM: окно = N префиксов, чьи серийники влезают в долю
// свободной памяти (см. syslimits.WindowPrefixes). Окно генерируется в RAM,
// сканируется, отпускается — следующее. Чекпоинт по окнам: падение посреди
// окна = перезапуск окна, готовые окна не трогаем.
package scanner

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync/atomic"

	"krushitel/cloud"
	"krushitel/i18n"
	"krushitel/syslimits"
)

// suffixCombos — 00000..FFFFF вариантов суффикса на префикс.
const suffixCombos = 1 << 20

// prefixProgress — чекпоинт префикс-прогона: готовые окна можно не трогать.
// Список префиксов храним целиком: resume не зависит от того, поменяли ли
// файл префиксов после падения (сверили — не сошёлся, стартуем с нуля).
type prefixProgress struct {
	Prefixes []string `json:"prefixes"`
	// Window — размер окна, которым считали. Храним, чтобы resume не
	// поплыл, если свободная RAM изменилась между прогонами (границы
	// окон обязаны совпасть, иначе часть префиксов пересканится).
	Window      int `json:"window"`
	DoneWindows int `json:"done_windows"`
}

// progressPath — чекпоинт рядом с выходным файлом.
func progressPath(outFile string) string { return outFile + ".progress" }

// savePrefixProgress — записать чекпоинт (ошибки игнорим: прогон важнее).
func savePrefixProgress(path string, p prefixProgress) {
	b, err := json.Marshal(p)
	if err != nil {
		return
	}
	_ = os.WriteFile(path, b, 0644)
}

// CheckPrefixResume — есть ли недобитый прогон по выходному файлу?
// Возвращает человекочитаемое описание для confirm-формы и флаг.
// Движок зовёт отдельно: UI спрашивает юзера, потом launch с resume=true.
func CheckPrefixResume(outFile string) (string, bool) {
	b, err := os.ReadFile(progressPath(outFile))
	if err != nil {
		return "", false
	}
	var p prefixProgress
	if err := json.Unmarshal(b, &p); err != nil {
		return "", false
	}
	if p.DoneWindows <= 0 || len(p.Prefixes) == 0 {
		return "", false
	}
	w := p.Window
	if w < 1 {
		w = syslimits.WindowPrefixes(syslimits.FreeRAM())
	}
	windows := (len(p.Prefixes) + w - 1) / w
	return fmt.Sprintf(i18n.Tr("найден незавершённый прогон: окно %d/%d. продолжить?"),
		p.DoneWindows+1, windows), true
}

// loadAliveSet — живые серийники из выходного файла (для resume: хвост
// прерванного окна пересканится, но повторы в файл не попадут).
func loadAliveSet(outFile string) map[string]struct{} {
	set := make(map[string]struct{})
	f, err := os.Open(outFile)
	if err != nil {
		return set
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		if s := strings.TrimSpace(sc.Text()); s != "" {
			set[s] = struct{}{}
		}
	}
	return set
}

const hexChars = "0123456789ABCDEF"

// expandWindow — развернуть префиксы окна в серийники (prefix + 00000..FFFFF).
// Быстрый битовый генератор без fmt.Sprintf и лишних аллокаций.
func expandWindow(prefixes []string) []string {
	out := make([]string, 0, len(prefixes)*suffixCombos)
	var buf [15]byte
	for _, p := range prefixes {
		copy(buf[:10], p)
		for i := 0; i < suffixCombos; i++ {
			buf[10] = hexChars[(i>>16)&0xF]
			buf[11] = hexChars[(i>>12)&0xF]
			buf[12] = hexChars[(i>>8)&0xF]
			buf[13] = hexChars[(i>>4)&0xF]
			buf[14] = hexChars[i&0xF]
			out = append(out, string(buf[:]))
		}
	}
	return out
}


// RunPrefixes — скан списка префиксов (один или несколько) без промежуточных файлов:
// окна по свободной RAM, генерация в память, скан тем же пайплайном, чекпоинт по окнам.
func RunPrefixes(ctx context.Context, prefixes []string, outFile string, appendMode bool, resume bool, workers int, stats *ScanStats, events chan<- string) {
	defer func() { stats.Done = true }()

	if len(prefixes) == 0 {
		stats.ErrorMsg = i18n.Tr("список префиксов пуст")
		return
	}

	freeRAM := syslimits.FreeRAM()
	window := syslimits.WindowPrefixes(freeRAM)
	total := int64(len(prefixes)) * suffixCombos
	atomic.StoreInt64(&stats.Total, total)
	emitEvent(events, "[SYS] "+fmt.Sprintf(i18n.Tr("свободно RAM %.1f ГБ → окно %d префиксов (%d млн серийников)"),
		float64(freeRAM)/1073741824, window, window))

	prog := prefixProgress{Prefixes: prefixes, Window: window}
	startWindow := 0
	if resume {
		if b, rerr := os.ReadFile(progressPath(outFile)); rerr == nil {
			var saved prefixProgress
			if jerr := json.Unmarshal(b, &saved); jerr == nil &&
				saved.DoneWindows > 0 && len(saved.Prefixes) == len(prefixes) {
				match := saved.Window > 0
				if match {
					for i := range prefixes {
						if saved.Prefixes[i] != prefixes[i] {
							match = false
							break
						}
					}
				}
				if match {
					prog = saved
					window = saved.Window // границы окон обязаны совпасть
					startWindow = saved.DoneWindows
					appendMode = true // resume всегда дописывает: готовые окна уже в файле
					emitEvent(events, "[SYS] "+fmt.Sprintf(i18n.Tr("продолжаю с окна %d"),
						startWindow+1))
				} else {
					emitEvent(events, "[SYS] "+i18n.Tr("файл префиксов изменился — стартую с нуля"))
				}
			}
		}
	}

	// Окна: режем префиксы кусками по window штук.
	var windows [][]string
	for i := 0; i < len(prefixes); i += window {
		end := i + window
		if end > len(prefixes) {
			end = len(prefixes)
		}
		windows = append(windows, prefixes[i:end])
	}
	if startWindow >= len(windows) {
		stats.ErrorMsg = i18n.Tr("прогон уже завершён (все окна готовы)")
		return
	}

	outF, outWriter, oerr := openOutput(outFile, appendMode, stats)
	if oerr != "" {
		stats.ErrorMsg = oerr
		return
	}
	defer outF.Close()

	// Resume: подгружаем уже записанные живые в seedAlive — хвост
	// прерванного окна пересканится заново, но в файл не задвоится.
	// Живых на порядки меньше входа, в RAM влезет.
	var seedAlive map[string]struct{}
	if startWindow > 0 {
		seedAlive = loadAliveSet(outFile)
		emitEvent(events, "[SYS] "+fmt.Sprintf(i18n.Tr("подгружено живых из файла: %d"),
			len(seedAlive)))
	}

	var emitted int64
	feed := func(jobs chan string) {
		defer close(jobs)
		for w := startWindow; w < len(windows); w++ {
			select {
			case <-ctx.Done():
				return
			default:
			}
			win := expandWindow(windows[w])
			emitEvent(events, "[SYS] "+fmt.Sprintf(i18n.Tr("окно %d/%d: %d префиксов, %d серийников"),
				w+1, len(windows), len(windows[w]), len(win)))
			for _, s := range win {
				select {
				case <-ctx.Done():
					return
				case jobs <- s:
					emitted++
				}
			}
			win = nil // отпустить окно до следующего (GC подберёт)
			prog.DoneWindows = w + 1
			savePrefixProgress(progressPath(outFile), prog)
		}
	}
	if perr := runPipe(ctx, stats, events, outWriter, workers, feed, seedAlive); perr != "" {
		stats.ErrorMsg = perr
		return
	}
	if emitted == 0 && stats.ErrorMsg == "" {
		stats.ErrorMsg = i18n.Tr("Файл пуст")
		return
	}
	// Чистый финиш: чекпоинт больше не нужен.
	_ = os.Remove(progressPath(outFile))
}

// RunPrefixScan — скан префиксов из файла: обёртка над RunPrefixes.
func RunPrefixScan(ctx context.Context, prefixFile, outFile string, appendMode bool, resume bool, workers int, stats *ScanStats, events chan<- string) {
	prefixes, err := cloud.LoadPrefixes(prefixFile)
	if err != nil || len(prefixes) == 0 {
		msg := i18n.Tr("нет префиксов в файле (нужно >= 10 символов, берутся первые 10)")
		if err != nil {
			msg = err.Error()
		}
		stats.ErrorMsg = msg
		stats.Done = true
		return
	}
	RunPrefixes(ctx, prefixes, outFile, appendMode, resume, workers, stats, events)
}

