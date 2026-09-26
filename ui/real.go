package ui

// real.go — оболочка экрана прогона для РЕАЛЬНЫХ движков krushitel
// (exploit/scanner/cloud/xmlde/ironscan через go.mod replace).
//
// Режим exploit показывает ЖИВЫЕ СТРОКИ СЕССИЙ (Stats.SetRow): у каждого
// серийника одна строка, обновляющаяся на месте по стадиям
// (пречек → туннель → exploit… → PWNED!/ADDED/FAIL/OFFLINE).
// Остальные режимы — лента событий, размер которой подстраивается
// под высоту терминала. Help-строку здесь НЕ рисуем — её прижимает
// к низу withBottom (иначе дубль).

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"

	"krushitel/exploit"
	"krushitel/scanner"
)

const (
	runExploit = iota
	runCheck
	runPrefix
	runTitles
)

// runState — состояние живого прогона (реальные движки).
type runState struct {
	mode     int
	panel    string
	cancel   context.CancelFunc
	start    time.Time
	endTime  time.Time // момент финиша — таймер замирает на нём
	h        int       // высота терминала (обновляется из тика)
	events   []string
	eventsCh chan string

	// exploit (krushitel/exploit)
	exp *exploit.Stats
	// check (krushitel/scanner)
	chk *scanner.ScanStats
	// titles (krushitel/exploit, подменю «титры по списку»)
	ttl *exploit.TitlesStats
	// genErr — общая строка ошибки прогона (поиск префиксов: krushitel/ironscan)
	genErr string
	// prefix (krushitel/ironscan)
	preScanned int64
	preFound   int64
	preTotal   int
	preDone    int64 // atomic

	// файл логов прогона (append в папку результатов)
	logFile *os.File
	logMu   sync.Mutex
}

var activeRunState atomic.Pointer[runState]

type runStateLogger struct{}

func (runStateLogger) Write(p []byte) (n int, err error) {
	r := activeRunState.Load()
	if r != nil {
		msg := strings.TrimSpace(string(p))
		if msg != "" {
			select {
			case r.eventsCh <- msg:
			default:
			}
		}
	}
	return len(p), nil
}

func init() {
	log.SetOutput(runStateLogger{})
	log.SetFlags(0)
}

func newRunState(mode int, panel string) *runState {
	r := &runState{
		mode:     mode,
		panel:    panel,
		start:    time.Now(),
		eventsCh: make(chan string, 256),
	}
	activeRunState.Store(r)
	return r
}

// openLog — включает запись ленты в файл (append). Путь пустой/ошибка —
// лог-файла нет, экранная лента работает как раньше.
func (r *runState) openLog(path string) {
	if path == "" {
		return
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	r.logFile = f
}

// crashLines — последние строки для экрана краша (main recover читает
// их после паники, когда модель уже недоступна). Кормится из writeLog
// (сетевые дампы воркеров) и drain (лента событий).
var crashLinesMu sync.Mutex
var crashLines []string

const crashLinesCap = 8

func noteCrashLine(s string) {
	s = stripANSI(s)
	s = strings.TrimSpace(s)
	if s == "" {
		return
	}
	crashLinesMu.Lock()
	crashLines = append(crashLines, s)
	if len(crashLines) > crashLinesCap {
		crashLines = crashLines[len(crashLines)-crashLinesCap:]
	}
	crashLinesMu.Unlock()
}

// NoteCrashLine — экспорт для тестов/диагностики (внутри пакета — noteCrashLine).
func NoteCrashLine(s string) { noteCrashLine(s) }

// LastCrashLines — копия последних n строк для сплеша в main recover.
func LastCrashLines(n int) []string {
	crashLinesMu.Lock()
	defer crashLinesMu.Unlock()
	if n <= 0 || n > len(crashLines) {
		n = len(crashLines)
	}
	out := make([]string, n)
	copy(out, crashLines[len(crashLines)-n:])
	return out
}

// writeLog — строка → файл с таймштампом (потокобезопасно; dbg-строки
// из сотен туннелей пишутся напрямую, минуя каналы — иначе лог решето).
func (r *runState) writeLog(line string) {
	noteCrashLine(line)
	if r.logFile == nil {
		return
	}
	ts := time.Now().Format("15:04:05")
	plain := stripANSI(line)
	r.logMu.Lock()
	r.logFile.WriteString(fmt.Sprintf("[%s] %s\n", ts, plain))
	r.logMu.Unlock()
}

// closeLog — флуш и закрытие (выход из прогона).
func (r *runState) closeLog() {
	if r.logFile != nil {
		r.logFile.Close()
		r.logFile = nil
	}
}

// stripANSI — срезает ANSI-коды раскраски: в файле логов цвет не нужен.
func stripANSI(s string) string {
	if !strings.Contains(s, "\x1b[") {
		return s
	}
	var sb strings.Builder
	for i := 0; i < len(s); {
		if s[i] == 0x1b && i+1 < len(s) && s[i+1] == '[' {
			j := i + 2
			for j < len(s) && !((s[j] >= 'a' && s[j] <= 'z') || (s[j] >= 'A' && s[j] <= 'Z')) {
				j++
			}
			if j < len(s) {
				j++
			}
			i = j
			continue
		}
		sb.WriteByte(s[i])
		i++
	}
	return sb.String()
}

// logMax — сколько строк ленты влезает: высота минус баннер/панель/
// статус/подсказка (≈15), зажато в [3..400].
func (r *runState) logMax() int {
	// вычитаем высоту шапки (баннер + статсы + рамки ~ 20 строк)
	// берём с запасом 24, чтобы интерфейс гарантированно не скроллил терминал!
	n := r.h - 24
	if n < 5 {
		n = 5
	}
	if n > 400 {
		n = 400
	}
	return n
}

// drain — перекладка событий движков в ленту (размер — по высоте).
// Каждая строка дублируется в лог-файл, если открыт.
func (r *runState) drain() {
	max := r.logMax()
	for {
		select {
		case ev := <-r.eventsCh:
			r.events = append(r.events, ev)
			if len(r.events) > max {
				r.events = r.events[len(r.events)-max:]
			}
			noteCrashLine(ev)
			r.writeLog(ev)
		default:
			return
		}
	}
}

func (r *runState) finished() bool {
	switch r.mode {
	case runExploit:
		// прогон завершён, только когда и движок дошёл до конца, И
		// хвост extras (титры/снапы) догорел: ранний esc убивает
		// недоделанные снапы, «готово» не должно врать
		return r.exp != nil && r.exp.Done &&
			atomic.LoadInt64(&r.exp.ExtrasInFlight) == 0
	case runCheck:
		return r.chk != nil && r.chk.Done
	case runPrefix:
		return atomic.LoadInt64(&r.preDone) == 1
	case runTitles:
		return r.ttl != nil && r.ttl.Done
	}
	return false
}

// elapsed — таймер от начала скана; после финиша замирает на конечном
// времени (счёт не убегает, пока любуешься результатом).
func (r *runState) elapsed() string {
	if r.finished() {
		if r.endTime.IsZero() {
			r.endTime = time.Now()
		}
		return fmtDuration(r.endTime.Sub(r.start).Seconds())
	}
	return fmtDuration(time.Since(r.start).Seconds())
}

func (r *runState) statusMsg() string {
	switch r.mode {
	case runExploit:
		return r.exp.ErrorMsg
	case runCheck:
		return r.chk.ErrorMsg
	case runPrefix:
		return r.genErr
	case runTitles:
		return r.ttl.ErrorMsg
	}
	return ""
}

// view — экран прогона с реальными счётчиками движка.
func (r *runState) view() string {
	var sb strings.Builder
	sb.WriteString(bannerBlock())
	sb.WriteString(strings.Repeat("\n", 4)) // шапка ниже баннера
	sb.WriteString(panelS(r.panel) + "\n\n")

	if msg := r.statusMsg(); msg != "" {
		sb.WriteString(centerLine(red(msg)) + "\n")
		return sb.String()
	}

	switch r.mode {
	case runExploit:
		sb.WriteString(r.exploitView())
	case runCheck:
		sb.WriteString(r.checkView())
	case runPrefix:
		sb.WriteString(r.prefixView())
	case runTitles:
		sb.WriteString(r.titlesView())
	}
	return sb.String()
}

// exploitView — счётчики + лента логов (таблицу SN→статус выпилили:
// захлёбывалась на сотнях серийников и перегружала экран; полный
// ход прогона теперь в ленте и в log.txt папки результатов).
// Прогресс — по УНИКАЛЬНЫМ серийникам (Progress), а не по Checked:
// дохлые (probe miss/404/туннель-фейл) тоже отмечаются — бар
// двигается на каждом исходе и добегает до 100%.
func (r *runState) exploitView() string {
	st := r.exp
	progress := st.Progress()
	pct := 0.0
	if st.Total > 0 {
		pct = float64(progress) / float64(st.Total) * 100
	}
	// снапы: зелёные успешные + красный счётчик фейлов (причины — в логе)
	snapStr := green(fmt.Sprint(atomic.LoadInt64(&st.Snaps)))
	if fails := atomic.LoadInt64(&st.SnapFails); fails > 0 {
		snapStr += red("/" + fmt.Sprint(fails))
	}
	// pwned включает ADDED (dummy через CVE-2024-39943 — тоже pwned)
	pwned := atomic.LoadInt64(&st.Pwned) + atomic.LoadInt64(&st.Added)
	var sb strings.Builder
	sb.WriteString(centerLine(fmt.Sprintf("%s %.1f%%", bar(progress, st.Total, 30), pct)) + "\n")
	sb.WriteString(centerLine(fmt.Sprintf("%d/%d | pwned: %s | fail: %s | snaps: %s | %s",
		progress, st.Total,
		green(fmt.Sprint(pwned)),
		red(fmt.Sprint(atomic.LoadInt64(&st.Failed))),
		snapStr,
		r.elapsed())) + "\n\n")
	sb.WriteString(r.eventsBlock())
	return sb.String()
}

// titlesView — экран прогона «титры по списку»: бар по уникальным
// серийникам, счётчики titled/offline/fail, лента диагнозов.
func (r *runState) titlesView() string {
	st := r.ttl
	progress := st.Progress()
	pct := 0.0
	if st.Total > 0 {
		pct = float64(progress) / float64(st.Total) * 100
	}
	var sb strings.Builder
	sb.WriteString(centerLine(fmt.Sprintf("%s %.1f%%", bar(progress, st.Total, 30), pct)) + "\n")
	sb.WriteString(centerLine(fmt.Sprintf("%d/%d | titled: %s | off: %s | fail: %s | %s | %s",
		progress, st.Total,
		green(fmt.Sprint(atomic.LoadInt64(&st.Titled))), dim(fmt.Sprint(atomic.LoadInt64(&st.Offline))), red(fmt.Sprint(atomic.LoadInt64(&st.Failed))),
		fmt.Sprintf(tr("%.1f/сек"), st.Speed),
		r.elapsed())) + "\n\n")
	sb.WriteString(r.eventsBlock())
	return sb.String()
}

// eventsBlock — лента событий в рамке: шапка, строки с левым и правым бортиком "│",
// нижняя граница по ширине блока. Размер ленты — по высоте терминала.
func (r *runState) eventsBlock() string {
	var sb strings.Builder

	rawLines := r.events
	if len(rawLines) == 0 {
		rawLines = []string{""}
	}

	maxEvW := 0
	for _, ev := range rawLines {
		if w := lipgloss.Width(ev); w > maxEvW {
			maxEvW = w
		}
	}

	barW := maxEvW + 4 // +4 для левого/правого бортиков '│ ' и ' │'
	if barW < 117 {
		barW = 117 // минимальная ширина как в ТЗ
	}
	if termWidth > 0 && barW > termWidth-8 {
		barW = termWidth - 8
	}
	if barW < 30 {
		barW = 30
	}

	innerW := barW - 2

	title := tr("логи")
	tLen := len([]rune(title)) + 2 // " логи "
	left := (barW - tLen) / 2
	if left < 1 {
		left = 1
	}
	right := barW - tLen - left
	if right < 1 {
		right = 1
	}

	leftLines := left - 1
	if leftLines < 0 {
		leftLines = 0
	}
	rightLines := right - 1
	if rightLines < 0 {
		rightLines = 0
	}

	topBorder := dim("╭"+strings.Repeat("─", leftLines)) +
		" " + title + " " +
		dim(strings.Repeat("─", rightLines)+"╮")

	sb.WriteString(centerLine(topBorder) + "\n")

	var lines []string
	for _, ev := range rawLines {
		evW := lipgloss.Width(ev)
		padLen := innerW - evW - 2 // -2 for leading and trailing spaces
		if padLen < 0 {
			padLen = 0
		}
		// Обрезаем если текст с пробелами длиннее доступного innerW
		safeEv := ev
		if evW > innerW-2 {
			safeEv = ansi.Truncate(ev, innerW-2, "")
			padLen = 0
		}
		lines = append(lines, dim("│")+" "+safeEv+strings.Repeat(" ", padLen)+" "+dim("│"))
	}

	pad := len(margin)
	if termWidth > 0 {
		pad = (termWidth - barW) / 2
		if pad < 0 {
			pad = 0
		}
	}
	p := strings.Repeat(" ", pad)
	for _, ln := range lines {
		sb.WriteString(fitWidth(p+ln) + "\n")
	}

	bottomBorder := dim("╰" + strings.Repeat("─", barW-2) + "╯")
	sb.WriteString(centerLine(bottomBorder) + "\n")

	if r.mode == runExploit && r.exp != nil && r.exp.Done {
		if inflight := atomic.LoadInt64(&r.exp.ExtrasInFlight); inflight > 0 {
			// прогресс дошёл до 100%, но снапы/титры ещё качаются —
			// esc сейчас прервёт их
			sb.WriteString(centerLine(yellow(fmt.Sprintf(
				tr("[i] снапы/титры в работе: %d — esc прервёт всю работу"), inflight))) + "\n")
			return sb.String()
		}
	}
	if r.finished() {
		sb.WriteString(centerLine(green(tr("[+] готово"))) + "\n")
	}
	return sb.String()
}

func (r *runState) checkView() string {
	st := r.chk
	// фаза чтения входного файла: бар показывает загрузку только пока скан не стартовал
	if atomic.LoadInt64(&st.Reading) == 1 && atomic.LoadInt64(&st.Checked) == 0 {
		readBytes := atomic.LoadInt64(&st.ReadBytes)
		totalBytes := atomic.LoadInt64(&st.ReadTotalBytes)
		lines := atomic.LoadInt64(&st.ReadLines)
		valid := atomic.LoadInt64(&st.ReadValid)
		var sb strings.Builder
		if totalBytes > 0 {
			pct := float64(readBytes) / float64(totalBytes) * 100
			sb.WriteString(centerLine(fmt.Sprintf("%s %.1f%%", bar(readBytes, totalBytes, 30), pct)) + "\n")
			sb.WriteString(centerLine(fmt.Sprintf("%.1f/%.1f %s", float64(readBytes)/1048576, float64(totalBytes)/1048576, tr("МБ"))+
				" | "+fmt.Sprintf(tr("%d строк"), lines)+
				" | "+fmt.Sprintf(tr("серийников: %s"), green(fmt.Sprint(valid)))+
				" | "+r.elapsed())+"\n\n")
		} else {
			sb.WriteString(centerLine(yellow(tr("читаю файл…"))) + "\n\n")
		}
		sb.WriteString(r.eventsBlock())
		return sb.String()
	}
	pct := 0.0
	if st.Total > 0 {
		pct = float64(st.Checked) / float64(st.Total) * 100
	}
	var sb strings.Builder
	sb.WriteString(centerLine(fmt.Sprintf("%s %.1f%%", bar(st.Checked, st.Total, 30), pct)) + "\n")
	sb.WriteString(centerLine(fmt.Sprintf("%d/%d | alive: %s | dead: %s | %s | %s | %s",
		st.Checked, st.Total,
		green(fmt.Sprint(st.Alive)), red(fmt.Sprint(st.Dead)),
		fmt.Sprintf(tr("%.0f/мин"), st.AliveRate),
		fmt.Sprintf(tr("%.0f/сек"), st.Speed),
		r.elapsed())) + "\n\n")
	sb.WriteString(r.eventsBlock())
	return sb.String()
}

func (r *runState) prefixView() string {
	scanned := atomic.LoadInt64(&r.preScanned)
	found := atomic.LoadInt64(&r.preFound)
	var sb strings.Builder
	sb.WriteString(centerLine(fmt.Sprintf("%s %s", bar(scanned, int64(r.preTotal), 30),
		fmt.Sprintf(tr("%d/%d хостов"), scanned, r.preTotal))) + "\n")
	sb.WriteString(centerLine(fmt.Sprintf("%s | %s",
		fmt.Sprintf(tr("найдено SN: %s"), green(fmt.Sprint(found))), r.elapsed())) + "\n\n")
	sb.WriteString(r.eventsBlock())
	return sb.String()
}
