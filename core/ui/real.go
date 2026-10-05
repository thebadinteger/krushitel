package ui

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

	"krushitel/core/exploit"
	"krushitel/core/scanner"
)

const (
	runExploit = iota
	runCheck
	runPrefix
	runTitles
)

type runState struct {
	mode     int
	panel    string
	cancel   context.CancelFunc
	start    time.Time
	endTime  time.Time
	h        int
	events   []string
	eventsCh chan string

	exp        *exploit.TwoPhaseStats
	saveDir    string
	chk        *scanner.ScanStats
	ttl        *exploit.TitlesStats
	genErr     string
	preScanned int64
	preFound   int64
	preTotal   int
	preDone    int64

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

func NoteCrashLine(s string) { noteCrashLine(s) }

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

func (r *runState) closeLog() {
	if r.logFile != nil {
		r.logFile.Close()
		r.logFile = nil
	}
}

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

func (r *runState) logMax() int {
	n := r.h - 24
	if n < 5 {
		n = 5
	}
	if n > 400 {
		n = 400
	}
	return n
}

func isAlnumSN(s string) bool {
	if len(s) < 14 || len(s) > 15 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) {
			return false
		}
	}
	return true
}

func feedVisible(line string) bool {
	if cfg.Debug {
		return true
	}
	if strings.HasPrefix(line, "[VALID]") {
		return false
	}
	if i := strings.Index(line, " — "); i > 0 && isAlnumSN(line[:i]) {
		return false
	}
	return true
}

func (r *runState) drain() {
	max := r.logMax()
	for {
		select {
		case ev := <-r.eventsCh:
			noteCrashLine(ev)
			r.writeLog(ev)
			if !feedVisible(ev) {
				continue
			}
			r.events = append(r.events, ev)
			if len(r.events) > max {
				r.events = r.events[len(r.events)-max:]
			}
		default:
			return
		}
	}
}

func (r *runState) finished() bool {
	switch r.mode {
	case runExploit:
		tp := r.exp
		return tp != nil && tp.PhaseNum() == 2 && tp.Exp != nil && tp.Exp.Done &&
			atomic.LoadInt64(&tp.Exp.ExtrasInFlight) == 0
	case runCheck:
		return r.chk != nil && r.chk.Done
	case runPrefix:
		return atomic.LoadInt64(&r.preDone) == 1
	case runTitles:
		return r.ttl != nil && r.ttl.Done
	}
	return false
}

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
		if r.exp != nil && r.exp.PhaseNum() == 1 {
			return r.exp.Scan.ErrorMsg
		}
		if r.exp != nil {
			return r.exp.Exp.ErrorMsg
		}
		return ""
	case runCheck:
		return r.chk.ErrorMsg
	case runPrefix:
		return r.genErr
	case runTitles:
		return r.ttl.ErrorMsg
	}
	return ""
}

func (r *runState) view() string {
	var sb strings.Builder
	sb.WriteString(bannerBlock())
	sb.WriteString(strings.Repeat("\n", 4))
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

func (r *runState) exploitView() string {
	tp := r.exp
	var sb strings.Builder

	if tp.PrefixCount > 0 {
		sb.WriteString(centerLine(dim(fmt.Sprintf(tr("%d префикс(ов) | %d серийников на входе · //%s"),
			tp.PrefixCount, tp.ScanTotal, r.saveDir))) + "\n")
	} else {
		sb.WriteString(centerLine(dim(fmt.Sprintf(tr("%d серийников на входе · //%s"),
			tp.DirectCount, r.saveDir))) + "\n")
	}

	if tp.PrefixCount > 0 && tp.PhaseNum() == 1 {
		st := tp.Scan
		sb.WriteString(centerLine(fmt.Sprintf(tr("[1/2] сканируем %d серийников"), tp.ScanTotal)) + "\n")
		pct := 0.0
		if st.Total > 0 {
			pct = float64(st.Checked) / float64(st.Total) * 100
		}
		sb.WriteString(centerLine(fmt.Sprintf("%s %.1f%%", bar(st.Checked, st.Total, 30), pct)) + "\n")
		sb.WriteString(centerLine(fmt.Sprintf("%d/%d | found: %s | %s | %s",
			atomic.LoadInt64(&st.PrefixDone), int64(tp.PrefixCount),
			green(fmt.Sprint(tp.FoundCount())),
			fmt.Sprintf(tr("%.0f/сек"), st.Speed),
			fmtDuration(tp.ScanSeconds()))) + "\n\n")
		sb.WriteString(r.eventsBlock())
		return sb.String()
	}

	st := tp.Exp
	if tp.PrefixCount > 0 {
		sb.WriteString(centerLine(fmt.Sprintf(tr("[2/2] ломаем %d серийников"), tp.TargetCount())) + "\n")
	}
	progress := st.Progress()
	pct := 0.0
	if st.Total > 0 {
		pct = float64(progress) / float64(st.Total) * 100
	}
	snapStr := green(fmt.Sprint(atomic.LoadInt64(&st.Snaps)))
	if fails := atomic.LoadInt64(&st.SnapFails); fails > 0 {
		snapStr += red("/" + fmt.Sprint(fails))
	}
	pwned := atomic.LoadInt64(&st.Pwned) + atomic.LoadInt64(&st.Added)
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

	barW := maxEvW + 4
	if barW < 117 {
		barW = 117
	}
	if termWidth > 0 && barW > termWidth-8 {
		barW = termWidth - 8
	}
	if barW < 30 {
		barW = 30
	}

	innerW := barW - 2

	title := tr("логи")
	tLen := len([]rune(title)) + 2
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
		padLen := innerW - evW - 2
		if padLen < 0 {
			padLen = 0
		}
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

	if r.mode == runExploit && r.exp != nil && r.exp.PhaseNum() == 2 && r.exp.Exp.Done {
		if inflight := atomic.LoadInt64(&r.exp.Exp.ExtrasInFlight); inflight > 0 {
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
				" | "+r.elapsed()) + "\n\n")
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
