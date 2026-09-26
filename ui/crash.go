package ui

// crash.go — экран смерти. Bubbletea по дефолту глотает паники сам
// (recoverFromPanic → "program was killed"), поэтому наш сплеш бы никогда
// не показался: Run создаёт программу с WithoutCatchPanics и ловит панику
// своим recover ниже. Сюда же пишет crash.log, т.к. main recover при
// UI-панике уже не срабатывает (мы сами делаем os.Exit).

import (
	"fmt"
	"os"
	"strings"
	"time"

	"krushitel/update"
)

func truncateRunesCrash(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}

// Ширина переноса строк стека: рамка широкая, режем по пробелу,
// длинные токены (пути, дампы структур) — жёстко.
const crashWrapW = 150

// wrapRunesCrash режет строку на куски ≤ n рун. Ничего не выкидываем —
// весь текст виден, в отличие от обрезки.
func wrapRunesCrash(s string, n int) []string {
	r := []rune(strings.TrimRight(s, "\r"))
	var out []string
	for len(r) > n {
		cut := n
		for i := n; i > n/2 && i < len(r); i-- {
			if r[i] == ' ' {
				cut = i
				break
			}
		}
		out = append(out, strings.TrimRight(string(r[:cut]), " "))
		if cut < len(r) && r[cut] == ' ' {
			r = r[cut+1:]
		} else {
			r = r[cut:]
		}
	}
	out = append(out, string(r))
	return out
}

// CrashSplash — экран смерти: плоский текст + стек в рамке. Лого нет.
// Причина живая (сообщение рантайма), версия — из update.CurrentVersion.
// Окно уже рамки — отдаём тот же текст без бокса. Возвращает готовый
// текст (терминал уже выведен из alt-экрана вызывателем).
func CrashSplash(reason string, stack string) string {
	title := " stacktrace "
	inner := 0
	var rows []string
	for _, ln := range strings.Split(strings.TrimRight(stack, "\n"), "\n") {
		for _, chunk := range wrapRunesCrash(strings.TrimSpace(ln), crashWrapW) {
			rows = append(rows, chunk)
			if w := len([]rune(chunk)); w > inner {
				inner = w
			}
		}
	}
	if inner < len([]rune(title)) {
		inner = len([]rune(title))
	}
	bar := strings.Repeat("─", inner+2)
	boxW := inner + 4

	info := []string{
		"krushitel crashed :(",
		"reason - " + truncateRunesCrash(reason, 100),
		"version v" + update.CurrentVersion,
		"stacktrace in crash.log",
		"dev - t.me/kronaphasia",
		"discord: undervolter",
	}
	infoMax := 0
	for _, ln := range info {
		if w := len([]rune(ln)); w > infoMax {
			infoMax = w
		}
	}
	contentW := boxW
	if infoMax > contentW {
		contentW = infoMax
	}

	// Контент шире окна — рамка разъедется переносами консоли,
	// отдаём плоский текст без бокса.
	if termW := termWidthCrash(); termW > 0 && contentW > termW {
		var flat strings.Builder
		for _, ln := range info {
			flat.WriteString(ln + "\n")
		}
		return flat.String()
	}

	// Центрируем всё от ширины контента, потом весь блок — от окна.
	termPad := ""
	if termW := termWidthCrash(); termW > contentW {
		termPad = strings.Repeat(" ", (termW-contentW)/2)
	}
	center := func(s string, w int) string {
		if w >= contentW {
			return s
		}
		return strings.Repeat(" ", (contentW-w)/2) + s
	}
	var out strings.Builder
	out.WriteString("\x1b[?1049l\x1b[?25h\r\n") // выйти из alt-экрана, вернуть курсор
	for _, ln := range info {
		out.WriteString(termPad + center(ln, len([]rune(ln))) + "\n")
	}
	out.WriteString("\n")
	out.WriteString(termPad + center("╭"+bar+"╮", boxW) + "\n")
	out.WriteString(termPad + center("│ "+title+strings.Repeat(" ", inner-len([]rune(title)))+" │", boxW) + "\n")
	for _, ln := range rows {
		out.WriteString(termPad + center("│ "+ln+strings.Repeat(" ", inner-len([]rune(ln)))+" │", boxW) + "\n")
	}
	out.WriteString(termPad + center("╰"+bar+"╯", boxW) + "\n")
	return out.String()
}

// WaitForKey — после краш-сплеша держим окно открытым: печатаем
// подсказку и ждём любую клавишу. Без консоли не висим.
// Для тех, кто запускает даблкликом, а не из терминала.
func WaitForKey(out *os.File) {
	defer func() { _ = recover() }()
	if out == nil {
		return
	}
	fmt.Fprintln(out, tr("нажми любую клавишу..."))
	waitKey()
}

// crashDump пишет панику+стек в crash.log рядом с бинарником.
func crashDump(stack []byte, r interface{}) {
	f, err := os.OpenFile("crash.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "=== PANIC %s ===\n%v\n%s\n", time.Now().Format("02.01.2006 15:04:05"), r, string(stack))
}
