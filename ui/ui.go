package ui

// krushitel-test — TUI-стенд: реплика старого консольного крушителя на
// bubbletea. Движков нет и не надо (они в krushitel → krushitel_linux) —
// все режимы гоняют симуляцию, проверяется интерфейс.

import (
	_ "embed"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"krushitel/update"
)

//go:embed banner.txt
var embeddedBanner string

// bannerArt — активный арт: banner.txt из рабочей папки, если есть
// (можно менять без пересборки), иначе вшитый дефолт.
var bannerArt = embeddedBanner

func init() {
	if b, err := os.ReadFile("banner.txt"); err == nil && len(strings.TrimSpace(string(b))) > 0 {
		bannerArt = string(b)
	} else if err != nil && !os.IsNotExist(err) {
		log.SetFlags(0)
		_ = log.Output(2, "banner.txt: "+err.Error()) // не фатально
	}
}

var (
	styleCyan   = lipgloss.NewStyle().Foreground(lipgloss.Color("6"))
	styleDim    = lipgloss.NewStyle().Faint(true)
	styleGreen  = lipgloss.NewStyle().Foreground(lipgloss.Color("2"))
	styleRed    = lipgloss.NewStyle().Foreground(lipgloss.Color("1"))
	styleYellow = lipgloss.NewStyle().Foreground(lipgloss.Color("3"))
	styleBold   = lipgloss.NewStyle().Bold(true)
)

func dim(s string) string    { return styleDim.Render(s) }
func cyan(s string) string   { return styleCyan.Render(s) }
func green(s string) string  { return styleGreen.Render(s) }
func red(s string) string    { return styleRed.Render(s) }
func yellow(s string) string { return styleYellow.Render(s) }
func bold(s string) string   { return styleBold.Render(s) }

const margin = "    "

// artInfoGap — отступ между артом и инфо-блоком справа.
const artInfoGap = "        "

// termWidth — ширина терминала (обновляется из WindowSizeMsg в main.go).
// 0 = неизвестна (не TTY / до первого resize) — тогда отступ по умолчанию.
var termWidth int

// bannerBlock — арта + инфо-блок. Центрируется САМ (блоком: один отступ
// на все строки арта — иначе ёлка разваливается), остальные строки экрана
// центрируются centerLine'ом по отдельности.
func bannerBlock() string {
	art := strings.Split(strings.TrimRight(bannerArt, "\n"), "\n")
	info := []string{
		"",
		styleCyan.Bold(true).Render("крушитель v"+update.CurrentVersion),
		styleYellow.Bold(true).Render(tr("Это бета версия")),
		styleDim.Render("exploit-based dahua sn scanner"),
		styleDim.Render("t.me/kkrushitel"),
		styleDim.Render("github.com/undervolter/krushitel"),
		"",
	}

	// ширина арта — по самой длинной строке (уши/крылья), а не магическая
	// константа: арт меняется без правки кода
	artWidth := 0
	for _, ln := range art {
		if n := len([]rune(ln)); n > artWidth {
			artWidth = n
		}
	}

	var lines []string
	widths := make([]int, 0, len(art))
	for i, ln := range art {
		runes := []rune(ln)
		pad := artWidth - len(runes)
		if pad < 0 {
			pad = 0
		}
		line := styleCyan.Render(ln) + strings.Repeat(" ", pad)
		if i < len(info) && info[i] != "" {
			line += artInfoGap + info[i]
		}
		lines = append(lines, line)
		widths = append(widths, lipgloss.Width(line))
	}
	for i := len(art); i < len(info); i++ {
		if info[i] == "" {
			continue
		}
		line := strings.Repeat(" ", artWidth) + artInfoGap + info[i]
		lines = append(lines, line)
		widths = append(widths, lipgloss.Width(line))
	}

	maxW := 0
	for _, w := range widths {
		if w > maxW {
			maxW = w
		}
	}
	leftPad := len(margin)
	if termWidth > 0 {
		leftPad = (termWidth - maxW) / 2
		if leftPad < 0 {
			leftPad = 0
		}
	}

	var sb strings.Builder
	sb.WriteString("\n")
	padStr := strings.Repeat(" ", leftPad)
	for _, line := range lines {
		sb.WriteString(fitWidth(padStr+line) + "\n")
	}
	return sb.String()
}

// fitWidth — последний рубеж против ползущего рендера: строка НЕ должна
// быть ровно или шире терминала. Ровно-полная строка оставляет курсор
// в pending wrap, а рендерер bubbletea (standard_renderer.go) на полных
// строках не пишет EraseLineRight и пропускает неизменённые строки голым
// '\n' без '\r' — в связке кадры уезжают вниз и оставляют хвосты прошлых
// кадров. Поэтому капаем на termWidth-1.
func fitWidth(s string) string {
	if termWidth <= 0 {
		return s
	}
	if lipgloss.Width(s) < termWidth {
		return s
	}
	return ansi.Truncate(s, termWidth-1, "")
}

// centerLine — центрирование ОДНОЙ строки по ширине терминала.
func centerLine(s string) string {
	if termWidth <= 0 {
		return margin + s
	}
	pad := (termWidth - lipgloss.Width(s)) / 2
	if pad < 0 {
		pad = 0
	}
	return fitWidth(strings.Repeat(" ", pad) + s)
}

// centerBlock — группа строк, выровненных влево друг относительно друга
// (прибиты к общему левому краю), но весь блок отцентрирован по терминалу.
// Для меню/настроек: пункты разной длины не разъезжаются по отдельным центрам.
func centerBlock(lines []string) string {
	maxW := 0
	for _, ln := range lines {
		if w := lipgloss.Width(ln); w > maxW {
			maxW = w
		}
	}
	pad := len(margin)
	if termWidth > 0 {
		pad = (termWidth - maxW) / 2
		if pad < 0 {
			pad = 0
		}
	}
	p := strings.Repeat(" ", pad)
	var sb strings.Builder
	for _, ln := range lines {
		sb.WriteString(fitWidth(p+ln) + "\n")
	}
	return sb.String()
}

// withBottom — прижимает строку help к нижнему краю терминала: контент,
// добивка пустыми строками до height-1, затем help.
func withBottom(content, help string, height int) string {
	lines := strings.Split(strings.TrimRight(content, "\n"), "\n")
	if height > 0 {
		for len(lines) < height-1 {
			lines = append(lines, "")
		}
		if len(lines) > height-1 {
			lines = lines[:height-1] // контент не влезает — help идёт следом
		}
	}
	return strings.Join(lines, "\n") + "\n" + centerLine(help)
}

// panelS — разделитель с заголовком: ───────── настройки ─────────
// Тире с обеих сторон, заголовок по центру линии. Ширина адаптивная:
// termWidth-8, капнутая в [30..80]; при неизвестной ширине — 56.
func panelS(title string) string {
	// -10, а не -8: по бокам пад 4+4, и при -8 строка выходит ровно в
	// ширину терминала — а ровно-полные строки ломают рендер (fitWidth)
	w := 56
	if termWidth > 0 {
		w = termWidth - 10
		if w > 80 {
			w = 80
		}
		if w < 30 {
			w = 30
		}
	}
	t := len([]rune(title)) + 2 // " title "
	left := (w - t) / 2
	if left < 1 {
		left = 1
	}
	right := w - t - left
	if right < 1 {
		right = 1
	}
	return centerLine(styleDim.Render(strings.Repeat("─", left)) +
		styleCyan.Render(" "+title+" ") +
		styleDim.Render(strings.Repeat("─", right)))
}

// bar — прогресс-бар (как scanBar в старом TUI).
func bar(cur, total int64, width int) string {
	if total <= 0 {
		total = 1
	}
	if cur < 0 {
		cur = 0
	}
	if cur > total {
		cur = total
	}
	filled := int(cur * int64(width) / total)
	return styleGreen.Render(strings.Repeat("█", filled)) +
		styleDim.Render(strings.Repeat("─", width-filled))
}

// fmtDuration — mm:ss / hh:mm:ss.
func fmtDuration(d seconds) string {
	s := int(d)
	h := s / 3600
	m := (s % 3600) / 60
	sec := s % 60
	if h > 0 {
		return fmt.Sprintf("%d:%02d:%02d", h, m, sec)
	}
	return fmt.Sprintf("%02d:%02d", m, sec)
}

// seconds — просто алиас для читаемости fmtDuration.
type seconds = float64
