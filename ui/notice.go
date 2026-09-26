package ui

// notice.go — механика уведомлений (по мотивам интро-оверлея из dev-ветки):
// бокс с круглой рамкой по центру экрана. Два режима:
//
//   - обычное уведомление (апдейт): жёлтый бокс, фона нет вообще;
//   - предупреждение: фон UI чуть затемнён, бокс подсвечен красным.
//
// Цвета рамок — как в dev: жёлтый lipgloss.Color("3").

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// Рамки боксов.
const (
	noticeYellow = lipgloss.Color("3")
	noticeRed    = lipgloss.Color("1")
)

// noticeWidth — ширина бокса от ширины терминала (как в dev).
func noticeWidth(termW int) int {
	w := termW - 10
	if w > 78 || w <= 0 {
		w = 78
	}
	if w < 34 {
		w = 34
	}
	return w
}

// noticeBox — бокс: жирный заголовок + тело, текст по центру.
func noticeBox(title string, body []string, border lipgloss.Color, width int) []string {
	lines := make([]string, 0, len(body)+2)
	if title != "" {
		lines = append(lines, styleBold.Render(title), "")
	}
	lines = append(lines, body...)
	box := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(border).
		Padding(1, 3).
		Width(width).
		Align(lipgloss.Center).
		Render(strings.Join(lines, "\n"))
	return strings.Split(box, "\n")
}

// centerBox — бокс по центру экрана вертикально и горизонтально.
// Вокруг пусто, без фона. help прижимает withBottom у вызывателя.
func centerBox(box []string, w, h int) string {
	if w <= 0 {
		w = 80
	}
	maxW := 0
	for _, ln := range box {
		if vw := lipgloss.Width(ln); vw > maxW {
			maxW = vw
		}
	}
	padL := (w - maxW) / 2
	if padL < 0 {
		padL = 0
	}
	padT := (h - 1 - len(box)) / 2
	if padT < 0 {
		padT = 0
	}
	out := make([]string, 0, len(box)+padT)
	for i := 0; i < padT; i++ {
		out = append(out, "")
	}
	pad := strings.Repeat(" ", padL)
	for _, ln := range box {
		out = append(out, pad+ln)
	}
	return strings.Join(out, "\n")
}

// overlayWarning — предупреждение поверх чуть затемнённого фона (баннер):
// фон чистим от ANSI и димим (как в dev), бокс врезаем по центру.
func overlayWarning(box []string, w, h int) string {
	if w <= 0 {
		w = 80
	}
	rows := h - 1
	if rows <= 0 {
		rows = 24
	}
	bgLines := strings.Split(stripANSI(bannerBlock()+"\n\n\n\n"), "\n")
	for len(bgLines) < rows {
		bgLines = append(bgLines, "")
	}
	for i, l := range bgLines {
		r := []rune(l)
		if len(r) < w {
			r = append(r, []rune(strings.Repeat(" ", w-len(r)))...)
		}
		bgLines[i] = string(r)
	}
	boxWidth := lipgloss.Width(box[0])
	rowStart := (rows - len(box)) / 2
	if rowStart < 0 {
		rowStart = 0
	}
	colStart := (w - boxWidth) / 2
	if colStart < 0 {
		colStart = 0
	}
	out := make([]string, rows)
	for r := 0; r < rows; r++ {
		if r < rowStart || r >= rowStart+len(box) {
			out[r] = styleDim.Render(bgLines[r])
			continue
		}
		runes := []rune(bgLines[r])
		left := colStart
		if left > len(runes) {
			left = len(runes)
		}
		right := ""
		if rightStart := colStart + boxWidth; rightStart < len(runes) {
			right = string(runes[rightStart:])
		}
		out[r] = styleDim.Render(string(runes[:left])) + box[r-rowStart] + styleDim.Render(right)
	}
	return strings.Join(out, "\n")
}
