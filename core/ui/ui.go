package ui

import (
	_ "embed"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"krushitel/core/update"
)

//go:embed banner.txt
var embeddedBanner string

var bannerArt = embeddedBanner

func init() {
	if b, err := os.ReadFile("banner.txt"); err == nil && len(strings.TrimSpace(string(b))) > 0 {
		bannerArt = string(b)
	} else if err != nil && !os.IsNotExist(err) {
		log.SetFlags(0)
		_ = log.Output(2, "banner.txt: "+err.Error())
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

const artInfoGap = "        "

var termWidth int

func bannerBlock() string {
	art := strings.Split(strings.TrimRight(bannerArt, "\n"), "\n")
	info := []string{
		"",
		styleCyan.Bold(true).Render("крушитель v" + update.CurrentVersion),
		styleYellow.Bold(true).Render(tr("Это бета версия")),
		styleDim.Render("exploit-based dahua sn scanner"),
		styleDim.Render("t.me/kkrushitel"),
		styleDim.Render("github.com/undervolter/krushitel"),
		"",
	}

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

func fitWidth(s string) string {
	if termWidth <= 0 {
		return s
	}
	if lipgloss.Width(s) < termWidth {
		return s
	}
	return ansi.Truncate(s, termWidth-1, "")
}

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

func withBottom(content, help string, height int) string {
	lines := strings.Split(strings.TrimRight(content, "\n"), "\n")
	if height > 0 {
		for len(lines) < height-1 {
			lines = append(lines, "")
		}
		if len(lines) > height-1 {
			lines = lines[:height-1]
		}
	}
	return strings.Join(lines, "\n") + "\n" + centerLine(help)
}

func panelS(title string) string {
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
	t := len([]rune(title)) + 2
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

type seconds = float64
