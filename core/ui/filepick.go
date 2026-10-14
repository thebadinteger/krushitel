package ui

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type pickMode int

const (
	pickNone pickMode = iota
	pickFile
	pickDir
)

type pickRow struct {
	name    string
	isDir   bool
	here    bool
	size    int64
	modTime time.Time
}

type pickState struct {
	mode     pickMode
	field    int
	cwd      string
	rows     []pickRow
	cur      int
	top      int
	vis      int
	err      string
	selected string
	find     string
}

var lastPickDir string

var styleWhite = lipgloss.NewStyle().Foreground(lipgloss.Color("15")).Bold(true)

func newPicker(mode pickMode, field int, startVal string) *pickState {
	start := ""
	if startVal != "" {
		if st, err := os.Stat(startVal); err == nil {
			if st.IsDir() {
				start = startVal
			} else {
				start = filepath.Dir(startVal)
			}
		}
	}
	if start == "" {
		start = lastPickDir
	}
	if start == "" {
		if wd, err := os.Getwd(); err == nil {
			start = wd
		} else {
			start = "."
		}
	}
	p := &pickState{mode: mode, field: field, cwd: start, vis: 20}
	p.load()
	return p
}

func (p *pickState) load() {
	p.err = ""
	p.find = ""
	ents, err := os.ReadDir(p.cwd)
	if err != nil {
		p.err = err.Error()
		// оставляем "..", чтобы было куда уйти назад;
		// без этого cur указывает в пустоту и enter роняет activate().
		p.rows = []pickRow{{name: "..", isDir: true}}
		p.cur, p.top = 0, 0
		return
	}
	type statRow struct {
		row   pickRow
		isDir bool
	}
	list := make([]statRow, 0, len(ents))
	for _, e := range ents {
		r := pickRow{name: e.Name(), isDir: e.IsDir()}
		if info, ierr := e.Info(); ierr == nil {
			r.modTime = info.ModTime()
			if !e.IsDir() {
				r.size = info.Size()
			}
		}
		list = append(list, statRow{row: r, isDir: e.IsDir()})
	}
	sort.Slice(list, func(i, j int) bool {
		a, b := list[i], list[j]
		if a.isDir != b.isDir {
			return a.isDir
		}
		return strings.ToLower(a.row.name) < strings.ToLower(b.row.name)
	})
	p.rows = make([]pickRow, 0, len(list)+2)
	p.rows = append(p.rows, pickRow{name: "..", isDir: true})
	if p.mode == pickDir {
		p.rows = append(p.rows, pickRow{here: true})
	}
	for _, s := range list {
		p.rows = append(p.rows, s.row)
	}
	p.cur, p.top = 0, 0
}

func (p *pickState) rowCount() int { return len(p.rows) }

func (p *pickState) goUp() {
	parent := filepath.Dir(p.cwd)
	if parent == p.cwd {
		return
	}
	p.cwd = parent
	p.load()
}

func (p *pickState) activate() bool {
	if p.cur < 0 || p.cur >= len(p.rows) {
		return false
	}
	if p.cur == 0 {
		p.goUp()
		return false
	}
	if p.mode == pickDir && p.rows[p.cur].here {
		p.selected = p.cwd
		return true
	}
	r := p.rows[p.cur]
	path := filepath.Join(p.cwd, r.name)
	if r.isDir {
		p.cwd = path
		p.load()
		return false
	}
	p.selected = path
	return true
}

func (p *pickState) update(msg tea.KeyMsg) (done bool) {
	switch msg.Type {
	case tea.KeyUp, tea.KeyShiftTab:
		p.step(-1)
	case tea.KeyDown, tea.KeyTab:
		p.step(1)
	case tea.KeyLeft:
		p.goUp()
	case tea.KeyBackspace:
		if p.find != "" {
			r := []rune(p.find)
			p.find = string(r[:len(r)-1])
			p.snapToMatch()
		}
	case tea.KeyRunes:
		if len(msg.Runes) > 0 {
			p.find += string(msg.Runes)
			if r := []rune(p.find); len(r) > 64 {
				p.find = string(r[:64])
			}
			p.snapToMatch()
		}
	case tea.KeyEsc:
		if p.find != "" {
			p.find = ""
			p.cur, p.top = 0, 0
			return false
		}
		return true
	case tea.KeyEnter:
		if p.find != "" {
			ok := false
			for _, i := range p.matches() {
				if i == p.cur {
					ok = true
					break
				}
			}
			if !ok {
				return false
			}
		}
		done = p.activate()
	}
	p.fixScroll()
	return done
}

// matches — индексы строк под текущий find. Без find — все строки.
// Служебный here-ряд ("[ выбрать эту папку ]") в выдачу не попадает.
func (p *pickState) matches() []int {
	out := make([]int, 0, len(p.rows))
	if p.find == "" {
		for i := range p.rows {
			out = append(out, i)
		}
		return out
	}
	q := strings.ToLower(p.find)
	for i, r := range p.rows {
		if r.here {
			continue
		}
		if strings.Contains(strings.ToLower(r.name), q) {
			out = append(out, i)
		}
	}
	return out
}

// snapToMatch — после правки find встать на первое совпадение.
// Если текущий курсор и так в выдаче — не дёргаем.
func (p *pickState) snapToMatch() {
	m := p.matches()
	if len(m) == 0 {
		return
	}
	for _, i := range m {
		if i == p.cur {
			return
		}
	}
	p.cur = m[0]
	p.top = 0
}

// step — шаг навигации внутри выдачи. В края упираемся, без телепортов:
// вверх на первой строке и вниз на последней — стоим на месте.
func (p *pickState) step(dir int) {
	m := p.matches()
	if len(m) == 0 {
		return
	}
	pos := -1
	for i, ri := range m {
		if ri == p.cur {
			pos = i
			break
		}
	}
	if pos < 0 {
		if dir > 0 {
			p.cur = m[0]
		} else {
			p.cur = m[len(m)-1]
		}
		return
	}
	pos += dir
	if pos < 0 {
		pos = 0
	}
	if pos > len(m)-1 {
		pos = len(m) - 1
	}
	p.cur = m[pos]
}

func (p *pickState) fixScroll() {
	if p.vis < 1 {
		p.vis = 20
	}
	if p.cur < p.top {
		p.top = p.cur
	}
	if p.cur >= p.top+p.vis {
		p.top = p.cur - p.vis + 1
	}
}

func padEnd(s string, w int) string {
	d := w - lipgloss.Width(s)
	if d <= 0 {
		return s
	}
	return s + strings.Repeat(" ", d)
}

func padStart(s string, w int) string {
	d := w - lipgloss.Width(s)
	if d <= 0 {
		return s
	}
	return strings.Repeat(" ", d) + s
}

func fmtSize(n int64) string {
	switch {
	case n < 1024:
		return fmt.Sprintf("%d B", n)
	case n < 1024*1024:
		return fmt.Sprintf("%.1f KB", float64(n)/1024)
	case n < 1024*1024*1024:
		return fmt.Sprintf("%.1f MB", float64(n)/(1024*1024))
	default:
		return fmt.Sprintf("%.1f GB", float64(n)/(1024*1024*1024))
	}
}

const (
	fmTimeLayout = "02.01.06 15:04"
	fmTimeW      = 16
	fmSizeW      = 9
	fmTypeW      = 6
	fmGap        = 2
	fmMinNameW   = 14
	fmMinPanelW  = 52
	fmMaxPanelW  = 160
	fmMaxVisRows = 40
)

func (p *pickState) view(w, h int) string {
	banner := bannerBlock()
	bannerH := strings.Count(banner, "\n") + 1
	vis := h - bannerH - 9
	if vis < 4 {
		vis = 4
	}
	if vis > fmMaxVisRows {
		vis = fmMaxVisRows
	}
	p.vis = vis
	p.fixScroll()

	panelW := w - 8
	if panelW < fmMinPanelW {
		panelW = fmMinPanelW
	}
	if panelW > fmMaxPanelW {
		panelW = fmMaxPanelW
	}
	inner := panelW - 4
	nameW := inner - (fmTimeW + fmSizeW + fmTypeW + fmGap*3) - 2
	if nameW < fmMinNameW {
		nameW = fmMinNameW
	}

	top := "╭" + styleDim.Render(strings.Repeat("─", panelW-2)) + "╮"
	bottom := "╰" + styleDim.Render(strings.Repeat("─", panelW-2)) + "╯"

	wrap := func(s string, selected bool) string {
		if selected {
			s = styleWhite.Render(s)
		}
		return "│ " + padEnd(s, inner) + " │"
	}

	var lines []string
	lines = append(lines, top, wrap(cyan(cutStr(p.cwd, inner-2)), false))
	if p.find != "" {
		lines = append(lines, wrap(blue("find: ")+cutStr(p.find, inner-8), false))
	}

	if p.err != "" {
		lines = append(lines, wrap(red("↑ "+p.err), false))
	}
	if len(p.rows) <= 1 && p.mode == pickFile && p.err == "" && p.find == "" {
		lines = append(lines, wrap(dim(tr("(папка пуста)")), false))
	}

	renderRow := func(i int) string {
		r := p.rows[i]
		sel := i == p.cur
		var content string
		if r.here {
			content = green(tr("[ выбрать эту папку ]"))
		} else {
			name := r.name
			if r.isDir {
				name = "/" + name
			}
			cols := padEnd(cutStr(name, nameW), nameW) + strings.Repeat(" ", fmGap)
			cols += padEnd(r.modTime.Format(fmTimeLayout), fmTimeW) + strings.Repeat(" ", fmGap)
			if r.isDir {
				cols += padStart("", fmSizeW) + strings.Repeat(" ", fmGap) + padEnd("Folder", fmTypeW)
			} else {
				cols += padStart(fmtSize(r.size), fmSizeW) + strings.Repeat(" ", fmGap) + padEnd("File", fmTypeW)
			}
			content = cols
		}
		prefix := "  "
		if sel {
			prefix = "▶ "
		}
		return wrap(prefix+content, sel)
	}

	order := p.matches()
	if p.find == "" {
		for i := p.top; i < len(p.rows) && i < p.top+vis; i++ {
			lines = append(lines, renderRow(i))
		}
	} else {
		if len(order) == 0 {
			lines = append(lines, wrap(dim(tr("(ничего не найдено)")), false))
		}
		pos := 0
		for i, ri := range order {
			if ri == p.cur {
				pos = i
				break
			}
		}
		start := pos
		if start > len(order)-vis {
			start = len(order) - vis
		}
		if start < 0 {
			start = 0
		}
		for _, ri := range order[start:min(start+vis, len(order))] {
			lines = append(lines, renderRow(ri))
		}
	}

	for len(lines) < 5 {
		lines = append(lines, wrap("", false))
	}
	lines = append(lines, bottom)

	return banner + strings.Repeat("\n", 4) + centerBlock(lines)
}

func pickHelpLine() string {
	return tr("↑↓ навигация · буквы - поиск · enter - открыть/выбрать · ← - наверх · backspace - стереть · esc - сброс/назад")
}
