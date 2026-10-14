package ui

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"krushitel/core/dhip"
	"krushitel/core/exploit"
	"krushitel/core/i18n"
	"krushitel/core/scanner"
	"krushitel/core/update"
)

func tr(s string) string { return i18n.Tr(s) }

type sessionState int

const (
	stMenu sessionState = iota
	stForm
	stRun
	stXMLMenu
	stMsg
	stSettings
	stGreet
	stUpdate
	stUpdating
	stFilePick
)

type tickMsg time.Time

type crashTestMsg struct{}

type model struct {
	w, h     int
	state    sessionState
	prevMenu sessionState
	cursor   int
	xmlCur   int
	setCur   int
	greetCur int

	form       *formState
	run        *runState
	picker     *pickState
	msgLines   []string
	msgPanel   string
	quitting   bool
	restarting bool

	setEdit    int
	setInput   textinput.Model
	setEditErr string
	setEditLW  int

	bruteCur    int
	bruteAdding bool
	bruteFocus  bool

	upd       *update.Release
	updCancel context.CancelFunc
	updCur    int
}

var teaProg *tea.Program

// realTerm — настоящий терминал. В Run() os.Stdout уводится в devNull, чтобы
// TUI-рендер не пачкал вывод, поэтому сплэш после краша нужно писать сюда.
var realTerm = os.Stdout

// StopForFatal гасит TUI и отдаёт настоящий терминал для сплэша.
// Без этого bubbletea продолжит рисовать поверх рамки со стектрейсом.
func StopForFatal() *os.File {
	if teaProg != nil {
		_ = teaProg.ReleaseTerminal()
	}
	if realTerm != nil {
		return realTerm
	}
	return os.Stdout
}

func Run() bool {
	realStdout := os.Stdout
	realTerm = realStdout
	realStderr := os.Stderr
	if devNull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0); err == nil {
		os.Stdout = devNull
		os.Stderr = devNull
		defer func() {
			os.Stdout = realStdout
			os.Stderr = realStderr
			_ = devNull.Close()
		}()
	}
	update.Sweep()
	ctx, cancel := context.WithTimeout(context.Background(), update.CheckTimeout)
	upd, _ := update.Check(ctx)
	cancel()
	p := tea.NewProgram(initialModel(upd), tea.WithAltScreen(), tea.WithOutput(realStdout), tea.WithoutCatchPanics())
	teaProg = p
	defer discordStop()
	defer func() {
		if r := recover(); r != nil {
			stack := debug.Stack()
			crashDump(stack, r)
			_ = p.ReleaseTerminal()
			reason := strings.TrimSpace(strings.SplitN(fmt.Sprintf("%v", r), "\n", 2)[0])
			if reason == "" {
				reason = "unknown (see crash.log)"
			}
			fmt.Fprint(realStdout, CrashSplash(reason, string(stack)))
			WaitForKey(realStdout)
			os.Exit(1)
		}
	}()
	finalM, err := p.Run()
	if err != nil {
		fmt.Fprintf(realStdout, tr("ошибка: %v")+"\n", err)
		os.Exit(1)
	}
	if fm, ok := finalM.(model); ok && fm.restarting {
		return true
	}
	return false
}

func initialModel(upd *update.Release) model {
	loadSettings()
	m := model{state: stMenu, setEdit: -1}
	if upd != nil {
		i18n.SetLang(cfg.Lang)
		m.upd = upd
		m.state = stUpdate
		return m
	}
	if cfg.IsActivated {
		i18n.SetLang(cfg.Lang)
	} else {
		m.state = stGreet
	}
	return m
}

func (m model) Init() tea.Cmd {
	if os.Getenv("KRUSHITEL_PANIC_TEST") != "" {
		return tea.Batch(tickCmd(), tea.Tick(5*time.Second, func(t time.Time) tea.Msg {
			return crashTestMsg{}
		}))
	}
	return tickCmd()
}

func tickCmd() tea.Cmd {
	return tea.Tick(time.Millisecond*200, func(t time.Time) tea.Msg { return tickMsg(t) })
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.w, m.h = msg.Width, msg.Height
		termWidth = msg.Width
		m.fitEditBox()
		return m, nil

	case tickMsg:
		if m.state == stRun && m.run != nil {
			m.run.h = m.h
			m.run.drain()
		}
		if m.state == stUpdating {
			if cmd := m.checkUpdDone(); cmd != nil {
				return m, cmd
			}
		}
		discordTick(m.run)
		return m, tickCmd()

	case crashTestMsg:
		panic("test crash: KRUSHITEL_PANIC_TEST")

	case tea.KeyMsg:
		if msg.Type == tea.KeyCtrlC {
			discordStop()
			m.quitting = true
			return m, tea.Quit
		}

		switch m.state {
		case stGreet:
			return m.updateGreet(msg)
		case stMenu:
			return m.updateMenu(msg)
		case stForm:
			return m.updateForm(msg)
		case stFilePick:
			return m.updateFilePick(msg)
		case stRun:
			return m.updateRun(msg)
		case stXMLMenu:
			return m.updateXMLMenu(msg)
		case stMsg:
			return m.updateMsg(msg)
		case stSettings:
			return m.updateSettings(msg)
		case stUpdate:
			return m.updateUpdatePrompt(msg)
		case stUpdating:
			return m.updateUpdating(msg)
		}
	}
	return m, nil
}

var greetOptions = []string{"русский", "english"}

func (m model) updateGreet(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.Type {
	case tea.KeyUp, tea.KeyShiftTab:
		m.greetCur = (m.greetCur - 1 + len(greetOptions)) % len(greetOptions)
	case tea.KeyDown, tea.KeyTab:
		m.greetCur = (m.greetCur + 1) % len(greetOptions)
	case tea.KeyEnter:
		return m.selectGreet(m.greetCur)
	case tea.KeyRunes:
		r := msg.Runes[0]
		if r >= '1' && r <= '2' {
			return m.selectGreet(int(r - '0' - 1))
		}
	}
	return m, nil
}

func (m model) selectGreet(idx int) (tea.Model, tea.Cmd) {
	if idx == 0 {
		cfg.Lang = "ru"
	} else {
		cfg.Lang = "en"
	}
	i18n.SetLang(cfg.Lang)
	cfg.IsActivated = true
	saveSettings()
	m.state = stMenu
	return m, nil
}

func (m model) greetView() string {
	var sb strings.Builder
	sb.WriteString(bannerBlock())
	sb.WriteString(strings.Repeat("\n", 4))
	sb.WriteString(panelS("welcome") + "\n\n")
	var rows []string
	for i, opt := range greetOptions {
		num := fmt.Sprintf("%d", i+1)
		if i == m.greetCur {
			rows = append(rows, styleGreen.Render("▶")+"  "+styleBold.Render(num)+"  "+styleBold.Render(opt))
		} else {
			rows = append(rows, "   "+styleDim.Render(num)+"  "+opt)
		}
	}
	sb.WriteString(centerBlock(rows))
	return sb.String()
}

type mainMenuItemKind int

const (
	menuItemExploit mainMenuItemKind = iota
	menuItemTitles
	menuItemClean
	menuItemXML
	menuItemFindPrefix
	menuItemSettings
)

type mainMenuItem struct {
	kind  mainMenuItemKind
	num   string
	label string
}

func (m model) mainMenuItems() []mainMenuItem {
	return []mainMenuItem{
		{kind: menuItemExploit, num: "1", label: "ломать камеры"},
		{kind: menuItemTitles, num: "2", label: "OSDChanger"},
		{kind: menuItemClean, num: "3", label: "OSDCleaner"},
		{kind: menuItemXML, num: "4", label: "расшифровать .xml от smartpss"},
		{kind: menuItemFindPrefix, num: "5", label: "искать префиксы с списка IP"},
		{kind: menuItemSettings, num: "6", label: "настройки"},
	}
}

func (m model) updateMenu(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	items := m.mainMenuItems()

	switch msg.Type {
	case tea.KeyUp, tea.KeyShiftTab:
		m.cursor = (m.cursor - 1 + len(items)) % len(items)
	case tea.KeyDown, tea.KeyTab:
		m.cursor = (m.cursor + 1) % len(items)
	case tea.KeyEnter:
		if m.cursor < len(items) {
			return m.selectMenuItem(items[m.cursor].kind)
		}
	case tea.KeyRunes:
		r := msg.Runes[0]
		if r >= '1' && r <= '6' {
			for i, item := range items {
				if item.num == string(r) {
					m.cursor = i
					return m.selectMenuItem(item.kind)
				}
			}
		}
	}
	return m, nil
}

func (m model) selectMenuItem(kind mainMenuItemKind) (tea.Model, tea.Cmd) {
	switch kind {
	case menuItemExploit:
		m.form = exploitForm()
		m.state = stForm
		m.prevMenu = stMenu
	case menuItemTitles:
		m.form = titlesForm()
		m.state = stForm
		m.prevMenu = stMenu
	case menuItemClean:
		m.form = cleanForm()
		m.state = stForm
		m.prevMenu = stMenu
	case menuItemXML:
		m.state = stXMLMenu
		m.xmlCur = 0
	case menuItemFindPrefix:
		m.form = prefixForm()
		m.state = stForm
		m.prevMenu = stMenu
	case menuItemSettings:
		m.state = stSettings
		m.setCur = 0
		m.setEdit = -1
		m.setEditErr = ""
	}
	if m.form != nil {
		m.form.focus()
	}
	return m, nil
}

func (m model) updateForm(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.Type {
	case tea.KeyEsc:
		m.form = nil
		if m.prevMenu != 0 {
			m.state = m.prevMenu
		} else {
			m.state = stMenu
		}
		return m, nil
	case tea.KeyCtrlF:
		if m.form.cur < len(m.form.fields) {
			fld := &m.form.fields[m.form.cur]
			if fld.kind == fStr && !fld.pass && fld.pick != pickNone {
				m.picker = newPicker(fld.pick, m.form.cur, fld.input.Value())
				m.state = stFilePick
				return m, nil
			}
		}
	}
	m.form.update(&m, msg)
	return m, nil
}

func (m model) updateFilePick(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if m.picker == nil || m.form == nil {
		m.picker = nil
		m.state = stForm
		return m, nil
	}
	if m.picker.update(msg) {
		if m.picker.selected != "" && m.picker.field < len(m.form.fields) {
			fld := &m.form.fields[m.picker.field]
			fld.input.SetValue(m.picker.selected)
			fld.strVal = m.picker.selected
			if dir := filepath.Dir(m.picker.selected); dir != "" {
				lastPickDir = dir
			}
		}
		m.picker = nil
		m.state = stForm
		m.form.focus()
	}
	return m, nil
}

func (m model) updateRun(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.Type {
	case tea.KeyEsc:
		if m.run.cancel != nil {
			m.run.cancel()
		}
		m.run.closeLog()
		m.run = nil
		m.state = stMenu
		return m, nil
	}

	switch strings.ToLower(msg.String()) {
	case "b":
		if m.run.cancel != nil {
			m.run.cancel()
		}
		m.run.closeLog()
		m.run = nil
		m.state = stMenu
		return m, nil
	}
	return m, nil
}

var xmlMenuOptions = []string{
	"расшифровать XML файл",
	"расшифровать blob (base64 → пароль)",
	"собрать xml с results.csv",
	"назад",
}

func (m model) updateXMLMenu(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.Type {
	case tea.KeyUp, tea.KeyShiftTab:
		m.xmlCur = (m.xmlCur - 1 + len(xmlMenuOptions)) % len(xmlMenuOptions)
	case tea.KeyDown, tea.KeyTab:
		m.xmlCur = (m.xmlCur + 1) % len(xmlMenuOptions)
	case tea.KeyEnter:
		switch m.xmlCur {
		case 0:
			m.form = xmlXMLForm()
			m.state = stForm
			m.prevMenu = stXMLMenu
			m.form.focus()
		case 1:
			m.form = xmlBlobForm()
			m.state = stForm
			m.prevMenu = stXMLMenu
			m.form.focus()
		case 2:
			m.form = txtXMLForm()
			m.state = stForm
			m.prevMenu = stXMLMenu
			m.form.focus()
		default:
			m.state = stMenu
		}
	case tea.KeyEsc:
		m.state = stMenu
	case tea.KeyRunes:
		r := msg.Runes[0]
		if r >= '1' && r <= '4' {
			m.xmlCur = int(r - '0' - 1)
			return m.updateXMLMenu(tea.KeyMsg{Type: tea.KeyEnter})
		}
	}
	return m, nil
}

func (m model) updateMsg(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.Type {
	case tea.KeyEsc:
		m.state = stMenu
	case tea.KeyRunes:
		switch strings.ToLower(string(msg.Runes)) {
		case "b":
			m.state = stMenu
		}
	}
	return m, nil
}

func (m *model) updEnter() {
	if m.updCancel != nil {
		m.updCancel()
		m.updCancel = nil
	}
	m.upd = nil
	if cfg.IsActivated {
		m.state = stMenu
	} else {
		m.state = stGreet
	}
}

func (m model) updateUpdatePrompt(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.Type {
	case tea.KeyUp, tea.KeyShiftTab:
		m.updCur = (m.updCur - 1 + 2) % 2
		return m, nil
	case tea.KeyDown, tea.KeyTab:
		m.updCur = (m.updCur + 1) % 2
		return m, nil
	case tea.KeyEnter:
		if m.updCur == 0 {
			return m.updStart()
		}
		m.updEnter()
		return m, nil
	case tea.KeyEsc:
		m.updEnter()
		return m, nil
	case tea.KeyRunes:
		switch strings.ToLower(string(msg.Runes)) {
		case "y", "н":
			return m.updStart()
		case "n", "т":
			m.updEnter()
			return m, nil
		}
	}
	return m, nil
}

func (m model) updStart() (tea.Model, tea.Cmd) {
	ctx, cancel := context.WithCancel(context.Background())
	m.updCancel = cancel
	m.state = stUpdating
	rel := m.upd
	go update.Install(ctx, rel)
	return m, nil
}

func (m model) updateUpdating(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	_, _, _, err, finished := update.St.Snap()
	switch msg.Type {
	case tea.KeyEsc:
		m.updEnter()
		return m, nil
	case tea.KeyEnter:
		if finished && err != nil {
			m.updEnter()
			return m, nil
		}
	}
	return m, nil
}

func (m *model) checkUpdDone() tea.Cmd {
	stage, _, _, _, finished := update.St.Snap()
	if !finished || stage != update.StageDone {
		return nil
	}
	m.quitting = true
	m.restarting = true
	return tea.Quit
}

func (m model) updatePromptView() string {
	body := []string{
		fmt.Sprintf(tr("доступна новая версия: v%s (у тебя v%s)"), m.upd.Version, update.CurrentVersion),
		"",
		dim(firstNoteLine(m.upd.Notes)),
		"",
	}
	for i, opt := range []string{tr("обновить"), tr("позже")} {
		if i == m.updCur {
			body = append(body, "▶  "+styleBold.Render(opt))
		} else {
			body = append(body, "   "+styleDim.Render(opt))
		}
	}
	box := noticeBox(tr("обновление"), body, noticeYellow, noticeWidth(m.w))
	return centerBox(box, m.w, m.h)
}

func (m model) updateProgressView() string {
	stage, done, total, err, _ := update.St.Snap()
	if err != nil {
		box := noticeBox(tr("обновление"),
			[]string{
				red(fmt.Sprintf(tr("не вышло обновиться: %v"), err)),
				"",
				dim(tr("enter — дальше")),
			},
			noticeRed, noticeWidth(m.w))
		return overlayWarning(box, m.w, m.h)
	}
	var body string
	switch stage {
	case update.StageApply:
		body = cyan(tr("применяю обновление..."))
	case update.StageDone:
		body = green(tr("перезапускаюсь..."))
	default:
		body = cyan(tr("качаю обновление...")) + "\n\n" + updBar(done, total)
	}
	box := noticeBox(tr("обновление"), strings.Split(body, "\n"), noticeYellow, noticeWidth(m.w))
	return centerBox(box, m.w, m.h)
}

func firstNoteLine(notes string) string {
	for _, ln := range strings.Split(notes, "\n") {
		if ln = strings.TrimSpace(ln); ln != "" {
			return cutStr(ln, 100)
		}
	}
	return ""
}

func updBar(done, total int64) string {
	const w = 24
	if total <= 0 {
		return fmt.Sprintf("%.1f MB", float64(done)/1048576)
	}
	if done > total {
		done = total
	}
	fill := int(done * w / total)
	bar := "[" + strings.Repeat("#", fill) + strings.Repeat("-", w-fill) + "]"
	return fmt.Sprintf("%s %d%% · %.1f/%.1f MB", bar, done*100/total,
		float64(done)/1048576, float64(total)/1048576)
}

type settingsRow struct {
	label string
	kind  int
}

const (
	rowSnaps = iota
	rowXML
	rowTitles
	rowEditChan
	rowEditCT0
	rowEditCT1
	rowEditCT2
	rowEditCT3
	rowOSDColor
	rowSkip
	rowDummy
	rowWipe
	rowBrute
	rowDebug
	rowGovernor
	rowGovCap
	rowDiscord
	rowLang
	rowBack
)

func govCapLabel(cap int) string {
	if cap <= 0 {
		return tr("авто")
	}
	return fmt.Sprintf("%d", cap)
}

func (m model) settingsRows() []settingsRow {
	rows := []settingsRow{
		{fmt.Sprintf(tr("снапы (%s)"), onOff(cfg.Snaps)), rowSnaps},
		{fmt.Sprintf(tr("autogen .xml (%s)"), onOff(cfg.XML)), rowXML},
		{fmt.Sprintf(tr("OSDChanger (%s)"), onOff(cfg.Titles)), rowTitles},
	}
	// сабы OSD всегда в списке: при выкл OSDChanger они серые
	// (setRowEnabled) и скипаются курсором (setStep).
	rows = append(rows,
		settingsRow{fmt.Sprintf(tr("   └ channel title: %s"), quoteVal(cfg.ChannelText)), rowEditChan},
		settingsRow{fmt.Sprintf(tr("   └ OSD слот %d: %s"), 1, quoteVal(cfg.CustomTexts[0])), rowEditCT0},
		settingsRow{fmt.Sprintf(tr("   └ OSD слот %d: %s"), 2, quoteVal(cfg.CustomTexts[1])), rowEditCT1},
		settingsRow{fmt.Sprintf(tr("   └ OSD слот %d: %s"), 3, quoteVal(cfg.CustomTexts[2])), rowEditCT2},
		settingsRow{fmt.Sprintf(tr("   └ OSD слот %d: %s"), 4, quoteVal(cfg.CustomTexts[3])), rowEditCT3},
		settingsRow{fmt.Sprintf(tr("   └ цвет OSD: %s"), "["+osdColorName(cfg.OSDColor)+"]"), rowOSDColor},
	)
	langLabel := "язык: русский"
	if cfg.Lang == "en" {
		langLabel = "language: english"
	}
	rows = append(rows,
		settingsRow{fmt.Sprintf(tr("пропускать проблемных (%s)"), onOff(cfg.SkipShitty)), rowSkip},
		settingsRow{tr("добавить нового юзера"), rowDummy},
		settingsRow{fmt.Sprintf(tr("вычистка юзеров (%s)"), onOff(cfg.WipeUsers)), rowWipe},
		settingsRow{fmt.Sprintf(tr("пары кредов: %s"), bruteCount()), rowBrute},
		settingsRow{fmt.Sprintf(tr("лог-режим (%s)"), onOff(cfg.Debug)), rowDebug},
		settingsRow{fmt.Sprintf(tr("губернатор скорости (%s)"), onOff(cfg.Governor)), rowGovernor},
		settingsRow{fmt.Sprintf(tr("потолок pps: %s"), govCapLabel(cfg.GovernorCap)), rowGovCap},
		settingsRow{fmt.Sprintf(tr("discord rpc (%s)"), onOff(cfg.DiscordRPC)), rowDiscord},
		settingsRow{langLabel, rowLang},
		settingsRow{tr("назад"), rowBack},
	)
	return rows
}

// setStep — шаг курсора с пропуском серых (неактивных) строк.
// Всегда завершается: строка-тоггл (OSDChanger) активна всегда.
func setStep(rows []settingsRow, cur, dir int) int {
	for i := 0; i < len(rows); i++ {
		cur = (cur + dir + len(rows)) % len(rows)
		if setRowEnabled(rows[cur].kind, &cfg) {
			return cur
		}
	}
	return cur
}

func (m model) updateSettings(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if m.setEdit >= 0 {
		return m.updateSettingsEdit(msg)
	}
	if m.bruteAdding {
		return m.updateBruteAdding(msg)
	}
	if m.bruteFocus {
		return m.updateBruteFocus(msg)
	}
	rows := m.settingsRows()
	if m.setCur >= len(rows) {
		m.setCur = len(rows) - 1
	}
	if m.setCur < 0 {
		m.setCur = 0
	}
	switch msg.Type {
	case tea.KeyUp:
		m.setCur = setStep(rows, m.setCur, -1)
		m.bruteFocus = false
	case tea.KeyDown:
		m.setCur = setStep(rows, m.setCur, 1)
		m.bruteFocus = false
	case tea.KeyEsc:
		m.state = stMenu
	case tea.KeyEnter, tea.KeySpace:
		if m.setCur >= len(rows) {
			m.setCur = 0
			return m, nil
		}
		// серая строка (OSD при выкл): enter/пробел ничего не делают.
		if !setRowEnabled(rows[m.setCur].kind, &cfg) {
			return m, nil
		}
		switch rows[m.setCur].kind {
		case rowSnaps:
			cfg.Snaps = !cfg.Snaps
			saveSettings()
		case rowXML:
			cfg.XML = !cfg.XML
			saveSettings()
		case rowTitles:
			cfg.Titles = !cfg.Titles
			saveSettings()
			// выключили стоя на серой строке — курсор на OSDChanger.
			if !setRowEnabled(rows[m.setCur].kind, &cfg) {
				m.setCur = setStep(rows, m.setCur, -1)
			}
		case rowEditChan, rowEditCT0, rowEditCT1, rowEditCT2, rowEditCT3, rowDummy, rowOSDColor:
			return m.openSetEdit(m.setCur)
		case rowSkip:
			cfg.SkipShitty = !cfg.SkipShitty
			saveSettings()
		case rowWipe:
			cfg.WipeUsers = !cfg.WipeUsers
			saveSettings()
		case rowBrute:
			m.bruteFocus = true
			m.bruteCur = 0
			m.bruteAdding = false
			m.setEditErr = ""
			return m, nil
		case rowGovCap:
			cfg.GovernorCap = nextGovCap(cfg.GovernorCap)
			scanner.GovernorCap = cfg.GovernorCap
			saveSettings()
		case rowDebug:
			cfg.Debug = !cfg.Debug
			saveSettings()
		case rowGovernor:
			cfg.Governor = !cfg.Governor
			scanner.GovernorOn = cfg.Governor
			saveSettings()
		case rowDiscord:
			cfg.DiscordRPC = !cfg.DiscordRPC
			saveSettings()
			if !cfg.DiscordRPC {
				discordStop()
			}
		case rowLang:
			if cfg.Lang == "en" {
				cfg.Lang = "ru"
			} else {
				cfg.Lang = "en"
			}
			i18n.SetLang(cfg.Lang)
			saveSettings()
		case rowBack:
			m.state = stMenu
		}
	}
	return m, nil
}

// govCaps — фиксированные ступени потолка pps, 0 = авто.
// Enter крутит по кругу: … → 10000 → авто → 250 → …
var govCaps = []int{250, 500, 750, 1000, 1500, 2000, 3000, 3500, 4000, 4500, 5000, 6000, 7000, 8000, 9000, 10000, 0}

func nextGovCap(cur int) int {
	for i, s := range govCaps {
		if s == cur {
			return govCaps[(i+1)%len(govCaps)]
		}
	}
	return govCaps[0]
}

func osdColorName(key string) string { return key }

// setEditLimit — лимит символов для строковой строки, 0 = не строка.
func setEditLimit(kind int) int {
	switch kind {
	case rowEditChan:
		return channelTextLimit
	case rowEditCT0, rowEditCT1, rowEditCT2, rowEditCT3:
		return customTextLimit
	case rowOSDColor:
		return 15
	case rowDummy:
		return 65
	}
	return 0
}

func setEditVal(kind int) string {
	switch kind {
	case rowEditChan:
		return cfg.ChannelText
	case rowEditCT0, rowEditCT1, rowEditCT2, rowEditCT3:
		return cfg.CustomTexts[kind-rowEditCT0]
	case rowOSDColor:
		return cfg.OSDColor
	case rowDummy:
		return cfg.DummyLogin + ":" + cfg.DummyPass
	}
	return ""
}

func (m model) openSetEdit(idx int) (tea.Model, tea.Cmd) {
	rows := m.settingsRows()
	if idx < 0 || idx >= len(rows) {
		return m, nil
	}
	kind := rows[idx].kind
	T, LW, _ := settingsWidths()
	need := setEditNeed(idx, rows)
	LW2 := LW
	if need > LW2 {
		LW2 = need
		if LW2 > T-7-20 {
			LW2 = T - 7 - 20
		}
	}
	// +1 клетка — курсор textinput всегда торчит за Width.
	w := LW2 - setRowPrefixW(kind) - len([]rune(setRowLabelText(kind))) - 5
	if w < 8 {
		w = 8
	}
	ti := textinput.New()
	ti.Prompt = ""
	ti.CharLimit = 512
	ti.Width = w
	if lim := setEditLimit(kind); lim > 0 {
		ti.CharLimit = lim
	}
	if kind == rowGovCap {
		ti.Placeholder = tr("авто")
	}
	ti.SetValue(setEditVal(kind))
	ti.Focus()
	m.setEdit = idx
	m.setEditLW = LW2
	m.setEditErr = ""
	m.setInput = ti
	m.bruteFocus = false
	m.bruteAdding = false
	return m, textinput.Blink
}

func (m model) updateSettingsEdit(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.Type {
	case tea.KeyEsc:
		m.setEdit = -1
		m.setEditErr = ""
		return m, nil
	case tea.KeyEnter:
		return m.commitSetEdit()
	}
	var cmd tea.Cmd
	m.setInput, cmd = m.setInput.Update(msg)
	return m, cmd
}

func (m model) commitSetEdit() (tea.Model, tea.Cmd) {
	rows := m.settingsRows()
	if m.setEdit < 0 || m.setEdit >= len(rows) {
		m.setEdit = -1
		return m, nil
	}
	kind := rows[m.setEdit].kind
	val := noNewlines(strings.TrimSpace(m.setInput.Value()))
	switch kind {
	case rowEditChan, rowEditCT0, rowEditCT1, rowEditCT2, rowEditCT3:
		limit := setEditLimit(kind)
		if n := len([]rune(val)); n > limit {
			m.setEditErr = fmt.Sprintf(tr("ограничение: максимум %d символов (у тебя %d)"), limit, n)
			return m, nil
		}
		if kind == rowEditChan {
			cfg.ChannelText = val
		} else {
			cfg.CustomTexts[kind-rowEditCT0] = val
		}
		saveSettings()
	case rowOSDColor:
		if _, ok := dhip.ParseOSDColor(val); !ok {
			m.setEditErr = tr("формат: R,G,B (0-255)")
			return m, nil
		}
		cfg.OSDColor = dhip.SetOSDColor(val)
		saveSettings()
	case rowDummy:
		login, pass, ok := strings.Cut(val, ":")
		if !ok || login == "" || pass == "" {
			m.setEditErr = tr("нужен формат login:passwd")
			return m, nil
		}
		if err := exploit.ValidateDummy(login, pass); err != nil {
			m.setEditErr = err.Error()
			return m, nil
		}
		cfg.DummyLogin, cfg.DummyPass = login, pass
		saveSettings()
	}
	m.setEdit = -1
	m.setEditErr = ""
	return m, nil
}

func noNewlines(s string) string {
	s = strings.ReplaceAll(s, "\r", "")
	return strings.ReplaceAll(s, "\n", " ")
}

// fitEditBox переживает ресайз посреди правки: панель ужимается,
// вьюпорт инпута пересчитывается, оффсеты обновляются через SetCursor.
func (m *model) fitEditBox() {
	if m.state != stSettings || m.setEdit < 0 {
		return
	}
	rows := m.settingsRows()
	if m.setEdit >= len(rows) {
		return
	}
	T, _, _ := settingsWidths()
	LW2 := m.setEditLW
	if max := T - 7 - 20; LW2 > max {
		LW2 = max
	}
	kind := rows[m.setEdit].kind
	w := LW2 - setRowPrefixW(kind) - len([]rune(setRowLabelText(kind))) - 5
	if w < 8 {
		w = 8
	}
	m.setEditLW = LW2
	m.setInput.Width = w
	m.setInput.SetCursor(m.setInput.Position())
}

func (m model) settingsHelp() string {
	if m.setEdit >= 0 {
		return tr("enter — сохранить · esc — отмена")
	}
	if m.bruteAdding {
		return tr("enter — добавить · esc — отмена")
	}
	if m.bruteFocus {
		return tr("↑↓ — выбор · a — добавить · d — удалить · enter/esc — назад")
	}
	return tr("↑↓ навигация  ·  enter/пробел - переключить  ·  esc — назад")
}

func bruteCount() string {
	n := len(cfg.BrutePasswords)
	if n == 0 {
		return tr("(пусто)")
	}
	return fmt.Sprintf(tr("%d шт."), n)
}

// updateBruteFocus — курсор в списке паролей (правая панель):
// ↑↓ — выбор, d — удалить, a — добавить, esc/enter — назад в строки.
func (m model) updateBruteFocus(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.Type {
	case tea.KeyUp:
		if len(cfg.BrutePasswords) > 0 {
			m.bruteCur = (m.bruteCur - 1 + len(cfg.BrutePasswords)) % len(cfg.BrutePasswords)
		}
	case tea.KeyDown:
		if len(cfg.BrutePasswords) > 0 {
			m.bruteCur = (m.bruteCur + 1) % len(cfg.BrutePasswords)
		}
	case tea.KeyEsc, tea.KeyEnter:
		m.bruteFocus = false
		return m, nil
	case tea.KeyRunes:
		if len(msg.Runes) != 1 {
			return m, nil
		}
		switch msg.Runes[0] {
		case 'a', 'A', 'ф', 'Ф':
			_, _, listRW := settingsWidths()
			ti := textinput.New()
			ti.Prompt = ""
			ti.Placeholder = "admin:password"
			ti.CharLimit = 128
			// -14 метка, -1 курсор: View всегда шире Width на клетку.
			ti.Width = listRW - len("login:passwd: ") - 1
			if ti.Width < 10 {
				ti.Width = 10
			}
			ti.Focus()
			m.setInput = ti
			m.setEditErr = ""
			m.bruteAdding = true
			return m, textinput.Blink
		case 'd', 'D', 'в', 'В':
			if len(cfg.BrutePasswords) > 0 && m.bruteCur < len(cfg.BrutePasswords) {
				cfg.BrutePasswords = append(cfg.BrutePasswords[:m.bruteCur], cfg.BrutePasswords[m.bruteCur+1:]...)
				saveSettings()
				refreshLiveCreds()
				if m.bruteCur >= len(cfg.BrutePasswords) {
					m.bruteCur = len(cfg.BrutePasswords) - 1
				}
				if m.bruteCur < 0 {
					m.bruteCur = 0
				}
			}
		}
	}
	return m, nil
}

// updateBruteAdding — строка ввода нового пароля. Все клавиши,
// включая d, идут в инпут и ничего не удаляют.
func (m model) updateBruteAdding(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.Type {
	case tea.KeyEsc:
		m.bruteAdding = false
		m.setEditErr = ""
		return m, nil
	case tea.KeyEnter:
		val := strings.TrimSpace(m.setInput.Value())
		login, pass, ok := strings.Cut(val, ":")
		if !ok || login == "" || pass == "" {
			m.setEditErr = tr("нужен формат login:passwd")
			return m, nil
		}
		cfg.BrutePasswords = append(cfg.BrutePasswords, val)
		saveSettings()
		refreshLiveCreds()
		m.bruteAdding = false
		m.setEditErr = ""
		m.bruteCur = len(cfg.BrutePasswords) - 1
		return m, nil
	}
	var cmd tea.Cmd
	m.setInput, cmd = m.setInput.Update(msg)
	return m, cmd
}

func (m model) View() string {
	if m.quitting {
		return ""
	}

	var content, help string
	switch m.state {
	case stGreet:
		content, help = m.greetView(), tr("↑↓ навигация  ·  enter / 0-9 - выбор")
	case stMenu:
		help = tr("↑↓ навигация  ·  enter / 0-9 - выбор")
		content = m.menuView()
	case stForm:
		content, help = m.form.view(), m.form.helpLine()
	case stFilePick:
		if m.picker != nil {
			content, help = m.picker.view(m.w, m.h), pickHelpLine()
		} else {
			content, help = m.form.view(), m.form.helpLine()
		}
	case stRun:
		content = m.run.view()
		help = tr("esc/b — стоп и в меню")
		if m.run.finished() {
			help = tr("esc/b — в меню")
		}
	case stXMLMenu:
		content, help = m.xmlMenuView(), tr("↑↓ навигация  ·  enter / 0-9 - выбор  ·  esc - назад")
	case stMsg:
		content = m.msgView()
	case stSettings:
		content, help = m.settingsView(), m.settingsHelp()
	case stUpdate:
		content, help = m.updatePromptView(), ""
	case stUpdating:
		content, help = m.updateProgressView(), tr("esc — отмена")
	}
	return withBottom(content, help, m.h)
}

func (m model) menuView() string {
	var sb strings.Builder
	sb.WriteString(bannerBlock())
	sb.WriteString(strings.Repeat("\n", 4))
	sb.WriteString(panelS(tr("меню")) + "\n\n")

	items := m.mainMenuItems()
	var rows []string
	for i, item := range items {
		if i == m.cursor {
			rows = append(rows, styleGreen.Render("▶")+"  "+styleBold.Render(item.num)+"  "+styleBold.Render(tr(item.label)))
		} else {
			rows = append(rows, "   "+styleDim.Render(item.num+"  "+tr(item.label)))
		}
	}
	sb.WriteString(centerBlock(rows))
	return sb.String()
}

func (m model) xmlMenuView() string {
	var sb strings.Builder
	sb.WriteString(bannerBlock())
	sb.WriteString(strings.Repeat("\n", 4))
	sb.WriteString(panelS("smartpss") + "\n\n")
	var rows []string
	for i, opt := range xmlMenuOptions {
		num := fmt.Sprintf("%d", i+1)
		if i == m.xmlCur {
			rows = append(rows, styleGreen.Render("▶")+"  "+styleBold.Render(num)+"  "+styleBold.Render(tr(opt)))
		} else {
			rows = append(rows, "   "+styleDim.Render(num)+"  "+tr(opt))
		}
	}
	sb.WriteString(centerBlock(rows))
	return sb.String()
}

func (m model) msgView() string {
	var sb strings.Builder
	sb.WriteString(bannerBlock())
	sb.WriteString(strings.Repeat("\n", 4))
	sb.WriteString(panelS(m.msgPanel) + "\n\n")
	sb.WriteString(centerBlock(m.msgLines))
	return sb.String()
}

func (m model) settingsView() string {
	rows := m.settingsRows()
	if len(rows) == 0 {
		return ""
	}
	if m.setCur < 0 || m.setCur >= len(rows) {
		m.setCur = 0
	}
	if termWidth > 0 && termWidth-4 < 72 {
		return m.settingsViewSingle(rows)
	}
	var sb strings.Builder
	sb.WriteString(bannerBlock())
	sb.WriteString(strings.Repeat("\n", 4))

	T, LW, RW := settingsWidths()
	// в режиме правки панель заморожена на ширине, посчитанной
	// при открытии (setEditLW): инпут скроллится вьюпортом,
	// рамка не прыгает и не рвётся.
	editing := m.setEdit >= 0 && m.setEdit < len(rows)
	if editing && m.setEditLW > 0 {
		LW = m.setEditLW
		if LW > T-7-20 {
			LW = T - 7 - 20
		}
		RW = T - 7 - LW
	}

	left := m.settingsLeftLines(rows, LW)
	var right []string
	rightTitle := tr("описание")
	if rows[m.setCur].kind == rowBrute || m.bruteFocus || m.bruteAdding {
		rightTitle, right = m.settingsBruteList(RW)
	} else {
		_, right = m.settingsDesc(rows[m.setCur].kind, RW)
	}

	var lines []string
	lines = append(lines,
		"┌"+borderTitle(tr("настройки"), LW+2)+
			"┬"+borderTitle(rightTitle, RW+2)+"┐")
	lines = append(lines, setCellRow("", "", LW, RW))
	n := len(left)
	if len(right) > n {
		n = len(right)
	}
	for i := 0; i < n; i++ {
		l, r := "", ""
		if i < len(left) {
			l = left[i]
		}
		if i < len(right) {
			r = right[i]
		}
		lines = append(lines, setCellRow(l, r, LW, RW))
	}
	lines = append(lines, setCellRow("", "", LW, RW))
	lines = append(lines,
		"└"+strings.Repeat("─", LW+2)+
			"┴"+strings.Repeat("─", RW+2)+"┘")

	pad := 4
	if termWidth > 0 {
		pad = (termWidth - T) / 2
		if pad < 0 {
			pad = 0
		}
	}
	for i := range lines {
		lines[i] = strings.Repeat(" ", pad) + lines[i]
	}
	sb.WriteString(strings.Repeat("\n", m.settingsPadTop(len(lines))))
	sb.WriteString(strings.Join(lines, "\n"))
	return sb.String()
}

// settingsPadTop — сколько пустых строк всунуть между баннером и
// панелью, чтобы та висела по середине терминала.
func (m model) settingsPadTop(boxH int) int {
	if m.h <= 0 {
		return 0
	}
	bannerH := strings.Count(bannerBlock(), "\n") + 1 + 4
	if avail := m.h - bannerH - 1; avail > boxH {
		return (avail - boxH) / 2
	}
	return 0
}

func clampSetW(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func settingsWidths() (T, LW, RW int) {
	T = 95
	if termWidth > 0 {
		T = termWidth - 4
		if T > 120 {
			T = 120
		}
	}
	LW = clampSetW(T*45/100, 37, 54)
	RW = T - 7 - LW
	return T, LW, RW
}

// setEditNeed — сколько клеток нужно строке правки целиком.
func setEditNeed(idx int, rows []settingsRow) int {
	kind := rows[idx].kind
	label := setRowLabelText(kind)
	lim := setEditLimit(kind)
	val := len([]rune(setEditVal(kind)))
	if lim > 0 && val > lim {
		val = lim
	}
	return setRowPrefixW(kind) + len([]rune(label)) + 2 + 2 + val
}

func setRowPrefixW(kind int) int {
	if kind == rowEditChan || (kind >= rowEditCT0 && kind <= rowEditCT3) {
		return 4
	}
	return 2
}

// setRowLabelText — метка строки без значения (для ширины и рендера).
func setRowLabelText(kind int) string {
	switch kind {
	case rowSnaps:
		return tr("снапы")
	case rowXML:
		return "autogen .xml"
	case rowTitles:
		return "OSDChanger"
	case rowEditChan:
		return tr("└ channel title")
	case rowEditCT0, rowEditCT1, rowEditCT2, rowEditCT3:
		return fmt.Sprintf(tr("└ OSD слот %d"), int(kind-rowEditCT0)+1)
	case rowOSDColor:
		return tr("└ цвет OSD")
	case rowDummy:
		return tr("добавить нового юзера")
	case rowDebug:
		return tr("лог-режим")
	case rowGovernor:
		return tr("губернатор скорости")
	case rowGovCap:
		return tr("потолок pps")
	case rowDiscord:
		return tr("discord rpc")
	case rowLang:
		return tr("язык")
	case rowBack:
		return tr("назад")
	}
	return ""
}

func (m model) settingsViewSingle(rows []settingsRow) string {
	var sb strings.Builder
	sb.WriteString(bannerBlock())
	sb.WriteString(strings.Repeat("\n", 4))
	sb.WriteString(panelS(tr("настройки")) + "\n\n")

	var lines []string
	for i, row := range rows {
		if i == m.setCur {
			lines = append(lines, styleGreen.Render("▶")+"  "+styleBold.Render(row.label))
		} else {
			lines = append(lines, "   "+row.label)
		}
	}
	sb.WriteString(strings.Repeat("\n", m.settingsPadTop(len(lines))))
	sb.WriteString(centerBlock(lines))
	return sb.String()
}

func borderTitle(title string, w int) string {
	t := " " + title + " "
	if n := w - len([]rune(t)); n >= 0 {
		left := n / 2
		return styleDim.Render(strings.Repeat("─", left)) + t +
			styleDim.Render(strings.Repeat("─", n-left))
	}
	return cutStr(t, w)
}

func setCellRow(l, r string, LW, RW int) string {
	// страховка: ячейка шире колонки режется (ANSI-safe),
	// рамка не порвётся ни при каком значении.
	if lipgloss.Width(l) > LW {
		l = ansi.Truncate(l, LW, "…")
	}
	if lipgloss.Width(r) > RW {
		r = ansi.Truncate(r, RW, "…")
	}
	return "│" + " " + padEnd(l, LW) + " " +
		"│" + " " + padEnd(r, RW) + " " + "│"
}

func setValBool(b bool) string {
	if b {
		return styleGreen.Render("[" + tr("вкл") + "]")
	}
	return styleRed.Render("[" + tr("выкл") + "]")
}

func setValBlue(s string) string { return styleBlue.Render("[" + s + "]") }

func setValWhite(s string) string { return styleWhite.Render("[" + s + "]") }

// settingsLeftLines строит левую колонку: метка слева, значение справа.
// Значение стрипается под ширину: влезает — целиком, нет —
// первые N (минимум 10) + …. Строка правки показывает инпут как есть.
func (m model) settingsLeftLines(rows []settingsRow, LW int) []string {
	var out []string
	for i, row := range rows {
		var label, val string
		center := false
		switch row.kind {
		case rowSnaps:
			label, val = tr("снапы"), setValBool(cfg.Snaps)
		case rowXML:
			label, val = "autogen .xml", setValBool(cfg.XML)
		case rowTitles:
			label, val = "OSDChanger", setValBool(cfg.Titles)
		case rowEditChan:
			label = tr("└ channel title")
			val = quoteValN(cfg.ChannelText, stripBudget(LW, 4+len([]rune(label))))
		case rowEditCT0, rowEditCT1, rowEditCT2, rowEditCT3:
			n := int(row.kind - rowEditCT0)
			label = fmt.Sprintf(tr("└ OSD слот %d"), n+1)
			val = quoteValN(cfg.CustomTexts[n], stripBudget(LW, 4+len([]rune(label))))
		case rowOSDColor:
			label, val = tr("└ цвет OSD"), setValWhite(osdColorName(cfg.OSDColor))
		case rowDummy:
			label = tr("добавить нового юзера")
		case rowSkip:
			label, val = tr("пропускать проблемные"), setValBool(cfg.SkipShitty)
		case rowWipe:
			label, val = tr("вычистка юзеров"), setValBool(cfg.WipeUsers)
		case rowBrute:
			label, val = tr("пары кредов"), bruteCount()
		case rowDebug:
			label, val = tr("лог-режим"), setValBool(cfg.Debug)
		case rowGovernor:
			label, val = tr("губернатор скорости"), setValBool(cfg.Governor)
		case rowGovCap:
			label, val = tr("потолок pps"), setValBlue(govCapLabel(cfg.GovernorCap))
		case rowDiscord:
			label, val = tr("discord rpc"), setValBool(cfg.DiscordRPC)
		case rowLang:
			label, val = tr("язык"), setValWhite(langName(cfg.Lang))
		case rowBack:
			label, center = tr("назад"), true
		}
		sub := row.kind == rowEditChan ||
			(row.kind >= rowEditCT0 && row.kind <= rowEditCT3)
		prefix := "  "
		if sub {
			prefix = "    "
		}
		if i == m.setCur {
			prefix = "▶ "
			if sub {
				prefix = "▶   "
			}
		}
		var line string
		switch {
		case center:
			line = prefix + centerPad(label, LW-lipgloss.Width(prefix))
		case i == m.setEdit:
			// строка правки: метка + живой инпут, без стрипов
			line = prefix + label + ": " + `"` + m.setInput.View() + `"`
			if m.setEditErr != "" {
				out = append(out, line)
				line = "  " + red("↑ "+m.setEditErr)
				break
			}
		case val == "":
			if i == m.setCur {
				line = prefix + styleBold.Render(label)
			} else {
				line = prefix + label
			}
		default:
			gap := LW - lipgloss.Width(prefix) - lipgloss.Width(label) - lipgloss.Width(val)
			if gap < 1 {
				gap = 1
			}
			if i == m.setCur {
				line = prefix + styleBold.Render(label) + strings.Repeat(" ", gap) + val
			} else {
				line = prefix + label + strings.Repeat(" ", gap) + val
			}
		}
		if !setRowEnabled(row.kind, &cfg) {
			line = dim(stripANSI(line))
		}
		out = append(out, line)
	}
	return out
}

// setRowEnabled — активна ли строка: сабы OSD только при вкл OSDChanger.
func setRowEnabled(kind int, cfg *Settings) bool {
	switch kind {
	case rowEditChan, rowEditCT0, rowEditCT1, rowEditCT2, rowEditCT3, rowOSDColor:
		return cfg.Titles
	}
	return true
}

// stripBudget — сколько клеток отдаём значению: влезает — всё,
// нет — минимум 10 символов + кавычки и … .
func stripBudget(LW, used int) int {
	avail := LW - used - 1
	if avail < 13 {
		avail = 13
	}
	return avail
}

// quoteValN — значение в кавычках: влезает целиком — целиком,
// нет — первые avail-3 символа + … (но не меньше 10 символов).
func quoteValN(s string, avail int) string {
	r := []rune(s)
	if s == "" {
		return tr("(пусто)")
	}
	if len(r)+2 <= avail {
		return fmt.Sprintf("%q", s)
	}
	n := avail - 3
	if n < 10 {
		n = 10
	}
	if n > len(r) {
		n = len(r)
	}
	return fmt.Sprintf("%q…", string(r[:n]))
}

func centerPad(s string, w int) string {
	if w <= 0 {
		return s
	}
	if pad := w - lipgloss.Width(s); pad > 0 {
		return strings.Repeat(" ", pad/2) + s
	}
	return s
}

func langName(l string) string {
	if l == "en" {
		return "english"
	}
	return "русский"
}

// settingsDesc возвращает правую колонку: заголовок и сырые строки.
// Числа — правда из кода: слот 22, channel 32.
func (m model) settingsDesc(kind int, RW int) (string, []string) {
	var title string
	var raw []string
	kv := func(name, desc string) string { return "  " + name + " — " + desc }
	switch kind {
	case rowSnaps:
		title = tr("снапы")
		raw = append(raw, tr("Снапы со взломанных камер складываются в папку прогона."), "",
			tr("Значения:"),
			kv(tr("вкл"), tr("снапы сохраняются")),
			kv(tr("выкл"), tr("только креды, без картинок")), "",
			fmt.Sprintf(tr("По умолчанию: %s"), tr("вкл")))
	case rowXML:
		title = "autogen .xml"
		raw = append(raw, tr("Генерирует .xml для импорта камер в SmartPSS."), "",
			tr("Значения:"),
			kv(tr("вкл"), tr("файлы создаются")),
			kv(tr("выкл"), tr("ничего не генерируем")), "",
			fmt.Sprintf(tr("По умолчанию: %s"), tr("выкл")))
	case rowTitles:
		title = "OSDChanger"
		raw = append(raw, tr("Меняет название канала + текст до 4х слотов в OSD "), "",
			tr("Значения:"),
			kv(tr("вкл"), tr("подмена активна")),
			kv(tr("выкл"), tr("используются оригиналы")), "",
			tr("Макс. длина слота: 22 символа"), "",
			fmt.Sprintf(tr("По умолчанию: %s"), tr("выкл")))
	case rowEditChan:
		title = "channel title"
		raw = append(raw,
			tr("Название канала. Видят все, у кого открыт поток."),
			tr("Макс. длина: 32 символа. Пусто — поле не используется."))
	case rowEditCT0, rowEditCT1, rowEditCT2, rowEditCT3:
		n := int(kind - rowEditCT0)
		title = fmt.Sprintf(tr("OSD слот %d"), n+1)
		raw = append(raw,
			tr("Строка поверх картинки."),
			tr("Макс. длина: 22 символа. Пусто — поле не используется."))
	case rowOSDColor:
		title = tr("цвет OSD")
		raw = append(raw,
			tr("Цвет текста на OSD."),
			tr("Формат: R,G,B (0-255)"), "",
			fmt.Sprintf(tr("По умолчанию: %s"), "255,255,255"))
	case rowDummy:
		title = tr("добавить нового юзера")
		raw = append(raw,
			tr("Юзер, которого крушитель добавит на взломанные камеры."),
			tr("Формат: login:passwd."))
	case rowSkip:
		title = tr("пропускать проблемные")
		raw = append(raw, tr("Если включено - пропускает все камеры со своими болячками (например - проблемы с туннелем)"), "",
			tr("Значения:"),
			kv(tr("вкл"), tr("проблемные скипаются")),
			kv(tr("выкл"), tr("долбим все до конца")), "",
			fmt.Sprintf(tr("По умолчанию: %s"), tr("вкл")))
	case rowWipe:
		title = tr("вычистка юзеров")
		raw = append(raw, tr("Удаляет лишних юзеров на взломанных камерах"), "",
			tr("Значения:"),
			kv(tr("вкл"), tr("удаление всех юзеров")),
			kv(tr("выкл"), tr("не тронуто")), "",
			fmt.Sprintf(tr("По умолчанию: %s"), tr("выкл")))
	case rowBrute:
		title = tr("пары кредов")
		raw = append(raw,
			tr("Пары кредов для брута"),
			tr("Формат: login:passwd, по одной на строку."), "",
			fmt.Sprintf(tr("По умолчанию: %s"), tr("(пусто)")))
	case rowDebug:
		title = tr("лог-режим")
		raw = append(raw, tr("Подробные логи: туннели, запросы, ошибки."), "",
			tr("Значения:"),
			kv(tr("вкл"), tr("логировать всё")),
			kv(tr("выкл"), tr("только важное")), "",
			fmt.Sprintf(tr("По умолчанию: %s"), tr("выкл")))
	case rowGovernor:
		title = tr("губернатор скорости")
		raw = append(raw, tr("Режет скорость скана, чтобы не упираться в лимиты."), "",
			tr("Значения:"),
			kv(tr("вкл"), tr("скан идёт ровно")),
			kv(tr("выкл"), tr("на полную мощность")), "",
			fmt.Sprintf(tr("По умолчанию: %s"), tr("вкл")))
	case rowGovCap:
		title = tr("потолок pps")
		raw = append(raw,
			tr("Потолок скорости в пакетах в секунду"),
			tr("Enter — следующее: 250 … 10000, авто."), "",
			fmt.Sprintf(tr("По умолчанию: %s"), tr("авто")))
	case rowDiscord:
		title = tr("discord rpc")
		raw = append(raw, tr("Показывает всем в дискорде что ты скид"), "",
			tr("Значения:"),
			kv(tr("вкл"), tr("статус виден")),
			kv(tr("выкл"), tr("статус скрыт")), "",
			fmt.Sprintf(tr("По умолчанию: %s"), tr("выкл")))
	case rowLang:
		title = tr("язык")
		raw = append(raw, tr("Язык интерфейса."), "",
			tr("Значения:"),
			kv("русский", tr("по-русски")),
			kv("english", tr("in english")), "",
			fmt.Sprintf(tr("По умолчанию: %s"), "русский"))
	case rowBack:
		title = tr("назад")
		raw = append(raw, tr("вернуться в главное меню"))
	}
	var out []string
	out = append(out, wrapCells([]string{title}, RW)...)
	out = append(out, styleDim.Render(strings.Repeat("─", RW)), "")
	for _, ln := range wrapCells(raw, RW) {
		out = append(out, ln)
	}
	return title, out
}

// settingsBruteList — правая панель "список паролей": превью,
// а в фокусе — со своим курсором и строкой ввода.
func (m model) settingsBruteList(RW int) (string, []string) {
	title := tr("список паролей")
	var raw []string
	if len(cfg.BrutePasswords) == 0 && !m.bruteAdding {
		raw = append(raw, tr("(пусто)"))
	}
	for i, p := range cfg.BrutePasswords {
		mark := " "
		if m.bruteFocus && i == m.bruteCur && !m.bruteAdding {
			mark = "▶"
		}
		raw = append(raw, fmt.Sprintf("%s %d) %s", mark, i+1, p))
	}
	var out []string
	for _, ln := range wrapCells(raw, RW) {
		out = append(out, ln)
	}
	// строка ввода и ошибка — мимо враппера: там ANSI курсора,
	// резать по рунам её нельзя. ширина инпута уже ужата под панель.
	if m.bruteAdding {
		out = append(out, "", "login:passwd: "+m.setInput.View())
		if m.setEditErr != "" {
			out = append(out, "", red(cutStr("↑ "+m.setEditErr, RW)))
		}
	}
	return title, out
}

func wrapCells(lines []string, w int) []string {
	if w < 10 {
		w = 10
	}
	var out []string
	for _, p := range lines {
		r := []rune(p)
		if len(r) == 0 {
			out = append(out, "")
			continue
		}
		for len(r) > w {
			cut := w
			for i := w; i > w-15 && i > 0; i-- {
				if r[i] == ' ' {
					cut = i
					break
				}
			}
			out = append(out, string(r[:cut]))
			r = r[cut:]
			if len(r) > 0 && r[0] == ' ' {
				r = r[1:]
			}
		}
		out = append(out, string(r))
	}
	return out
}

func quoteVal(s string) string {
	if s == "" {
		return tr("(пусто)")
	}
	return fmt.Sprintf("%q", cutStr(s, 24))
}

func cutStr(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n]) + "…"
	}
	return s
}

func showMsg(m *model, panel string, lines ...string) {
	m.msgPanel = panel
	m.msgLines = lines
	m.state = stMsg
}

func ensureDir(path string) string {
	if err := os.MkdirAll(path, 0755); err != nil {
		return err.Error()
	}
	return ""
}
