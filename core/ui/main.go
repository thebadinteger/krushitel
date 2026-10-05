package ui

import (
	"context"
	"fmt"
	"os"
	"runtime/debug"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
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
	stTitleEdit
	stDummyEdit
	stGreet
	stUpdate
	stUpdating
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
	msgLines   []string
	msgPanel   string
	quitting   bool
	restarting bool

	titleInput textinput.Model
	titleErr   string
	titleField int

	dummyInput textinput.Model
	dummyErr   string

	upd       *update.Release
	updCancel context.CancelFunc
	updCur    int
}

var teaProg *tea.Program

func Run() bool {
	realStdout := os.Stdout
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
	ti := textinput.New()
	ti.Placeholder = "pwned by krushitel"
	ti.CharLimit = 64
	ti.Width = 50
	di := textinput.New()
	di.Placeholder = "login:passwd"
	di.CharLimit = 65
	di.Width = 50
	m := model{state: stMenu, titleInput: ti, dummyInput: di}
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
		case stRun:
			return m.updateRun(msg)
		case stXMLMenu:
			return m.updateXMLMenu(msg)
		case stMsg:
			return m.updateMsg(msg)
		case stSettings:
			return m.updateSettings(msg)
		case stTitleEdit:
			return m.updateTitleEdit(msg)
		case stDummyEdit:
			return m.updateDummyEdit(msg)
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
		if r == 'q' || r == 'Q' {
			m.quitting = true
			return m, tea.Quit
		}
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
		{kind: menuItemXML, num: "3", label: "расшифровать .xml от smartpss"},
		{kind: menuItemFindPrefix, num: "4", label: "искать префиксы с списка IP"},
		{kind: menuItemSettings, num: "5", label: "настройки"},
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
		if r == 'q' || r == 'Q' {
			m.quitting = true
			return m, tea.Quit
		}
		if r >= '1' && r <= '5' {
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
	case tea.KeyRunes:
		if m.form.curIsBool() && strings.ToLower(string(msg.Runes)) == "q" {
			m.quitting = true
			return m, tea.Quit
		}
	}
	m.form.update(&m, msg)
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
	case "q":
		m.run.closeLog()
		discordStop()
		m.quitting = true
		return m, tea.Quit
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
		if r == 'q' || r == 'Q' {
			m.quitting = true
			return m, tea.Quit
		}
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
		case "q":
			m.quitting = true
			return m, tea.Quit
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
		case "q", "й":
			m.quitting = true
			return m, tea.Quit
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
	case tea.KeyRunes:
		if r := strings.ToLower(string(msg.Runes)); r == "q" || r == "й" {
			m.quitting = true
			return m, tea.Quit
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
	rowDummy
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

func nextGovCap(cur int) int {
	steps := []int{0, 250, 500, 1000, 2000, 3000, 5000, 10000}
	for i, s := range steps {
		if s == cur {
			return steps[(i+1)%len(steps)]
		}
	}
	return 0
}

func (m model) settingsRows() []settingsRow {
	rows := []settingsRow{
		{fmt.Sprintf(tr("снапы (%s)"), onOff(cfg.Snaps)), rowSnaps},
		{fmt.Sprintf(tr("autogen .xml (%s)"), onOff(cfg.XML)), rowXML},
		{fmt.Sprintf(tr("настройки OSDChanger (%s)"), onOff(cfg.Titles)), rowTitles},
	}
	if cfg.Titles {
		rows = append(rows,
			settingsRow{fmt.Sprintf(tr("   └ channel title: %s"), quoteVal(cfg.ChannelText)), rowEditChan},
			settingsRow{fmt.Sprintf(tr("   └ OSD слот %d: %s"), 1, quoteVal(cfg.CustomTexts[0])), rowEditCT0},
			settingsRow{fmt.Sprintf(tr("   └ OSD слот %d: %s"), 2, quoteVal(cfg.CustomTexts[1])), rowEditCT1},
			settingsRow{fmt.Sprintf(tr("   └ OSD слот %d: %s"), 3, quoteVal(cfg.CustomTexts[2])), rowEditCT2},
			settingsRow{fmt.Sprintf(tr("   └ OSD слот %d: %s"), 4, quoteVal(cfg.CustomTexts[3])), rowEditCT3},
		)
	}
	langLabel := "язык: русский"
	if cfg.Lang == "en" {
		langLabel = "language: english"
	}
	rows = append(rows,
		settingsRow{tr("добавить нового юзера"), rowDummy},
		settingsRow{fmt.Sprintf(tr("лог-режим (%s)"), onOff(cfg.Debug)), rowDebug},
		settingsRow{fmt.Sprintf(tr("губернатор скорости (%s)"), onOff(cfg.Governor)), rowGovernor},
		settingsRow{fmt.Sprintf(tr("потолок pps: %s"), govCapLabel(cfg.GovernorCap)), rowGovCap},
		settingsRow{fmt.Sprintf(tr("discord rpc (%s)"), onOff(cfg.DiscordRPC)), rowDiscord},
		settingsRow{langLabel, rowLang},
		settingsRow{tr("назад"), rowBack},
	)
	return rows
}

func (m model) updateSettings(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	rows := m.settingsRows()
	switch msg.Type {
	case tea.KeyUp:
		m.setCur = (m.setCur - 1 + len(rows)) % len(rows)
	case tea.KeyDown:
		m.setCur = (m.setCur + 1) % len(rows)
	case tea.KeyEsc:
		m.state = stMenu
	case tea.KeyRunes:
		if strings.ToLower(string(msg.Runes)) == "q" {
			m.quitting = true
			return m, tea.Quit
		}
	case tea.KeyEnter, tea.KeySpace:
		if m.setCur >= len(rows) {
			m.setCur = 0
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
		case rowEditChan:
			m.openTitleEdit(0)
			return m, textinput.Blink
		case rowEditCT0:
			m.openTitleEdit(1)
			return m, textinput.Blink
		case rowEditCT1:
			m.openTitleEdit(2)
			return m, textinput.Blink
		case rowEditCT2:
			m.openTitleEdit(3)
			return m, textinput.Blink
		case rowEditCT3:
			m.openTitleEdit(4)
			return m, textinput.Blink
		case rowDummy:
			m.openDummyEdit()
			return m, textinput.Blink
		case rowDebug:
			cfg.Debug = !cfg.Debug
			saveSettings()
		case rowGovernor:
			cfg.Governor = !cfg.Governor
			scanner.GovernorOn = cfg.Governor
			saveSettings()
		case rowGovCap:
			cfg.GovernorCap = nextGovCap(cfg.GovernorCap)
			scanner.GovernorCap = cfg.GovernorCap
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

func (m model) View() string {
	if m.quitting {
		return ""
	}

	var content, help string
	switch m.state {
	case stGreet:
		content, help = m.greetView(), tr("↑↓ навигация  ·  enter / 0-9 - выбор  ·  q - выход")
	case stMenu:
		help = tr("↑↓ навигация  ·  enter / 0-9 - выбор  ·  q - выход")
		content = m.menuView()
	case stForm:
		content, help = m.form.view(), m.form.helpLine()
	case stRun:
		content = m.run.view()
		help = tr("esc/b — стоп и в меню  ·  q — выход")
		if m.run.finished() {
			help = tr("esc/b — в меню  ·  q — выход")
		}
	case stXMLMenu:
		content, help = m.xmlMenuView(), tr("↑↓ навигация  ·  enter / 0-9 - выбор  ·  esc - назад  ·  q - выход")
	case stMsg:
		content = m.msgView()
	case stSettings:
		content, help = m.settingsView(), tr("↑↓ навигация  ·  enter/пробел - переключить  ·  esc — назад  ·  q - выход")
	case stTitleEdit:
		content, help = m.titleEditView(), tr("enter - сохранить  ·  esc - назад  ·  ctrl+c - выход")
	case stDummyEdit:
		content, help = m.dummyEditView(), tr("enter - сохранить  ·  esc - назад  ·  ctrl+c - выход")
	case stUpdate:
		content, help = m.updatePromptView(), ""
	case stUpdating:
		content, help = m.updateProgressView(), tr("esc — отмена · q — выход")
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
	var sb strings.Builder
	sb.WriteString(bannerBlock())
	sb.WriteString(strings.Repeat("\n", 4))
	sb.WriteString(panelS(tr("настройки")) + "\n\n")

	rows := m.settingsRows()
	var lines []string
	for i, row := range rows {
		if i == m.setCur {
			lines = append(lines, styleGreen.Render("▶")+"  "+styleBold.Render(row.label))
		} else {
			lines = append(lines, "   "+row.label)
		}
	}
	sb.WriteString(centerBlock(lines))
	return sb.String()
}

func (m *model) openTitleEdit(field int) {
	m.titleField = field
	if field == 0 {
		m.titleInput.SetValue(cfg.ChannelText)
		m.titleInput.CharLimit = 32
	} else {
		m.titleInput.SetValue(cfg.CustomTexts[field-1])
		m.titleInput.CharLimit = 22
	}
	m.titleErr = ""
	m.titleInput.Focus()
	m.state = stTitleEdit
}

func (m model) updateTitleEdit(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.Type {
	case tea.KeyEsc:
		m.titleErr = ""
		m.state = stSettings
		return m, nil
	case tea.KeyEnter:
		val := strings.TrimSpace(m.titleInput.Value())
		val = strings.ReplaceAll(val, "\r", "")
		val = strings.ReplaceAll(val, "\n", " ")
		limit := 32
		if m.titleField > 0 {
			limit = 22
		}
		if n := len([]rune(val)); n > limit {
			m.titleErr = fmt.Sprintf(tr("ограничение: максимум %d символов (у тебя %d)"), limit, n)
			return m, nil
		}
		if m.titleField == 0 {
			cfg.ChannelText = val
		} else {
			cfg.CustomTexts[m.titleField-1] = val
		}
		saveSettings()
		m.titleErr = ""
		m.state = stSettings
		return m, nil
	}
	var cmd tea.Cmd
	m.titleInput, cmd = m.titleInput.Update(msg)
	return m, cmd
}

func (m model) titleEditView() string {
	label := tr("channel title")
	limit := 32
	if m.titleField > 0 {
		label = fmt.Sprintf(tr("текст OSD-слота %d "), m.titleField)
		limit = 22
	}
	var sb strings.Builder
	sb.WriteString(bannerBlock())
	sb.WriteString(strings.Repeat("\n", 4))
	sb.WriteString(panelS(tr("титры")) + "\n\n")
	sb.WriteString(centerLine(cyan(tr("впиши сюда что-то, что будут видеть все:"))) + "\n")
	sb.WriteString(centerLine(cyan(label)+": "+m.titleInput.View()) + "\n")
	sb.WriteString("\n" + centerLine(dim(fmt.Sprintf(tr("! до %d символов ! пусто — поле не используется !"), limit))) + "\n")
	if m.titleErr != "" {
		sb.WriteString("\n" + centerLine(red("↑ "+m.titleErr)) + "\n")
	}
	return sb.String()
}

func (m *model) openDummyEdit() {
	m.dummyInput.SetValue(cfg.DummyLogin + ":" + cfg.DummyPass)
	m.dummyErr = ""
	m.dummyInput.Focus()
	m.state = stDummyEdit
}

func (m model) updateDummyEdit(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.Type {
	case tea.KeyEsc:
		m.dummyErr = ""
		m.state = stSettings
		return m, nil
	case tea.KeyEnter:
		val := strings.TrimSpace(m.dummyInput.Value())
		val = strings.ReplaceAll(val, "\r", "")
		val = strings.ReplaceAll(val, "\n", "")
		login, pass, ok := strings.Cut(val, ":")
		if !ok || login == "" || pass == "" {
			m.dummyErr = tr("нужен формат login:passwd")
			return m, nil
		}
		if err := exploit.ValidateDummy(login, pass); err != nil {
			m.dummyErr = err.Error()
			return m, nil
		}
		cfg.DummyLogin, cfg.DummyPass = login, pass
		saveSettings()
		m.dummyErr = ""
		m.state = stSettings
		return m, nil
	}
	var cmd tea.Cmd
	m.dummyInput, cmd = m.dummyInput.Update(msg)
	return m, cmd
}

func (m model) dummyEditView() string {
	var sb strings.Builder
	sb.WriteString(bannerBlock())
	sb.WriteString(strings.Repeat("\n", 4))
	sb.WriteString(panelS(tr("креды юзера")) + "\n\n")
	sb.WriteString(centerLine(cyan(tr("новый юзер в формате login:passwd:"))) + "\n")
	sb.WriteString(centerLine(m.dummyInput.View()) + "\n")
	sb.WriteString("\n" + centerLine(dim(tr("по дефолту/by default: krushitel:TancuiPantera1337"))) + "\n")
	if m.dummyErr != "" {
		sb.WriteString("\n" + centerLine(red("↑ "+m.dummyErr)) + "\n")
	}
	return sb.String()
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
