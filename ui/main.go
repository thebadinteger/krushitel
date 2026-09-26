package ui

// krushitel-test — реплика старого консольного крушителя на bubbletea:
// ОДИН tea.Program со state machine (menu → form → run → msg → settings),
// вместо отдельной tea.Program на каждый промпт, как в старом ui.go.

import (
	"context"
	"fmt"
	"os"
	"runtime/debug"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"krushitel/exploit"
	"krushitel/i18n"
	"krushitel/update"
)

// tr — обёртка локализации: ru = ключ как есть, en = перевод из словаря.
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
	stDummyEdit // редактор dummy-кредов (login:passwd)
	stGreet     // приветствие: выбор языка при первом запуске
	stUpdate    // вопрос про обнову (есть релиз новее)
	stUpdating  // скачивание + применение обновы
)

type tickMsg time.Time

// TEMP-TEST краш-скрина: убрать после проверки.
type crashTestMsg struct{}

type model struct {
	w, h           int
	state          sessionState
	prevMenu       sessionState // откуда открыли форму (для возврата по esc)
	cursor         int          // меню
	xmlCur         int          // подменю режима 4
	prefixExpanded bool         // раскрыт ли пункт 3 (бургер-подменю)
	setCur         int          // настройки
	greetCur       int          // приветствие: выбор языка

	form     *formState
	run      *runState
	msgLines   []string
	msgPanel   string
	quitting   bool
	restarting bool

	titleInput textinput.Model
	titleErr   string
	titleField int // редактируемое поле: 0 = ChannelTitle, 1-4 = слоты CustomTitle

	dummyInput textinput.Model
	dummyErr   string

	upd       *update.Release // свежий релиз, если Check нашёл
	updCancel context.CancelFunc
	updCur    int // курсор промпта обновы: 0 = обновить, 1 = позже
}

// teaProg — ссылка на активную программу (нужна для SuspendExec в elevate.go).
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
	// Автоапдейт: хвосты прошлой подмены долой, проверка свежего
	// релиза с коротким таймаутом. Без сети/ошибки — молча как обычно.
	update.Sweep()
	ctx, cancel := context.WithTimeout(context.Background(), update.CheckTimeout)
	upd, _ := update.Check(ctx)
	cancel()
	// WithoutCatchPanics: паники TUI-потока идут к нам, а не глотаются
	// bubbletea ("program was killed") — иначе наш сплеш никогда не покажется.
	p := tea.NewProgram(initialModel(upd), tea.WithAltScreen(), tea.WithOutput(realStdout), tea.WithoutCatchPanics())
	teaProg = p
	defer discordStop() // rpc always-on: гасим presence при любом выходе
	// Паника TUI-потока: чиним терминал, дампим стек, рисуем сплеш.
	// Зарегистрирован ПОСЛЕ дефера ресторa stdout — срабатывает первым.
	defer func() {
		if r := recover(); r != nil {
			stack := debug.Stack()
			crashDump(stack, r)
			_ = p.ReleaseTerminal() // best effort: raw-режим, курсор, буфер
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
	di.CharLimit = 65 // логин 32 + ':' + пароль 32
	di.Width = 50
	m := model{state: stMenu, titleInput: ti, dummyInput: di}
	if upd != nil {
		// Есть релиз новее — сначала вопрос про обнову, меню потом.
		i18n.SetLang(cfg.Lang)
		m.upd = upd
		m.state = stUpdate
		return m
	}
	if cfg.IsActivated {
		// уже активированы — сразу в меню на сохранённом языке
		i18n.SetLang(cfg.Lang)
	} else {
		// первый запуск — приветствие с выбором языка
		m.state = stGreet
	}
	return m
}

func (m model) Init() tea.Cmd {
	// TEMP-TEST краш-скрина: TUI грузится как обычно, паника прилетает
	// сообщением через 5 сек в горутину event-loop — ловит наш recover
	// в Run (как настоящая паника TUI-потока). Убрать после проверки.
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
			m.run.h = m.h // высота терминала — для размеров сессий/логов
			m.run.drain()
		}
		if m.state == stUpdating {
			if cmd := m.checkUpdDone(); cmd != nil {
				return m, cmd
			}
		}
		discordTick(m.run) // rpc always-on: хоть в меню, хоть в прогоне
		return m, tickCmd()

	case crashTestMsg: // TEMP-TEST краш-скрина: убрать после проверки.
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

// ── приветствие (первый запуск) ──────────────────────────────────────

// greetOptions — языки приветствия: каждый пункт подписан сам на себе,
// перевод не нужен.
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

// selectGreet — язык выбран: персистенс в config.json (lang + isActivated),
// дальше — главное меню.
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
	sb.WriteString(strings.Repeat("\n", 4)) // шапка ниже баннера
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

// ── меню ─────────────────────────────────────────────────────────────

type mainMenuItemKind int

const (
	menuItemExploit mainMenuItemKind = iota
	menuItemTitles
	menuItemPrefixParent
	menuItemPrefixSingle
	menuItemPrefixFile
	menuItemXML
	menuItemFindPrefix
	menuItemSettings
)

type mainMenuItem struct {
	kind  mainMenuItemKind
	num   string
	label string
	isSub bool
}

func (m model) mainMenuItems() []mainMenuItem {
	items := []mainMenuItem{
		{kind: menuItemExploit, num: "1", label: "крушим)"},
		{kind: menuItemTitles, num: "2", label: "OSDChanger"},
		{kind: menuItemPrefixParent, num: "3", label: "сканим префиксы (без генерации)"},
	}
	if m.prefixExpanded {
		items = append(items,
			mainMenuItem{kind: menuItemPrefixSingle, label: tr("скан одного префикса"), isSub: true},
			mainMenuItem{kind: menuItemPrefixFile, label: tr("скан файла с префиксами"), isSub: true},
		)
	}
	items = append(items,
		mainMenuItem{kind: menuItemXML, num: "4", label: "расшифровываем .xml от smartpss"},
		mainMenuItem{kind: menuItemFindPrefix, num: "5", label: "ищем префиксы"},
		mainMenuItem{kind: menuItemSettings, num: "6", label: "настройки"},
	)
	return items
}

func (m model) updateMenu(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	items := m.mainMenuItems()

	if m.prefixExpanded {
		// Подменю активно: навигация и выбор ТОЛЬКО внутри бургер-меню (2..4),
		// все остальные пункты серые и недоступны.
		switch msg.Type {
		case tea.KeyUp, tea.KeyShiftTab:
			m.cursor--
			if m.cursor < 2 {
				m.cursor = 4
			}
		case tea.KeyDown, tea.KeyTab:
			m.cursor++
			if m.cursor > 4 {
				m.cursor = 2
			}
		case tea.KeyRight:
			if m.cursor == 2 {
				m.cursor = 3
			}
		case tea.KeyLeft:
			if m.cursor > 2 {
				m.cursor = 2
			} else {
				m.prefixExpanded = false
			}
		case tea.KeyEsc:
			m.prefixExpanded = false
			m.cursor = 2
			return m, nil
		case tea.KeyEnter:
			if m.cursor == 2 {
				m.prefixExpanded = false
				return m, nil
			}
			if m.cursor < len(items) {
				return m.selectMenuItem(items[m.cursor].kind)
			}
		case tea.KeyRunes:
			r := msg.Runes[0]
			if r == 'q' || r == 'Q' {
				m.quitting = true
				return m, tea.Quit
			}
			switch r {
			case '1':
				m.cursor = 3
				return m.selectMenuItem(menuItemPrefixSingle)
			case '2':
				m.cursor = 4
				return m.selectMenuItem(menuItemPrefixFile)
			case '3':
				m.prefixExpanded = false
				m.cursor = 2
				return m, nil
			}
		}
		return m, nil
	}

	// Обычный режим (подменю закрыто)
	switch msg.Type {
	case tea.KeyUp, tea.KeyShiftTab:
		m.cursor = (m.cursor - 1 + len(items)) % len(items)
	case tea.KeyDown, tea.KeyTab:
		m.cursor = (m.cursor + 1) % len(items)
	case tea.KeyRight:
		if m.cursor < len(items) && items[m.cursor].kind == menuItemPrefixParent {
			m.prefixExpanded = true
			m.cursor = 3
		}
	case tea.KeyEnter:
		if m.cursor < len(items) {
			if items[m.cursor].kind == menuItemPrefixParent {
				m.prefixExpanded = true
				m.cursor = 3
				return m, nil
			}
			return m.selectMenuItem(items[m.cursor].kind)
		}
	case tea.KeyRunes:
		r := msg.Runes[0]
		if r == 'q' || r == 'Q' {
			m.quitting = true
			return m, tea.Quit
		}
		if r >= '1' && r <= '6' {
			num := string(r)
			if num == "3" {
				m.prefixExpanded = true
				m.cursor = 3
				return m, nil
			}
			for i, item := range items {
				if item.num == num {
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
	case menuItemPrefixParent:
		m.prefixExpanded = !m.prefixExpanded
		if !m.prefixExpanded && m.cursor > 2 {
			m.cursor = 2
		}
		return m, nil
	case menuItemPrefixSingle:
		m.form = prefixSingleScanForm()
		m.state = stForm
		m.prevMenu = stMenu
	case menuItemPrefixFile:
		m.form = prefixFileScanForm()
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
		// q — выход только там, где не набирается текст (поля да/нет).
		if m.form.curIsBool() && strings.ToLower(string(msg.Runes)) == "q" {
			m.quitting = true
			return m, tea.Quit
		}
	}
	m.form.update(&m, msg)
	return m, nil
}

// ── экран прогона ────────────────────────────────────────────────────

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

// ── подменю режима 4 ─────────────────────────────────────────────────

var xmlMenuOptions = []string{
	"расшифровать XML (SmartPSS export → креды)",
	"расшифровать blob (base64 → пароль)",
	"собрать xml (креды txt → SmartPSS импорт)",
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

// ── экран результата (режим 4) ───────────────────────────────────────

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

// ── автообновление ─────────────────────────────────────────────────

// updEnter — дальше как обычно: первый запуск → приветствие, иначе меню.
// Заодно отменяет недокачанную установку.
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

// updateUpdatePrompt — вопрос про обнову: стрелки + enter, дубли y/n.
// y (и н) — качаем, n/esc — пропускаем, q — выход.
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

// updStart — погнали качать: стейт прогресса + воркер установки в фоне.
func (m model) updStart() (tea.Model, tea.Cmd) {
	ctx, cancel := context.WithCancel(context.Background())
	m.updCancel = cancel
	m.state = stUpdating
	rel := m.upd
	go update.Install(ctx, rel)
	return m, nil
}

// updateUpdating — экран прогресса. Esc — отмена и дальше, enter при
// ошибке — дальше, q — выход. Успех тик сам уводит в рестарт.
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

// checkUpdDone — установка докачалась и встала: штатно выходим из TUI,
// выставляя restarting. Сам перезапуск произойдет в main() после того,
// как bubbletea полностью очистит и вернет терминал в cooked-режим.
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
	// Уведомление: жёлтый бокс по центру, фона нет вообще.
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
		// Предупреждение: фон чуть темнее, бокс подсвечен красным.
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

// firstNoteLine — первая непустая строка релиз-ноутов, ужатая до 100 рун.
func firstNoteLine(notes string) string {
	for _, ln := range strings.Split(notes, "\n") {
		if ln = strings.TrimSpace(ln); ln != "" {
			return cutStr(ln, 100)
		}
	}
	return ""
}

// updBar — [####----] 42% · 3.1/7.4 MB; без total — только мегабайты.
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

// ── настройки ────────────────────────────────────────────────────────

// settingsRow — строка меню настроек.
type settingsRow struct {
	label string
	kind  int
}

// типы строк настроек
const (
	rowSnaps = iota
	rowXML
	rowTitles
	rowPreflight // пре-флайт перед боем: глухая камера → SKIP без полного сценария
	rowEditChan  // ChannelTitle (имя канала), огр 32 симв.
	rowEditCT0   // OSD слот 1 (CustomTitle[0]), огр 22 симв.
	rowEditCT1   // OSD слот 2
	rowEditCT2   // OSD слот 3
	rowEditCT3   // OSD слот 4
	rowDummy     // dummy-креды: ввод login:passwd одной строкой
	rowDebug     // лог-режим: дампы протокола облака в ленту логов
	rowDiscord    // discord rpc: вкл/выкл
	rowLang        // язык: «язык: русский» / «language: english»
	rowBack
)

// settingsRows — динамическое меню: подпункты титров видны,
// только когда автозамена включена.
func (m model) settingsRows() []settingsRow {
	rows := []settingsRow{
		{fmt.Sprintf(tr("снапы (%s)"), onOff(cfg.Snaps)), rowSnaps},
		{fmt.Sprintf(tr("autogen .xml (%s)"), onOff(cfg.XML)), rowXML},
		{fmt.Sprintf(tr("настройки OSDChanger (%s)"), onOff(cfg.Titles)), rowTitles},
		{fmt.Sprintf(tr("пре-флайт (%s)"), onOff(cfg.Preflight)), rowPreflight},
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
	// язык: пункт подписан на текущем языке («язык: русский» /
	// «language: english»); сами флаги lang/isActivated живут в config.json
	langLabel := "язык: русский"
	if cfg.Lang == "en" {
		langLabel = "language: english"
	}
	rows = append(rows,
		settingsRow{tr("добавить нового юзера"), rowDummy},
		settingsRow{fmt.Sprintf(tr("лог-режим (%s)"), onOff(cfg.Debug)), rowDebug},
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
		case rowPreflight:
			cfg.Preflight = !cfg.Preflight
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

// ── выход ────────────────────────────────────────────────────────────

func (m model) View() string {
	if m.quitting {
		return ""
	}

	var content, help string
	switch m.state {
	case stGreet:
		content, help = m.greetView(), tr("↑↓ навигация  ·  enter / 0-9 — выбор  ·  q — выход")
	case stMenu:
		help = tr("↑↓ навигация  ·  enter / 0-9 — выбор  ·  q — выход")
		if m.prefixExpanded {
			help = tr("↑↓ навигация  ·  enter / 1-2 — выбор  ·  esc — закрыть  ·  q — выход")
		}
		content = m.menuView()
	case stForm:
		content, help = m.form.view(), m.form.helpLine()
	case stRun:
		content = m.run.view()
		// плашка навигации — всегда (после финиша — своя)
		help = tr("esc/b — стоп и в меню  ·  q — выход")
		if m.run.finished() {
			help = tr("esc/b — в меню  ·  q — выход")
		}
	case stXMLMenu:
		content, help = m.xmlMenuView(), tr("↑↓ навигация  ·  enter / 0-9 — выбор  ·  esc — назад  ·  q — выход")
	case stMsg:
		content = m.msgView()
	case stSettings:
		content, help = m.settingsView(), tr("↑↓ навигация  ·  enter/пробел — переключить  ·  esc — назад  ·  q — выход")
	case stTitleEdit:
		content, help = m.titleEditView(), tr("enter — сохранить  ·  esc — назад  ·  ctrl+c — выход")
	case stDummyEdit:
		content, help = m.dummyEditView(), tr("enter — сохранить  ·  esc — назад  ·  ctrl+c — выход")
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
	// шапка — на 4 пустые строки ниже баннера (просили опустить)
	sb.WriteString(strings.Repeat("\n", 4))
	// пункты меню — одна пустая строка после шапки
	sb.WriteString(panelS(tr("что сегодня делаем?")) + "\n\n")

	items := m.mainMenuItems()
	var rows []string
	for i, item := range items {
		if item.isSub {
			if i == m.cursor {
				rows = append(rows, "       "+styleGreen.Render("▶")+"  "+styleBold.Render("└ ")+styleBold.Render(item.label))
			} else {
				rows = append(rows, "          "+styleDim.Render("└ ")+item.label)
			}
		} else if m.prefixExpanded {
			if item.kind == menuItemPrefixParent {
				if i == m.cursor {
					rows = append(rows, styleGreen.Render("▶")+"  "+styleBold.Render(item.num)+"  "+styleBold.Render(tr(item.label)))
				} else {
					rows = append(rows, "   "+styleBold.Render(item.num)+"  "+styleBold.Render(tr(item.label)))
				}
			} else {
				// Все остальные пункты становятся серыми, пока открыто бургер-подменю
				rows = append(rows, "   "+styleDim.Render(item.num+"  "+tr(item.label)))
			}
		} else {
			if i == m.cursor {
				rows = append(rows, styleGreen.Render("▶")+"  "+styleBold.Render(item.num)+"  "+styleBold.Render(tr(item.label)))
			} else {
				rows = append(rows, "   "+styleDim.Render(item.num)+"  "+tr(item.label))
			}
		}
	}
	sb.WriteString(centerBlock(rows))
	return sb.String()
}

func (m model) xmlMenuView() string {
	var sb strings.Builder
	sb.WriteString(bannerBlock())
	sb.WriteString(strings.Repeat("\n", 4)) // шапка ниже баннера
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
	sb.WriteString(strings.Repeat("\n", 4)) // шапка ниже баннера
	sb.WriteString(panelS(m.msgPanel) + "\n\n")
	sb.WriteString(centerBlock(m.msgLines))
	return sb.String()
}

func (m model) settingsView() string {
	var sb strings.Builder
	sb.WriteString(bannerBlock())
	sb.WriteString(strings.Repeat("\n", 4)) // шапка ниже баннера
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

// openTitleEdit — открывает редактор поля титров: 0 = ChannelTitle
// (огр 32), 1-4 = слоты CustomTitle (огр 22). Префилл из конфига.
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

// updateTitleEdit — экран ввода одного поля титров. Пусто = поле не
// используется (на камере слот очистится). Выход — esc/ctrl+c.
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
		// Огры камеры: ChannelTitle длиннее 32 символов отклоняется,
		// слоты CustomTitle режем на 22.
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

// ── редактор dummy-кредов ────────────────────────────────────────────

// openDummyEdit — редактор dummy-кредов: одна строка login:passwd,
// валидация через exploit.ValidateDummy (правила Dahua userManager:
// логин 5-32, пароль 8-32, только латиница и цифры — заодно отсекает
// пробелы и кириллицу). Префилл — текущие креды из конфига.
func (m *model) openDummyEdit() {
	m.dummyInput.SetValue(cfg.DummyLogin + ":" + cfg.DummyPass)
	m.dummyErr = ""
	m.dummyInput.Focus()
	m.state = stDummyEdit
}

// updateDummyEdit — ввод login:passwd. Формат проверяем сами (нужен
// ровно один разделитель), остальное — движковый ValidateDummy.
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
	sb.WriteString(panelS(tr("dummy-креды")) + "\n\n")
	sb.WriteString(centerLine(cyan(tr("новый юзер в формате login:passwd:"))) + "\n")
	sb.WriteString(centerLine(m.dummyInput.View()) + "\n")
	sb.WriteString("\n" + centerLine(dim(tr("по дефолту/by default: krushitel:TancuiPantera1337"))) + "\n")
	if m.dummyErr != "" {
		sb.WriteString("\n" + centerLine(red("↑ "+m.dummyErr)) + "\n")
	}
	return sb.String()
}

// quoteVal — значение поля для строки меню: (пусто) или "текст".
// quoteVal — значение поля для строки меню: (пусто) или "текст".
func quoteVal(s string) string {
	if s == "" {
		return tr("(пусто)")
	}
	return fmt.Sprintf("%q", cutStr(s, 24))
}

// cutStr — обрезка для превью в меню.
func cutStr(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n]) + "…"
	}
	return s
}

// runMsg — показ результата вместо прогона (мелкие флоу).
func showMsg(m *model, panel string, lines ...string) {
	m.msgPanel = panel
	m.msgLines = lines
	m.state = stMsg
}

// ensureDir — MkdirAll с сообщением об ошибке.
func ensureDir(path string) string {
	if err := os.MkdirAll(path, 0755); err != nil {
		return err.Error()
	}
	return ""
}
