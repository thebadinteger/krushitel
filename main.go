package main

import (
	"fmt"
	"net/http"
	"os"
	"runtime/debug"
	"time"

	_ "net/http/pprof"

	"krushitel/core/scanner"
	"krushitel/core/ui"
	"krushitel/core/update"
)

func main() {
	// Профайлер для охоты за жиром (RSS/CPU): выключен по дефолту.
	// KRUSH_PPROF=127.0.0.1:6060 ./krushitel — дальше go tool pprof.
	if addr := os.Getenv("KRUSH_PPROF"); addr != "" {
		go func() {
			_ = http.ListenAndServe(addr, nil)
		}()
	}
	lf, lerr := os.OpenFile("crash.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if lerr == nil {
		defer lf.Close()
		redirectToCrashLog(lf)
	}

	// Паники из горутин воркеров main-recover не ловит: recover работает
	// только на той горутине, где стоит defer. Поэтому сплэш «krushitel
	// crashed» показывался лишь для крашей UI, а любой panic в scanWorker
	// печатал голый трейс Go и просто уносил процесс. Здесь поднимаем
	// общий обработчик, чтобы сплэш был для всех паник.
	scanner.FatalHook = func(reason string, stack []byte) {
		fatalCrash(lf, reason, stack)
	}
	defer func() {
		if r := recover(); r != nil {
			fatalCrash(lf, scanner.PanicReason(r), debug.Stack())
		}
	}()
	if runHeadless() {
		return
	}
	if ui.Run() {
		if lf != nil {
			_ = lf.Close()
		}
		if err := update.Restart(os.Stdout, lf); err != nil {
			fmt.Fprintf(os.Stderr, "ошибка перезапуска: %v\n", err)
			os.Exit(1)
		}
	}
}

// fatalCrash — единая точка смерти: пишем в crash.log, показываем сплэш,
// выходим. Зовется и из main-recover, и из scanner.FatalHook.
func fatalCrash(lf *os.File, reason string, stack []byte) {
	if lf != nil {
		fmt.Fprintf(lf, "=== PANIC %s ===\n%s\n%s\n",
			time.Now().Format("02.01.2006 15:04:05"), reason, string(stack))
		_ = lf.Sync()
	}
	// Логика и сплэш живут в ui.Fatal: там гасится TUI и пишется в
	// настоящий терминал, а не в devNull, куда Run() уводит os.Stdout.
	ui.Fatal(reason, stack)
}
