package main

import (
	"fmt"
	"os"
	"runtime/debug"
	"strings"
	"time"

	"krushitel/core/ui"
	"krushitel/core/update"
)

func main() {
	lf, lerr := os.OpenFile("crash.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if lerr == nil {
		defer lf.Close()
		redirectToCrashLog(lf)
	}
	defer func() {
		if r := recover(); r != nil {
			stack := debug.Stack()
			msg := fmt.Sprintf("=== PANIC %s ===\n%v\n%s\n", time.Now().Format("02.01.2006 15:04:05"), r, string(stack))
			if lf != nil {
				_, _ = lf.WriteString(msg)
			}
			reason := strings.TrimSpace(strings.SplitN(fmt.Sprintf("%v", r), "\n", 2)[0])
			if reason == "" {
				reason = "unknown (see crash.log)"
			}
			fmt.Fprint(os.Stdout, ui.CrashSplash(reason, string(stack)))
			ui.WaitForKey(os.Stdout)
			os.Exit(1)
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
