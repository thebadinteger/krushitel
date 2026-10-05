package scanner

import (
	"context"
	"fmt"
	"sync/atomic"

	"krushitel/core/i18n"
)

const SuffixCombos = 1 << 20

const hexChars = "0123456789ABCDEF"

func resumeSkipMargin(workers int) int64 {
	return int64(workers)*10 + 4096
}

func ResumeSkip(emitted, checked int64, workers int) int64 {
	skip := checked - resumeSkipMargin(workers)
	if skip < 0 {
		skip = 0
	}
	if emitted > 0 && skip > emitted {
		skip = emitted
	}
	return skip
}

func streamSerialsMem(prefixes []string, skip int64, emit func(string) bool) int64 {
	var fed, out int64
	var buf [15]byte
	for _, p := range prefixes {
		copy(buf[:10], p)
		for i := 0; i < SuffixCombos; i++ {
			if fed < skip {
				fed++
				continue
			}
			buf[10] = hexChars[(i>>16)&0xF]
			buf[11] = hexChars[(i>>12)&0xF]
			buf[12] = hexChars[(i>>8)&0xF]
			buf[13] = hexChars[(i>>4)&0xF]
			buf[14] = hexChars[i&0xF]
			out++
			if !emit(string(buf[:])) {
				return out
			}
			fed++
		}
	}
	return out
}

func RunPrefixesMem(ctx context.Context, prefixes []string, skip int64, workers int, stats *ScanStats, events chan<- string, onAlive func(string)) string {
	if len(prefixes) == 0 {
		return i18n.Tr("список префиксов пуст")
	}
	total := int64(len(prefixes)) * SuffixCombos
	atomic.StoreInt64(&stats.Total, total)
	atomic.StoreInt64(&stats.PrefixTotal, int64(len(prefixes)))
	if skip > 0 {
		atomic.StoreInt64(&stats.Checked, skip)
		emitEvent(events, "[SYS] "+fmt.Sprintf(i18n.Tr("resume: пропускаю %d уже отскормленных серийников"), skip))
	}

	feed := func(jobs chan string) {
		defer close(jobs)
		emit := func(s string) bool {
			select {
			case <-ctx.Done():
				return false
			case jobs <- s:
			}
			fed := atomic.AddInt64(&stats.Fed, 1)
			if fed&4095 == 0 {
				stats.LastSerial.Store(s)
			}
			atomic.StoreInt64(&stats.PrefixDone, (skip+fed)/SuffixCombos)
			return true
		}
		streamSerialsMem(prefixes, skip, emit)
	}
	return runPipe(ctx, stats, events, onAlive, workers, feed, nil)
}
