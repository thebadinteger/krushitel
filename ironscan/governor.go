package ironscan

// governor — AIMD-регулятор для прямого TCP-скана. Сигналы отличаются от
// облачного сканера: refused (RST) — это ЖИВОЙ путь, не потеря. Задушить
// могут: локальные ошибки сокета, резкий обвал доли ответивших и
// RTT-bufferbloat на успешных коннектах.

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// LogHook — лог-приёмник губернатора (nil = тихо).
var LogHook func(string, ...any)

const (
	ironTick     = 2500 * time.Millisecond
	ironStartPPS = 100
	ironFloorPPS = 50
	ironCeilPPS  = 5000
	ironSlowPct  = 3 // доля таймаутов < 3% — slow start
)

var (
	ironPPS       int64 = ironStartPPS
	ironSlowStart int64 = 1

	ironOK      int64 // коннект + ответ девайса
	ironRefused int64 // RST — путь жив (порт закрыт)
	ironTO      int64 // тихий таймаут (firewall или congestion)
	ironErr     int64 // ЛОКАЛЬНЫЕ ошибки сокета — прямой сигнал перегрузки

	ironRTT     [512]int64 // µs, только успешные коннекты
	ironRTTIdx  int64
	ironRTTBase int64 // нс, EMA медианы на здоровой фазе

	ironLastRate int64 // success-rate прошлого тика (×1000)
)

type ironOutcome int

const (
	ironResOK ironOutcome = iota
	ironResRefused
	ironResTimeout
	ironResLocalErr
)

func ironRecord(k ironOutcome, rtt time.Duration) {
	switch k {
	case ironResOK:
		atomic.AddInt64(&ironOK, 1)
		if rtt > 0 {
			i := atomic.AddInt64(&ironRTTIdx, 1) % 512
			atomic.StoreInt64(&ironRTT[i], rtt.Microseconds())
		}
	case ironResRefused:
		atomic.AddInt64(&ironRefused, 1)
	case ironResTimeout:
		atomic.AddInt64(&ironTO, 1)
	case ironResLocalErr:
		atomic.AddInt64(&ironErr, 1)
	}
}

func ironMedianRTT() int64 {
	vals := make([]int64, 0, 512)
	for i := 0; i < 512; i++ {
		if v := atomic.LoadInt64(&ironRTT[i]); v > 0 {
			vals = append(vals, v*1000)
		}
	}
	if len(vals) == 0 {
		return 0
	}
	sort.Slice(vals, func(a, b int) bool { return vals[a] < vals[b] })
	return vals[len(vals)/2]
}

// ironLim — активный лимитер (ставится Run'ом).
var ironLim atomic.Pointer[ironLimiter]

func ironLimiterSet(l *ironLimiter) { ironLim.Store(l) }

func ironWait(ctx context.Context) error {
	if l := ironLim.Load(); l != nil {
		return l.wait(ctx)
	}
	return nil
}

// ironLimiter — виртуальный leaky bucket с динамическим потолком.
type ironLimiter struct {
	mu       sync.Mutex
	interval time.Duration
	next     time.Time
}

func newIronLimiter(pps int) *ironLimiter {
	return &ironLimiter{interval: time.Second / time.Duration(pps), next: time.Now()}
}

func (l *ironLimiter) setPPS(pps int) {
	if l == nil || pps <= 0 {
		return
	}
	l.mu.Lock()
	l.interval = time.Second / time.Duration(pps)
	l.mu.Unlock()
}

func (l *ironLimiter) wait(ctx context.Context) error {
	l.mu.Lock()
	now := time.Now()
	earliest := now.Add(-time.Second)
	if l.next.Before(earliest) {
		l.next = earliest
	}
	if l.next.Before(now) {
		l.next = now
	}
	reserve := l.next
	l.next = l.next.Add(l.interval)
	l.mu.Unlock()

	t := time.NewTimer(time.Until(reserve))
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// governorLoop — тик 2.5с: AIMD по TCP-специфичным сигналам.
func governorLoop(ctx context.Context, l *ironLimiter, logf func(string, ...any)) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(ironTick):
			ok := atomic.SwapInt64(&ironOK, 0)
			ref := atomic.SwapInt64(&ironRefused, 0)
			to := atomic.SwapInt64(&ironTO, 0)
			er := atomic.SwapInt64(&ironErr, 0)
			total := ok + ref + to + er
			if total == 0 {
				continue
			}
			pps := atomic.LoadInt64(&ironPPS)
			newPPS := pps

			// 1. Локальные ошибки сокета — самая громкая перегрузка
			if er > 0 {
				newPPS = pps / 2
				atomic.StoreInt64(&ironSlowStart, 0)
			} else {
				// 2. Доля «ответивших» (ok+refused): резкий обвал = congestion
				rate := (ok + ref) * 1000 / total
				last := atomic.LoadInt64(&ironLastRate)
				atomic.StoreInt64(&ironLastRate, rate)
				if last > 100 && rate*100 < last*60 {
					newPPS = pps * 85 / 100
					atomic.StoreInt64(&ironSlowStart, 0)
				} else {
					// 3. Bufferbloat: медиана успешных коннектов против базы
					bloat := false
					if med := ironMedianRTT(); med > 0 {
						base := atomic.LoadInt64(&ironRTTBase)
						if base > 0 && med > base*5/2 {
							bloat = true
						}
						timeoutPct := to * 100 / total
						if timeoutPct < ironSlowPct {
							if base == 0 {
								atomic.StoreInt64(&ironRTTBase, med)
							} else {
								atomic.StoreInt64(&ironRTTBase, base*9/10+med/10)
							}
						}
					}
					if bloat {
						newPPS = pps * 7 / 10
						atomic.StoreInt64(&ironSlowStart, 0)
					} else if timeoutPctSafe(to, total) < ironSlowPct && atomic.LoadInt64(&ironSlowStart) == 1 {
						newPPS = pps * 3 / 2
					} else {
						newPPS = pps + pps/33 // линейный +3%
					}
				}
			}

			if newPPS < ironFloorPPS {
				newPPS = ironFloorPPS
			}
			if newPPS > ironCeilPPS {
				newPPS = ironCeilPPS
			}
			if newPPS != pps {
				atomic.StoreInt64(&ironPPS, newPPS)
				l.setPPS(int(newPPS))
			}
			if logf != nil {
				logf(fmt.Sprintf("[iron-gov] pps=%d ok=%d refused=%d to=%d err=%d rtt=%dms",
					newPPS, ok, ref, to, er, ironMedianRTT()/1e6))
			}
		}
	}
}

func timeoutPctSafe(to, total int64) int64 {
	if total == 0 {
		return 0
	}
	return to * 100 / total
}
