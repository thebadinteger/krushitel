package scanner

// governor — AIMD-регулятор скорости UDP-проб (дизайн: TCP-стайл
// congestion control для облака Дахуа).
//
// Фазы (тик 2.5с, дельты Success/Timeouts/Errors):
//   - Slow Start: потери < 3% — PPS ×1.5, пока не нащупан потолок;
//   - Congestion Avoidance: потери 3..15% — линейный +5% за тик;
//   - Backoff: потери > 15% ИЛИ локальные ошибки сокетов — PPS ÷2;
//   - Bufferbloat (опережающий сигнал): медианный RTT вырос в 2.5× от
//     базового — режем ×0.7 ДО того как пошли таймауты.
//
// Старт с безопасного минимума (150 PPS) — вывезет 3G и дохлый роутер.

import (
	"context"
	"fmt"
	"sort"
	"sync/atomic"
	"time"
)

const (
	govTick         = 2500 * time.Millisecond
	govStartPPS     = 150
	govFloorPPS     = 50
	govSlowStartPct = 3  // потери < 3% — slow start
	govCaPct        = 15 // потери 3..15% — линейный рост
	govBackoffPct   = 15 // потери > 15% — backoff ÷2
	govRTTRing      = 512
)

var (
	govPPS       int64 = govStartPPS
	govSlowStart int64 = 1
	govHealthy   int64 // тиков подряд без беды — ре-арм slow start

	govOK  int64
	govTO  int64
	govErr int64

	govRTT     [govRTTRing]int64 // микросекунды
	govRTTIdx  int64
	govRTTBase int64 // наносекунды, EMA медианы на здоровой фазе
)

// resetGov — чистое состояние губернатора на прогон. Состояние глобальное
// и жило между прогонами: новый Run стартовал с PPS прошлого круга (рывок
// без разгона — лимитер создаётся на 150, а первый тик подменял его
// устаревшим значением) и навсегда выключенным slow start.
func resetGov() {
	atomic.StoreInt64(&govPPS, govStartPPS)
	atomic.StoreInt64(&govSlowStart, 1)
	atomic.StoreInt64(&govHealthy, 0)
	atomic.StoreInt64(&govOK, 0)
	atomic.StoreInt64(&govTO, 0)
	atomic.StoreInt64(&govErr, 0)
	atomic.StoreInt64(&govRTTIdx, 0)
	atomic.StoreInt64(&govRTTBase, 0)
	for i := range govRTT {
		atomic.StoreInt64(&govRTT[i], 0)
	}
}

// govRecordOK — ответ от облака получен (любой, даже «offline»: важен
// факт живого пути). rtt — от отправки пробы до ответа.
func govRecordOK(rtt time.Duration) {
	atomic.AddInt64(&govOK, 1)
	if rtt > 0 {
		i := atomic.AddInt64(&govRTTIdx, 1) % govRTTRing
		atomic.StoreInt64(&govRTT[i], rtt.Microseconds())
	}
}

// govRecordTO — проба протухла (облако не ответило в дедлайн).
func govRecordTO() { atomic.AddInt64(&govTO, 1) }

// govRecordErr — ЛОКАЛЬНАЯ сетевая ошибка (no route to host,
// WSAEWOULDBLOCK и пр.) — прямой сигнал переполнения буферов.
func govRecordErr() { atomic.AddInt64(&govErr, 1) }

// govMedianRTT — медиана последнего кольца RTT (нс; 0 — данных нет).
func govMedianRTT() int64 {
	vals := make([]int64, 0, govRTTRing)
	for i := 0; i < govRTTRing; i++ {
		if v := atomic.LoadInt64(&govRTT[i]); v > 0 {
			vals = append(vals, v*1000) // мкс → нс
		}
	}
	if len(vals) == 0 {
		return 0
	}
	sort.Slice(vals, func(a, b int) bool { return vals[a] < vals[b] })
	return vals[len(vals)/2]
}

// setRPS — динамическая подмена потолка лимитера на лету.
func (rl *rateLimiter) setRPS(rps int) {
	if rl == nil || rps <= 0 {
		return
	}
	rl.mu.Lock()
	rl.interval = time.Second / time.Duration(rps)
	rl.burst = time.Duration(BURST_LIMIT) * rl.interval
	rl.mu.Unlock()
}

// govErrBackoff — локальные ошибки считаются перегрузом, только если их
// неединично и много: одна transient-ошибка записи из тысяч отправок за
// тик — не повод резать скорость вдвое. Порог: ≥3 ошибок И ≥5% тика.
func govErrBackoff(er, total int64) bool {
	return er >= 3 && er*100 >= total*5
}

// governorLoop — тик 2.5с: дельты → фаза AIMD → подмена лимита.
func governorLoop(ctx context.Context, rl *rateLimiter) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(govTick):
			ok := atomic.SwapInt64(&govOK, 0)
			to := atomic.SwapInt64(&govTO, 0)
			er := atomic.SwapInt64(&govErr, 0)
			total := ok + to + er
			if total == 0 {
				continue // тишина за тик — не дёргаемся
			}
			lossPct := float64(to+er) * 100 / float64(total)

			pps := atomic.LoadInt64(&govPPS)
			newPPS := pps
			hard := false // тик с бедой — обнуляет счётчик здоровья

			// RTT-сигнал: медиана против базы (bufferbloat раньше потерь)
			bloat := false
			if med := govMedianRTT(); med > 0 {
				base := atomic.LoadInt64(&govRTTBase)
				if base > 0 && med > base*5/2 {
					bloat = true
				}
				if lossPct < float64(govSlowStartPct) {
					if base == 0 {
						atomic.StoreInt64(&govRTTBase, med)
					} else {
						atomic.StoreInt64(&govRTTBase, base*9/10+med/10)
					}
				}
			}

			switch {
			case govErrBackoff(er, total) || lossPct > float64(govBackoffPct):
				newPPS = pps / 2
				atomic.StoreInt64(&govSlowStart, 0)
				hard = true
			case bloat:
				newPPS = pps * 7 / 10
				atomic.StoreInt64(&govSlowStart, 0)
				hard = true
			case lossPct < float64(govSlowStartPct) && atomic.LoadInt64(&govSlowStart) == 1:
				newPPS = pps * 3 / 2
			case lossPct < float64(govCaPct):
				newPPS = pps + pps/20
			}
			// ре-арм slow start: 8 тиков (~20с) без беды при низкой потере —
			// иначе после первого инцидента рост навсегда линейный +5%
			if !hard && lossPct < float64(govSlowStartPct) {
				if atomic.AddInt64(&govHealthy, 1) >= 8 {
					atomic.StoreInt64(&govSlowStart, 1)
				}
			} else {
				atomic.StoreInt64(&govHealthy, 0)
			}
			if newPPS < govFloorPPS {
				newPPS = govFloorPPS
			}
			if newPPS > MAX_RPS {
				newPPS = MAX_RPS
			}
			if newPPS != pps {
				atomic.StoreInt64(&govPPS, newPPS)
				rl.setRPS(int(newPPS))
			}
			if LogHook != nil {
				LogHook(fmt.Sprintf("[gov] pps=%d loss=%.1f%% ok=%d to=%d err=%d rtt=%dms bloat=%v",
					newPPS, lossPct, ok, to, er, govMedianRTT()/1e6, bloat))
			}
		}
	}
}
