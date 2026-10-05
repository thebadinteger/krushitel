package scanner

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
	govSlowStartPct = 3
	govCaPct        = 15
	govBackoffPct   = 15
	govRTTRing      = 512
)

var (
	govPPS       int64 = govStartPPS
	govSlowStart int64 = 1
	govHealthy   int64

	govOK  int64
	govTO  int64
	govErr int64

	govRTT     [govRTTRing]int64
	govRTTIdx  int64
	govRTTBase int64
)

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

func govRecordOK(rtt time.Duration) {
	atomic.AddInt64(&govOK, 1)
	if rtt > 0 {
		i := atomic.AddInt64(&govRTTIdx, 1) % govRTTRing
		atomic.StoreInt64(&govRTT[i], rtt.Microseconds())
	}
}

func govRecordTO() { atomic.AddInt64(&govTO, 1) }

func govRecordErr() { atomic.AddInt64(&govErr, 1) }

func govMedianRTT() int64 {
	vals := make([]int64, 0, govRTTRing)
	for i := 0; i < govRTTRing; i++ {
		if v := atomic.LoadInt64(&govRTT[i]); v > 0 {
			vals = append(vals, v*1000)
		}
	}
	if len(vals) == 0 {
		return 0
	}
	sort.Slice(vals, func(a, b int) bool { return vals[a] < vals[b] })
	return vals[len(vals)/2]
}

func (rl *rateLimiter) setRPS(rps int) {
	if rl == nil || rps <= 0 {
		return
	}
	rl.mu.Lock()
	rl.interval = time.Second / time.Duration(rps)
	rl.burst = time.Duration(BURST_LIMIT) * rl.interval
	rl.mu.Unlock()
}

func govErrBackoff(er, total int64) bool {
	return er >= 3 && er*100 >= total*5
}

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
				continue
			}
			lossPct := float64(to+er) * 100 / float64(total)

			pps := atomic.LoadInt64(&govPPS)
			newPPS := pps
			hard := false

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
