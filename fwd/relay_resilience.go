package fwd

// relay_resilience.go — устойчивость relay-пути на деградированных
// серверах easy4ip (live 2026-09-13: 177 alloc'ов → 52 ответа, 52
// start'а → 0 ответов, 176/178 lookup'ов живы). Три слоя защиты:
//
//  1. Глобальный семафор на /relay/agent — чтобы параллельные туннели не
//     душили друг друга на диспетчере.
//  2. Ротация диспетчеров с per-host backoff: хосты, не ответившие на
//     /online/relay, штрафуются; кэшированные альтернативы подбираются
//     при отказе текущего.
//  3. Зомби-вотчдог: bind'ы на релее получают (relay-фабрикованные) ack'и,
//     heartbeat'ы ходят, но DATA от камеры не идёт — девайс молчит.
//     Если есть исходящий up-трафик без байт в ответ дольше
//     zombieRelayTimeout — признаём туннель зомби; ошибка триггерит
//     runWithRetries со sticky forceAppRelay (пропуск 0x17/0x19
//     на data-сокете, лечит девайсы 2024+).

import (
	"errors"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// isTransportDead reports whether a ReadPTCP error means the underlying
// socket is gone (as opposed to "the datagram wasn't a PTCP frame").
// Parse errors from ParsePTCP and short reads are payload problems — the
// readLoop treats them as ignorable noise. Everything else (closed conn,
// ICMP-induced reset, out-of-fd) is terminal.
func isTransportDead(err error) bool {
	if err == nil {
		return false
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return false
	}
	// ParsePTCP / ParsePTCPPayload / tou framing errors are content errors.
	msg := err.Error()
	for _, marker := range []string{
		"packet too short",
		"invalid magic",
		"invalid padding",
		"invalid length",
		"invalid tou message",
	} {
		if strings.Contains(msg, marker) {
			return false
		}
	}
	return true
}

var errZombieRelay = errors.New("relay zombie: bind acks pass but no DATA comes back")

// RelayAllocLimit —   /relay/agent   .
var RelayAllocLimit = 6

// Лимиты relay-агентов. Vars — чтобы тесты могли сжимать.
var (
	relayAgentAllocRetries = 3
	relayAgentAllocDelay   = 1500 * time.Millisecond
	relayAgentAllocTimeout = 4 * time.Second
	relayDispatchBase      = 3 * time.Second
	relayDispatchMax       = 15 * time.Second
	relayStartRetries      = 3
	relayStartRetransDelay = 1200 * time.Millisecond
	zombieRelayTimeout     = 12 * time.Second
	zombieScanEvery        = 3 * time.Second
)

var (
	relaySemOnce  sync.Once
	relayAllocSem chan struct{}
)

func relayAllocSlot() chan struct{} {
	relaySemOnce.Do(func() { relayAllocSem = make(chan struct{}, RelayAllocLimit) })
	return relayAllocSem
}

// Кэш диспетчеров: ротация адресов, полученных из /online/relay, + штрафы.
type relayDispatchState struct {
	mu       sync.Mutex
	known    []string
	failures map[string]int
	until    map[string]time.Time
}

var relayDispatch = &relayDispatchState{
	failures: map[string]int{},
	until:    map[string]time.Time{},
}

func (s *relayDispatchState) remember(hostport string) {
	if hostport == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, h := range s.known {
		if h == hostport {
			return
		}
	}
	s.known = append(s.known, hostport)
	if len(s.known) > 8 {
		s.known = s.known[1:]
	}
}

func (s *relayDispatchState) penalize(hostport string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := s.failures[hostport] + 1
	s.failures[hostport] = n
	d := relayDispatchBase << (n - 1)
	if d > relayDispatchMax || d <= 0 {
		d = relayDispatchMax
	}
	s.until[hostport] = time.Now().Add(d)
}

func (s *relayDispatchState) forgive(hostport string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.failures, hostport)
	delete(s.until, hostport)
}

func (s *relayDispatchState) backoffLeft(hostport string) time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	if d, ok := s.until[hostport]; ok {
		return time.Until(d)
	}
	return 0
}

// nextTo возвращает альтернативный диспетчер: первый из известных, не
// находящийся под штрафом. "" — альтернатив нет.
func (s *relayDispatchState) nextTo(current string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, h := range s.known {
		if h == current {
			continue
		}
		if d, ok := s.until[h]; ok && time.Now().Before(d) {
			continue
		}
		return h
	}
	return ""
}

// allocRelayAgent — выделение (smartpss) агента релея: семафор
// одновременности, per-host backoff, перебор кэшированных диспетчеров.
// При ok=false все диспетчеры промолчали — фатально для попытки,
// runWithRetries пересоберёт туннель.
func (t *Tunnel) allocRelayAgent(mainRemote *UDP, dispatcher string) (host string, port int, token string, ok bool) {
	relayAllocSlot()
	select {
	case relayAllocSem <- struct{}{}:
		defer func() { <-relayAllocSem }()
	case <-t.done:
		return "", 0, "", false
	}

	candidates := []string{dispatcher}
	if alt := relayDispatch.nextTo(dispatcher); alt != "" {
		candidates = append(candidates, alt)
	}

	for i, hp := range candidates {
		parts := strings.SplitN(hp, ":", 2)
		if len(parts) != 2 || parts[0] == "" {
			continue
		}
		cport, cportOK := strconv.Atoi(parts[1])
		if cportOK != nil {
			continue
		}
		if left := relayDispatch.backoffLeft(hp); left > 0 {
			if i < len(candidates)-1 {
				continue //   —   
			}
			//   —   backoff ( )
			if left > 2*time.Second {
				left = 2 * time.Second
			}
			select {
			case <-time.After(left):
			case <-t.done:
				return "", 0, "", false
			}
		}

		mainRemote.SetRemote(parts[0], cport)
		var res *DHResponse
		var err error
		for attempt := 0; attempt < relayAgentAllocRetries; attempt++ {
			if t.isStopped() {
				return "", 0, "", false
			}
			mainRemote.RequestEx("/relay/agent", "", true, false, reqOpts{})
			res, err = mainRemote.Read(true, relayAgentAllocDelay)
			if err == nil && res != nil && res.Body["body/Token"] != "" {
				break
			}
			if attempt+1 < relayAgentAllocRetries {
				t.logf("relay agent alloc retransmit %d/%d to %s (%v)", attempt+1, relayAgentAllocRetries, hp, err)
			}
		}
		if err != nil || res == nil || res.Body["body/Token"] == "" {
			t.logf("relay agent alloc silent on %s (%v) — host backoff, next dispatcher", hp, err)
			relayDispatch.penalize(hp)
			continue
		}
		relayDispatch.forgive(hp)
		agent := strings.SplitN(res.Body["body/Agent"], ":", 2)
		if len(agent) != 2 || agent[0] == "" {
			relayDispatch.penalize(hp)
			continue
		}
		port, _ = strconv.Atoi(agent[1])
		return agent[0], port, res.Body["body/Token"], true
	}
	return "", 0, "", false
}

// startRelayAgent — /relay/start с ретрансмитами: шлёт до relayStartRetries
// раз. Первый send регистрирует клиента на агенте (агент начинает
// слушать PTCP-фреймы от нас).
func (t *Tunnel) startRelayAgent(mainRemote *UDP, agentHost string, agentPort int, agentToken string) {
	mainRemote.SetRemote(agentHost, agentPort)
	for i := 0; i < relayStartRetries; i++ {
		mainRemote.RequestEx("/relay/start/"+agentToken, "<body><Client>:0</Client></body>", true, false, reqOpts{})
		if _, err := mainRemote.Read(true, relayStartRetransDelay); err == nil {
			return
		}
	}
}

// zombieWatchdog следит за дата-пасом: если есть up-трафик, но ни одного байта
// DATA не пришло за zombieRelayTimeout — дата-пас мёртв (зомби-релей). Ошибка
// триггерит рестарт попытки (runWithRetries) со sticky forceAppRelay (пропуск
// 0x17/0x19, спасающий девайсы 2024+).
func (t *Tunnel) zombieWatchdog(done chan struct{}) {
	defer t.readerWG.Done()
	tick := time.NewTicker(zombieScanEvery)
	defer tick.Stop()
	for {
		select {
		case <-done:
			return
		case <-tick.C:
		}
		now := time.Now()
		var (
			rid    uint32
			port   int
			up     uint64
			age    time.Duration
			zombie bool
		)
		t.clientsMu.Lock()
		for id, c := range t.clients {
			up = atomic.LoadUint64(&c.dataUp)
			down := atomic.LoadUint64(&c.dataDown)
			if up == 0 || down > 0 {
				continue
			}
			if a := now.Sub(c.created); a > zombieRelayTimeout {
				rid, port, age, zombie = id, c.remotePort, a, true
				break
			}
		}
		t.clientsMu.Unlock()
		if zombie {
			t.logf("zombie data path: realm=%#010x port=%d sent %d bytes, 0 back for %.0fs — fail for retry (app dialect next)",
				rid, port, up, age.Seconds())
			t.forceAppRelay = true
			t.fail(errZombieRelay)
			return
		}
	}
}

