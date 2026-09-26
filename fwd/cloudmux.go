package fwd

// cloudmux.go — единый UDP-канал к главному облачному серверу
// (www.easy4ipcloud.com:8800) для пречека серийников с диспетчеризацией
// ответов по CSeq.
//
// Исторически мультиплексор обслуживал и облачные фазы хендшейков, но
// после core-swap на эталонный dh-fwd v2.1 хендшейки ходят per-tunnel
// сокетами (шторм сокетов лечит InitLimit), а мультиплексор остался
// только у ProbeOnline: кеш (TTL) + дедуп + лимит одновременных.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

// облако под нагрузкой отвечает 1-15с: бюджет на транзакцию — с запасом
const (
	muxRetransmitEvery = 1500 * time.Millisecond
	muxBudgetLookup    = 20 * time.Second
	muxBudgetRelay     = 20 * time.Second

	probeCacheTTL      = 15 * time.Minute // камера онлайн — живёт в облаке
	probeNegCacheTTL   = 3 * time.Minute  // offline мигает, но не мгновенно
	probeMaxConcurrent = 16               // при 500 воркерах очередь из 4 не успевала
)

var errMuxClosed = errors.New("cloud mux closed")

type cloudMux struct {
	conn  *net.UDPConn
	raddr *net.UDPAddr

	mu      sync.Mutex
	pending map[uint32]chan *DHResponse
	dying   bool

	wg sync.WaitGroup
}

var (
	muxOnce sync.Once
	muxRef  *cloudMux
	muxErr  error
)

// GetCloudMux — процессный синглтон. Ошибка создания возвращается всем.
func GetCloudMux() (*cloudMux, error) {
	muxOnce.Do(func() {
		m, err := newCloudMux()
		if err != nil {
			muxErr = err
			return
		}
		muxRef = m
	})
	return muxRef, muxErr
}

func newCloudMux() (*cloudMux, error) {
	raddr, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:%d", MAIN_SERVER, MAIN_PORT))
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", MAIN_SERVER, err)
	}
	pc, err := udpListenCfg.ListenPacket(context.Background(), "udp4", "0.0.0.0:0")
	if err != nil {
		return nil, fmt.Errorf("udp socket: %w", err)
	}
	conn := pc.(*net.UDPConn)
	_ = conn.SetReadBuffer(2 * 1024 * 1024)
	_ = conn.SetWriteBuffer(1 * 1024 * 1024)

	m := &cloudMux{
		conn:    conn,
		raddr:   raddr,
		pending: make(map[uint32]chan *DHResponse),
	}
	go m.readLoop()
	return m, nil
}

// readLoop вычитывает датаграммы и роутит по CSeq из заголовка.
func (m *cloudMux) readLoop() {
	buf := make([]byte, 65535)
	for {
		n, _, err := m.conn.ReadFromUDP(buf)
		if err != nil {
			if isConnReset(err) {
				continue // Windows-шум, читаем дальше
			}
			return
		}
		res := ParseDHResponse(string(buf[:n]))
		if res == nil || res.Code == 0 {
			continue
		}
		cseqStr, ok := res.Headers["CSeq"]
		if !ok {
			continue
		}
		var cseq uint32
		if _, err := fmt.Sscanf(cseqStr, "%d", &cseq); err != nil {
			continue
		}
		m.mu.Lock()
		ch, ok := m.pending[cseq]
		delete(m.pending, cseq)
		m.mu.Unlock()
		if ok {
			ch <- res
		}
	}
}

// Exchange — одна DHGET/DHPOST транзакция с ретранмитами. Блокируется до
// ответа или до бюджета.
func (m *cloudMux) Exchange(method, path, body string, auth bool, budget time.Duration) (*DHResponse, error) {
	myCseq := nextCSeq()

	req := buildDHRequest(method, path, body, auth, myCseq, activeProfile, "", false)

	ch := make(chan *DHResponse, 4) // буфер: дубликаты ответов не блочат ридера
	m.mu.Lock()
	if m.dying {
		m.mu.Unlock()
		return nil, errMuxClosed
	}
	m.pending[myCseq] = ch
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		delete(m.pending, myCseq)
		m.mu.Unlock()
	}()

	deadline := time.Now().Add(budget)
	if _, err := m.conn.WriteToUDP(req, m.raddr); err != nil {
		return nil, fmt.Errorf("send: %w", err)
	}

	for {
		select {
		case res := <-ch:
			if res.Code < 200 {
				// Провизорный ответ (100 Trying с пустым телом): НЕ финал —
				// ждём настоящий ответ в рамках бюджета, иначе пустое тело
				// проскакивает как результат (ложные "not found"/offline).
				continue
			}
			return res, nil
		case <-time.After(muxRetransmitEvery):
			if time.Now().After(deadline) {
				return nil, fmt.Errorf("cloud silent %v: %s %s", budget, method, path)
			}
			// ретрансмит свежим WSSE-дайджестом (Created протухает)
			req = buildDHRequest(method, path, body, auth, myCseq, activeProfile, "", false)
			if _, err := m.conn.WriteTo(req, m.raddr); err != nil {
				return nil, fmt.Errorf("retransmit: %w", err)
			}
		}
	}
}

// Close глушит мультиплексор (конец прогона).
func (m *cloudMux) Close() {
	m.mu.Lock()
	if m.dying {
		m.mu.Unlock()
		return
	}
	m.dying = true
	for _, ch := range m.pending {
		close(ch)
	}
	m.pending = make(map[uint32]chan *DHResponse)
	m.mu.Unlock()
	m.conn.Close()
}

// ── пречек серийников через мультиплексор ────────────────────────────

type probeCacheEntry struct {
	online bool
	expiry time.Time
}

var (
	probeCacheMu  sync.Mutex
	probeCache    = make(map[string]probeCacheEntry)
	probeSemOnce  sync.Once
	probeSem      chan struct{}
	probeInFlight sync.Map // serial → *sync.WaitGroup для дедупа
)

// ProbeOnline — пречек одного серийника через общий облачный канал:
// DHGET /online/p2psrv/<SN>. Кеш (TTL) + дедуп одновременных одинаковых
// + глобальный лимит одновременных запросов. false при молчании облака —
// НЕ авторитетно (ре-очередь разберётся).
func ProbeOnline(serial string) bool {
	// кеш
	probeCacheMu.Lock()
	if e, ok := probeCache[serial]; ok && time.Now().Before(e.expiry) {
		probeCacheMu.Unlock()
		return e.online
	}
	probeCacheMu.Unlock()

	// мультиплексор мог не подняться (нет сети/DNS) — не авторитетный
	// фейл, серийник уйдёт в ре-очередь
	mux, err := GetCloudMux()
	if err != nil || mux == nil {
		return false
	}

	// дедуп: тот же серийник уже в полёте — ждём его результат.
	// Add(1) делается ДО LoadOrStore: иначе ждущий мог бы вызвать Wait()
	// на ещё пустом счётчике (Wait вернулся бы мгновенно до записи в кеш).
	wg := &sync.WaitGroup{}
	wg.Add(1)
	w, loaded := probeInFlight.LoadOrStore(serial, wg)
	if loaded {
		wg = w.(*sync.WaitGroup)
		wg.Wait()
		probeCacheMu.Lock()
		e, ok := probeCache[serial]
		probeCacheMu.Unlock()
		if ok {
			return e.online
		}
		return false
	}
	defer func() {
		wg.Done()
		probeInFlight.Delete(serial)
	}()

	// лимит одновременных пречеков
	ensureProbeSem()
	select {
	case probeSem <- struct{}{}:
		defer func() { <-probeSem }()
	case <-time.After(30 * time.Second):
		return false
	}

	// DHGET /online/p2psrv/<SN> — WSSE username/key те же, что у пакета
	// cloud; тут зеркалим buildDHRequest'ом
	res, err := mux.Exchange("DHGET", "/online/p2psrv/"+serial, "", true, muxBudgetLookup)
	online := false
	if err == nil && res.Code == 200 && res.Body["body/US"] != "" {
		online = true
	}
	if err != nil {
		// облако молчит: не кешируем негатив — серийник останется без
		// вердикта и уйдёт в ре-очередь
		return false
	}

	ttl := probeNegCacheTTL
	if online {
		ttl = probeCacheTTL
	}
	probeCacheMu.Lock()
	probeCache[serial] = probeCacheEntry{online: online, expiry: time.Now().Add(ttl)}
	probeCacheMu.Unlock()
	return online
}

func ensureProbeSem() {
	probeSemOnce.Do(func() { probeSem = make(chan struct{}, probeMaxConcurrent) })
}
