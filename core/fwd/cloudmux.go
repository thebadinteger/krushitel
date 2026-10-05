package fwd

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

const (
	muxRetransmitEvery = 1500 * time.Millisecond
	muxBudgetLookup    = 20 * time.Second
	muxBudgetRelay     = 20 * time.Second

	probeCacheTTL      = 15 * time.Minute
	probeNegCacheTTL   = 3 * time.Minute
	probeMaxConcurrent = 16
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

func (m *cloudMux) readLoop() {
	buf := make([]byte, 65535)
	for {
		n, _, err := m.conn.ReadFromUDP(buf)
		if err != nil {
			if isConnReset(err) {
				continue
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

func (m *cloudMux) Exchange(method, path, body string, auth bool, budget time.Duration) (*DHResponse, error) {
	myCseq := nextCSeq()

	req := buildDHRequest(method, path, body, auth, myCseq, activeProfile, "", false)

	ch := make(chan *DHResponse, 4)
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
				continue
			}
			return res, nil
		case <-time.After(muxRetransmitEvery):
			if time.Now().After(deadline) {
				return nil, fmt.Errorf("cloud silent %v: %s %s", budget, method, path)
			}
			req = buildDHRequest(method, path, body, auth, myCseq, activeProfile, "", false)
			if _, err := m.conn.WriteTo(req, m.raddr); err != nil {
				return nil, fmt.Errorf("retransmit: %w", err)
			}
		}
	}
}

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

type probeCacheEntry struct {
	online bool
	expiry time.Time
}

var (
	probeCacheMu  sync.Mutex
	probeCache    = make(map[string]probeCacheEntry)
	probeSemOnce  sync.Once
	probeSem      chan struct{}
	probeInFlight sync.Map
)

func ProbeOnline(serial string) bool {
	probeCacheMu.Lock()
	if e, ok := probeCache[serial]; ok && time.Now().Before(e.expiry) {
		probeCacheMu.Unlock()
		return e.online
	}
	probeCacheMu.Unlock()

	mux, err := GetCloudMux()
	if err != nil || mux == nil {
		return false
	}

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

	ensureProbeSem()
	select {
	case probeSem <- struct{}{}:
		defer func() { <-probeSem }()
	case <-time.After(30 * time.Second):
		return false
	}

	res, err := mux.Exchange("DHGET", "/online/p2psrv/"+serial, "", true, muxBudgetLookup)
	online := false
	if err == nil && res.Code == 200 && res.Body["body/US"] != "" {
		online = true
	}
	if err != nil {
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
