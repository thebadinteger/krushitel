// Package cloud — работа с облаком Dahua (easy4ipcloud).
// Префиксы (10 символов) читаются через LoadPrefixes; развёртка
// XXXXXXXXXYYYYY (Y = 00000..FFFFF) — на лету в скан-пайплайне
// (см. scanner.RunPrefixScan), файлов со списками больше нет.
// Функция 3: онлайн-чек серийников через /online/p2psrv/<SN>.
package cloud

import (
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf16"
	"unicode/utf8"
)

const (
	MainServer = "www.easy4ipcloud.com"
	MainPort   = 8800

	// стоковые креды WSSE облачного клиента
	CloudUsername = "cba1b29e32cb17aa46b8ff9e73c7f40b"
	CloudUserKey  = "996103384cdf19179e19243e959bbf8b"
)

// LoadPrefixes читает файл префиксов. Строка длиной 10 символов — уже
// префикс; строка длиннее (например, целый серийник 5L04507PAJBD5F6) —
// берутся первые 10 символов (5L04507PAJ). Дедуп с сохранением порядка.
// Понимает UTF-8 и UTF-16 файлы с BOM.
func LoadPrefixes(path string) ([]string, error) {
	raw, err := readFileBytes(path)
	if err != nil {
		return nil, fmt.Errorf("open: %w", err)
	}
	text := decodeText(raw)

	seen := make(map[string]struct{})
	var prefixes []string
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(strings.Trim(line, "\r\x00"))
		// меряем рунами: кириллица в байтах длиннее, чем выглядит
		if utf8.RuneCountInString(line) < 10 {
			continue
		}
		p := string([]rune(line)[:10])
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		prefixes = append(prefixes, p)
	}
	if len(prefixes) == 0 {
		return nil, fmt.Errorf("no 10-char prefixes found")
	}
	return prefixes, nil
}

// decodeText — файл в UTF-8 или UTF-16 (BOM).
func decodeText(raw []byte) string {
	if len(raw) >= 2 && raw[0] == 0xFF && raw[1] == 0xFE || len(raw) >= 2 && raw[0] == 0xFE && raw[1] == 0xFF {
		be := raw[0] == 0xFE && raw[1] == 0xFF
		u16 := make([]uint16, 0, len(raw)/2)
		for i := 2; i+1 < len(raw); i += 2 {
			if be {
				u16 = append(u16, uint16(raw[i])<<8|uint16(raw[i+1]))
			} else {
				u16 = append(u16, uint16(raw[i+1])<<8|uint16(raw[i]))
			}
		}
		return strings.Map(func(r rune) rune {
			if r == 0xFEFF {
				return -1
			}
			return r
		}, string(utf16.Decode(u16)))
	}
	return strings.TrimPrefix(string(raw), "\xEF\xBB\xBF")
}

// LogHook — дампы протокола пречека (nil = выключено).
var LogHook func(string)

func cloudLog(format string, args ...any) {
	if LogHook != nil {
		LogHook(fmt.Sprintf(format, args...))
	}
}

// CheckOnline — одиночная проверка серийника (мягкий пречек воркера:
// врёт на части сетей, поэтому фейл пречека не фатален).
func CheckOnline(serial string) bool {
	raddr, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:%d", MainServer, MainPort))
	if err != nil {
		return false
	}
	conn, err := net.ListenUDP("udp4", nil)
	if err != nil {
		return false
	}
	defer conn.Close()

	req := buildRequest(serial)
	buf := make([]byte, 8192)
	for i := 0; i < 2; i++ {
		conn.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := conn.WriteToUDP([]byte(req), raddr); err != nil {
			cloudLog("%s: send try %d: %v", serial, i+1, err)
			continue
		}
		cloudLog("%s: >>> /online/p2psrv (try %d)", serial, i+1)
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			cloudLog("%s: <<< silent (try %d): %v", serial, i+1, err)
			continue
		}
		resp := string(buf[:n])
		first := resp
		if j := strings.Index(resp, "\r\n"); j >= 0 {
			first = resp[:j]
		}
		cloudLog("%s: <<< %s (US=%v)", serial, first, strings.Contains(resp, "<US>"))
		if strings.HasPrefix(resp, "HTTP/1.1 200") && strings.Contains(resp, "<US>") {
			return true
		}
		if strings.Contains(resp, " 404 ") {
			return false
		}
	}
	cloudLog("%s: тишина после 2 попыток", serial)
	return false
}

func itoa(n int) string { return strconv.Itoa(n) }

type Checker struct {
	Workers   int
	Timeout   time.Duration // на одну попытку чтения
	Retries   int           // попыток на серийник
	Results   chan Result
	jobs      chan string
	wg        sync.WaitGroup
	conns     []*net.UDPConn
	checked   int64
	valid     int64
	started   bool
	startMu   sync.Mutex
	closeOnce sync.Once
}

type Result struct {
	Serial string
	Valid  bool
}

func NewChecker(workers int, timeout time.Duration, retries int) *Checker {
	if workers < 1 {
		workers = 1
	}
	if retries < 1 {
		retries = 1
	}
	return &Checker{
		Workers: workers,
		Timeout: timeout,
		Retries: retries,
		Results: make(chan Result, workers*100),
		jobs:    make(chan string, workers*4), // малый буфер: пауза (:p) срабатывает быстро
	}
}

// Start поднимает воркеры с connected-UDP сокетами на облачный сервер.
func (c *Checker) Start() error {
	c.startMu.Lock()
	if c.started {
		c.startMu.Unlock()
		return nil
	}
	c.started = true
	c.startMu.Unlock()

	raddr, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:%d", MainServer, MainPort))
	if err != nil {
		return fmt.Errorf("resolve cloud: %w", err)
	}

	for i := 0; i < c.Workers; i++ {
		conn, err := net.DialUDP("udp4", nil, raddr)
		if err != nil {
			continue
		}
		conn.SetWriteBuffer(512 * 1024)
		conn.SetReadBuffer(512 * 1024)
		c.conns = append(c.conns, conn)
		c.wg.Add(1)
		go c.worker(conn)
	}
	if len(c.conns) == 0 {
		return fmt.Errorf("no udp sockets could be created")
	}
	return nil
}

// Push ставит серийник в очередь. Безопасно до Close.
func (c *Checker) Push(serial string) {
	c.jobs <- serial
}

// TryPush — неблокирующий Push: false, если очередь полна.
func (c *Checker) TryPush(serial string) bool {
	select {
	case c.jobs <- serial:
		return true
	default:
		return false
	}
}

// Close завершает очередь и воркеров, затем закрывает Results.
func (c *Checker) Close() {
	c.closeOnce.Do(func() {
		close(c.jobs)
		c.wg.Wait()
		for _, conn := range c.conns {
			conn.Close()
		}
		close(c.Results)
	})
}

// Stats — текущие счётчики (атомарные).
func (c *Checker) Stats() (checked, valid int64) {
	return atomic.LoadInt64(&c.checked), atomic.LoadInt64(&c.valid)
}

// buildRequest — DHGET /online/p2psrv/<serial> со свежим WSSE-дайджестом
// (пересчёт на каждый запрос: сервер отбивает протухший Created).
func buildRequest(serial string) string {
	nonce := time.Now().UnixNano() & 0x7FFFFFFF
	created := time.Now().UTC().Format("2006-01-02T15:04:05Z")
	pwd := fmt.Sprintf("%d%sDHP2P:%s:%s", nonce, created, CloudUsername, CloudUserKey)
	hash := sha1.Sum([]byte(pwd))
	digest := base64.StdEncoding.EncodeToString(hash[:])

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("DHGET /online/p2psrv/%s HTTP/1.1\r\nCSeq: 1\r\n", serial))
	sb.WriteString("Authorization: WSSE profile=\"UsernameToken\"\r\n")
	sb.WriteString(fmt.Sprintf(
		"X-WSSE: UsernameToken Username=\"%s\", PasswordDigest=\"%s\", Nonce=\"%d\", Created=\"%s\"\r\n\r\n",
		CloudUsername, digest, nonce, created))
	return sb.String()
}

func (c *Checker) worker(conn *net.UDPConn) {
	defer c.wg.Done()
	defer conn.Close()

	buf := make([]byte, 8192)
	for serial := range c.jobs {
		valid := false
		req := buildRequest(serial)
		for attempt := 0; attempt < c.Retries && !valid; attempt++ {
			conn.SetDeadline(time.Now().Add(c.Timeout))
			if _, err := conn.Write([]byte(req)); err != nil {
				continue
			}
			n, err := conn.Read(buf)
			if err != nil {
				continue
			}
			resp := string(buf[:n])
			if strings.HasPrefix(resp, "HTTP/1.1 200") && strings.Contains(resp, "<US>") {
				valid = true
			}
			// 404 — авторитетный «камеры нет/выключена», ретраи бессмысленны
			if strings.Contains(resp, " 404 ") {
				break
			}
		}
		c.Results <- Result{Serial: serial, Valid: valid}
		atomic.AddInt64(&c.checked, 1)
		if valid {
			atomic.AddInt64(&c.valid, 1)
		}
	}
}
