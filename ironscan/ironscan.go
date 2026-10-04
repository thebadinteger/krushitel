// Package ironscan — IP→serial сканер Dahua (TCP 37777), база — dhscp
// (github.com/thebadinteger/dhscp, MIT):
//
//	одним куском: hello (a0 05 00 60, magic tail a1aa) + 0xa4:0x07 (серийник)
//	+ 0xa4:0x0b (модель) → 3 фрейма: ack, серийник, модель; прошивка —
//	0xa4:0x08 тем же коннектом (best-effort)
//
// Вход: masscan -oG («Discovered open port 37777/tcp on 1.2.3.4» — tcp/udp
// без разницы), IP, IP:port, CIDR, диапазоны a.b.c.d-e.f.g.h и a.b.c.d-x.
// Порядок скана псевдослучайный: перестановка Фейстеля по всему списку
// (как blackrock в masscan), детерминирована Options.Seed (0 = от времени).
package ironscan

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"math/bits"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf16"
	"unicode/utf8"
)

var (
	// reDahua — серийник Dahua: префикс 4-7 символов + маркер P?? (PAx/PBx/…,
	// новые XVR идут с PBQ) + хвост. Рабочая длина 14-15.
	reDahua = regexp.MustCompile(`[A-Z0-9]{4,7}P[A-Z][A-Z][A-Z0-9]{3,6}`)
	// reHexJunk — md5-подобный мусор из Realm (32 lowercase hex), бывает
	// склеен с настоящим серийником: e3597da4…94K0043FPBQ0635A.
	reHexJunk = regexp.MustCompile(`^[0-9a-f]{16,}|[0-9a-f]{16,}$`)
)

// maxRangeIPs — потолок разворота одного диапазона/CIDR (как в dhscp).
const maxRangeIPs = 5_000_000

// pickSerial — вытаскивает первый структурно валидный серийник из строки.
// Пустой результат — серийника тут нет.
func pickSerial(s string) string {
	up := strings.ToUpper(s)
	for _, m := range reDahua.FindAllString(up, -1) {
		if len(m) >= 14 && len(m) <= 15 {
			return m
		}
	}
	return ""
}

// SanitizeSerial — качественная выборка серийника из сырой строки (фрейм
// 0xa4:0x07, строка serials-файла). Режет «;модель», lowercase-hex мусор,
// проверяет структуру. Пустая строка — это не серийник.
func SanitizeSerial(raw string) string {
	s := strings.TrimSpace(raw)
	if i := strings.IndexByte(s, ';'); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}
	s = reHexJunk.ReplaceAllString(s, "")
	if s == "" {
		return ""
	}
	return pickSerial(s)
}

// SanitizeSerialBytes — как SanitizeSerial, но вход []byte без аллокаций:
// string() делаем один раз и только для строк, прошедших дешёвые фильтры
// (пусто / «;модель» / короче минимального серийника 14). Мусор отваливается
// с нулём аллокаций — на сотнях млн строк это разы по скорости и GC.
func SanitizeSerialBytes(raw []byte) string {
	s := bytes.TrimSpace(raw)
	if len(s) == 0 {
		return ""
	}
	if i := bytes.IndexByte(s, ';'); i >= 0 {
		s = bytes.TrimSpace(s[:i])
	}
	// короче 14 — валидного серийника Dahua тут нет точно (рабочая длина
	// 14-15), regex не гоняем.
	if len(s) < 14 {
		return ""
	}
	return SanitizeSerial(string(s))
}

// Options — параметры скана.
type Options struct {
	Targets     []string
	Port        int
	Timeout     time.Duration
	Concurrency int
	Retries     int
	// Seed сид перестановки Фейстеля: одинаковый сид = одинаковый порядок
	// скана (как --seed в masscan). 0 = сид от времени.
	Seed int64
}

// Result — итог одного проба.
type Result struct {
	Target   string
	Serial   string
	Model    string
	Firmware string
	Err      string
}

// Ok — проб дал серийник.
func (r Result) Ok() bool { return r.Serial != "" }

// LogHook — лог-приёмник (сид/порядок скана и т.п.; nil = тихо).
var LogHook func(format string, args ...any)

// hello — dhscp-проба: 0xa0 0x05 0x00 0x60 + клиентский вер-блок, magic tail.
var hello = []byte{
	0xa0, 0x05, 0x00, 0x60, 0x00, 0x00, 0x00, 0x00,
	0xc4, 0xa3, 0xaf, 0x48, 0x99, 0x56, 0xb6, 0xb4,
	0x70, 0x02, 0x64, 0x9a, 0xfa, 0x55, 0x24, 0x04,
	0x05, 0x02, 0x00, 0x01, 0x00, 0x00, 0xa1, 0xaa,
}

// command — 32-байтовый 0xa4-syscall: тип в [0], опкод в [8].
func command(commandType, commandID byte) []byte {
	pkt := make([]byte, 32)
	pkt[0] = commandType
	pkt[8] = commandID
	return pkt
}

// readFrame — фрейм DHIP: 32-байтовый заголовок, длина payload — u16 LE
// в [4:6] (НЕ u32: на части камер байты [6:8] не нулевые — сессия/флаги).
func readFrame(conn net.Conn) ([]byte, error) {
	header := make([]byte, 32)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}
	bodyLen := int(binary.LittleEndian.Uint16(header[4:6]))
	if bodyLen > 1024*1024 {
		return nil, fmt.Errorf("response body too large")
	}
	body := make([]byte, bodyLen)
	if _, err := io.ReadFull(conn, body); err != nil {
		return nil, err
	}
	return body, nil
}

func cleanValue(body []byte) string {
	return strings.TrimSpace(strings.TrimRight(string(body), "\x00"))
}

func timeoutOrErr(err error) string {
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return "timeout"
	}
	return err.Error()
}

// probeDevice — проб с ретраями. Отмена по ctx: до попытки, между
// ретраями и прямо в dial. refused (RST) — терминален: путь жив,
// порт закрыт, ретраить бессмысленно.
func probeDevice(ctx context.Context, target string, port int, timeout time.Duration, retries int) Result {
	var lastErr string
	for attempt := 0; attempt <= retries; attempt++ {
		if ctx.Err() != nil {
			return Result{Target: target, Err: "cancelled"}
		}
		r := tryConnect(ctx, target, port, timeout)
		if r.Err == "" {
			r.Target = target
			return r
		}
		if r.Err == "refused" {
			return Result{Target: target, Err: "refused"}
		}
		lastErr = r.Err
		if attempt < retries {
			select {
			case <-ctx.Done():
				return Result{Target: target, Err: "cancelled"}
			case <-time.After(500 * time.Millisecond):
			}
		}
	}
	return Result{Target: target, Err: lastErr}
}

func tryConnect(ctx context.Context, target string, port int, timeout time.Duration) Result {
	addr := target
	if _, _, err := net.SplitHostPort(target); err != nil {
		addr = net.JoinHostPort(target, strconv.Itoa(port))
	}

	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		if strings.Contains(err.Error(), "connection refused") {
			return Result{Err: "refused"}
		}
		return Result{Err: err.Error()}
	}
	defer conn.Close()

	// Отмена: немедленный дедлайн будит блокирующий read при ctx.Done,
	// иначе отмену видно только между пробами.
	stop := context.AfterFunc(ctx, func() { conn.SetDeadline(time.Now()) })
	defer stop()

	return probeConn(conn, timeout)
}

// probeConn — dhscp-проба по живому коннекту: burst 96 байт (hello +
// серийник 0xa4:0x07 + модель 0xa4:0x0b) одним куском — один RTT, потом
// прошивка 0xa4:0x08 тем же коннектом (best-effort, как в dahua-info.py).
func probeConn(conn net.Conn, timeout time.Duration) Result {
	if tc, ok := conn.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
	}
	conn.SetDeadline(time.Now().Add(timeout))

	burst := make([]byte, 0, 96)
	burst = append(burst, hello...)
	burst = append(burst, command(0xa4, 0x07)...)
	burst = append(burst, command(0xa4, 0x0b)...)
	if _, err := conn.Write(burst); err != nil {
		return Result{Err: err.Error()}
	}

	// фрейм 1 — ack hello, дренится
	if _, err := readFrame(conn); err != nil {
		return Result{Err: timeoutOrErr(err)}
	}
	// фрейм 2 — серийник
	serialBody, err := readFrame(conn)
	if err != nil {
		return Result{Err: timeoutOrErr(err)}
	}
	serial := SanitizeSerial(cleanValue(serialBody))
	if serial == "" {
		return Result{Err: "no serial"}
	}

	// фрейм 3 — модель (best-effort: на части прошивок не приходит)
	var model string
	if body, err := readFrame(conn); err == nil {
		model = cleanValue(body)
	}

	// прошивка 0xa4:0x08 тем же коннектом (best-effort, как в dahua-info.py)
	conn.SetDeadline(time.Now().Add(timeout))
	var firmware string
	if _, err := conn.Write(command(0xa4, 0x08)); err == nil {
		if body, err := readFrame(conn); err == nil {
			firmware = cleanValue(body)
		}
	}

	return Result{Serial: serial, Model: model, Firmware: firmware}
}

// ── вход: masscan -oG / IP / IP:port / CIDR / диапазоны ─────────────

// parseRangeIPs — «a.b.c.d-e.f.g.h» или «a.b.c.d-x» (последний октет).
// start>end разворачивается (как в dhscp). Потолок maxRangeIPs.
func parseRangeIPs(rangeStr string) []string {
	parts := strings.SplitN(rangeStr, "-", 2)
	startIP := net.ParseIP(strings.TrimSpace(parts[0])).To4()
	if startIP == nil {
		return nil
	}
	var endVal uint32
	if endIP := net.ParseIP(strings.TrimSpace(parts[1])).To4(); endIP != nil {
		endVal = binary.BigEndian.Uint32(endIP)
	} else if octet, err := strconv.Atoi(strings.TrimSpace(parts[1])); err == nil && octet >= 0 && octet <= 255 {
		endVal = binary.BigEndian.Uint32(startIP)&0xffffff00 | uint32(octet)
	} else {
		return nil
	}
	startVal := binary.BigEndian.Uint32(startIP)
	if startVal > endVal {
		startVal, endVal = endVal, startVal
	}
	count := int64(endVal-startVal+1)
	if count > maxRangeIPs {
		count = maxRangeIPs
	}
	res := make([]string, 0, count)
	ip := make(net.IP, 4)
	for v := startVal; v <= startVal+uint32(count)-1; v++ {
		binary.BigEndian.PutUint32(ip, v)
		res = append(res, ip.String())
	}
	return res
}

// parseCIDRIPs — разворот CIDR, потолок maxRangeIPs (как в dhscp).
func parseCIDRIPs(cidrStr string) []string {
	_, ipnet, err := net.ParseCIDR(cidrStr)
	if err != nil || ipnet == nil || ipnet.IP.To4() == nil {
		return nil
	}
	startVal := binary.BigEndian.Uint32(ipnet.IP.To4())
	maskVal := binary.BigEndian.Uint32(ipnet.Mask)
	endVal := startVal | (^maskVal)
	count := int64(endVal - startVal + 1)
	if count > maxRangeIPs {
		count = maxRangeIPs
	}
	res := make([]string, 0, count)
	ip := make(net.IP, 4)
	for v := startVal; v <= startVal+uint32(count)-1; v++ {
		binary.BigEndian.PutUint32(ip, v)
		res = append(res, ip.String())
	}
	return res
}

// appendTarget — классификация строки входа. Порядок важен: masscan-строка
// содержит и «/», и дефисы, разбирается первой. Неопознанное (хосты и
// мусор) проходит как есть — диал сам разберётся.
func appendTarget(items []string, line string) []string {
	// masscan -oG: «Discovered open port 37777/tcp on 1.2.3.4»
	if f := strings.Fields(line); len(f) >= 6 &&
		strings.EqualFold(f[0], "discovered") &&
		strings.EqualFold(f[1], "open") &&
		strings.EqualFold(f[2], "port") {
		if port, err := strconv.Atoi(strings.SplitN(f[3], "/", 2)[0]); err == nil && port > 0 && port <= 65535 {
			if net.ParseIP(f[5]) != nil {
				return append(items, net.JoinHostPort(f[5], strconv.Itoa(port)))
			}
		}
		return append(items, line)
	}
	// ip:port
	if host, portStr, err := net.SplitHostPort(line); err == nil {
		if port, err := strconv.Atoi(portStr); err == nil && port > 0 && port <= 65535 && net.ParseIP(host) != nil {
			return append(items, net.JoinHostPort(host, portStr))
		}
	}
	// CIDR
	if strings.Contains(line, "/") {
		if ips := parseCIDRIPs(line); len(ips) > 0 {
			return append(items, ips...)
		}
	}
	// диапазон
	if strings.Contains(line, "-") {
		if ips := parseRangeIPs(line); len(ips) > 0 {
			return append(items, ips...)
		}
	}
	// одиночный IP
	if net.ParseIP(line) != nil {
		return append(items, line)
	}
	return append(items, line)
}

// ParseTarget — классификация одной строки входа без файла (инлайн -i):
// masscan-строка, ip:port, CIDR, диапазон, IP; неопознанное — как есть.
func ParseTarget(line string) []string {
	return appendTarget(nil, line)
}

// LoadTargets читает файл целей: masscan -oG, IP, IP:port, CIDR, диапазоны.
// Пропускает пустые строки и # комменты, понимает UTF-16 файлы с BOM.
// Диапазоны/CIDR разворачиваются (потолок maxRangeIPs на токен); порядок
// НЕ случайный — его делает Run своей LCG-перестановкой.
func LoadTargets(filepath string) ([]string, error) {
	raw, err := os.ReadFile(filepath)
	if err != nil {
		return nil, err
	}

	text := string(raw)
	if len(raw) >= 2 && (raw[0] == 0xFF && raw[1] == 0xFE || raw[0] == 0xFE && raw[1] == 0xFF) {
		u16 := make([]uint16, 0, len(raw)/2)
		be := raw[0] == 0xFE && raw[1] == 0xFF
		for i := 2; i+1 < len(raw); i += 2 {
			if be {
				u16 = append(u16, uint16(raw[i])<<8|uint16(raw[i+1]))
			} else {
				u16 = append(u16, uint16(raw[i+1])<<8|uint16(raw[i]))
			}
		}
		text = string(utf16.Decode(u16))
	} else if !utf8.Valid(raw) {
		text = strings.ToValidUTF8(string(raw), "")
	}

	var targets []string
	scanner := bufio.NewScanner(strings.NewReader(text))
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(strings.Trim(scanner.Text(), "\r\n\x00"))
		if line != "" && !strings.HasPrefix(line, "#") {
			targets = appendTarget(targets, line)
		}
	}
	return targets, scanner.Err()
}

// ── перестановка Фейстеля (порядок скана, как blackrock в masscan) ──

// ironPerm — биекция [0,n) → [0,n): равнополый Фейстель над доменом
// 2^(2c) ≥ n + cycle-walking (пока значение ≥ n — применяем снова).
// LCG тут не годится: полный цикл x'=(ax+b) mod n требует условий Кнута
// по всем простым делителям n, а перестановка Фейстеля честная при любом n.
type ironPerm struct {
	n     uint64 // размер выходного пространства
	dom   uint64 // размер домена 2^(2c)
	c     uint   // битов в каждой половине
	rmask uint64
	seed  uint64
}

func newPerm(n int64, seed uint64) ironPerm {
	b := bits.Len64(uint64(n) - 1)
	c := uint(b+1) / 2
	return ironPerm{
		n:     uint64(n),
		dom:   uint64(1) << (2 * c),
		c:     c,
		rmask: uint64(1)<<c - 1,
		seed:  seed,
	}
}

// f — раундовая функция: splitmix64-финализатор с сидом и номером раунда.
func (p ironPerm) f(r uint64, round uint) uint64 {
	h := r ^ p.seed ^ (uint64(round)*0x9E3779B97F4A7C15 + 1)
	h ^= h >> 33
	h *= 0xff51afd7ed558ccd
	h ^= h >> 33
	h *= 0xc4ceb9fe1a85ec53
	h ^= h >> 33
	return h
}

// perm — биекция на домене: 4 инвертируемых раунда Фейстеля.
func (p ironPerm) perm(x uint64) uint64 {
	l := (x >> p.c) & p.rmask
	r := x & p.rmask
	for round := uint(0); round < 4; round++ {
		l, r = r, l^(p.f(r, round)&p.rmask)
	}
	return l<<p.c | r
}

// at — k-й элемент перестановки [0,n).
func (p ironPerm) at(k int64) int64 {
	v := p.perm(uint64(k))
	for v >= p.n {
		v = p.perm(v)
	}
	return int64(v)
}

// Run исполняет скан, onResult вызывается для каждого завершённого проба
// (сериализовано под мьютексом). Отмена по ctx: воркеры прекращают брать
// новые цели и бросают начатые пробы, Run возвращает nil при отмене.
// Порядок целей — перестановка Фейстеля по всему списку (как blackrock
// в masscan): детерминирована Options.Seed, 0 = сид от времени.
func Run(ctx context.Context, opts Options, onResult func(Result)) error {
	if len(opts.Targets) == 0 {
		return fmt.Errorf("no targets")
	}
	if opts.Port == 0 {
		opts.Port = 37777
	}
	if opts.Timeout == 0 {
		opts.Timeout = 5 * time.Second
	}
	if opts.Concurrency < 1 {
		opts.Concurrency = 1
	}
	if opts.Retries < 0 {
		opts.Retries = 0
	}

	workers := opts.Concurrency
	if workers > len(opts.Targets) {
		workers = len(opts.Targets)
	}

	n := int64(len(opts.Targets))
	seed := opts.Seed
	if seed == 0 {
		seed = time.Now().UnixNano()
	}
	perm := newPerm(n, uint64(seed))
	if LogHook != nil {
		LogHook("[iron] seed=%d targets=%d (порядок Фейстель)", seed, n)
	}

	jobs := make(chan string)
	var wg sync.WaitGroup
	var mu sync.Mutex

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for t := range jobs {
				if ctx.Err() != nil {
					continue // дренируем канал, не пробуя
				}
				r := probeDevice(ctx, t, opts.Port, opts.Timeout, opts.Retries)
				if ctx.Err() != nil {
					continue // отменили в середине пробы — результат не факт
				}
				mu.Lock()
				onResult(r)
				mu.Unlock()
			}
		}()
	}

feed:
	for k := int64(0); k < n; k++ {
		select {
		case <-ctx.Done():
			break feed
		case jobs <- opts.Targets[perm.at(k)]:
		}
	}
	close(jobs)
	wg.Wait()
	return nil
}
