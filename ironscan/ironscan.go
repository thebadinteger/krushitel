// Package ironscan — IP→serial DVRIP scanner (порт 37777). Портирован из
// ironscan-src + dahua-info.py:
//
//	probe 0xa001 (32 байта, magic tail a1aa) → ответ
//	  → серийник из строки «Realm:Login to <SN>» (regex — fallback)
//	→ модель: DVRIP-команда 0x0b (0xa4-пакет)
//	→ прошивка: DVRIP-команда 0x08 (best-effort)
package ironscan

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
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
	// reAmcrest — 18-символьные серийники Amcrest (AMC…PTB…).
	reAmcrest = regexp.MustCompile(`AMC[A-Z0-9]{6}P[A-Z][A-Z][A-Z0-9]{3,6}`)
	// reHexJunk — md5-подобный мусор из Realm (32 lowercase hex), бывает
	// склеен с настоящим серийником: e3597da4…94K0043FPBQ0635A.
	reHexJunk = regexp.MustCompile(`^[0-9a-f]{16,}|[0-9a-f]{16,}$`)
	reModel   = regexp.MustCompile(`(?:IPC|NVR|HCVR|DH)-[A-Z0-9\-]+`)
)

// pickSerial — вытаскивает первый структурно валидный серийник из строки.
// Пустой результат — серийника тут нет.
func pickSerial(s string) string {
	up := strings.ToUpper(s)
	for _, m := range reDahua.FindAllString(up, -1) {
		if len(m) >= 14 && len(m) <= 15 {
			return m
		}
	}
	if m := reAmcrest.FindString(up); len(m) == 18 {
		return m
	}
	return ""
}

// SanitizeSerial — качественная выборка серийника из сырой строки (Realm,
// строка serials-файла). Режет «;модель», lowercase-hex мусор, проверяет
// структуру. Пустая строка — это не серийник.
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
	// короче 14 — валидного серийника тут нет точно (Dahua 14-15, Amcrest 18),
	// regex не гоняем.
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

// generateProbe — 32-байтовый DVRIP Realm Request:
// [0-1] 0xa001, [2-23] нули, [24-31] Dahua magic tail (как в dahua-info.py:
// struct.pack('>I', 0xa0010000) + zeros + struct.pack('>Q', 0x050201010000a1aa)).
func generateProbe() []byte {
	header := make([]byte, 32)
	header[0] = 0xa0
	header[1] = 0x01
	copy(header[24:32], []byte{0x05, 0x02, 0x01, 0x01, 0x00, 0x00, 0xa1, 0xaa})
	return header
}

// dvripCmd — команда 0xa4 с опкодом (dahua-info.py dvrip_cmd):
// 0xa4, 0, code, 0 (LE u32 x4) + 16 нулей → ответ: 32-байтовый заголовок,
// длина payload — u16 в bytes[4:6] (НЕ u32: на части камер байты [6:8]
// не нулевые — сессия/флаги; u32-чтение давало мусорную длину, dvripCmd
// отдавал nil и модель терялась), payload строкой до \x00.
func dvripCmd(conn net.Conn, code uint32) []byte {
	pkt := make([]byte, 32)
	binary.LittleEndian.PutUint32(pkt[0:4], 0xa4)
	binary.LittleEndian.PutUint32(pkt[8:12], code)
	if _, err := conn.Write(pkt); err != nil {
		return nil
	}

	hdr := make([]byte, 32)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return nil
	}
	length := int(binary.LittleEndian.Uint16(hdr[4:6])) // dahua-info.py: '<H'
	if length == 0 || length > 64*1024 {
		return nil
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return payload[:0]
	}
	return payload
}

func nullTerm(b []byte) string {
	if i := indexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return strings.TrimSpace(string(b))
}

func indexByte(b []byte, c byte) int {
	for i := range b {
		if b[i] == c {
			return i
		}
	}
	return -1
}

// probeDevice — проб с ретраями. Отмена по ctx: до попытки, между
// ретраями и прямо в dial.
func probeDevice(ctx context.Context, target string, port int, timeout time.Duration, retries int) Result {
	addr := fmt.Sprintf("%s:%d", target, port)
	probe := generateProbe()

	var lastErr string
	for attempt := 0; attempt <= retries; attempt++ {
		if ctx.Err() != nil {
			return Result{Target: target, Err: "cancelled"}
		}
		r := tryConnect(ctx, addr, probe, timeout)
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

func tryConnect(ctx context.Context, addr string, probe []byte, timeout time.Duration) Result {
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

	if tc, ok := conn.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
	}
	conn.SetDeadline(time.Now().Add(timeout))

	if _, err = conn.Write(probe); err != nil {
		return Result{Err: err.Error()}
	}

	hdr := make([]byte, 32)
	if _, err = io.ReadFull(conn, hdr); err != nil {
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			return Result{Err: "timeout"}
		}
		return Result{Err: err.Error()}
	}

	var response []byte
	if hdr[0] == 0xb0 && (hdr[1] == 0x00 || hdr[1] == 0x01) || hdr[0] == 0xf6 {
		// длина — u16 [4:6], как в dvrip_cmd dahua-info.py; обрыв payload
		// по таймауту не валим — парсим что пришло (питон читает до тишины)
		payloadLen := int(binary.LittleEndian.Uint16(hdr[4:6]))
		if payloadLen > 0 {
			payload := make([]byte, payloadLen)
			if _, err = io.ReadFull(conn, payload); err != nil && err != io.EOF {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					// частичный ответ лучше пустого
				} else {
					return Result{Err: err.Error()}
				}
			}
			response = append(hdr, payload...)
		} else {
			response = hdr
		}
	} else {
		// неизвестный заголовок — читаем до тишины короткими таймаутами
		// (dahua-info.py: recv-цикл с 0.3s). Один Read терял хвосты
		// многосегментных ответов — с ними улетали серийник и модель.
		buf := make([]byte, 4096)
		for {
			conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
			n, rerr := conn.Read(buf)
			if n > 0 {
				response = append(response, buf[:n]...)
			}
			if rerr != nil {
				break
			}
		}
	}

	res := parseResponse(response)

	// серийник не найден в probe-ответе — пробуем уточнить модель/прошивку
	// и fallback-regex только по leftovers
	if res.Serial == "" {
		return res
	}

	// модель по 0x0b, прошивка по 0x08 (dahua-info.py)
	conn.SetDeadline(time.Now().Add(timeout))
	if raw := dvripCmd(conn, 0x0b); len(raw) > 0 {
		if m := nullTerm(raw); m != "" {
			res.Model = m
		}
	}
	conn.SetDeadline(time.Now().Add(timeout))
	if raw := dvripCmd(conn, 0x08); len(raw) > 0 {
		if fw := nullTerm(raw); fw != "" {
			res.Firmware = fw
		}
	}

	return res
}

func parseResponse(response []byte) Result {
	var serial, model string

	// точный источник серийника (dahua-info.py): «Realm:Login to <SN>»
	payload := response
	if len(payload) > 32 {
		payload = payload[32:]
	}
	for _, line := range strings.Split(string(payload), "\n") {
		line = strings.TrimSpace(strings.TrimRight(line, "\r"))
		if strings.HasPrefix(line, "Realm:Login to ") {
			serial = SanitizeSerial(line[len("Realm:Login to "):])
			break
		}
	}
	// regex fallback по всему ответу
	if serial == "" {
		serial = pickSerial(string(response))
	}
	// модель regex'ом — только если 0x0b не даст
	if m := reModel.Find(response); m != nil {
		model = string(m)
	}

	if serial == "" {
		return Result{Err: "no serial"}
	}
	return Result{Serial: serial, Model: model}
}

// Run исполняет скан, onResult вызывается для каждого завершённого проба
// (сериализовано под мьютексом). Отмена по ctx: воркеры прекращают брать
// новые цели и бросают начатые пробы, Run возвращает nil при отмене.
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
	for _, t := range opts.Targets {
		select {
		case <-ctx.Done():
			break feed
		case jobs <- t:
		}
	}
	close(jobs)
	wg.Wait()
	return nil
}

// LoadTargets читает список IP/хостов: пропускает пустые строки и # комменты,
// понимает UTF-16 файлы с BOM (как dahua-info.py).
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
			targets = append(targets, line)
		}
	}
	return targets, scanner.Err()
}
