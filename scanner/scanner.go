package scanner

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"krushitel/i18n"
	"krushitel/ironscan"
	"krushitel/syslimits"
)

const (
	MAIN_SERVER = "www.easy4ipcloud.com"
	MAIN_PORT   = 8800
	USERNAME    = "cba1b29e32cb17aa46b8ff9e73c7f40b"
	USERKEY     = "996103384cdf19179e19243e959bbf8b"
	SOCKET_BUF  = 65536

	// пайплайн: окно p2p-channel запросов в полёте управляется governor'ом
	// в [W_MIN..W_MAX], старт = PIPELINE_WINDOW. доля истёкших без ответа
	// ниже 2% — окно растёт, выше 10% — сжимается (облако молча дропает
	// перегруз). Буфер сокета поднят до 256КБ (см. newEgress) — окно W_MAX влезает.
	PIPELINE_WINDOW = 32
	W_MIN           = 8
	W_MAX           = 128
	GOV_GROW        = 8
	GOV_SHRINK      = 16
	ACK_TIMEOUT     = 15 * time.Second

	// междатаграммная пауза при наполнении окна
	SEND_STAGGER = 100 * time.Microsecond

	// кладбище: истёкший по дедлайну запрос переносится сюда ещё на
	// ACK_GRACE — опоздавший ack находит свой CSeq и выносит честный
	// вердикт. Тишина дольше ACK_GRACE — это ретрай.
	ACK_GRACE = 15 * time.Second

	// CHANNEL_RETRIES — сколько раз переотправлять p2p-channel проб,
	// если облако молчит (тишина дольше ACK_GRACE). Всего попыток =
	// 1 + CHANNEL_RETRIES.
	CHANNEL_RETRIES = 2

	// MAX_RPS — жесткий потолок запросов в секунду на всё приложение,
	// чтобы облако Dahua не захлёбывалось от шквала датаграмм.
	MAX_RPS     = 3000
	BURST_LIMIT = 64

	// teardown-эксперимент: после живого ack шлём валидный STUN-init на
	// LocalAddr/PubAddr из ack (прямо и через облако) и молчим — девайс
	// переходит из «ждёт клиента» в «ведёт переговоры», чей таймаут
	// короче. Если бюджет живых сессий в облаке освобождается быстрее —
	// alive/мин вырастет. Эффект меряется счётчиком alive/мин в UI.
	TEARDOWN_ALIVE = true
)

// rateLimiter — потокобезопасный ограничитель частоты отправки запросов (virtual-time leaky bucket).
// Гарантирует строгий потолок RPS суммарно по всем воркерам и сокетам.
type rateLimiter struct {
	interval time.Duration
	burst    time.Duration
	mu       sync.Mutex
	next     time.Time
}

func newRateLimiter(rps int, burst int) *rateLimiter {
	if rps <= 0 {
		return nil
	}
	if burst <= 0 {
		burst = 1
	}
	inv := time.Second / time.Duration(rps)
	return &rateLimiter{
		interval: inv,
		burst:    time.Duration(burst) * inv,
		next:     time.Now(),
	}
}

func (rl *rateLimiter) wait(ctx context.Context) error {
	if rl == nil {
		return nil
	}
	rl.mu.Lock()
	now := time.Now()
	earliest := now.Add(-rl.burst)
	if rl.next.Before(earliest) {
		rl.next = earliest
	}
	if rl.next.Before(now) {
		rl.next = now
	}
	reserve := rl.next
	rl.next = rl.next.Add(rl.interval)
	rl.mu.Unlock()

	delay := reserve.Sub(now)
	if delay <= 0 {
		return nil
	}

	timer := time.NewTimer(delay)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

var cseqCounter int64

type ScanStats struct {
	Checked  int64
	Alive    int64
	Dead     int64
	Errors   int64
	Total    int64
	Speed    float64
	Done     bool
	ErrorMsg string

	// фаза чтения входного файла (до старта воркеров). Все поля
	// атомарные: тикер UI читает их из другого горутинного потока.
	// Чтение — один стрим-проход (см. streamSerials): прогресс по байтам,
	// память O(окно дедупа), а не O(файл).
	Reading        int64   // 1 = идёт чтение/санитайз входного файла
	ReadLines      int64   // обработано строк на фазе санитайза
	ReadBytes      int64   // прочитано байт входа
	ReadTotalBytes int64   // размер входа в байтах (0 = неизвестен)
	ReadValid      int64   // найдено валидных серийников
	DedupResets    int64   // сколько раз сбросилось окно дедупа (см. DedupWindow)
	AliveRate      float64 // живых в минуту за последнее окно наблюдения (обнова каждые 10с)

	// телеметрия mem-скана префиксов (RunPrefixesMem): нужна движку
	// двухфазного режима для чекпоинта (crashscan.json) и для UI.
	Fed         int64        // atomic: скормлено пайплайну в этом прогоне (после resume-скипа)
	PrefixTotal int64        // atomic: префиксов в прогоне
	PrefixDone  int64        // atomic: префиксов добито
	LastSerial  atomic.Value // string: последний скормленный серийник (обновляется раз в 4096 — без аллокационного шквала)
}

// LastSerialOf — чтение LastSerial без паники на пустом Value (для
// чекпоинта двухфазного движка).
func LastSerialOf(stats *ScanStats) string {
	s, ok := stats.LastSerial.Load().(string)
	if !ok {
		return ""
	}
	return s
}

// CrashHook — вызывается при панике в горутинах пайплайна (воркер/писатель)
// ДО re-panic: движок двухфазного режима успевает force-писать чекпоинт
// скана (crashscan.json/txt). nil — просто re-panic как раньше.
var CrashHook func(recovered any)

// crashGuard — мостик recover'а в хук (nil-безопасно).
func crashGuard(r any) {
	if CrashHook != nil {
		CrashHook(r)
	}
}

// dhResp — мини-парсер DH HTTP-over-UDP ответа облака.
type dhResp struct {
	Code   int
	CSeq   int64
	Body   string
	usNode string // содержимое <US>...</US>, если есть
}

func parseDHResp(data []byte) dhResp {
	r := dhResp{}
	head := data
	rest := ""
	if i := bytes.Index(data, []byte("\r\n\r\n")); i >= 0 {
		head = data[:i]
		rest = string(data[i+4:])
	}
	lines := bytes.Split(head, []byte("\r\n"))
	for i, ln := range lines {
		if i == 0 {
			parts := bytes.SplitN(ln, []byte(" "), 3)
			if len(parts) >= 2 {
				r.Code, _ = strconv.Atoi(string(parts[1]))
			}
			continue
		}
		// CSeq: N — облако эхом возвращает номер запроса; по нему
		// отличаем ответ на НАШ запрос от залипшего чужого
		if j := bytes.IndexByte(ln, byte(':')); j > 0 {
			if bytes.EqualFold(ln[:j], []byte("CSeq")) {
				r.CSeq, _ = strconv.ParseInt(strings.TrimSpace(string(ln[j+1:])), 10, 64)
			}
		}
	}
	r.Body = rest
	r.usNode = strBetween(rest, "<US>", "</US>")
	return r
}

func strBetween(s, open, close string) string {
	i := strings.Index(s, open)
	if i < 0 {
		return ""
	}
	rest := s[i+len(open):]
	j := strings.Index(rest, close)
	if j < 0 {
		return ""
	}
	return rest[:j]
}

func dhReq(method, path, body string, cseq int64, digest, nonce, curdate string) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%s %s HTTP/1.1\r\nCSeq: %d\r\n", method, path, cseq))
	sb.WriteString(fmt.Sprintf("Authorization: WSSE profile=\"UsernameToken\"\r\nX-WSSE: UsernameToken Username=\"%s\", PasswordDigest=\"%s\", Nonce=\"%s\", Created=\"%s\"\r\n",
		USERNAME, digest, nonce, curdate))
	if body != "" {
		sb.WriteString(fmt.Sprintf("Content-Type: \r\nContent-Length: %d\r\n", len(body)))
	}
	sb.WriteString("\r\n" + body)
	return sb.String()
}

func p2pChannelBody(lport int, aid []byte) string {
	aidHex := make([]string, 8)
	for i, b := range aid {
		aidHex[i] = fmt.Sprintf("%x", b)
	}
	return fmt.Sprintf("<body><Identify>%s</Identify><IpEncrpt>true</IpEncrpt><LocalAddr>127.0.0.1:%d</LocalAddr><version>5.0.0</version></body>",
		strings.Join(aidHex, " "), lport)
}

// channelAckAlive — критерий живости (прежний, не менялся): финальный
// 2xx-3xx ack на p2p-channel с непустым <LocalAddr> — устройство само
// отчиталось своим адресом. 2xx без LocalAddr — облако приняло запрос в
// очередь, девайс молчал. 4xx — облако/US ответил финальным отказом.
func channelAckAlive(r dhResp) bool {
	return r.Code >= 200 && r.Code < 400 &&
		strBetween(r.Body, "<LocalAddr>", "</LocalAddr>") != ""
}

// randomAID — 8 случайных байт Identify. На вердикт не влияет (облако их
// не проверяет на существование), поэтому math/rand достаточен — его
// глобальные функции конкурентно-безопасны.
func randomAID() []byte {
	v := rand.Uint64()
	out := make([]byte, 8)
	for i := 0; i < 8; i++ {
		out[i] = byte(v >> (8 * uint(i)))
	}
	return out
}

// inflightChannel — один channel-запрос в полёте.
type inflightChannel struct {
	serial   string
	aid      []byte // Identify этого запроса — нужен teardown после ack
	deadline time.Time
	extended bool      // provisional (1xx) уже продлевал дедлайн
	retries  int       // сколько ретраев уже потрачено на этот серийник
	sentAt   time.Time // для RTT-метрики губернатора
}

// graveEntry — запрос, чей дедлайн истёк: вердикт отложен до ACK_GRACE,
// чтобы опоздавший ack (живой идёт через релей и всегда медленнее
// облачных 404) всё же нашёл свой CSeq. Тишина дольше грейса — ретрай
// (см. expire), а не dead.
type graveEntry struct {
	serial   string
	aid      []byte
	retries  int
	deadline time.Time
}

// channelPipeline — конвейер p2p-channel пробов на одном UDP-сокете.
// Раньше воркер на каждый серийник делал 3 последовательных обмена
// (probe → online → channel), каждый со своим RTT и 3с дедлайном; probe
// и online ничего не дискриминируют (облако по hash-роутингу отвечает
// 200+US и на фиктивный SN — проверено контролем). Теперь на сокет
// уходит окно channel-запросов подряд, ответы мэтчатся по CSeq (уникальный
// глобальный счётчик — залипшие датаграммы прошлых серийников отсекаются
// так же, как раньше). RTT перестаёт складываться — скорость упирается
// в полосу сокета и облако, а не в сумму задержек.
type channelPipeline struct {
	conn                      *net.UDPConn
	lport                     int
	digest, nonceStr, curdate string
	timeout                   time.Duration
	graceTTL                  time.Duration // сколько истёкший запрос живёт в кладбище
	window                    int           // текущее окно в полёте (governor)
	sent                      int64         // отправок в текущем цикле
	resolvedCycle             int64         // ответов в текущем цикле
	expiredCycle              int64         // истёкших без ответа в текущем цикле
	inflight                  map[int64]*inflightChannel
	graveyard                 map[int64]*graveEntry
	counted                   map[string]struct{} // серийники, уже учтённые в Checked
	buf                       []byte
	limiter                   *rateLimiter
	ctx                       context.Context
}

func (p *channelPipeline) waitRate() bool {
	if p.limiter == nil {
		return true
	}
	ctx := p.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	return p.limiter.wait(ctx) == nil
}

func newChannelPipeline(conn *net.UDPConn, timeout time.Duration) *channelPipeline {
	p := &channelPipeline{
		conn:      conn,
		lport:     conn.LocalAddr().(*net.UDPAddr).Port,
		timeout:   timeout,
		graceTTL:  ACK_GRACE,
		window:    PIPELINE_WINDOW,
		inflight:  make(map[int64]*inflightChannel, PIPELINE_WINDOW),
		graveyard: make(map[int64]*graveEntry, PIPELINE_WINDOW),
		counted:   make(map[string]struct{}),
		buf:       make([]byte, 65536),
	}
	// WSSE-блок один на сокет (как раньше): nonce/curdate фиксируются на
	// старте, дайджест считается один раз.
	nonce := time.Now().UnixNano()
	p.nonceStr = fmt.Sprintf("%d", nonce)
	p.curdate = time.Now().UTC().Format("2006-01-02T15:04:05Z")
	pwd := fmt.Sprintf("%d%sDHP2P:%s:%s", nonce, p.curdate, USERNAME, USERKEY)
	hash := sha1.Sum([]byte(pwd))
	p.digest = base64.StdEncoding.EncodeToString(hash[:])

	// warm-up облака — раз на сокет (раньше слался на каждый серийник).
	// Ответ по контенту не проверяется — факт сессии.
	cseq := atomic.AddInt64(&cseqCounter, 1)
	p.write("DHGET", "/probe/p2psrv", "", cseq)
	dl := time.Now().Add(timeout)
	for {
		p.conn.SetReadDeadline(dl)
		n, err := p.conn.Read(p.buf)
		if err != nil {
			break
		}
		if r := parseDHResp(p.buf[:n]); r.CSeq == cseq {
			break
		}
	}
	return p
}

func (p *channelPipeline) write(method, path, body string, cseq int64) bool {
	p.conn.SetWriteDeadline(time.Now().Add(p.timeout))
	_, err := p.conn.Write([]byte(dhReq(method, path, body, cseq, p.digest, p.nonceStr, p.curdate)))
	return err == nil
}

// markChecked — Checked считается один раз на серийник: первая отправка
// (или её невозможность), истечение или вердикт. Ретраи молчунов счётчик
// не двигают — иначе прогресс и суммы врали бы.
func (p *channelPipeline) markChecked(serial string, stats *ScanStats) {
	if _, ok := p.counted[serial]; !ok {
		p.counted[serial] = struct{}{}
		atomic.AddInt64(&stats.Checked, 1)
	}
}

// sendFail — сокет умер на записи: финальный dead, ретраить нечего
// (умрёт и следующая запись).
func (p *channelPipeline) sendFail(serial string, stats *ScanStats) {
	p.markChecked(serial, stats)
	atomic.AddInt64(&stats.Dead, 1)
}

// send ставит channel-проб серийника в окно. false — сокет умер на записи.
func (p *channelPipeline) send(serial string) bool {
	if !p.waitRate() {
		return false
	}
	cseq := atomic.AddInt64(&cseqCounter, 1)
	aid := randomAID()
	if !p.write("DHPOST", fmt.Sprintf("/device/%s/p2p-channel", serial), p2pChannelBody(p.lport, aid), cseq) {
		protolog("× %s send fail (socket write, cseq=%d)", serial, cseq)
		govRecordErr()
		return false
	}
	protolog("> DHPOST /device/%s/p2p-channel cseq=%d", serial, cseq)
	p.inflight[cseq] = &inflightChannel{serial: serial, aid: aid, deadline: time.Now().Add(p.timeout), sentAt: time.Now()}
	p.sent++
	return true
}

// readResp читает одну датаграмму с дедлайном dl.
func (p *channelPipeline) readResp(dl time.Time) (dhResp, bool) {
	p.conn.SetReadDeadline(dl)
	n, err := p.conn.Read(p.buf)
	if err != nil {
		return dhResp{}, false
	}
	return parseDHResp(p.buf[:n]), true
}

// minDeadline — ближайший дедлайн среди окна и кладбища.
func (p *channelPipeline) minDeadline() time.Time {
	var m time.Time
	for _, ir := range p.inflight {
		if m.IsZero() || ir.deadline.Before(m) {
			m = ir.deadline
		}
	}
	for _, g := range p.graveyard {
		if m.IsZero() || g.deadline.Before(m) {
			m = g.deadline
		}
	}
	return m
}

// expire: просроченные запросы окна переезжают в кладбище (вердикт
// отложен — ждём опоздавший ack), просроченное кладбище — РЕТРАЙ:
// облако молча дропает пакеты, тишина дольше ACK_GRACE это повод
// переотправить пробу, а не хоронить серийник. Dead — только после
// исчерпания CHANNEL_RETRIES.
func (p *channelPipeline) expire(stats *ScanStats) {
	now := time.Now()
	for c, ir := range p.inflight {
		if now.After(ir.deadline) {
			delete(p.inflight, c)
			p.expiredCycle++
			govRecordTO()
			p.markChecked(ir.serial, stats)
			p.graveyard[c] = &graveEntry{serial: ir.serial, aid: ir.aid, retries: ir.retries, deadline: now.Add(p.graceTTL)}
		}
	}
	for c, g := range p.graveyard {
		if now.After(g.deadline) {
			delete(p.graveyard, c)
			if g.retries >= CHANNEL_RETRIES {
				atomic.AddInt64(&stats.Dead, 1)
				protolog("× %s dead (silence, retries exhausted)", g.serial)
				continue
			}
			p.sendRetry(g, stats)
		}
	}
}

// sendRetry — переотправка замолчавшего серийника новым CSeq.
// Checked не трогаем: серийник посчитан при первой попытке.
func (p *channelPipeline) sendRetry(g *graveEntry, stats *ScanStats) {
	if !p.waitRate() {
		return
	}
	cseq := atomic.AddInt64(&cseqCounter, 1)
	aid := randomAID()
	if !p.write("DHPOST", fmt.Sprintf("/device/%s/p2p-channel", g.serial), p2pChannelBody(p.lport, aid), cseq) {
		govRecordErr()
		p.sendFail(g.serial, stats)
		return
	}
	protolog("~ %s retry %d/%d cseq=%d", g.serial, g.retries+1, CHANNEL_RETRIES, cseq)
	p.inflight[cseq] = &inflightChannel{serial: g.serial, aid: aid, retries: g.retries + 1, deadline: time.Now().Add(p.timeout), sentAt: time.Now()}
	p.sent++
}

// resolve разбирает датаграмму ответа.
func (p *channelPipeline) resolve(r dhResp, aliveCh chan<- string, stats *ScanStats) {
	if r.Code < 200 {
		// provisional (1xx): дедлайн продлевается один раз — так же,
		// как раньше работал второй read с полным таймаутом
		if ir, ok := p.inflight[r.CSeq]; ok && !ir.extended {
			ir.extended = true
			ir.deadline = time.Now().Add(p.timeout)
			protolog("< %d cseq=%d %s (provisional, deadline+)", r.Code, r.CSeq, ir.serial)
		}
		return
	}
	if ir, ok := p.inflight[r.CSeq]; ok {
		delete(p.inflight, r.CSeq)
		p.resolvedCycle++
		p.markChecked(ir.serial, stats)
		if !ir.sentAt.IsZero() {
			govRecordOK(time.Since(ir.sentAt))
		}
		if channelAckAlive(r) {
			atomic.AddInt64(&stats.Alive, 1)
			protolog("< %d cseq=%d %s (alive)", r.Code, r.CSeq, ir.serial)
			aliveCh <- ir.serial
			p.teardown(ir.aid, r)
		} else {
			atomic.AddInt64(&stats.Dead, 1)
			protolog("< %d cseq=%d %s (dead)", r.Code, r.CSeq, ir.serial)
		}
		return
	}
	// CSeq в окне не нашёлся: может, это опоздавший ack из кладбища —
	// тогда он выносит честный вердикт (Checked уже посчитан при первом
	// истечении — здесь лишь раскладываем alive/dead).
	if g, ok := p.graveyard[r.CSeq]; ok {
		delete(p.graveyard, r.CSeq)
		p.resolvedCycle++
		if channelAckAlive(r) {
			atomic.AddInt64(&stats.Alive, 1)
			protolog("< %d cseq=%d %s (late alive)", r.Code, r.CSeq, g.serial)
			aliveCh <- g.serial
			p.teardown(g.aid, r)
		} else {
			atomic.AddInt64(&stats.Dead, 1)
			protolog("< %d cseq=%d %s (late dead)", r.Code, r.CSeq, g.serial)
		}
		return
	}
	// совсем чужой CSeq (залипшая датаграмма прошлой попытки/сокета) —
	// игнорируем полностью: ни вердикта, ни статистики.
}

// teardown — эксперимент (TEARDOWN_ALIVE): после живого ack шлём
// валидный STUN-init (пара по AID) на адреса из ack: напрямую в
// LocalAddr/PubAddr и через облако (conn.Write — путь как в dh-fwd), и
// молчим. Девайс переходит из «ждёт клиента» в «ведёт переговоры», чей
// таймаут короче — бюджет живых сессий в облаке должен освобождаться
// быстрее. Ответы девайса на это — бинарный мусор для DH-потока
// (parseDHResp даёт Code 0) и на вердикты не влияют.
func (p *channelPipeline) teardown(aid []byte, ack dhResp) {
	if !TEARDOWN_ALIVE {
		return
	}
	invAid := make([]byte, 8)
	for i, b := range aid {
		invAid[i] = ^b
	}
	build := func(eaddr []byte) []byte {
		out := make([]byte, 0, 40)
		out = append(out, 0xFF, 0xFE, 0xFF, 0xE7)
		c1, c2 := randomAID(), randomAID()
		out = append(out, c1[:4]...) // cookie
		out = append(out, c2[:]...)  // transID (12)
		out = append(out, c1[4:]...)
		out = append(out, 0x7F, 0xD5, 0xFF, 0xF7)
		out = append(out, invAid...)
		out = append(out, 0xFF, 0xFB, 0xFF, 0xF7, 0xFF, 0xFE)
		out = append(out, eaddr...)
		return out
	}
	for _, addrStr := range []string{
		strBetween(ack.Body, "<LocalAddr>", "</LocalAddr>"),
		strBetween(ack.Body, "<PubAddr>", "</PubAddr>"),
	} {
		host, portStr, err := net.SplitHostPort(addrStr)
		if err != nil {
			continue
		}
		port, err := strconv.Atoi(portStr)
		if err != nil {
			continue
		}
		ip := net.ParseIP(host).To4()
		if ip == nil {
			continue
		}
		eaddr := make([]byte, 6)
		binary.BigEndian.PutUint16(eaddr[0:2], uint16(port))
		copy(eaddr[2:], ip)
		for i := range eaddr {
			eaddr[i] = ^eaddr[i]
		}
		init := build(eaddr)
		p.conn.WriteTo(init, &net.UDPAddr{IP: ip, Port: port}) // напрямую
		p.conn.Write(init)                                     // через облако
	}
}

// govern — адаптивное окно: доля истёкших без ответа ниже 2% — облако
// отвечает нормально, окно растёт; выше 10% — облако дропает, окно сжимается.
func (p *channelPipeline) govern() {
	total := p.resolvedCycle + p.expiredCycle
	if total == 0 {
		return
	}
	share := float64(p.expiredCycle) / float64(total)
	switch {
	case share < 0.02:
		p.window += GOV_GROW
		if p.window > W_MAX {
			p.window = W_MAX
		}
	case share > 0.10:
		p.window -= GOV_SHRINK
		if p.window < W_MIN {
			p.window = W_MIN
		}
	}
	p.sent = 0
	p.resolvedCycle, p.expiredCycle = 0, 0
}

// run — главный цикл воркера: непрерывный скользящий конвейер (sliding window).
// Новые запросы уходят сразу, как только освобождается слот в p.window, не
// дожидаясь опорожнения всего окна (устраняет stop-and-wait задержку).
func (p *channelPipeline) run(ctx context.Context, jobs <-chan string, aliveCh chan<- string, stats *ScanStats) {
	p.ctx = ctx
	for {
		if ctx.Err() != nil {
			return
		}

		// Дозаполняем окно до p.window, пока в jobs есть данные
		for len(p.inflight) < p.window {
			select {
			case <-ctx.Done():
				return
			case s, ok := <-jobs:
				if !ok {
					goto drain
				}
				if !p.send(s) {
					if ctx.Err() != nil {
						return
					}
					p.sendFail(s, stats)
				}
			default:
				// в jobs прямо сейчас нет готовых элементов — переходим к чтению
				goto readPhase
			}
		}

	readPhase:
		// Если ничего не летит и в кладбище пусто — ждём блокирующе новую работу
		if len(p.inflight) == 0 && len(p.graveyard) == 0 {
			select {
			case <-ctx.Done():
				return
			case s, ok := <-jobs:
				if !ok {
					return
				}
				if !p.send(s) {
					if ctx.Err() != nil {
						return
					}
					p.sendFail(s, stats)
				}
			}
			continue
		}

		// Читаем датаграмму или обрабатываем таймаут
		p.pump(ctx, aliveCh, stats)

		// Адаптируем окно по завершении порции запросов
		if (p.resolvedCycle + p.expiredCycle) >= int64(p.window) {
			p.govern()
		}
	}

drain:
	// jobs закрыты: дожидаемся завершения окна и кладбища
	for (len(p.inflight) > 0 || len(p.graveyard) > 0) && ctx.Err() == nil {
		p.pump(ctx, aliveCh, stats)
		if (p.resolvedCycle + p.expiredCycle) >= int64(p.window) {
			p.govern()
		}
	}
}

// pump — одна итерация чтения: читает датаграмму до ближайшего дедлайна
// (окно+кладбище), expiry — при тишине. Читаем даже за просроченным
// дедлайном с миллисекундным окном: датаграмма могла уже лежать в буфере.
func (p *channelPipeline) pump(ctx context.Context, aliveCh chan<- string, stats *ScanStats) {
	dl := p.minDeadline()
	now := time.Now()
	wait := dl.Sub(now)
	if wait < time.Millisecond {
		wait = time.Millisecond
	}
	r, got := p.readResp(now.Add(wait))
	if !got {
		p.expire(stats)
		return
	}
	p.resolve(r, aliveCh, stats)
	p.expire(stats)
}

func scanWorker(ctx context.Context, conn *net.UDPConn, jobs <-chan string, aliveCh chan<- string, stats *ScanStats, timeout time.Duration, limiter *rateLimiter) {
	p := newChannelPipeline(conn, timeout)
	p.limiter = limiter
	p.run(ctx, jobs, aliveCh, stats)
}

// readSerialsFile — загрузка входного файла в два прохода с прогрессом
// в stats: фаза 1 быстро считает строки (чистый подсчёт \n по чанкам —
// бар знает свой 100% заранее), фаза 2 санитайзит серийники и двигает бар.
const (
	// ReadBufSize — буфер последовательного чтения входа (один ридер —
	// диск любит последовательность; 4 МБ сглаживают рывки).
	ReadBufSize = 4 << 20
	// ScanBufMax — потолок строки входа для bufio.Scanner.
	ScanBufMax = 1 << 20
	// DedupWindow — сколько уникальных серийников держим для дедупа.
	// Дальше окно сбрасывается (память фиксирована ~десятки МБ): дубли
	// через границу окна уйдут в повторный проб, но на выход не задвоятся
	// (writer давит повторы через seenAlive — живых мало, мапа крошечная).
	DedupWindow = 1 << 20
)

// countReader — считает байты, прочитанные из входа, для прогресса.
// Атомарно: продьюсер в своей горутине, UI тикает из другой.
type countReader struct {
	r io.Reader
	n *int64
}

func (c *countReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	if n > 0 {
		atomic.AddInt64(c.n, int64(n))
	}
	return n, err
}

// emitEvent — одна строка в канал событий без блокировки (канал может
// быть nil или забит — тогда молча пропускаем).
func emitEvent(events chan<- string, s string) {
	if events == nil {
		return
	}
	select {
	case events <- s:
	default:
	}
}

// Debug — тумблер протокольного логирования (дампы DH-запросов/ответов
// как в dh-fwd: направление, метод/код, CSeq, серийник).
// Осторожно: на миллионах проб лог распухает до гигабайтов.
var Debug bool

// LogHook — кастомный логгер протокола (nil = молча).
// Дёргается из хот-пасса воркеров — обязана быть быстрой и потокобезопасной.
var LogHook func(string)

// protolog — одна строка протокола в хук (ноль работы при выключенном дебаге).
func protolog(format string, args ...any) {
	if !Debug || LogHook == nil {
		return
	}
	LogHook(fmt.Sprintf(format, args...))
}

// streamSerials — стрим-поставщик серийников: один проход по файлу, санитайз
// без аллокаций (string только для валидных), дедуп окном фиксированного
// размера, прогресс по байтам (stats.Total растёт по мере отдачи — бар
// скана честный). Ничего не копит: память O(окно), а не O(файл) —
// многогигабайтные входы не жрут RAM. Закрывает out по завершении.
// Возвращает число отданных уникальных и текст ошибки ("" = ок).
// dedupWindow — размер окна дедупа (тесты подсовывают маленькое).
func streamSerials(ctx context.Context, f *os.File, stats *ScanStats, events chan<- string, out chan<- string, dedupWindow int) (int64, string) {
	atomic.StoreInt64(&stats.Reading, 1)
	defer atomic.StoreInt64(&stats.Reading, 0)
	defer close(out)

	if dedupWindow < 1 {
		dedupWindow = DedupWindow
	}
	var readBytes int64
	sc := bufio.NewScanner(&countReader{r: f, n: &readBytes})
	sc.Buffer(make([]byte, 64*1024), ScanBufMax)

	seen := make(map[string]struct{})
	var emitted, lines, valid, resets int64
	flush := func() {
		atomic.StoreInt64(&stats.ReadLines, lines)
		atomic.StoreInt64(&stats.ReadValid, valid)
		atomic.StoreInt64(&stats.Total, emitted)
	}
	for sc.Scan() {
		lines++
		s := ironscan.SanitizeSerialBytes(sc.Bytes())
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		if len(seen) >= dedupWindow {
			seen = make(map[string]struct{})
			resets++
		}
		select {
		case <-ctx.Done():
			flush()
			return emitted, ""
		case out <- s:
		}
		emitted++
		valid++
		if emitted&4095 == 0 {
			flush()
		}
	}
	flush()
	atomic.StoreInt64(&stats.ReadBytes, readBytes)
	atomic.StoreInt64(&stats.DedupResets, resets)
	if resets > 0 {
		emitEvent(events, "[SYS] "+fmt.Sprintf(i18n.Tr("дедуп-окно переполнено %d раз(а) — дубли могли уйти в повторный проб"), resets))
	}
	if err := sc.Err(); err != nil {
		return emitted, i18n.Tr("ошибка чтения входного файла: ") + err.Error()
	}
	return emitted, ""
}

// lookupCloudIPs — все IPv4 A-записи облака. Бюджеты облака могут
// вестись на пару клиент↔сервер: распределение воркеров по всем адресам
// (round-robin) даёт шанс масштабировать бюджет на число серверов.
// Пустой срез — фолбэк на единственный адрес через ResolveUDPAddr.
func lookupCloudIPs() []net.IP {
	ips, err := net.LookupIP(MAIN_SERVER)
	if err != nil {
		return nil
	}
	var v4 []net.IP
	for _, ip := range ips {
		if ip4 := ip.To4(); ip4 != nil {
			v4 = append(v4, ip4)
		}
	}
	return v4
}

// newEgress — шов для будущих исходящих идентичностей (SOCKS5 UDP
// ASSOCIATE и т.п.): сокет на облако создаётся только здесь. При появлении
// прокси пул egress'ов раздаётся воркерам вместо round-robin по IP.
func newEgress(ip net.IP) (*net.UDPConn, error) {
	conn, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: ip, Port: MAIN_PORT})
	if err != nil {
		return nil, err
	}
	conn.SetWriteBuffer(SOCKET_BUF)
	// окно W_MAX ответов в полёте + запас на burst — 256КБ
	conn.SetReadBuffer(256 * 1024)
	return conn, nil
}

// openOutput — выходной файл + буферизированный writer.
// appendMode: true — дописывать в конец (накопление по префиксам),
// false — перезаписать файл текущим прогоном.
func openOutput(outputFile string, appendMode bool, stats *ScanStats) (*os.File, *bufio.Writer, string) {
	outFlags := os.O_CREATE | os.O_WRONLY | os.O_APPEND
	if !appendMode {
		outFlags |= os.O_TRUNC
	}
	outFile, err := os.OpenFile(outputFile, outFlags, 0644)
	if err != nil {
		return nil, nil, i18n.Tr("ошибка создания выходного файла: ") + err.Error()
	}
	return outFile, bufio.NewWriterSize(outFile, 256*1024), ""
}

// runPipe — общий движок скана: лимиты ОС, резолв облака, egress-сокеты,
// воркеры, писатель с seenAlive (каждый живой отдаётся в sink один раз;
// seedAlive — предзагруженные живые для resume), updater статистики.
// sink — приёмник живых серийников (файловый writer или колбэк mem-скана;
// сам отвечает за флеш/потокобезопасность). feed льёт серийники в jobs
// (бэкпрешер полного канала — память плоская) и закрывает его.
// Возвращает текст ошибки ("" = ок).
func runPipe(ctx context.Context, stats *ScanStats, events chan<- string, sink func(string), workers int, feed func(jobs chan string), seedAlive map[string]struct{}) string {
	// Лимиты ОС — сами, чтобы юзер не парился: на линуксе мягкий лимит fd
	// поднимаем через Setrlimit, на винде берём безопасный кап.
	wantWorkers := workers
	lim := syslimits.Ensure()
	workers = lim.ClampWorkers(workers)
	if lim.Raised {
		emitEvent(events, "[SYS] fd limit "+strconv.FormatUint(lim.FDBefore, 10)+" → "+strconv.FormatUint(lim.FDAfter, 10))
	}
	if lim.ManualFix != "" {
		emitEvent(events, "[SYS] "+i18n.Tr("подними лимит вручную: ")+lim.ManualFix)
	}

	cloudIPs := lookupCloudIPs()
	if len(cloudIPs) == 0 {
		if raddr, rerr := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", MAIN_SERVER, MAIN_PORT)); rerr == nil {
			cloudIPs = []net.IP{raddr.IP}
		}
	}
	if len(cloudIPs) == 0 {
		return i18n.Tr("ошибка резолва сервера: ") + MAIN_SERVER
	}
	// «пинг» = резолв облака: без сети скан невозможен, юзер видит,
	// что прогон не завис, а стучится к серверу
	emitEvent(events, "[SYS] "+fmt.Sprintf(i18n.Tr("пинг %s — ок"), fmt.Sprintf("%s:%d", MAIN_SERVER, MAIN_PORT)))

	conns := make([]*net.UDPConn, 0, workers)
	for i := 0; i < workers; i++ {
		conn, err := newEgress(cloudIPs[i%len(cloudIPs)])
		if err != nil {
			workers = i
			break
		}
		conns = append(conns, conn)
	}

	if len(conns) == 0 {
		return i18n.Tr("не смог создать сокеты (фикс: ") + syslimits.SocketHint() + ")"
	}
	// фактическое число воркеров — ПОСЛЕ создания сокетов: сокет умер на
	// середине — счётчик честно меньше запрошенного
	emitEvent(events, "[SYS] "+fmt.Sprintf(i18n.Tr("воркеров: %d"), len(conns)))
	if workers < wantWorkers {
		emitEvent(events, "[SYS] "+fmt.Sprintf(i18n.Tr("лимит ОС: воркеров не больше %d"), lim.MaxWorkers))
	}
	defer func() {
		for _, conn := range conns {
			conn.Close()
		}
	}()

	// Один круг: воркеры на живых сокетах, alive сразу в выходной файл.
	// Тишина облака отрабатывается ретраями внутри пайплайна
	// (expire → sendRetry) — отдельных кругов нет.
	limiter := newRateLimiter(govStartPPS, BURST_LIMIT)
	// губернатор AIMD: старт с безопасного минимума, дальше сам находит
	// предел канала/роутера и держится у него
	go governorLoop(ctx, limiter)
	jobs := make(chan string, workers*10)
	aliveCh := make(chan string, workers*10)

	var rwg sync.WaitGroup
	for _, conn := range conns {
		rwg.Add(1)
		go func(c *net.UDPConn) {
			defer rwg.Done()
			// Паника воркера = смерть процесса, но ДО неё движок двухфазного
			// режима успевает дампить чекпоинт скана (см. CrashHook).
			defer func() {
				if r := recover(); r != nil {
					crashGuard(r)
					panic(r)
				}
			}()
			scanWorker(ctx, c, jobs, aliveCh, stats, ACK_TIMEOUT, limiter)
		}(conn)
	}

	var writeWg sync.WaitGroup
	writeWg.Add(1)
	// seenAlive давит повторы на выходе: дубли через границу дедуп-окна
	// могут уйти в повторный проб, но в приёмник каждый живой попадает
	// один раз. Живых на порядки меньше входа — мапа крошечная.
	seenAlive := make(map[string]struct{}, len(seedAlive))
	for s := range seedAlive {
		seenAlive[s] = struct{}{}
	}
	go func() {
		defer writeWg.Done()
		defer func() {
			if r := recover(); r != nil {
				crashGuard(r)
				panic(r)
			}
		}()
		for s := range aliveCh {
			if _, ok := seenAlive[s]; ok {
				continue
			}
			seenAlive[s] = struct{}{}
			sink(s)
			emitEvent(events, "[VALID] "+s)
		}
	}()

	// Stats updater loop стартует ДО фида (иначе скорость мёртвая всё время
	// подачи входа). ETA выпилен — врёт.
	start := time.Now()
	updStop := make(chan struct{})
	var lastAliveMark int64
	lastAliveT := start
	go func() {
		ticker := time.NewTicker(300 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-updStop:
				return
			case <-ticker.C:
				checked := atomic.LoadInt64(&stats.Checked)
				elapsed := time.Since(start).Seconds()
				if elapsed > 0 {
					stats.Speed = float64(checked) / elapsed
				}
				// alive/мин за последнее 10-секундное окно: отличает
				// «застряло намертво» от «капает по бюджету облака»
				now := time.Now()
				if now.Sub(lastAliveT) >= 10*time.Second {
					alive := atomic.LoadInt64(&stats.Alive)
					stats.AliveRate = float64(alive-lastAliveMark) / now.Sub(lastAliveT).Seconds() * 60
					lastAliveMark, lastAliveT = alive, now
				}
			}
		}
	}()

	feed(jobs)

	rwg.Wait()
	close(aliveCh)
	writeWg.Wait()

	// Круг один: ретраи молчунов — внутри пайплайна, второго круга нет.
	// Хроника молчит после всех ретраев — это оффлайн, а не медленный ack.
	close(updStop)
	return ""
}

func RunScanner(ctx context.Context, inputFile, outputFile string, appendMode bool, workers int, stats *ScanStats, events chan<- string) {
	defer func() { stats.Done = true }()

	// Вход читаем стримом (см. streamSerials) — в RAM ничего не копим,
	// поэтому многогигабайтные файлы не жрут память. Размер нужен сразу
	// для прогресса по байтам.
	f, err := os.Open(inputFile)
	if err != nil {
		stats.ErrorMsg = i18n.Tr("ошибка открытия входного файла: ") + err.Error()
		return
	}
	fi, serr := f.Stat()
	if serr != nil {
		f.Close()
		stats.ErrorMsg = i18n.Tr("ошибка открытия входного файла: ") + serr.Error()
		return
	}
	if fi.Size() == 0 {
		f.Close()
		stats.ErrorMsg = i18n.Tr("Файл пуст")
		return
	}
	atomic.StoreInt64(&stats.ReadTotalBytes, fi.Size())

	outFile, outWriter, oerr := openOutput(outputFile, appendMode, stats)
	if oerr != "" {
		f.Close()
		stats.ErrorMsg = oerr
		return
	}
	defer outFile.Close()

	// Один круг: продьюсер льёт валидные серийники в jobs по мере чтения
	// (бэкпрешер полного канала тормозит ридер — RAM плоская), jobs
	// закрывается концом входа. Ретраи молчунов — внутри пайплайна,
	// второго круга нет.
	sink := func(s string) {
		outWriter.WriteString(s + "\n")
		outWriter.Flush() // пишем сразу в файл, а не в память
	}
	var emitted int64
	var feedErr string
	feed := func(jobs chan string) {
		emitted, feedErr = streamSerials(ctx, f, stats, events, jobs, DedupWindow)
		f.Close()
	}
	if perr := runPipe(ctx, stats, events, sink, workers, feed, nil); perr != "" {
		stats.ErrorMsg = perr
		return
	}
	if feedErr != "" {
		stats.ErrorMsg = feedErr
	}
	if emitted == 0 && stats.ErrorMsg == "" {
		stats.ErrorMsg = i18n.Tr("Файл пуст")
	}
}
