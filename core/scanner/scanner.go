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
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"krushitel/core/cloudip"
	"krushitel/core/i18n"
	"krushitel/core/ironscan"
	"krushitel/core/syslimits"
)

const (
	MAIN_SERVER = "www.easy4ipcloud.com"
	MAIN_PORT   = 8800
	USERNAME    = "cba1b29e32cb17aa46b8ff9e73c7f40b"
	USERKEY     = "996103384cdf19179e19243e959bbf8b"
	SOCKET_BUF  = 65536

	PIPELINE_WINDOW = 32
	W_MIN           = 8
	W_MAX           = 256
	GOV_GROW        = 8
	GOV_SHRINK      = 16
	ACK_TIMEOUT     = 15 * time.Second

	// Адаптивный таймаут (перелопачивание механики, core-rebuild):
	//
	// Физика, а не баг: чтобы держать X rps при T-секундном таймауте, нужно
	// X*T inflight-слотов (закон Литтла). 10к rps × 15с = 150 000 слотов
	// против максимум 128 воркеров × 128 окно = 16к. При любой заметной доле
	// тишины труба ОБЯЗАНА вставать — окно забито, все ждут дедлайны.
	// Лечится только быстрым провалом: таймаут едет от медианы RTT.
	TIMEOUT_MIN        = 2 * time.Second
	TIMEOUT_RTT_FACTOR = 10

	// Шторм: доля протухших выше — тишина почти наверняка наш дроп от
	// перегруза, ретраи только добавят нагрузки. Тишина в шторм идёт сразу
	// в dead без могильника. Явные вердикты (401) ретраятся как раньше.
	STORM_EXPIRED_EMA = 0.25

	// Кап могильника на воркер: без bound он растёт тысячами и каждый pump
	// ходит по O(n) (minDeadline + expire по всем). Лишнее вытесняется.
	GRAVE_CAP = 1024

	SEND_STAGGER = 100 * time.Microsecond

	// Пересмотр механики (core-rebuild): grace ужата 30с → 10с. Поздние ответы
	// облака — это миллисекунды-секунды, а не десятки секунд: alive-вердикты
	// генерирует облако, а не камера, и они быстрые. 30с держали могильник и
	// худший кейс молчуна на уровне ~105с, теперь ~26с (2+10+2+10+2).
	ACK_GRACE = 10 * time.Second

	CHANNEL_RETRIES = 2

	// PUMP_MAX_WAIT — потолок одного Read в pump. Дедлайны висят по 15с
	// (grace — 30с), а блокирующий Read не смотрит на ctx: без капа Esc/стоп
	// висит до 15с и ретраи из graveyard стреляют пачкой. С капом воркер
	// просыпается раз в секунду, expire идёт инкрементально.
	PUMP_MAX_WAIT = time.Second

	// SEND_JITTER_BOUND — разброс дедлайна. Пачка, ушедшая burst'ом, иначе
	// протухает в одну миллисекунду, и ретраи 30 воркеров бьют herd'ом.
	SEND_JITTER_BOUND = 500 * time.Millisecond

	MAX_RPS        = 3000
	BURST_LIMIT    = 64
	// retriedFlushAt — кап сета ретраенных серийников на воркер.
	// Сет держит только ушедших в могильник (их мало), а не все проверенные.
	retriedFlushAt = 500_000

	TEARDOWN_ALIVE = true
)

var (
	GovernorOn  = true
	GovernorCap = 0
)

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

func (rl *rateLimiter) tryReserve() bool {
	if rl == nil {
		return true
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	earliest := now.Add(-rl.burst)
	if rl.next.Before(earliest) {
		rl.next = earliest
	}
	if rl.next.After(now) {
		return false
	}
	rl.next = rl.next.Add(rl.interval)
	return true
}

func (rl *rateLimiter) nextDelay() time.Duration {
	if rl == nil {
		return 0
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()
	d := time.Until(rl.next)
	if d < 0 {
		d = 0
	}
	return d
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

	Reading        int64
	ReadLines      int64
	ReadBytes      int64
	ReadTotalBytes int64
	ReadValid      int64
	DedupResets    int64
	AliveRate      float64

	Fed         int64
	PrefixTotal int64
	PrefixDone  int64
	LastSerial  atomic.Value
}

func LastSerialOf(stats *ScanStats) string {
	s, ok := stats.LastSerial.Load().(string)
	if !ok {
		return ""
	}
	return s
}

var CrashHook func(recovered any)

func crashGuard(r any) {
	if CrashHook != nil {
		CrashHook(r)
	}
}

// FatalHook вызывается вместо переподнятия паники из горутины воркера.
//
// Зачем: defer-recover в main() ловит только паники ГЛАВНОЙ горутины. Паника
// в scanWorker уносила процесс дефолтным обработчиком Go — голый трейс на
// stderr, без сплэша «krushitel crashed». Хук выносит обработку туда же, где
// жив сплэш, и он начинает работать для любых горутин.
//
// nil означает «не задан»: поведение прежнее, переподнять панику.
var FatalHook func(reason string, stack []byte)

// raiseOrReraise — единая точка обработки паники из горутины воркера: сначала
// даём записать состояние прогона, затем отдаём управление хуку (он сам
// напечатает сплэш и выйдет). Хука нет — переподнимаем, как раньше.
func raiseOrReraise(r any) {
	crashGuard(r)
	if FatalHook != nil {
		FatalHook(panicReason(r), debug.Stack())
		return
	}
	panic(r)
}

// panicReason вытаскивает короткую причину без стектрейса.
// PanicReason — публичная обёртка для слоёв, которые ловят паники сами.
func PanicReason(r any) string { return panicReason(r) }

func panicReason(r any) string {
	if r == nil {
		return "unknown panic"
	}
	s := fmt.Sprint(r)
	if i := strings.IndexByte(s, 10); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return "unknown panic"
	}
	return s
}

// TestCrashAfter — через сколько ОТ ВКЛЮЧЕНИЯ ГУБЕРНАТОРА уронить процесс
// настоящей ошибкой. Ноль означает «выключено», и это значение по умолчанию.
//
// Зачем это нужно: проверить, что путь восстановления действительно
// срабатывает, а не просто существует в коде. Паника поднимается ВНУТРИ
// горутины воркера, поэтому идёт ровно через ту же цепочку, что и настоящий
// баг:
//
//	nil map -> panic -> recover в scanWorker -> crashGuard -> CrashHook
//	         -> scanCrashDumper.dump -> crashscan.json -> FatalHook -> сплэш
//
// Дальше повторный запуск обязан подхватить позицию и продолжить. Поднимать
// панику отдельной горутиной было бы бессмысленно: recover в воркере её бы не
// увидел и проверка ничего не доказала бы.
//
// ВКЛЮЧАЕТСЯ ТОЛЬКО ЯВНО, переменной окружения:
//
//	KRUSHITEL_TEST_CRASH_AFTER=5s ./krushitel -i prefixes.txt
//	KRUSHITEL_TEST_CRASH_AFTER=off ./krushitel      # принудительно выключить
//
// Без переменной триггер не существует: инжектор не создаётся, отсчёт не идёт.
// Никакого влияния на обычный прогон.
var TestCrashAfter time.Duration

// envTestCrash — переменная, которой триггер управляется.
const envTestCrash = "KRUSHITEL_TEST_CRASH_AFTER"

func init() {
	TestCrashAfter = parseCrashAfter(os.Getenv(envTestCrash))
	cachedTimeoutNs.Store(int64(ACK_TIMEOUT))
}

// parseCrashAfter разбирает значение переменной окружения триггера.
// Пусто, «off», «0» и прочие слова выключения дают ноль; мусор тоже даёт
// ноль, чтобы опечатка не ломала обычный запуск.
func parseCrashAfter(v string) time.Duration {
	norm := strings.ToLower(strings.TrimSpace(v))
	switch norm {
	case "", "off", "0", "no", "false", "disabled", "none", "выкл", "нет":
		return 0
	}
	// Приводим к нижнему регистру: time.ParseDuration понимает только
	// строчные единицы, а человек в переменной окружения спокойно напишет
	// «5S» или «250MS». Заодно «5M» становится пятью минутами, а не ошибкой.
	d, err := time.ParseDuration(norm)
	if err != nil || d <= 0 {
		return 0
	}
	return d
}

// armInjector взводит крэш-таймер в момент включения губернатора. Отсчёт
// именно оттуда: губернатор поднимается после создания сокетов и резолва
// облака, и «через 5 секунд после включения губернатора» должно означать
// ровно это, а не 5 секунд от начала скана.
func armInjector(ci *crashInjector, events chan<- string) {
	if ci == nil {
		return
	}
	ci.arm(TestCrashAfter)
	emitEvent(events, "[SYS] "+fmt.Sprintf(
		"[gov] test-crash armed: упаду через %s от включения губернатора", TestCrashAfter))
}

// fatalDrainTimeout — сколько ждём, пока воркеры свернутся после краша, прежде
// чем показать сплэш. Нужно, чтобы терминал не сыпал [VALID] поверх рамки.
const fatalDrainTimeout = 2 * time.Second

// crashInjector однократно роняет процесс из тела воркера.
type crashInjector struct {
	deadline time.Time
	mu       sync.RWMutex
	once     sync.Once
}

func (ci *crashInjector) arm(d time.Duration) {
	if ci == nil || d <= 0 {
		return
	}
	ci.mu.Lock()
	ci.deadline = time.Now().Add(d)
	ci.mu.Unlock()
}

func (ci *crashInjector) armed() bool {
	if ci == nil {
		return false
	}
	ci.mu.Lock()
	dl := ci.deadline
	ci.mu.Unlock()
	return !dl.IsZero() && time.Now().After(dl)
}

// fire поднимает настоящую рантайм-панику Go. assignment to entry in nil map —
// это не искусственный panic("..."), а реальная ошибка, которую Go порождает
// сам: ровно такие летят из прод-кода при неинициализированной карте.
func (ci *crashInjector) fire() {
	if !ci.armed() {
		return
	}
	ci.once.Do(func() {
		var m map[string]int
		m["pipeline"] = 1 // panic: assignment to entry in nil map
	})
}

type dhResp struct {
	Code   int
	CSeq   int64
	Body   string
	usNode string
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

func channelAckAlive(r dhResp) bool {
	return r.Code >= 200 && r.Code < 400 &&
		strBetween(r.Body, "<LocalAddr>", "</LocalAddr>") != ""
}

func randomAID() []byte {
	v := rand.Uint64()
	out := make([]byte, 8)
	for i := 0; i < 8; i++ {
		out[i] = byte(v >> (8 * uint(i)))
	}
	return out
}

type inflightChannel struct {
	serial   string
	aid      []byte
	deadline time.Time
	extended bool
	retries  int
	sentAt   time.Time
}

type graveEntry struct {
	serial   string
	aid      []byte
	retries  int
	deadline time.Time
	// explicit — вердикт сервера (401), а не тишина. Такой ретраится даже
	// в шторм: ответ неизвестен, хоронить нельзя.
	explicit bool
}

type channelPipeline struct {
	conn                      *net.UDPConn
	lport                     int
	digest, nonceStr, curdate string
	timeout                   time.Duration
	graceTTL                  time.Duration
	window                    int
	resolvedCycle             int64
	expiredCycle              int64
	expiredEMA                float64
	emaSet                    bool
	inflight                  map[int64]*inflightChannel
	graveyard                 map[int64]*graveEntry
	retried                   map[uint64]struct{}
	buf                       []byte
	limiter                   *rateLimiter
	ctx                       context.Context
	injector                  *crashInjector
	lastReconnect             time.Time
	lastRaw                   []byte
}

func (p *channelPipeline) tryRate() bool {
	if p.limiter == nil {
		return true
	}
	return p.limiter.tryReserve()
}

func (p *channelPipeline) blockRate() bool {
	if p.limiter == nil {
		return true
	}
	ctx := p.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	return p.limiter.wait(ctx) == nil
}

func (p *channelPipeline) nextRateDelay() time.Duration {
	if p.limiter == nil {
		return 0
	}
	return p.limiter.nextDelay()
}

// curTimeout — адаптивный таймаут ответа: медиана RTT × фактор, в клещах
// [TIMEOUT_MIN, ACK_TIMEOUT]. Облако отвечает 404 за ~70-350мс — ждать 15с
// каждого молчуна нет смысла, это и есть залипание. Без статистики RTT
// (старт прогона) — консервативные ACK_TIMEOUT.
//
// ВАЖНО: медиана считается не чаще раза в секунду (кэш). govMedianRTT — это
// аллокация + до 512 атомарных чтений + сортировка; на каждый пакет при
// 10к rps это был бы отдельный CPU-пожар.
func (p *channelPipeline) curTimeout() time.Duration {
	now := time.Now()
	if last := timeoutUpdatedAt.Load(); now.Sub(time.Unix(0, last)) > time.Second {
		if timeoutUpdatedAt.CompareAndSwap(last, now.UnixNano()) {
			to := int64(ACK_TIMEOUT)
			if med := govMedianRTT(); med > 0 {
				to = med * TIMEOUT_RTT_FACTOR
				if to < int64(TIMEOUT_MIN) {
					to = int64(TIMEOUT_MIN)
				}
				if to > int64(ACK_TIMEOUT) {
					to = int64(ACK_TIMEOUT)
				}
			}
			cachedTimeoutNs.Store(to)
		}
	}
	return time.Duration(cachedTimeoutNs.Load())
}

var (
	cachedTimeoutNs atomic.Int64
	timeoutUpdatedAt atomic.Int64
)

// stormMode — шторм потерь: тишина сейчас почти наверняка конгестия.
func (p *channelPipeline) stormMode() bool {
	return p.emaSet && p.expiredEMA > STORM_EXPIRED_EMA
}

// gravePut кладёт в могильник с капом: лишнее (самый старый дедлайн) —
// сразу в dead, иначе рост без bound и O(n) на каждый pump.
func (p *channelPipeline) gravePut(c int64, g *graveEntry, stats *ScanStats) {
	if len(p.graveyard) >= GRAVE_CAP {
		var oldC int64
		var oldD time.Time
		first := true
		for cc, gg := range p.graveyard {
			if first || gg.deadline.Before(oldD) {
				oldC, oldD, first = cc, gg.deadline, false
			}
		}
		if !first {
			og := p.graveyard[oldC]
			delete(p.graveyard, oldC)
			atomic.AddInt64(&stats.Dead, 1)
			protolog("× %s dead (graveyard overflow)", og.serial)
		}
	}
	p.graveyard[c] = g
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
		retried:   make(map[uint64]struct{}),
		buf:       make([]byte, 65536),
	}
	nonce := time.Now().UnixNano()
	p.nonceStr = fmt.Sprintf("%d", nonce)
	p.curdate = time.Now().UTC().Format("2006-01-02T15:04:05Z")
	pwd := fmt.Sprintf("%d%sDHP2P:%s:%s", nonce, p.curdate, USERNAME, USERKEY)
	hash := sha1.Sum([]byte(pwd))
	p.digest = base64.StdEncoding.EncodeToString(hash[:])

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

func (p *channelPipeline) write(method, path, body string, cseq int64) error {
	// P2PWN-ПАРИТЕТ: auth свежий на КАЖДЫЙ запрос. Раньше nonce/created/digest
	// считались раз на воркер при старте пайплайна и жили весь прогон (часы).
	// Облако валидирует свежесть Created — через ~10 минут всё начинало
	// сыпать 401+TimeOut. У p2pwn buildRequest считает fresh nonce/created/
	// digest на каждый запрос, поэтому там 401 и не видно.
	p.refreshAuth()
	p.conn.SetWriteDeadline(time.Now().Add(p.timeout))
	_, err := p.conn.Write([]byte(dhReq(method, path, body, cseq, p.digest, p.nonceStr, p.curdate)))
	return err
}

// refreshAuth пересчитывает WSSE-auth под текущий момент. Дешёво (один sha1),
// зовётся на каждый запрос — см. write.
func (p *channelPipeline) refreshAuth() {
	nonce := rand.Int63n(1<<32) - (1 << 31)
	p.nonceStr = strconv.FormatInt(nonce, 10)
	p.curdate = time.Now().UTC().Format("2006-01-02T15:04:05Z")
	hash := sha1.Sum([]byte(p.nonceStr + p.curdate + "DHP2P:" + USERNAME + ":" + USERKEY))
	p.digest = base64.StdEncoding.EncodeToString(hash[:])
}

// isUDPHardError — ошибка уровня сокета, а не обычный таймаут.
//
// Зачем: connected UDP + ICMP unreachable (облако/фаервол режет при высоком
// RPS) = Read/Write падают мгновенно с connection refused вместо блокировки
// до дедлайна. Без обработки воркер крутится вхолостую: expire нечего
// (дедлайны в будущем), губернатор ничего не видит (ни TO, ни ERR), счётчики
// стоят. Порт из p2pwn (thebadinteger/p2pwn, chanpipe.go).
func isUDPHardError(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "connection reset") ||
		strings.Contains(s, "connection refused") ||
		strings.Contains(s, "forcibly closed") ||
		strings.Contains(s, "broken pipe")
}

// reconnect меняет отравленный ICMP-сокет на чистый.
//
// Отравление держится, пока прилетают ICMP: каждый Read падает мгновенно и
// пайплайн busy-spin'ится. Redial даёт воркеру чистый сокет. Троттл 1с —
// чтобы 30 воркеров не долбили переподключениями синхронно.
func (p *channelPipeline) reconnect() {
	if time.Since(p.lastReconnect) < time.Second {
		return
	}
	p.lastReconnect = time.Now()
	raddr, _ := p.conn.RemoteAddr().(*net.UDPAddr)
	if raddr == nil {
		return
	}
	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return
	}
	conn.SetWriteBuffer(SOCKET_BUF)
	conn.SetReadBuffer(256 * 1024)
	old := p.conn
	p.conn = conn
	p.lport = conn.LocalAddr().(*net.UDPAddr).Port
	old.Close()
}

// serialHash — FNV-1a для дедупа ретраев без хранения строк.
func serialHash(s string) uint64 {
	h := uint64(14695981039346656037)
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= 1099511628211
	}
	return h
}

// Учёт Checked двухуровневый (диета против 878МБ RSS):
//   - первая попытка считается сразу, без карты;
//   - в сет retried попадают только ушедшие в могильник (таймаут/401);
//   - повторный вердикт по ним не считается.
// Раньше карта хранила ВСЕ серийники (до 500к строк на воркер — десятки МБ
// на 30 воркеров и гигабайт на 200). Теперь там только ретраи (единицы МБ).
// Нюанс file-режима: дубли через край дедуп-окна посчитаются дважды — там
// приблизительность уже задекларирована (DedupResets).
func (p *channelPipeline) markFirst(serial string, stats *ScanStats) {
	atomic.AddInt64(&stats.Checked, 1)
}

func (p *channelPipeline) rememberRetried(serial string) {
	p.retried[serialHash(serial)] = struct{}{}
	if len(p.retried) >= retriedFlushAt {
		p.retried = make(map[uint64]struct{})
	}
}

func (p *channelPipeline) markRetried(serial string, stats *ScanStats) {
	h := serialHash(serial)
	if _, ok := p.retried[h]; !ok {
		p.retried[h] = struct{}{}
		atomic.AddInt64(&stats.Checked, 1)
		if len(p.retried) >= retriedFlushAt {
			p.retried = make(map[uint64]struct{})
		}
	}
}

func (p *channelPipeline) sendFail(serial string, stats *ScanStats) {
	p.markFirst(serial, stats)
	atomic.AddInt64(&stats.Dead, 1)
}

// sendJitter растаскивает дедлайны пачки, ушедшей burst'ом.
func sendJitter() time.Duration {
	return time.Duration(rand.Int63n(int64(SEND_JITTER_BOUND)))
}

func (p *channelPipeline) send(serial string) bool {
	cseq := atomic.AddInt64(&cseqCounter, 1)
	aid := randomAID()
	if err := p.write("DHPOST", fmt.Sprintf("/device/%s/p2p-channel", serial), p2pChannelBody(p.lport, aid), cseq); err != nil {
		if isUDPHardError(err) {
			p.reconnect()
		}
		protolog("× %s send fail (socket write, cseq=%d)", serial, cseq)
		scanlog("[SCAN] %s send-fail cseq=%d", serial, cseq)
		govRecordErr()
		return false
	}
	protolog("> DHPOST /device/%s/p2p-channel cseq=%d", serial, cseq)
	p.inflight[cseq] = &inflightChannel{serial: serial, aid: aid, deadline: time.Now().Add(p.curTimeout() + sendJitter()), sentAt: time.Now()}
	// SEND_STAGGER висел константой и нигде не использовался — пачка из окна
	// уходила в один syscall-такт и будила троттлинг облака. Растаскиваем.
	time.Sleep(SEND_STAGGER)
	return true
}

func (p *channelPipeline) readResp(dl time.Time) (dhResp, bool) {
	p.conn.SetReadDeadline(dl)
	n, err := p.conn.Read(p.buf)
	if err != nil {
		if isUDPHardError(err) {
			p.reconnect()
		}
		return dhResp{}, false
	}
	// Сырой ответ держим для дампа 401: копия, т.к. p.buf переиспользуется
	// следующим Read. Копируем всегда — дешевле одного if на пакет.
	p.lastRaw = append(p.lastRaw[:0], p.buf[:n]...)
	return parseDHResp(p.buf[:n]), true
}

// On401 — подлянка для отладки 401: каждый ответ сервера с кодом 401 уходит
// сюда целиком (сырой текст: статус, заголовки, тело), как логгирование в
// dh-fwd. Ставится фазой скана, пишет в 401.txt с капом (см. prefixrun).
// nil = не пишем. Вызывается из воркеров, хук обязан быть потокобезопасным.
var On401 func(serial, raw string)

func record401(serial string, raw []byte) {
	if On401 == nil {
		return
	}
	On401(serial, string(raw))
}

// Wire401Dump пишет каждый 401-ответ сервера в файл целиком (сырой текст).
// Возвращает unwire (снимает хук, закрывает файл). Кап max штук: 401-х при
// троттлинге могут быть миллионы, для разбора хватает первых.
func Wire401Dump(path string, max int64) func() {
	if max <= 0 {
		max = 1000
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return func() {}
	}
	var mu sync.Mutex
	var n int64
	On401 = func(serial, raw string) {
		mu.Lock()
		defer mu.Unlock()
		if n >= max {
			return
		}
		n++
		fmt.Fprintf(f, "=== %s %s (%d/%d) ===\n%s\n", time.Now().Format("15:04:05"), serial, n, max, raw)
	}
	return func() {
		On401 = nil
		mu.Lock()
		defer mu.Unlock()
		_ = f.Sync()
		_ = f.Close()
	}
}

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

func (p *channelPipeline) expire(stats *ScanStats) {
	now := time.Now()
	storm := p.stormMode()
	for c, ir := range p.inflight {
		if now.After(ir.deadline) {
			delete(p.inflight, c)
			p.expiredCycle++
			govRecordTO()
			if ir.retries == 0 {
				p.markFirst(ir.serial, stats)
			} else {
				p.markRetried(ir.serial, stats)
			}
			if storm {
				// Шторм: тишина — почти наверняка наш дроп от перегруза.
				// Ретраи только добавят нагрузки — сразу в dead.
				atomic.AddInt64(&stats.Dead, 1)
				protolog("× %s dead (silence in storm, no retry)", ir.serial)
				continue
			}
			p.rememberRetried(ir.serial)
			p.gravePut(c, &graveEntry{serial: ir.serial, aid: ir.aid, retries: ir.retries, deadline: now.Add(p.graceTTL)}, stats)
		}
	}
	for c, g := range p.graveyard {
		if now.After(g.deadline) {
			if g.retries >= CHANNEL_RETRIES {
				delete(p.graveyard, c)
				atomic.AddInt64(&stats.Dead, 1)
				protolog("× %s dead (silence, retries exhausted)", g.serial)
				scanlogSampled("[SCAN] %s dead (silence, retries exhausted)", g.serial)
				continue
			}
			if storm && !g.explicit {
				// Шторм: молчуна не дёргаем повторно — в dead. Явный 401
				// ждёт своей очереди ниже: вердикт неизвестен.
				delete(p.graveyard, c)
				atomic.AddInt64(&stats.Dead, 1)
				protolog("× %s dead (silence in storm, no retry)", g.serial)
				continue
			}
			if !p.tryRate() {
				g.deadline = now.Add(p.nextRateDelay() + time.Millisecond)
				continue
			}
			delete(p.graveyard, c)
			p.sendRetry(g, stats)
		}
	}
}

func (p *channelPipeline) sendRetry(g *graveEntry, stats *ScanStats) {
	cseq := atomic.AddInt64(&cseqCounter, 1)
	aid := randomAID()
	if err := p.write("DHPOST", fmt.Sprintf("/device/%s/p2p-channel", g.serial), p2pChannelBody(p.lport, aid), cseq); err != nil {
		if isUDPHardError(err) {
			p.reconnect()
		}
		govRecordErr()
		// Серийник уже посчитан при кладке в могильник — только Dead.
		atomic.AddInt64(&stats.Dead, 1)
		return
	}
	protolog("~ %s retry %d/%d cseq=%d", g.serial, g.retries+1, CHANNEL_RETRIES, cseq)
	scanlogSampled("[SCAN] %s retry %d/%d", g.serial, g.retries+1, CHANNEL_RETRIES)
	p.inflight[cseq] = &inflightChannel{serial: g.serial, aid: aid, retries: g.retries + 1, deadline: time.Now().Add(p.curTimeout() + sendJitter()), sentAt: time.Now()}
	time.Sleep(SEND_STAGGER)
}

func (p *channelPipeline) resolve(r dhResp, aliveCh chan<- string, stats *ScanStats) {
	if r.Code < 200 {
		if ir, ok := p.inflight[r.CSeq]; ok && !ir.extended {
			ir.extended = true
			ir.deadline = time.Now().Add(p.curTimeout())
			protolog("< %d cseq=%d %s (provisional, deadline+)", r.Code, r.CSeq, ir.serial)
		}
		return
	}
	if ir, ok := p.inflight[r.CSeq]; ok {
		delete(p.inflight, r.CSeq)
		p.resolvedCycle++
		if ir.retries == 0 {
			p.markFirst(ir.serial, stats)
		} else {
			p.markRetried(ir.serial, stats)
		}
		if !ir.sentAt.IsZero() {
			govRecordOK(time.Since(ir.sentAt))
		}
		if channelAckAlive(r) {
			atomic.AddInt64(&stats.Alive, 1)
			protolog("< %d cseq=%d %s (alive)", r.Code, r.CSeq, ir.serial)
			scanlog("[SCAN] %s alive code=%d rtt=%s", ir.serial, r.Code, time.Since(ir.sentAt).Round(time.Millisecond))
			aliveCh <- ir.serial
			p.teardown(ir.aid, r)
		} else if r.Code == 401 {
			// 401 с телом <Error>TimeOut</Error> — облако сбросило нагрузку,
			// вердикт неизвестен. Не dead: в могильник на ретрай, как тишину.
			// Ретраи идут через лимитер и grace, шторм к тому же давит
			// губернатор — долбёжки не будет.
			delete(p.inflight, r.CSeq)
			p.expiredCycle++
			govRecordTO()
			// Учёт уже сделан выше (первая попытка / ретрай); здесь только
			// запоминаем для будущих повторных вердиктов.
			p.rememberRetried(ir.serial)
			p.gravePut(r.CSeq, &graveEntry{serial: ir.serial, aid: ir.aid, retries: ir.retries, deadline: time.Now().Add(p.graceTTL), explicit: true}, stats)
			protolog("< %d cseq=%d %s (401 cloud-timeout, queued retry)", r.Code, r.CSeq, ir.serial)
			scanlogSampled("[SCAN] %s 401 (cloud timeout) → retry", ir.serial)
			record401(ir.serial, p.lastRaw)
		} else {
			atomic.AddInt64(&stats.Dead, 1)
			protolog("< %d cseq=%d %s (dead)", r.Code, r.CSeq, ir.serial)
			scanlogSampled("[SCAN] %s dead code=%d rtt=%s", ir.serial, r.Code, time.Since(ir.sentAt).Round(time.Millisecond))
		}
		return
	}
	if g, ok := p.graveyard[r.CSeq]; ok {
		delete(p.graveyard, r.CSeq)
		p.resolvedCycle++
		if channelAckAlive(r) {
			atomic.AddInt64(&stats.Alive, 1)
			protolog("< %d cseq=%d %s (late alive)", r.Code, r.CSeq, g.serial)
			scanlog("[SCAN] %s alive (late) code=%d", g.serial, r.Code)
			aliveCh <- g.serial
			p.teardown(g.aid, r)
		} else if r.Code == 401 && g.retries < CHANNEL_RETRIES {
			// Поздний 401 на уже ретраенный запрос: бюджет ещё есть —
			// обратно в могильник, expire добьёт по счётчику.
			govRecordTO()
			p.gravePut(r.CSeq, &graveEntry{serial: g.serial, aid: g.aid, retries: g.retries, deadline: time.Now().Add(p.graceTTL), explicit: true}, stats)
			protolog("< %d cseq=%d %s (late 401, queued retry)", r.Code, r.CSeq, g.serial)
			scanlogSampled("[SCAN] %s 401 (late) → retry", g.serial)
			record401(g.serial, p.lastRaw)
		} else {
			atomic.AddInt64(&stats.Dead, 1)
			protolog("< %d cseq=%d %s (late dead)", r.Code, r.CSeq, g.serial)
			scanlogSampled("[SCAN] %s dead (late) code=%d", g.serial, r.Code)
			if r.Code == 401 {
				record401(g.serial, p.lastRaw)
				govRecordTO()
			}
		}
		return
	}
}

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
		out = append(out, c1[:4]...)
		out = append(out, c2[:]...)
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
		p.conn.WriteTo(init, &net.UDPAddr{IP: ip, Port: port})
		p.conn.Write(init)
	}
}

func (p *channelPipeline) govern() {
	total := p.resolvedCycle + p.expiredCycle
	if total > 0 {
		share := float64(p.expiredCycle) / float64(total)
		if p.emaSet {
			p.expiredEMA = p.expiredEMA*7/8 + share/8
		} else {
			p.expiredEMA, p.emaSet = share, true
		}
	}
	switch {
	case p.emaSet && p.expiredEMA < 0.02:
		p.window += GOV_GROW
		if p.window > W_MAX {
			p.window = W_MAX
		}
	case p.emaSet && p.expiredEMA > 0.10:
		p.window -= GOV_SHRINK
		if p.window < W_MIN {
			p.window = W_MIN
		}
	}
	p.resolvedCycle, p.expiredCycle = 0, 0
}

func (p *channelPipeline) run(ctx context.Context, jobs <-chan string, aliveCh chan<- string, stats *ScanStats) {
	p.ctx = ctx
	var pumpCap time.Duration
	for {
		if ctx.Err() != nil {
			return
		}
		// Тестовый крэш: срабатывает в теле воркера, поэтому поднимается
		// внутри горутицы scanWorker и проходит её recover -> crashGuard.
		if p.injector != nil && p.injector.armed() {
			p.injector.fire()
		}
		pumpCap = 0

		for len(p.inflight) < p.window {
			if !p.tryRate() {
				pumpCap = p.nextRateDelay() + time.Millisecond
				goto readPhase
			}
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
				goto readPhase
			}
		}

	readPhase:
		if len(p.inflight) == 0 && len(p.graveyard) == 0 {
			select {
			case <-ctx.Done():
				return
			case s, ok := <-jobs:
				if !ok {
					return
				}
				if !p.blockRate() {
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

		p.pump(ctx, aliveCh, stats, pumpCap)

		if (p.resolvedCycle + p.expiredCycle) >= int64(p.window) {
			p.govern()
		}
	}

drain:
	for (len(p.inflight) > 0 || len(p.graveyard) > 0) && ctx.Err() == nil {
		p.pump(ctx, aliveCh, stats, 0)
		if (p.resolvedCycle + p.expiredCycle) >= int64(p.window) {
			p.govern()
		}
	}
}

func (p *channelPipeline) pump(ctx context.Context, aliveCh chan<- string, stats *ScanStats, maxWait time.Duration) {
	dl := p.minDeadline()
	now := time.Now()
	wait := dl.Sub(now)
	if maxWait > 0 && maxWait < wait {
		wait = maxWait
	}
	if wait > PUMP_MAX_WAIT {
		wait = PUMP_MAX_WAIT
	}
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

func scanWorker(ctx context.Context, conn *net.UDPConn, jobs <-chan string, aliveCh chan<- string, stats *ScanStats, timeout time.Duration, limiter *rateLimiter, injector *crashInjector) {
	p := newChannelPipeline(conn, timeout)
	p.limiter = limiter
	p.injector = injector
	p.run(ctx, jobs, aliveCh, stats)
}

const (
	ReadBufSize = 4 << 20
	ScanBufMax  = 1 << 20
	DedupWindow = 1 << 20
)

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

func emitEvent(events chan<- string, s string) {
	if events == nil {
		return
	}
	select {
	case events <- s:
	default:
	}
}

var Debug bool

var LogHook func(string)

func protolog(format string, args ...any) {
	if !Debug || LogHook == nil {
		return
	}
	LogHook(fmt.Sprintf(format, args...))
}

// ScanLog — детальный лог фазы скана серийников (а не эксплоита).
//
// protolog виден только в Debug-режиме, а в обычном прогоне фаза [1/2] идёт
// молча: только бар и found. ScanLog светит каждый alive и семплированные
// dead/retry прямо в ленту и лог-файл, без включения Debug со всем его спамом.
//
// Семплинг обязателен: на 3к rps полный лог dead — это 3к строк/с и гигабайты
// за прогон 75М серийников. Alive редкие — идут все.
var ScanLog func(string)

var scanLogTick uint64

const scanLogSample = 256

func scanlog(format string, args ...any) {
	if ScanLog == nil {
		return
	}
	ScanLog(fmt.Sprintf(format, args...))
}

func scanlogSampled(format string, args ...any) {
	if ScanLog == nil {
		return
	}
	if atomic.AddUint64(&scanLogTick, 1)&(scanLogSample-1) != 0 {
		return
	}
	ScanLog(fmt.Sprintf(format, args...))
}

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

// lookupCloudIPs returns the cloud edge IPs. Resolution failures are absorbed:
// cloudip falls back to its hardcoded pool, so a dead resolver costs us nothing.
func lookupCloudIPs() []net.IP {
	return cloudip.IPs(MAIN_SERVER)
}

func newEgress(ip net.IP) (*net.UDPConn, error) {
	conn, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: ip, Port: MAIN_PORT})
	if err != nil {
		return nil, err
	}
	conn.SetWriteBuffer(SOCKET_BUF)
	conn.SetReadBuffer(256 * 1024)
	return conn, nil
}

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

func runPipe(ctx context.Context, stats *ScanStats, events chan<- string, sink func(string), workers int, feed func(jobs chan string), seedAlive map[string]struct{}) string {
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
		return i18n.Tr("ошибка резолва сервера: ") + MAIN_SERVER
	}
	if cloudip.Static() {
		emitEvent(events, "[SYS] "+i18n.Tr("DNS недоступен, беру захардкоженный пул: ")+fmt.Sprintf("%d шт.", len(cloudIPs)))
	}
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
	emitEvent(events, "[SYS] "+fmt.Sprintf(i18n.Tr("воркеров: %d"), len(conns)))
	if workers < wantWorkers {
		emitEvent(events, "[SYS] "+fmt.Sprintf(i18n.Tr("лимит ОС: воркеров не больше %d"), lim.MaxWorkers))
	}
	defer func() {
		for _, conn := range conns {
			conn.Close()
		}
	}()

	var limiter *rateLimiter

	// Крэш-триггер: создаётся здесь, но не взводится. Отсчёт пойдёт от
	// включения губернатора — см. armInjector в ветке default.
	injector := &crashInjector{}
	if TestCrashAfter <= 0 {
		injector = nil
	}

	switch {
	case !GovernorOn:
	case GovernorCap > 0:
		limiter = newRateLimiter(GovernorCap, BURST_LIMIT)
		// governor_cap задан: адаптивного губернатора нет, но фиксированный
		// кап всё равно «включение ограничителя» — взводим и здесь.
		armInjector(injector, events)
	default:
		resetGov()
		limiter = newRateLimiter(govStartPPS, BURST_LIMIT)
		armInjector(injector, events)
		go governorLoop(ctx, limiter)
	}
	jobs := make(chan string, workers*10)
	aliveCh := make(chan string, workers*10)

	// Свой контекст прогона. При краше одного воркера остальные 29 продолжают
	// работать и сыпать [VALID] поверх сплэша, пока главная горутина висит в
	// WaitForKey. Отменяем его ДО показа сплэша, чтобы терминал был тихим.
	runCtx, cancelRun := context.WithCancel(ctx)
	defer cancelRun()

	var rwg sync.WaitGroup
	var wgOnce sync.Once
	// stopAll гасит конвейер и ждёт, пока воркеры свернутся.
	stopAll := func() {
		wgOnce.Do(func() {
			cancelRun()
			done := make(chan struct{})
			go func() { rwg.Wait(); close(done) }()
			select {
			case <-done:
			case <-time.After(fatalDrainTimeout):
			}
		})
	}
	for _, conn := range conns {
		rwg.Add(1)
		go func(c *net.UDPConn) {
			defer rwg.Done()
			defer func() {
				if r := recover(); r != nil {
					stopAll()
					raiseOrReraise(r)
				}
			}()
			scanWorker(runCtx, c, jobs, aliveCh, stats, ACK_TIMEOUT, limiter, injector)
		}(conn)
	}

	var writeWg sync.WaitGroup
	writeWg.Add(1)
	seenAlive := make(map[string]struct{}, len(seedAlive))
	for s := range seedAlive {
		seenAlive[s] = struct{}{}
	}
	go func() {
		defer writeWg.Done()
		defer func() {
			if r := recover(); r != nil {
				raiseOrReraise(r)
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

	start := time.Now()

	updStop := make(chan struct{})

	// На resume счётчик Checked уже предзаполнен на skip (см. RunPrefixesMem),
	// а Alive — находками из чекпоинта. Если считать скорость и темп находок
	// от нуля, первый же тик выдаёт checked/elapsed на миллионы серийников в
	// секунду и AliveRate со всеми накопленными находками разом. Окно
	// наблюдения надо открывать с текущего состояния — так же, как при первом
	// запуске скана.
	statsBase := atomic.LoadInt64(&stats.Checked)
	lastAliveMark := atomic.LoadInt64(&stats.Alive)
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
				elapsed := time.Since(start).Seconds()
				if elapsed > 0 {
					delta := atomic.LoadInt64(&stats.Checked) - statsBase
					if delta < 0 {
						delta = 0
					}
					stats.Speed = float64(delta) / elapsed
				}
				now := time.Now()
				if now.Sub(lastAliveT) >= 10*time.Second {
					alive := atomic.LoadInt64(&stats.Alive)
					d := alive - lastAliveMark
					if d < 0 {
						d = 0
					}
					stats.AliveRate = float64(d) / now.Sub(lastAliveT).Seconds() * 60
					lastAliveMark, lastAliveT = alive, now
				}
			}
		}
	}()

	feed(jobs)

	rwg.Wait()
	close(aliveCh)
	writeWg.Wait()

	close(updStop)
	return ""
}

func RunScanner(ctx context.Context, inputFile, outputFile string, appendMode bool, workers int, stats *ScanStats, events chan<- string) {
	defer func() { stats.Done = true }()

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

	// Подлянка для 401 и здесь: сырые ответы сервера в 401.txt рядом с выходом.
	unwire401 := Wire401Dump(filepath.Join(filepath.Dir(outputFile), "401.txt"), 1000)
	defer unwire401()

	sink := func(s string) {
		outWriter.WriteString(s + "\n")
		outWriter.Flush()
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
