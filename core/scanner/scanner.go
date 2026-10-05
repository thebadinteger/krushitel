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
	W_MAX           = 128
	GOV_GROW        = 8
	GOV_SHRINK      = 16
	ACK_TIMEOUT     = 15 * time.Second

	SEND_STAGGER = 100 * time.Microsecond

	ACK_GRACE = 15 * time.Second

	CHANNEL_RETRIES = 2

	MAX_RPS     = 3000
	BURST_LIMIT = 64

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
	counted                   map[string]struct{}
	buf                       []byte
	limiter                   *rateLimiter
	ctx                       context.Context
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

func (p *channelPipeline) write(method, path, body string, cseq int64) bool {
	p.conn.SetWriteDeadline(time.Now().Add(p.timeout))
	_, err := p.conn.Write([]byte(dhReq(method, path, body, cseq, p.digest, p.nonceStr, p.curdate)))
	return err == nil
}

func (p *channelPipeline) markChecked(serial string, stats *ScanStats) {
	if _, ok := p.counted[serial]; !ok {
		p.counted[serial] = struct{}{}
		atomic.AddInt64(&stats.Checked, 1)
	}
}

func (p *channelPipeline) sendFail(serial string, stats *ScanStats) {
	p.markChecked(serial, stats)
	atomic.AddInt64(&stats.Dead, 1)
}

func (p *channelPipeline) send(serial string) bool {
	cseq := atomic.AddInt64(&cseqCounter, 1)
	aid := randomAID()
	if !p.write("DHPOST", fmt.Sprintf("/device/%s/p2p-channel", serial), p2pChannelBody(p.lport, aid), cseq) {
		protolog("× %s send fail (socket write, cseq=%d)", serial, cseq)
		govRecordErr()
		return false
	}
	protolog("> DHPOST /device/%s/p2p-channel cseq=%d", serial, cseq)
	p.inflight[cseq] = &inflightChannel{serial: serial, aid: aid, deadline: time.Now().Add(p.timeout), sentAt: time.Now()}
	return true
}

func (p *channelPipeline) readResp(dl time.Time) (dhResp, bool) {
	p.conn.SetReadDeadline(dl)
	n, err := p.conn.Read(p.buf)
	if err != nil {
		return dhResp{}, false
	}
	return parseDHResp(p.buf[:n]), true
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
			if g.retries >= CHANNEL_RETRIES {
				delete(p.graveyard, c)
				atomic.AddInt64(&stats.Dead, 1)
				protolog("× %s dead (silence, retries exhausted)", g.serial)
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
	if !p.write("DHPOST", fmt.Sprintf("/device/%s/p2p-channel", g.serial), p2pChannelBody(p.lport, aid), cseq) {
		govRecordErr()
		p.sendFail(g.serial, stats)
		return
	}
	protolog("~ %s retry %d/%d cseq=%d", g.serial, g.retries+1, CHANNEL_RETRIES, cseq)
	p.inflight[cseq] = &inflightChannel{serial: g.serial, aid: aid, retries: g.retries + 1, deadline: time.Now().Add(p.timeout), sentAt: time.Now()}
}

func (p *channelPipeline) resolve(r dhResp, aliveCh chan<- string, stats *ScanStats) {
	if r.Code < 200 {
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
		if raddr, rerr := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", MAIN_SERVER, MAIN_PORT)); rerr == nil {
			cloudIPs = []net.IP{raddr.IP}
		}
	}
	if len(cloudIPs) == 0 {
		return i18n.Tr("ошибка резолва сервера: ") + MAIN_SERVER
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
	switch {
	case !GovernorOn:
	case GovernorCap > 0:
		limiter = newRateLimiter(GovernorCap, BURST_LIMIT)
	default:
		resetGov()
		limiter = newRateLimiter(govStartPPS, BURST_LIMIT)
		go governorLoop(ctx, limiter)
	}
	jobs := make(chan string, workers*10)
	aliveCh := make(chan string, workers*10)

	var rwg sync.WaitGroup
	for _, conn := range conns {
		rwg.Add(1)
		go func(c *net.UDPConn) {
			defer rwg.Done()
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
