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
	reDahua   = regexp.MustCompile(`[A-Z0-9]{4,7}P[A-Z][A-Z][A-Z0-9]{3,6}`)
	reHexJunk = regexp.MustCompile(`^[0-9a-f]{16,}|[0-9a-f]{16,}$`)
	reModel   = regexp.MustCompile(`(?:IPC|NVR|HCVR|DH)-[A-Z0-9\-]+`)
)

const maxRangeIPs = 5_000_000

func pickSerial(s string) string {
	up := strings.ToUpper(s)
	for _, m := range reDahua.FindAllString(up, -1) {
		if len(m) >= 14 && len(m) <= 15 {
			return m
		}
	}
	return ""
}

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

func SanitizeSerialBytes(raw []byte) string {
	s := bytes.TrimSpace(raw)
	if len(s) == 0 {
		return ""
	}
	if i := bytes.IndexByte(s, ';'); i >= 0 {
		s = bytes.TrimSpace(s[:i])
	}
	if len(s) < 14 {
		return ""
	}
	return SanitizeSerial(string(s))
}

type Options struct {
	Targets     []string
	Port        int
	Timeout     time.Duration
	Concurrency int
	Retries     int
	Seed        int64
}

type Result struct {
	Target   string
	Serial   string
	Model    string
	Firmware string
	Err      string
}

func (r Result) Ok() bool { return r.Serial != "" }

var LogHook func(format string, args ...any)

var hello = []byte{
	0xa0, 0x05, 0x00, 0x60, 0x00, 0x00, 0x00, 0x00,
	0xc4, 0xa3, 0xaf, 0x48, 0x99, 0x56, 0xb6, 0xb4,
	0x70, 0x02, 0x64, 0x9a, 0xfa, 0x55, 0x24, 0x04,
	0x05, 0x02, 0x00, 0x01, 0x00, 0x00, 0xa1, 0xaa,
}

func command(commandType, commandID byte) []byte {
	pkt := make([]byte, 32)
	pkt[0] = commandType
	pkt[8] = commandID
	return pkt
}

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

	conn, err := dialTarget(ctx, addr, timeout)
	if err != nil {
		if strings.Contains(err.Error(), "connection refused") {
			return Result{Err: "refused"}
		}
		return Result{Err: err.Error()}
	}
	stop := context.AfterFunc(ctx, func() { conn.SetDeadline(time.Now()) })
	r1 := probeConn(conn, timeout)
	stop()
	conn.Close()
	if r1.Err == "" {
		return r1
	}

	conn2, err := dialTarget(ctx, addr, timeout)
	if err != nil {
		return r1
	}
	stop2 := context.AfterFunc(ctx, func() { conn2.SetDeadline(time.Now()) })
	r2 := probeRealmConn(conn2, timeout)
	stop2()
	conn2.Close()
	return r2
}

func dialTarget(ctx context.Context, addr string, timeout time.Duration) (net.Conn, error) {
	d := net.Dialer{Timeout: timeout}
	return d.DialContext(ctx, "tcp", addr)
}

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

	if _, err := readFrame(conn); err != nil {
		return Result{Err: timeoutOrErr(err)}
	}
	serialBody, err := readFrame(conn)
	if err != nil {
		return Result{Err: timeoutOrErr(err)}
	}
	serial := SanitizeSerial(cleanValue(serialBody))
	if serial == "" {
		return Result{Err: "no serial"}
	}

	var model string
	if body, err := readFrame(conn); err == nil {
		model = cleanValue(body)
	}

	conn.SetDeadline(time.Now().Add(timeout))
	var firmware string
	if _, err := conn.Write(command(0xa4, 0x08)); err == nil {
		if body, err := readFrame(conn); err == nil {
			firmware = cleanValue(body)
		}
	}

	return Result{Serial: serial, Model: model, Firmware: firmware}
}

func generateProbe() []byte {
	header := make([]byte, 32)
	header[0] = 0xa0
	header[1] = 0x01
	copy(header[24:32], []byte{0x05, 0x02, 0x01, 0x01, 0x00, 0x00, 0xa1, 0xaa})
	return header
}

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
	length := int(binary.LittleEndian.Uint16(hdr[4:6]))
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
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return strings.TrimSpace(string(b))
}

func probeRealmConn(conn net.Conn, timeout time.Duration) Result {
	if tc, ok := conn.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
	}
	conn.SetDeadline(time.Now().Add(timeout))

	if _, err := conn.Write(generateProbe()); err != nil {
		return Result{Err: err.Error()}
	}

	hdr := make([]byte, 32)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return Result{Err: timeoutOrErr(err)}
	}

	var response []byte
	if hdr[0] == 0xb0 && (hdr[1] == 0x00 || hdr[1] == 0x01) || hdr[0] == 0xf6 {
		payloadLen := int(binary.LittleEndian.Uint16(hdr[4:6]))
		if payloadLen > 0 {
			payload := make([]byte, payloadLen)
			if _, err := io.ReadFull(conn, payload); err != nil && err != io.EOF {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
				} else {
					return Result{Err: err.Error()}
				}
			}
			response = append(hdr, payload...)
		} else {
			response = hdr
		}
	} else {
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
	if res.Err != "" {
		return res
	}

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
	if serial == "" {
		serial = pickSerial(string(response))
	}
	if m := reModel.Find(response); m != nil {
		model = string(m)
	}

	if serial == "" {
		return Result{Err: "no serial"}
	}
	return Result{Serial: serial, Model: model}
}

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

func appendTarget(items []string, line string) []string {
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
	if host, portStr, err := net.SplitHostPort(line); err == nil {
		if port, err := strconv.Atoi(portStr); err == nil && port > 0 && port <= 65535 && net.ParseIP(host) != nil {
			return append(items, net.JoinHostPort(host, portStr))
		}
	}
	if strings.Contains(line, "/") {
		if ips := parseCIDRIPs(line); len(ips) > 0 {
			return append(items, ips...)
		}
	}
	if strings.Contains(line, "-") {
		if ips := parseRangeIPs(line); len(ips) > 0 {
			return append(items, ips...)
		}
	}
	if net.ParseIP(line) != nil {
		return append(items, line)
	}
	return append(items, line)
}

func ParseTarget(line string) []string {
	return appendTarget(nil, line)
}

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

type ironPerm struct {
	n     uint64
	dom   uint64
	c     uint
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

func (p ironPerm) f(r uint64, round uint) uint64 {
	h := r ^ p.seed ^ (uint64(round)*0x9E3779B97F4A7C15 + 1)
	h ^= h >> 33
	h *= 0xff51afd7ed558ccd
	h ^= h >> 33
	h *= 0xc4ceb9fe1a85ec53
	h ^= h >> 33
	return h
}

func (p ironPerm) perm(x uint64) uint64 {
	l := (x >> p.c) & p.rmask
	r := x & p.rmask
	for round := uint(0); round < 4; round++ {
		l, r = r, l^(p.f(r, round)&p.rmask)
	}
	return l<<p.c | r
}

func (p ironPerm) at(k int64) int64 {
	v := p.perm(uint64(k))
	for v >= p.n {
		v = p.perm(v)
	}
	return int64(v)
}

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
					continue
				}
				r := probeDevice(ctx, t, opts.Port, opts.Timeout, opts.Retries)
				if ctx.Err() != nil {
					continue
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
