package fwd

// tcp_relay.go — TCP-relay data path («TOU over TCP»): HTTP-бинд к
// relay-агенту, затем сессионно-фреймированные TOU-пакеты поверх того же
// TCP-соединения. Реконструировано из P2PDll.dll.

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	tcpRelayDialTimeout    = 4 * time.Second
	tcpRelayBindTimeout    = 15 * time.Second
	tcpRelayAckTimeout     = 15 * time.Second
	tcpRelayFrameTimeout   = 10 * time.Second
	tcpRelayWriteTimeout   = 10 * time.Second
	// Keepalive обязан быть строго короче HEARTBEAT_TIMEOUT (10с):
	// каждый keepalive гоняет туда-обратно ACK, обновляющий LastRecv;
	// touReadLoop убивает туннель, если LastRecv превышает 10с.
	// 20с убивало здоровые каналы на любой паузе.
	tcpRelayKeepaliveEvery = 7 * time.Second
)

// touChannel — живая TOU-сессионная канализация к relay-агенту.
type touChannel struct {
	conn   *net.TCPConn
	rd     *bufio.Reader
	mu     sync.Mutex
	closed bool

	localSession uint32
	debug        bool
	logf         func(format string, args ...any)

	lastRecv time.Time
	lrMu     sync.Mutex
}

// dialTCPRelay выполняет полный attach к агенту:
// TCP connect → <post-глагол профиля> /tcprelay/client-bind {"Token":...} →
// SYN → ждём ACK.
func dialTCPRelay(prof *appProfile, agentHost string, agentPort int, token string, debug bool, logf func(string, ...any)) (*touChannel, error) {
	if prof == nil {
		prof = smartpssProfile
	}
	addr := net.JoinHostPort(agentHost, strconv.Itoa(agentPort))
	logf("tcp-relay: dialing agent %s", addr)
	conn, err := net.DialTimeout("tcp", addr, tcpRelayDialTimeout)
	if err != nil {
		return nil, fmt.Errorf("agent tcp dial: %v", err)
	}
	tc, ok := conn.(*net.TCPConn)
	if ok {
		_ = tc.SetNoDelay(true)
	}
	ch := &touChannel{conn: tc, rd: bufio.NewReaderSize(conn, 4096), debug: debug, logf: logf}

	// (A1) bind-запрос поверх того же TCP-сокета обычным DH HTTP с WSSE.
	// Глагол — post-глагол профиля: DHPOST для smartpss (легаси
	// байт-в-байт), NFPOST для dmss; CSeq — по диалекту профиля
	// (счётчик vs случайный signed int32).
	myCseq := nextCSeqFor(prof)
	bindBody, _ := json.Marshal(map[string]string{"Token": token})
	req := buildDHRequest(prof.verbPost, "/tcprelay/client-bind", string(bindBody), true, myCseq, prof, "", false)
	logf("tcp-relay: >>> bind\n%s", string(req))
	_ = conn.SetDeadline(time.Now().Add(tcpRelayBindTimeout))
	if _, err := conn.Write(req); err != nil {
		conn.Close()
		return nil, fmt.Errorf("agent bind write: %v", err)
	}
	resp, err := readHTTPResponse(ch.rd)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("agent bind read: %v", err)
	}
	logf("tcp-relay: <<< bind status=%d %s", resp.Code, strings.TrimSpace(resp.Status))

	// (A2) SYN со случайной локальной сессией; ждём ACK обратно.
	ch.localSession = rand.Uint32()
	syn := touBuildSyn(ch.localSession)
	logf("tcp-relay: >>> SYN session=%#010x", ch.localSession)
	if _, err := conn.Write(syn); err != nil {
		conn.Close()
		return nil, fmt.Errorf("syn write: %v", err)
	}

	_ = conn.SetDeadline(time.Now().Add(tcpRelayAckTimeout))
	for {
		typ, session, _, _, err := ch.readFrame(time.Now().Add(tcpRelayAckTimeout))
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("ack wait: %v", err)
		}
		switch typ {
		case touTypeAck:
			logf("tcp-relay: <<< ACK session=%#010x — channel up", session)
			_ = conn.SetDeadline(time.Time{})
			ch.markRecv()
			return ch, nil
		case touTypeKA, touTypeSrv:
			continue
		default:
			logf("tcp-relay: <<< type=0x%02x during ack wait (ignored)", typ)
		}
	}
}

// readHTTPResponse читает один заголовок HTTP/1.1-ответа из буферизованного
// ридера. Агент отвечает на бинд коротким телом; дреним до Content-Length,
// когда он есть (держит TOU-поток выровненным).
func readHTTPResponse(rd *bufio.Reader) (*DHResponse, error) {
	statusLine, err := rd.ReadString('\n')
	if err != nil {
		return nil, err
	}
	statusLine = strings.TrimRight(statusLine, "\r\n")
	contentLen := 0
	for {
		line, err := rd.ReadString('\n')
		if err != nil {
			return nil, err
		}
		trimmed := strings.TrimRight(line, "\r\n")
		if trimmed == "" {
			break
		}
		lc := strings.ToLower(trimmed)
		if strings.HasPrefix(lc, "content-length:") {
			fmt.Sscanf(strings.TrimSpace(lc[len("content-length:"):]), "%d", &contentLen)
		}
	}
	if contentLen > 0 && contentLen < 64*1024 {
		drain := make([]byte, contentLen)
		if _, err := readFull(rd, drain); err != nil {
			return nil, err
		}
	}
	parts := strings.SplitN(statusLine, " ", 3)
	code := 0
	if len(parts) >= 2 {
		fmt.Sscanf(parts[1], "%d", &code)
	}
	status := ""
	if len(parts) >= 3 {
		status = parts[2]
	}
	return &DHResponse{Code: code, Status: status}, nil
}

func (c *touChannel) markRecv() {
	c.lrMu.Lock()
	c.lastRecv = time.Now()
	c.lrMu.Unlock()
}

func (c *touChannel) LastRecv() time.Time {
	c.lrMu.Lock()
	defer c.lrMu.Unlock()
	return c.lastRecv
}

// readFrame блокирует (ограничено дедлайном), пока не будет доступен один
// полный TOU-фрейм. Использует bufio.Peek, который буферизует из TCP-конна
// внутренне.
func (c *touChannel) readFrame(deadline time.Time) (typ byte, session uint32, payload []byte, total int, err error) {
	_ = c.conn.SetReadDeadline(deadline)
	head, err := c.rd.Peek(4)
	if err != nil {
		return 0, 0, nil, 0, err
	}
	fixed, isFixed := touFixedLen(head[0])
	var need int
	switch {
	case isFixed:
		need = fixed
	case head[0]&0x0F == touTypeData:
		need = touHdrSize + int(binary.BigEndian.Uint16(head[2:4]))
		if need > touMaxPacketLen {
			return 0, 0, nil, 0, fmt.Errorf("tou packet too large: %d", need)
		}
	default:
		return 0, 0, nil, 0, fmt.Errorf("%w: 0x%02x", errTouVersion, head[0])
	}
	frame, err := c.rd.Peek(need)
	if err != nil {
		return 0, 0, nil, 0, err
	}
	discarded, err := c.rd.Discard(need)
	if err != nil || discarded != need {
		return 0, 0, nil, 0, fmt.Errorf("tou discard: n=%d err=%v", discarded, err)
	}
	t, s, pl, tot, perr := parseTouPacket(frame)
	if perr == nil {
		c.markRecv()
		if c.debug {
			c.logf("tcp-relay: <<< frame type=0x%02x session=%#010x len=%d", t, s, tot)
		}
	}
	return t, s, pl, tot, perr
}

func readFull(rd *bufio.Reader, out []byte) (int, error) {
	total := 0
	for total < len(out) {
		n, err := rd.Read(out[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// write шлёт один готовый фрейм.
func (c *touChannel) write(frame []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return fmt.Errorf("tou channel closed")
	}
	_ = c.conn.SetWriteDeadline(time.Now().Add(tcpRelayWriteTimeout))
	_, err := c.conn.Write(frame)
	return err
}

func (c *touChannel) writeData(session uint32, payload []byte) error {
	frame, err := touBuildData(session, payload)
	if err != nil {
		return err
	}
	return c.write(frame)
}

func (c *touChannel) writeAck(session, value uint32) error {
	return c.write(touBuildAck(session, value))
}

func (c *touChannel) writeKeepalive(session uint32) error {
	return c.write(touBuildKeepalive(session))
}

func (c *touChannel) close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	c.closed = true
	c.conn.Close()
}
