package fwd

// helpers.go содержит вспомогательные функции Dahua P2P протокола (криптография, PTCP wire format, UDP сокеты).

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/pbkdf2"
)

// Облачные эндпоинты и креды стоковых клиентов (публичные, зашиты в каждый
// официальный клиент Dahua: SmartPSS, DMSS, gDMSS).
const (
	MAIN_SERVER = "www.easy4ipcloud.com"
	MAIN_PORT   = 8800

	WSSE_USERNAME = "cba1b29e32cb17aa46b8ff9e73c7f40b"
	WSSE_USERKEY  = "996103384cdf19179e19243e959bbf8b"
	DEFAULT_SALT  = ""
	AES_IV        = "2z52*lk9o6HRyJrf"
)

var (
	cseqLock sync.Mutex
	cseq     uint32
)

// ---------------------------------------------------------------------------
// Device auth (Type 1): вывод мастер-ключа, AES-OFB шифрование адреса,
// HMAC-SHA256 подпись запросов. Зеркало раздела 4.3 спецификации DH-P2P.
// ---------------------------------------------------------------------------

// getDeriveKey строит 32-символьный uppercase-hex MD5 мастер-ключ:
//
//	MD5(user + ":Login to " + salt + ":" + pass), отрендеренный ASCII-hex.
func getDeriveKey(username, password, randsalt string) []byte {
	salt := randsalt
	if salt == "" {
		salt = DEFAULT_SALT
	}
	sum := md5.Sum([]byte(fmt.Sprintf("%s:Login to %s:%s", username, salt, password)))
	return []byte(fmt.Sprintf("%X", sum))
}

// getNonce возвращает случайный int32-range для соли PBKDF2. Приложение
// DMSS берёт отрицательные nonce (signed int32), так что используется весь
// диапазон −2^31..2^31−1 — не только положительная половина.
func getNonce() int {
	n, _ := rand.Int(rand.Reader, big.NewInt(1<<32))
	return int(n.Int64() - 1<<31)
}

// deriveDK разворачивает мастер-ключ: PBKDF2-HMAC-SHA256(key, decimal(nonce), 20000, 32).
func deriveDK(key []byte, nonce int) []byte {
	salt := []byte(strconv.Itoa(nonce))
	return pbkdf2.Key(key, salt, 20000, 32, sha256.New)
}

// getEnc шифрует LocalAddr AES-256-OFB на производном ключе (32 байта) и
// фиксированном IV, отдаёт Base64. Раздел 4.3 шаг 3 спецификации.
func getEnc(key []byte, nonce int, data string) string {
	dk := deriveDK(key, nonce)
	block, _ := aes.NewCipher(dk)
	stream := cipher.NewOFB(block, []byte(AES_IV))
	out := make([]byte, len(data))
	stream.XORKeyStream(out, []byte(data))
	return base64.StdEncoding.EncodeToString(out)
}

// getDec обращает getEnc: расшифровывает зашифрованный LocalAddr устройства.
func getDec(key []byte, nonce int, data string) string {
	dk := deriveDK(key, nonce)
	block, _ := aes.NewCipher(dk)
	stream := cipher.NewOFB(block, []byte(AES_IV))
	raw, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return data
	}
	out := make([]byte, len(raw))
	stream.XORKeyStream(out, raw)
	return string(out)
}

// getAuth собирает DevAuth XML-блок: Base64(HMAC-SHA256(masterKey,
// string(nonce) + string(unixNow) + payload)). Раздел 4.3 шаг 4.
func getAuth(username string, key []byte, nonce int, payload, randsalt string) string {
	return getAuthAt(username, key, nonce, payload, randsalt, time.Now().Unix())
}

// getAuthAt — getAuth с фиксированным CreateDate: ретрансмиты сохраняют
// исходный таймстамп и обновляют только nonce/payload-крипто.
func getAuthAt(username string, key []byte, nonce int, payload, randsalt string, created int64) string {
	salt := randsalt
	if salt == "" {
		salt = DEFAULT_SALT
	}
	msg := []byte(fmt.Sprintf("%d%d%s", nonce, created, payload))
	mac := hmac.New(sha256.New, key)
	mac.Write(msg)
	auth := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	return fmt.Sprintf(
		"<CreateDate>%d</CreateDate><DevAuth>%s</DevAuth><Nonce>%d</Nonce><RandSalt>%s</RandSalt><UserName>%s</UserName>",
		created, auth, nonce, salt, username,
	)
}

// Hardcoded devinfo-крипто, recovered из P2PDll.dll
// (CP2PClientImpl::parseDeviceInfo): поле "Info" из /info/device/<SN> —
// это Base64(AES-256-OFB(JSON)).
const (
	DEVINFO_KEY = "kRjmsUB&ezmdGLL67H#$ojw@XflcaIaf" // 32 байта, AES-256
	DEVINFO_IV  = "MydvJw*Iw1w&i^kk"                 // 16 байт IV
)

// decryptDevInfoInfo расшифровывает base64 AES-256-OFB поле "Info".
func decryptDevInfoInfo(field string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(field))
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher([]byte(DEVINFO_KEY))
	if err != nil {
		return nil, err
	}
	stream := cipher.NewOFB(block, []byte(DEVINFO_IV))
	out := make([]byte, len(raw))
	stream.XORKeyStream(out, raw)
	return out, nil
}

// ---------------------------------------------------------------------------
// PTCP wire format (Level 3). 24-байтный big-endian заголовок:
// "PTCP" | Rlid | Llid | Pid | Lmid | Rmid, затем тело.
// ---------------------------------------------------------------------------

// PTCPPayload — мультиплексированный по realm DATA-фрагмент (тип тела 0x10).
type PTCPPayload struct {
	Realm   uint32
	Payload []byte
}

func (p *PTCPPayload) Bytes() []byte {
	length := len(p.Payload) | 0x10000000
	buf := make([]byte, 12+len(p.Payload))
	binary.BigEndian.PutUint32(buf[0:4], uint32(length))
	binary.BigEndian.PutUint32(buf[4:8], p.Realm)
	binary.BigEndian.PutUint32(buf[8:12], 0)
	copy(buf[12:], p.Payload)
	return buf
}

func ParsePTCPPayload(data []byte) (*PTCPPayload, error) {
	if len(data) < 12 {
		return nil, errors.New("packet too short")
	}
	length := binary.BigEndian.Uint32(data[0:4])
	realm := binary.BigEndian.Uint32(data[4:8])
	pad := binary.BigEndian.Uint32(data[8:12])
	if pad != 0 {
		return nil, errors.New("invalid padding")
	}
	length &= 0xFFFF
	body := data[12:]
	if len(body) != int(length) {
		return nil, errors.New("invalid length")
	}
	return &PTCPPayload{Realm: realm, Payload: body}, nil
}

// PTCP — полный транспортный фрейм.
type PTCP struct {
	Rlid uint32 // ack байт-отправлено пира
	Llid uint32 // ack байт-получено локально
	Pid  uint32 // package id (SYNC-маркер или 0x0000FFFF - счётчик)
	Lmid uint32 // локальный счётчик сообщений
	Rmid uint32 // эхо пира Lmid
	Body []byte
}

func (p *PTCP) Bytes() []byte {
	buf := make([]byte, 24+len(p.Body))
	copy(buf[0:4], "PTCP")
	binary.BigEndian.PutUint32(buf[4:8], p.Rlid)
	binary.BigEndian.PutUint32(buf[8:12], p.Llid)
	binary.BigEndian.PutUint32(buf[12:16], p.Pid)
	binary.BigEndian.PutUint32(buf[16:20], p.Lmid)
	binary.BigEndian.PutUint32(buf[20:24], p.Rmid)
	copy(buf[24:], p.Body)
	return buf
}

func ParsePTCP(data []byte) (*PTCP, error) {
	if len(data) < 24 {
		return nil, errors.New("packet too short")
	}
	if string(data[0:4]) != "PTCP" {
		return nil, errors.New("invalid magic")
	}
	return &PTCP{
		Rlid: binary.BigEndian.Uint32(data[4:8]),
		Llid: binary.BigEndian.Uint32(data[8:12]),
		Pid:  binary.BigEndian.Uint32(data[12:16]),
		Lmid: binary.BigEndian.Uint32(data[16:20]),
		Rmid: binary.BigEndian.Uint32(data[20:24]),
		Body: data[24:],
	}, nil
}

// ---------------------------------------------------------------------------
// DH HTTP-over-UDP (Level 1) парсинг ответов.
// ---------------------------------------------------------------------------

type DHResponse struct {
	Version string
	Code    int
	Status  string
	Headers map[string]string
	Body    map[string]string
}

func ParseDHResponse(data string) *DHResponse {
	parts := strings.SplitN(data, "\r\n\r\n", 2)
	headPart := parts[0]
	bodyPart := ""
	if len(parts) > 1 {
		bodyPart = strings.TrimSpace(parts[1])
	}

	lines := strings.Split(headPart, "\r\n")
	statusParts := strings.SplitN(lines[0], " ", 3)
	// Не всякий payload, проходящий здесь, несёт DH status line (например,
	// infoFields прокидывает сырые ответы /info/device); парсим leniently
	// вместо паники на отсутствующем коде.
	code := 0
	if len(statusParts) > 1 {
		code, _ = strconv.Atoi(statusParts[1])
	}

	headers := make(map[string]string)
	for _, line := range lines[1:] {
		if hd := strings.SplitN(line, ": ", 2); len(hd) == 2 {
			headers[hd[0]] = hd[1]
		}
	}

	status := ""
	if len(statusParts) > 2 {
		status = strings.Join(statusParts[2:], " ")
	}
	resp := &DHResponse{
		Version: statusParts[0],
		Code:    code,
		Status:  status,
		Headers: headers,
	}
	if bodyPart != "" {
		resp.Body = parseXML(bodyPart)
	}
	return resp
}

// parseXML разворачивает <body> XML-документ в "path/to/tag" -> text.
func parseXML(data string) map[string]string {
	result := make(map[string]string)
	decoder := xml.NewDecoder(strings.NewReader(data))
	var stack []string

	for {
		tok, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}
		switch t := tok.(type) {
		case xml.StartElement:
			stack = append(stack, t.Name.Local)
		case xml.EndElement:
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		case xml.CharData:
			text := strings.TrimSpace(string(t))
			if text != "" && len(stack) > 0 {
				result[strings.Join(stack, "/")] = text
			}
		}
	}
	return result
}

// ---------------------------------------------------------------------------
// UDP-обёртка. Каждый сокет программы создаётся через NewUDP: форс udp4 и
// отключение SIO_UDP_CONNRESET на Windows (без этого прошлая ICMP
// port-unreachable травит следующий read ошибкой WSAECONNRESET).
// ---------------------------------------------------------------------------

type UDP struct {
	conn *net.UDPConn

	initErr error

	profile *appProfile // диалект запросов (никогда не nil — nil значит smartpss)

	lhost string
	lport int

	rhost string
	rport int

	// bindIP — локальный IPv4, которым ОС роутит к rhost (net.Dial на
	// UDP-сокете выбирает egress-интерфейс без отправки трафика). Это
	// последний элемент LocalAddr channel-запроса; при невозможности
	// лукапа (пустой хост, сбой маршрута) деградирует в loopback —
	// легаси-форма dh-fwd.
	bindIP string

	raddr *net.UDPAddr
	debug bool

	ptcpMu    sync.Mutex
	ptcpSent  uint32
	ptcpRecv  uint32
	ptcpCount uint32
	ptcpID    uint32
	rmid      uint32

	ackFrames uint32
	lastAck   time.Time

	rxMu        sync.Mutex
	rxBuf       []byte // переиспользуемый буфер приёма (один читатель на сокет)
	readTimeout time.Duration

	lastRecv time.Time
	debugLog func(format string, args ...any)
}

const udpRxMax = 65535

var udpListenCfg = net.ListenConfig{Control: udpControl}

func NewUDP(host string, port int, debug bool, prof *appProfile) *UDP {
	if prof == nil {
		prof = smartpssProfile
	}
	u := &UDP{rhost: host, rport: port, debug: debug, profile: prof, rxBuf: make([]byte, udpRxMax)}
	pc, err := udpListenCfg.ListenPacket(context.Background(), "udp4", "0.0.0.0:0")
	if err != nil {
		u.initErr = err
		return u
	}
	conn := pc.(*net.UDPConn)
	local := conn.LocalAddr().(*net.UDPAddr)

	// Глубокие кольца приёма/отправки: камера стримит ~1280-байтные сегменты
	// на wire rate; маленький kernel-буфер переполняется на всплесках
	// планировщика, и RTO-ретрансмиты устройства схлопывают пропускную.
	_ = conn.SetReadBuffer(4 * 1024 * 1024)
	_ = conn.SetWriteBuffer(1 * 1024 * 1024)

	u.conn = conn
	u.lhost = local.IP.String()
	u.lport = local.Port

	// Egress IP к этому пиру, резолвится один раз при создании сокета.
	// "Dial" лишь заставляет ОС выбрать маршрут — датаграмма не шлётся.
	// Приложение DMSS рекламирует этот адрес последним элементом LocalAddr.
	u.bindIP = "127.0.0.1"
	if host != "" {
		if c, err := net.Dial("udp4", net.JoinHostPort(host, strconv.Itoa(port))); err == nil {
			u.bindIP = c.LocalAddr().(*net.UDPAddr).IP.String()
			c.Close()
		}
	}

	if host != "" {
		u.raddr, err = net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:%d", host, port))
		if err != nil {
			u.initErr = err
		}
	}
	// lastRecv стартует с создания сокета, чтобы первый таймаут в readLoop
	// измерял тишину от создания, а не от epoch.
	u.lastRecv = time.Now()
	return u
}

func (u *UDP) String() string { return fmt.Sprintf(":%d", u.lport) }

func (u *UDP) Close() {
	if u.conn != nil {
		u.conn.Close()
	}
}

func (u *UDP) SetRemote(host string, port int) {
	u.rhost = host
	u.rport = port
	u.raddr, _ = net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:%d", host, port))
}

func (u *UDP) Send(data []byte) {
	if u.conn != nil && u.raddr != nil {
		u.conn.WriteTo(data, u.raddr)
	}
}

func (u *UDP) SendTo(data []byte, addr *net.UDPAddr) {
	if u.conn != nil {
		u.conn.WriteTo(data, addr)
	}
}

func (u *UDP) Recv(bufsize int, timeout time.Duration) ([]byte, error) {
	if u.conn == nil {
		if u.initErr != nil {
			return nil, u.initErr
		}
		return nil, fmt.Errorf("udp socket is not initialized")
	}

	var deadline time.Time
	if timeout > 0 {
		deadline = time.Now().Add(timeout)
	}
	u.rxMu.Lock()
	defer u.rxMu.Unlock()
	for {
		if timeout > 0 {
			u.conn.SetReadDeadline(deadline)
		} else {
			u.conn.SetReadDeadline(time.Time{})
		}
		n, _, err := u.conn.ReadFromUDP(u.rxBuf)
		if err == nil {
			u.lastRecv = time.Now()
			// Zero-copy: возвращаемый срез алиасит rxBuf и валиден до
			// следующего Recv на этом сокете. Потребители ReadPTCP
			// обрабатывают фреймы синхронно (routePTCP), так что ничего не
			// удерживает его. RecvFrom продолжает копировать, потому что
			// STUN-handshake держит буферы между чтениями.
			return u.rxBuf[:n], nil
		}
		// Windows может отравить unconnected-сокет WSAECONNRESET после
		// прошлой отправки в закрытый порт; считаем шумом и читаем дальше
		// до истечения дедлайна.
		if isConnReset(err) && timeout > 0 && time.Now().Before(deadline) {
			continue
		}
		return nil, err
	}
}

func (u *UDP) RecvFrom(bufsize int) ([]byte, *net.UDPAddr, error) {
	if u.conn == nil {
		return nil, nil, fmt.Errorf("udp socket is not initialized")
	}
	u.rxMu.Lock()
	defer u.rxMu.Unlock()
	if u.readTimeout > 0 {
		// rolling: окно пересчитывается на КАЖДЫЙ вызов. Абсолютная метка
		// после первого срабатывания превращала все следующие чтения в
		// мгновенные i/o timeout — STUN-луп успевал 296k «ретрансмитов»
		// за 44 секунды и никогда не доходил ни до успеха, ни до фейла.
		_ = u.conn.SetReadDeadline(time.Now().Add(u.readTimeout))
	} else {
		_ = u.conn.SetReadDeadline(time.Time{})
	}
	n, addr, err := u.conn.ReadFromUDP(u.rxBuf)
	if err != nil {
		if isConnReset(err) {
			return nil, addr, err
		}
		return nil, nil, err
	}
	u.lastRecv = time.Now()
	out := make([]byte, n)
	copy(out, u.rxBuf[:n])
	return out, addr, nil
}

func (u *UDP) LastRecv() time.Time { return u.lastRecv }

func (u *UDP) logf(format string, args ...any) {
	if u.debugLog != nil {
		u.debugLog(format, args...)
		return
	}
	fmt.Printf(format+"\n", args...)
}

func (u *UDP) SetTimeout(d time.Duration) {
	if u.conn == nil {
		return
	}
	if d > 0 {
		u.readTimeout = d
		_ = u.conn.SetReadDeadline(time.Now().Add(d))
	} else {
		u.readTimeout = 0
		_ = u.conn.SetReadDeadline(time.Time{})
	}
}

// Read ждёт один DH HTTP-ответ.
func (u *UDP) Read(returnError bool, timeout time.Duration) (*DHResponse, error) {
	data, err := u.Recv(4096, timeout)
	if err != nil {
		return nil, err
	}

	if u.debug {
		u.logf(":%d <<< %s:%d\n%s", u.lport, u.rhost, u.rport, string(data))
	}

	res := ParseDHResponse(string(data))
	if !returnError && res.Code >= 400 {
		return nil, fmt.Errorf("error %d: %s", res.Code, res.Status)
	}
	if u.debug {
		u.logf("Parsed <<< code=%d status=%s", res.Code, res.Status)
	}
	return res, nil
}

// clockOffset — поправка локальных часов, снятая с Date-заголовка облака.
// WSSE Created должен совпадать с серверным временем, иначе облако отвечает
// 401 Unauthorized с <Error>TimeOut</Error> (уехавшие часы машины).
var (
	clockOnce   sync.Once
	clockOffset time.Duration
)

// serverTimeSync пробует облако один раз (без auth — любой ответ несёт
// Date) и запоминает перекос локальных часов.
func serverTimeSync(u *UDP) {
	if _, err := u.Request("/probe/p2psrv", "", false, false); err != nil {
		return
	}
	data, err := u.Recv(4096, 3*time.Second)
	if err != nil {
		return
	}
	res := ParseDHResponse(string(data))
	if res == nil {
		return
	}
	if d, ok := res.Headers["Date"]; ok {
		for _, layout := range []string{"2006-01-02T15:04:05Z", time.RFC1123, time.RFC1123Z} {
			if tt, err := time.Parse(layout, d); err == nil {
				clockOffset = tt.UTC().Sub(time.Now().UTC())
				break
			}
		}
	}
}

func ensureClockSync(u *UDP) {
	clockOnce.Do(func() { serverTimeSync(u) })
}

// nowUTC — сервер-корректированное время для WSSE Created.
func nowUTC() time.Time {
	return time.Now().UTC().Add(clockOffset)
}

// nextCSeq выделяет следующий глобальный CSeq. Request делает это
// неявно; ретрансмит-запросы преаллоцируют, чтобы каждый (ре)send
// использовал одно значение.
func nextCSeq() uint32 {
	cseqLock.Lock()
	defer cseqLock.Unlock()
	cseq++
	return cseq
}

// nextCSeqFor выделяет CSeq одного логического запроса в диалекте профиля.
// smartpss держит легаси-глобальный счётчик (байт-паритет с апстримом);
// dmss берёт случайный SIGNED-int32, как приложение — маленький монотонный
// счётчик — часть dh-fwd-фингерпринта, который dmss-облако отбивало
// 403 DevPwd_InvalidDigest (live 2026-09-06). Выделяется ОДИН раз на
// логический запрос: ретрансмиты реплеят его через reqOpts.cseq /
// channelRequest.cseq, идентичность стабильна между (ре)send'ами.
func nextCSeqFor(prof *appProfile) uint32 {
	if prof.randomCSeq {
		return uint32(getNonce())
	}
	return nextCSeq()
}

// wsseDigest — облачный WSSE PasswordDigest:
// base64(SHA1(nonce + Created + "DHP2P:" + username + ":" + userkey)).
// Формула общая для всех стоковых клиентов; различается только пара
// (username, userkey) — константы в helpers / profile.go.
func wsseDigest(nonce, created, user, userkey string) string {
	h := sha1.Sum([]byte(nonce + created + "DHP2P:" + user + ":" + userkey))
	return base64.StdEncoding.EncodeToString(h[:])
}

// buildDHRequest сериализует одну DH/NF HTTP-over-UDP транзакцию с WSSE
// cloud auth-заголовками (общая для UDP-транспорта и TCP-relay бинда).
// Профиль несёт диалект стокового клиента: WSSE-пару, набор глаголов,
// лейаут Created-таймстампа и version-заголовки (smartpss не шлёт ничего —
// до-профильный wire-формат, байт в байт). Непустой pcsID добавляет
// заголовок x-pcs-request-id (DMSS p2p-channel). warmup помечает
// stun-style первый проб, который несёт только X-ToUType — без auth, без
// version-заголовков (DMSS /online/stun; у smartpss-профиля лишних
// заголовков нет, его warm-up байты не затронуты).
//
// Сериализация гейтится профилем (live 2026-09-06): dmss-профиль эмитит
// порядок заголовков ПРИЛОЖЕНИЯ — request line, X-Version, X-Sversion,
// x-pcs-request-id, X-ToUType, CSeq, Authorization, X-WSSE, Content-Type,
// Content-Length — рендеря CSeq знаковым десятичным (случайные int32
// приложения уходят в минус). smartpss держит легаси CSeq-first лейаут
// байт в байт; его счётчик CSeq не бывает отрицательным.
func buildDHRequest(method, path, body string, auth bool, myCseq uint32, prof *appProfile, pcsID string, warmup bool) []byte {
	// WSSE nonce: полный signed-int32 диапазон — приложение берёт и минуса.
	nonce, _ := rand.Int(rand.Reader, big.NewInt(1<<32))
	nonceStr := strconv.FormatInt(nonce.Int64()-(1<<31), 10)
	curdate := prof.createdNow()
	digest := wsseDigest(nonceStr, curdate, prof.wsseUser, prof.wsseUserKey)

	authBlock := ""
	if auth {
		authBlock = fmt.Sprintf(
			"Authorization: WSSE profile=\"UsernameToken\"\r\nX-WSSE: UsernameToken Username=\"%s\", PasswordDigest=\"%s\", Nonce=\"%s\", Created=\"%s\"\r\n",
			prof.wsseUser, digest, nonceStr, curdate,
		)
	}

	var sb strings.Builder
	if prof.appHeaderOrder {
		sb.WriteString(fmt.Sprintf("%s %s HTTP/1.1\r\n", method, path))
		if !warmup {
			if prof.version != "" {
				sb.WriteString(fmt.Sprintf("X-Version: %s\r\n", prof.version))
			}
			if prof.sversion != "" {
				sb.WriteString(fmt.Sprintf("X-Sversion: %s\r\n", prof.sversion))
			}
		}
		if pcsID != "" {
			sb.WriteString(fmt.Sprintf("x-pcs-request-id: %s\r\n", pcsID))
		}
		if prof.toUType != "" {
			sb.WriteString(fmt.Sprintf("X-ToUType: %s\r\n", prof.toUType))
		}
		sb.WriteString(fmt.Sprintf("CSeq: %d\r\n", int32(myCseq)))
		sb.WriteString(authBlock)
	} else {
		sb.WriteString(fmt.Sprintf("%s %s HTTP/1.1\r\nCSeq: %d\r\n", method, path, myCseq))
		sb.WriteString(authBlock)
		if pcsID != "" {
			sb.WriteString(fmt.Sprintf("x-pcs-request-id: %s\r\n", pcsID))
		}
		if warmup {
			if prof.toUType != "" {
				sb.WriteString(fmt.Sprintf("X-ToUType: %s\r\n", prof.toUType))
			}
		} else {
			if prof.version != "" {
				sb.WriteString(fmt.Sprintf("X-Version: %s\r\n", prof.version))
			}
			if prof.sversion != "" {
				sb.WriteString(fmt.Sprintf("X-Sversion: %s\r\n", prof.sversion))
			}
			if prof.toUType != "" {
				sb.WriteString(fmt.Sprintf("X-ToUType: %s\r\n", prof.toUType))
			}
		}
	}
	if body != "" {
		sb.WriteString(fmt.Sprintf("Content-Type: \r\nContent-Length: %d\r\n", len(body)))
	}
	sb.WriteString(fmt.Sprintf("\r\n%s", body))
	return []byte(sb.String())
}

// reqOpts несёт per-request расширения диалектов профилей: явный глагол
// ("" = вывести из тела), явный CSeq (ретрансмиты переиспользуют
// исходный), значение заголовка x-pcs-request-id и warmup-набор
// заголовков stun-пробы.
type reqOpts struct {
	verb   string
	cseq   uint32 // 0 = выделить по диалекту профиля (см. nextCSeqFor)
	pcsID  string // непустой → заголовок x-pcs-request-id
	warmup bool   // stun-проба: только ToUType, без version-заголовков
}

// Request отправляет одну DHGET/DHPOST транзакцию с WSSE cloud auth.
func (u *UDP) Request(path, body string, auth, shouldRead bool) (*DHResponse, error) {
	return u.RequestEx(path, body, auth, shouldRead, reqOpts{})
}

// RequestEx — Request с расширениями диалекта профиля (reqOpts).
func (u *UDP) RequestEx(path, body string, auth, shouldRead bool, ex reqOpts) (*DHResponse, error) {
	myCseq := ex.cseq
	if myCseq == 0 {
		myCseq = nextCSeqFor(u.profile)
	}

	method := ex.verb
	if method == "" {
		method = u.profile.verbGet
		if body != "" {
			method = u.profile.verbPost
		}
	}

	req := buildDHRequest(method, path, body, auth, myCseq, u.profile, ex.pcsID, ex.warmup)

	if u.debug {
		u.logf(":%d >>> %s:%d\n%s", u.lport, u.rhost, u.rport, string(req))
	}

	u.Send(req)

	if shouldRead {
		return u.Read(false, RELAY_READ_TIMEOUT)
	}
	return nil, nil
}

const (
	// Ack-коалесинг (TCP-style delayed ack): камера стримит тысячи
	// 1280-байтных DATA-фреймов в секунду; ack каждого отдельно удваивает
	// датаграммный rate и жрёт апстрим на связках chatty+bulk. Кумулятивные
	// байт-ack-и (Llid) делают delayed ack безопасными.
	ackEvery = 1
	ackDelay = 10 * time.Millisecond
)

// ScheduleAck шлёт один чистый ACK-фрейм на ackEvery принятых фреймов или
// ackDelay, что раньше. Любой исходящий фрейм тоже несёт кумулятивный ack,
// так что ничего не теряется от ожидания.
func (u *UDP) ScheduleAck() {
	u.ptcpMu.Lock()
	u.ackFrames++
	flush := u.ackFrames >= ackEvery || time.Since(u.lastAck) >= ackDelay
	if flush {
		u.ackFrames = 0
		u.lastAck = time.Now()
	}
	u.ptcpMu.Unlock()
	if flush {
		u.RequestPTCP(nil)
	}
}

// ReadPTCP ждёт один PTCP-фрейм и обновляет ack/rmid состояние.
func (u *UDP) ReadPTCP(timeout time.Duration) (*PTCP, error) {
	data, err := u.Recv(4096, timeout)
	if err != nil {
		return nil, err
	}
	ptcp, err := ParsePTCP(data)
	if err != nil {
		return nil, err
	}

	u.ptcpMu.Lock()
	// Кумулятивный ack синхронизируется со счётчиком ПИРА: его Sent несёт
	// весь переданный им объём, поэтому Recv = max(Recv, Sent + len(Body)).
	// Идемпотентно при ретрансмитах (дубль не двигает счётчик) и корректно
	// при потерях. Само-счёт `+= len(Body)` дрейфовал: недо-ack при
	// потерях — окно устройства заполнялось и камера замолкала (EOF на
	// снапах), пере-ack на дублях. Формула p2pwn ptcp.go:80-86.
	if v := ptcp.Rlid + uint32(len(ptcp.Body)); v > u.ptcpRecv {
		u.ptcpRecv = v
	}
	u.rmid = ptcp.Lmid
	u.ptcpMu.Unlock()

	return ptcp, nil
}

// RequestPTCP сериализует и шлёт один PTCP-фрейм, двигая счётчики.
// Пустое тело — чистый ACK. Тело SYNC получает специальный Pid.
//
// Семантика Pid на проводе: младшие 16 бит = окно приёма, которое мы
// рекламируем, старшие 16 бит = флаги (SYN=0x0002). Мы дреним сразу,
// поэтому всегда рекламируем полное окно 64KB — счётчик-окно, которое
// сжималось, троттлило длинные видео-сессии, потому что устройство
// честно соблюдает flow control.
func (u *UDP) RequestPTCP(body []byte) {
	u.ptcpMu.Lock()
	defer u.ptcpMu.Unlock()

	isSync := len(body) == 4 && body[0] == 0x00 && body[1] == 0x03 && body[2] == 0x01 && body[3] == 0x00

	pid := uint32(0x0000FFFF)
	if isSync {
		pid = 0x0002FFFF
	}

	ptcp := &PTCP{
		Rlid: u.ptcpSent,
		Llid: u.ptcpRecv,
		Pid:  pid,
		Lmid: u.ptcpID,
		Rmid: u.rmid,
		Body: body,
	}

	u.ptcpSent += uint32(len(body))
	u.ptcpID++
	if !isSync && len(body) > 0 {
		u.ptcpCount++
	}

	u.Send(ptcp.Bytes())
}

func GetInvertedBytes(data []byte) []byte {
	out := make([]byte, len(data))
	for i, b := range data {
		out[i] = ^b
	}
	return out
}
