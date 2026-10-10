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

func sdkLoginHash(username, password, realm, random string) string {
	firstHalf := standardRPCHash(username, password, realm, random)
	h := md5.Sum([]byte(username + ":" + random + ":" + gen1Hash(password)))
	secondHalf := strings.ToUpper(hex.EncodeToString(h[:]))
	return firstHalf + secondHalf
}

type Client struct {
	addr string
	conn net.Conn
	// dial opens a fresh connection to the camera. Login retries redial: a
	// challenge that arrives unusable is usually a stale realm rather than a
	// dead camera, and a brand new connection clears it.
	dial func() (net.Conn, error)
	user string
	pass string
}

func New(addr, user, pass string) *Client {
	return &Client{addr: addr, dial: func() (net.Conn, error) {
		return net.DialTimeout("tcp", addr, 10*time.Second)
	}, user: user, pass: pass}
}

func NewOnConn(conn net.Conn, user, pass string) *Client {
	used := false
	return &Client{conn: conn, dial: func() (net.Conn, error) {
		if used {
			return nil, fmt.Errorf("single-shot connection already consumed")
		}
		used = true
		return conn, nil
	}, user: user, pass: pass}
}

// NewOnDialer builds a client that can open as many fresh connections as the
// login flow needs. Used for the tunnel path, where the camera sometimes hands
// back a challenge bound to a realm we are not on.
func NewOnDialer(dial func() (net.Conn, error), user, pass string) *Client {
	return &Client{dial: dial, user: user, pass: pass}
}

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

// challengeField pulls one value out of a login challenge body.
//
// Firmware in the field is not consistent about how it terminates the last
// field: some builds omit the trailing CRLF entirely, some use bare LF, and
// some separate the key from the value with '=' instead of ':'. Requiring a
// CRLF after both fields rejected valid challenges, which showed up as
// "login: challenge without realm/random" on cameras that answer fine.
// Take everything up to the next line break, or to the end of the buffer.
func challengeField(text, key string) string {
	for _, sep := range []string{key + ":", key + "="} {
		idx := strings.Index(text, sep)
		if idx < 0 {
			continue
		}
		val := text[idx+len(sep):]
		if end := strings.IndexAny(val, "\r\n"); end >= 0 {
			val = val[:end]
		}
		if val = strings.TrimSpace(val); val != "" {
			return val
		}
	}
	return ""
}

func parseChallengeBody(body []byte) (realm, random string) {
	text := string(body)
	return challengeField(text, "Realm"), challengeField(text, "Random")
}

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

// readFrame reads one SDK frame: a 32-byte header plus the body.
//
// The length field at hdr[4:8] is ambiguous in the wild. Firmware that answers
// the way loginPacket addresses a packet excludes the header, so pl is the body
// length; other builds include it. Trusting either reading outright breaks one
// case or the other — the pl-32 formula truncates a body-only answer to a few
// bytes, and reading pl when the header is included blocks forever waiting for
// bytes that never arrive.
//
// So read what is actually there: accumulate until the frame looks complete by
// either reading, or until the buffered data already carries a login challenge
// (the extra trailing bytes of an over-long read do not confuse the parser,
// which searches for its keys).
func readFrame(conn net.Conn) ([]byte, error) {
	hdr := make([]byte, 32)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return nil, err
	}
	pl := binary.LittleEndian.Uint32(hdr[4:8])
	if pl > snapshotFrameCap {
		return nil, fmt.Errorf("sdk frame too large: %d", pl)
	}

	// Frames with no body (bare acks) are exactly the 32-byte header.
	if pl <= 32 {
		return hdr, nil
	}

	bodyWanted := int(pl - 32) // length includes the header
	if int(pl) > bodyWanted {
		bodyWanted = int(pl) // length is the body itself
	}
	if bodyWanted > snapshotFrameCap {
		bodyWanted = snapshotFrameCap
	}

	body := make([]byte, 0, bodyWanted+512)
	chunk := make([]byte, 4096)
	for len(body) < bodyWanted {
		n, err := conn.Read(chunk)
		if n > 0 {
			body = append(body, chunk[:n]...)
			// Enough to act on already.
			if looksComplete(body, len(body) >= bodyWanted) {
				break
			}
		}
		if err != nil {
			break
		}
	}
	return append(hdr, body...), nil
}

// looksComplete reports whether the buffered body is enough to work with: the
// declared length has been satisfied, or a login challenge has fully arrived.
func looksComplete(body []byte, lenSatisfied bool) bool {
	if lenSatisfied {
		return true
	}
	text := string(body)
	if i := strings.Index(text, "Realm"); i >= 0 {
		if challengeField(text[i:], "Random") != "" {
			return true
		}
	}
	return false
}

// loginRoundTrips is how many fresh connections a single snapshot may spend on
// authentication. A challenge that arrives unusable (stale realm, truncated
// frame, firmware quirk) is not a dead camera, and p2pwn recovers from exactly
// this by rebinding a new realm and re-reading the challenge. Here a new realm
// means a new connection through the tunnel.
const loginRoundTrips = 3

func (c *Client) login(timeout time.Duration) (net.Conn, error) {
	var lastErr error
	for attempt := 1; attempt <= loginRoundTrips; attempt++ {
		conn, err := c.dial()
		if err != nil {
			lastErr = err
			if attempt < loginRoundTrips {
				time.Sleep(loginRetryPause)
			}
			continue
		}

		ok, err := c.loginOnce(conn, timeout)
		if ok {
			return conn, nil
		}
		lastErr = err
		conn.Close()
		if attempt < loginRoundTrips {
			time.Sleep(loginRetryPause)
		}
	}
	return nil, lastErr
}

const loginRetryPause = 250 * time.Millisecond

// loginOnce performs the full challenge/response exchange on one connection.
// On failure it closes nothing and returns the error verbatim so the caller
// can decide whether a fresh connection is worth another round trip.
func (c *Client) loginOnce(conn net.Conn, timeout time.Duration) (bool, error) {
	conn.SetDeadline(time.Now().Add(timeout))

	if _, err := conn.Write(loginPacket(c.user, c.pass)); err != nil {
		return false, fmt.Errorf("login send: %w", err)
	}

	resp, err := readFrame(conn)
	if err != nil {
		return false, fmt.Errorf("login read: %w", err)
	}
	if len(resp) < 10 {
		return false, fmt.Errorf("login response too short (%d bytes)", len(resp))
	}
	if resp[8] == 0 {
		return true, nil
	}
	if resp[8] != 1 {
		return false, fmt.Errorf("login failed: code %d/%d", resp[8], resp[9])
	}

	cr, crnd := parseChallengeBody(resp)

	// A usable challenge sometimes only appears on the next frame: some
	// firmware answers the first request with a bare header and pushes the
	// challenge separately. Drain a little and look again before giving up.
	if cr == "" || crnd == "" {
		if extra, eerr := readChallengeFollowup(conn, 400*time.Millisecond); eerr == nil {
			if ncr, nrnd := parseChallengeBody(extra); ncr != "" && nrnd != "" {
				cr, crnd = ncr, nrnd
			}
		}
	}

	if cr == "" || crnd == "" {
		return false, fmt.Errorf("login: challenge without realm/random")
	}

	fullHash := sdkLoginHash(c.user, c.pass, cr, crnd)
	if _, err := conn.Write(hashLoginPacket(c.user, fullHash)); err != nil {
		return false, fmt.Errorf("hash login send: %w", err)
	}
	resp, err = readFrame(conn)
	if err != nil {
		return false, fmt.Errorf("hash login read: %w", err)
	}
	if len(resp) < 10 {
		return false, fmt.Errorf("hash login short (%d bytes)", len(resp))
	}
	if resp[8] != 0 {
		return false, fmt.Errorf("hash login code %d/%d", resp[8], resp[9])
	}
	return true, nil
}

// readChallengeFollowup waits briefly for an extra frame carrying the challenge.
func readChallengeFollowup(conn net.Conn, wait time.Duration) ([]byte, error) {
	deadline := time.Now().Add(wait)
	conn.SetReadDeadline(deadline)
	defer conn.SetReadDeadline(time.Time{})

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if n > 0 {
		return buf[:n], nil
	}
	return nil, err
}

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

// snapshotFrameCap bounds a single snapshot payload. A 4K frame is a few
// hundred kilobytes; 16 MB leaves room for a long frame without letting a
// broken stream spin forever.
const (
	snapshotFrameCap = 16 * 1024 * 1024
	snapshotMaxReads = 64
)

// GetSnapshot logs in, requests one channel and returns the JPEG.
//
// Ported from p2pwn's sdkbin.go (commit "snapshot fixes and recode"). The
// differences that mattered: accumulate over many reads instead of one, until
// the JPEG end marker shows up; locate SOI/EOI explicitly rather than
// assuming a fixed 32-byte header; and let the caller see every reason the
// frame failed instead of collapsing them into one error.
func (c *Client) GetSnapshot(channel int, timeout time.Duration) ([]byte, error) {
	conn, err := c.login(timeout)
	if err != nil {
		return nil, fmt.Errorf("snapshot login: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	// Drain whatever the device queued right after the login ack.
	conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	_, _ = readFrame(conn)
	conn.SetDeadline(time.Now().Add(timeout))

	if _, err := conn.Write(snapshotCmd(channel)); err != nil {
		return nil, fmt.Errorf("snapshot send: %w", err)
	}

	buf := make([]byte, 64*1024)
	var data []byte
	for i := 0; i < snapshotMaxReads; i++ {
		n, err := conn.Read(buf)
		if n > 0 {
			data = append(data, buf[:n]...)
			if len(data) > snapshotFrameCap {
				return nil, fmt.Errorf("snapshot: frame too large")
			}
		}
		if err != nil {
			if len(data) > 0 {
				break
			}
			return nil, fmt.Errorf("snapshot read: %w", err)
		}
		if containsJPEGEnd(data) {
			// Let the tail arrive, then stop.
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

	// Trim to the actual JPEG markers. Slicing a fixed 32 bytes off the front
	// only works when the frame starts with a 32-byte header; over a relay the
	// stream carries interleaved tunnel data, so find the markers instead.
	soi := index(data, []byte{0xff, 0xd8})
	if soi < 0 {
		return nil, fmt.Errorf("snapshot: no SOI found (%d bytes)", len(data))
	}
	// Первый EOI строго после SOI: хвост прошлого кадра в начале буфера даёт
	// EOI раньше SOI, и срез [soi:eoi+2] рвал процесс (panic slice bounds).
	eoi := -1
	for i := soi + 2; i+1 < len(data); i++ {
		if data[i] == 0xff && data[i+1] == 0xd9 {
			eoi = i
			break
		}
	}
	if eoi < 0 {
		return nil, fmt.Errorf("snapshot: no EOI found (%d bytes)", len(data))
	}
	data = data[soi : eoi+2]

	data = stripSnapshotGarbage(data, channel)

	if len(data) < 100 || data[0] != 0xFF || data[1] != 0xD8 {
		return nil, fmt.Errorf("snapshot: invalid jpeg (%d bytes)", len(data))
	}
	return data, nil
}

func lastIndexMarker(data []byte, a, b byte) int {
	for i := len(data) - 2; i >= 0; i-- {
		if data[i] == a && data[i+1] == b {
			return i
		}
	}
	return -1
}

type SDKUser struct {
	Index int
	Name  string
	Pass  string
	Group string
	Raw   string
}

func a1Packet() []byte {
	pkt := make([]byte, 32)
	pkt[0] = 0xa1
	return pkt
}

func a4Packet(op byte) []byte {
	pkt := make([]byte, 32)
	pkt[0] = 0xa4
	pkt[8] = op
	return pkt
}

func a6MgmtPacket(op uint32, payload []byte) []byte {
	pkt := make([]byte, 32+len(payload))
	pkt[0] = 0xa6
	pkt[4] = byte(len(payload))
	binary.LittleEndian.PutUint32(pkt[8:12], op)
	copy(pkt[32:], payload)
	return pkt
}

func (c *Client) sdkExchange(conn net.Conn, pkt []byte) ([]byte, error) {
	if _, err := conn.Write(pkt); err != nil {
		return nil, err
	}
	return readFrame(conn)
}

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

func (c *Client) GetUsers(timeout time.Duration) ([]SDKUser, string, error) {
	conn, err := c.login(timeout)
	if err != nil {
		return nil, "", fmt.Errorf("login: %w", err)
	}
	defer conn.Close()

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
