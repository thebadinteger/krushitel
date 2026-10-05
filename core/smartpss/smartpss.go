package smartpss

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
)

const (
	constXor = 0x33941615D
	mask32   = 0xFFFFFFFF
)

var (
	SmartPSSTail  = []byte("V2.02.1")
	SmartPSSExtra = []byte{
		0x71, 0xa1, 0x6b, 0x61, 0x91, 0x1c, 0xb7, 0x5a, 0xf8, 0xc0,
		0x38, 0xd2, 0x4d, 0x8b, 0x05, 0x6b, 0x61, 0x61,
	}
	SmartPSSSeed0 = uint32(0x1A7795F2)
)

var (
	P2PWNTail  = []byte("p2pwn")
	P2PWNExtra = []byte("p2pwnownsdahuacams")
	P2PWNSeed0 = uint32(0xDEADBEEF)
)

func nextSeed(seed uint32) uint32 {
	return uint32((uint64(seed) + constXor) & mask32)
}

func applyCore(buf []byte, seed0 uint32) {
	seed := nextSeed(seed0)
	n := len(buf)

	i := 0
	for i < n-3 {
		word := binary.LittleEndian.Uint32(buf[i:])
		word ^= seed
		binary.LittleEndian.PutUint32(buf[i:], word)
		i++
		seed = nextSeed(seed)
	}

	tailIdx := n - 3
	for tailIdx < n {
		seedBytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(seedBytes, seed)
		for j := 0; j < 4; j++ {
			rawPos := tailIdx + j
			pos := rawPos
			if pos >= n {
				pos = pos % n
			}
			buf[pos] ^= seedBytes[j]
		}
		tailIdx++
		seed = nextSeed(seed)
	}
}

func popUint32LE(buf []byte) (uint32, []byte, error) {
	if len(buf) < 4 {
		return 0, nil, fmt.Errorf("buffer too short for PopInt")
	}
	v := binary.LittleEndian.Uint32(buf[len(buf)-4:])
	buf = buf[:len(buf)-4]
	return v, buf, nil
}

func pushUint32LE(buf []byte, v uint32) []byte {
	var tmp [4]byte
	binary.LittleEndian.PutUint32(tmp[:], v)
	return append(buf, tmp[:]...)
}

func Encode(password string) string {
	return encodeWith(password, SmartPSSTail, SmartPSSExtra, SmartPSSSeed0)
}

func EncodeP2PWN(password string) string {
	return encodeWith(password, P2PWNTail, P2PWNExtra, P2PWNSeed0)
}

func encodeWith(password string, tail, extra []byte, seed0 uint32) string {
	buf := []byte(password)
	buf = append(buf, tail...)
	buf = pushUint32LE(buf, uint32(len(tail)))
	buf = append(buf, extra...)
	buf = pushUint32LE(buf, uint32(len(extra)))

	applyCore(buf, seed0)
	buf = pushUint32LE(buf, seed0)

	return base64.StdEncoding.EncodeToString(buf)
}

func Decode(blob string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(blob)
	if err != nil {
		return "", fmt.Errorf("base64: %w", err)
	}
	if len(data) <= 12 {
		return "", fmt.Errorf("blob too short")
	}

	seed0, rest, err := popUint32LE(data)
	if err != nil {
		return "", err
	}
	applyCore(rest, seed0)

	extraLen, rest, err := popUint32LE(rest)
	if err != nil {
		return "", err
	}
	if int(extraLen) > len(rest) {
		return "", fmt.Errorf("extra_len > buffer (%d > %d)", extraLen, len(rest))
	}
	rest = rest[:len(rest)-int(extraLen)]

	tailLen, rest, err := popUint32LE(rest)
	if err != nil {
		return "", err
	}
	if int(tailLen) > len(rest) {
		return "", fmt.Errorf("tail_len > buffer (%d > %d)", tailLen, len(rest))
	}
	rest = rest[:len(rest)-int(tailLen)]

	if len(rest) == 0 {
		return "", fmt.Errorf("empty plaintext")
	}
	for _, b := range rest {
		if b < 0x20 || b == 0x7f {
			return "", fmt.Errorf("plaintext contains control bytes (seed mismatch?)")
		}
	}
	return string(rest), nil
}

func EscapeAttr(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "\"", "&quot;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	return s
}

func DeviceRow(serial, login, encPassword string) string {
	s := EscapeAttr(serial)
	l := EscapeAttr(login)
	b := EscapeAttr(encPassword)
	return "\t<Device name=\"" + s + "\" domain=\"" + s + "\" port=\"37777\" username=\"" +
		l + "\" password=\"" + b + "\" protocol=\"1\" connect=\"19\" />"
}

const xmlHeader = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
const xmlFooter = "</DeviceManager>\n"

type PerDeviceFiles struct {
	mu     sync.Mutex
	dir    string
	count  int
	prefix string
	seen   map[string]struct{}
}

func NewDeviceFiles(dir string) (*PerDeviceFiles, error) {
	if dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, err
		}
	}
	p := &PerDeviceFiles{dir: dir, prefix: "import", seen: map[string]struct{}{}}
	p.scanExisting()
	return p, nil
}

func (p *PerDeviceFiles) scanExisting() {
	if p.dir == "" {
		return
	}
	matches, err := filepath.Glob(filepath.Join(p.dir, p.prefix+"_*.xml"))
	if err != nil {
		return
	}
	sort.Strings(matches)
	for _, path := range matches {
		chunkIdx := 0
		base := filepath.Base(path)
		if i := strings.LastIndexByte(base, '_'); i >= 0 {
			if n, err := strconv.Atoi(strings.TrimSuffix(base[i+1:], ".xml")); err == nil {
				chunkIdx = n - 1
			}
		}
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		rows := 0
		for _, line := range strings.Split(string(data), "\n") {
			if !strings.Contains(line, "<Device name=\"") {
				continue
			}
			rows++
			if i := strings.Index(line, "name=\""); i >= 0 {
				if rest := line[i+len("name=\""):]; len(rest) > 0 {
					if j := strings.IndexByte(rest, '"'); j > 0 {
						p.seen[rest[:j]] = struct{}{}
					}
				}
			}
		}
		if rows > 0 && chunkIdx >= p.count/64 {
			p.count = chunkIdx*64 + rows
		}
	}
}

func (p *PerDeviceFiles) Append(serial, login, password string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if _, ok := p.seen[serial]; ok {
		return nil
	}
	chunkIdx := p.count / 64
	p.count++
	p.seen[serial] = struct{}{}
	return p.appendRow(chunkIdx, DeviceRow(serial, login, Encode(password)))
}

func (p *PerDeviceFiles) appendRow(chunkIdx int, row string) error {
	path := fmt.Sprintf("%s_%d.xml", p.prefix, chunkIdx+1)
	if p.dir != "" {
		path = filepath.Join(p.dir, path)
	}

	existing, err := readFile(path)
	var sb strings.Builder
	if err != nil {
		sb.WriteString(xmlHeader)
		sb.WriteString("<DeviceManager version=\"2.0\">\n")
	} else {
		content := string(existing)
		if i := strings.Index(content, xmlFooter); i >= 0 {
			content = content[:i]
		}
		content = strings.TrimRight(content, "\n")
		if content != "" {
			sb.WriteString(content)
			sb.WriteString("\n")
		}
	}
	sb.WriteString(row)
	sb.WriteString("\n")
	sb.WriteString(xmlFooter)

	return writeFile(path, []byte(sb.String()))
}

func (p *PerDeviceFiles) Total() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.count
}
