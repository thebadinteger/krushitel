package fwd

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"sort"
	"strconv"
	"strings"
	"time"
)

var DefaultScanPorts = []int{
	21,
	22,
	23,
	80,
	443,
	554,
	1935,
	5000,
	5060,
	8000,
	8080,
	8888,
	37777,
	37778,
	38800,
}

func parseIntList(s string) ([]int, error) {
	var out []int
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if loStr, hiStr, ok := strings.Cut(part, "-"); ok {
			lo, err := strconv.Atoi(strings.TrimSpace(loStr))
			if err != nil {
				return nil, err
			}
			hi, err := strconv.Atoi(strings.TrimSpace(hiStr))
			if err != nil {
				return nil, err
			}
			if lo < 1 || hi > 65535 || lo > hi {
				return nil, fmt.Errorf("invalid range %q", part)
			}
			for v := lo; v <= hi; v++ {
				out = append(out, v)
			}
			continue
		}
		v, err := strconv.Atoi(part)
		if err != nil {
			return nil, err
		}
		if v < 0 || v > 65535 {
			return nil, fmt.Errorf("port out of range: %d", v)
		}
		out = append(out, v)
	}
	return out, nil
}

func ParseScanPortList(spec string) ([]int, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" || spec == "default" || spec == "top" {
		return DefaultScanPorts, nil
	}
	if strings.Contains(spec, ":") {
		parts := strings.SplitN(spec, ":", 2)
		spec = parts[1]
	}
	ports, err := parseIntList(spec)
	if err != nil {
		return nil, err
	}
	seen := make(map[int]bool)
	var out []int
	for _, p := range ports {
		if p >= 1 && p <= 65535 && !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	sort.Ints(out)
	return out, nil
}

type PortScanResult struct {
	Port   int
	IsOpen bool
}

func (t *Tunnel) ScanSinglePort(targetPort int) bool {
	p := t.getPrimary()
	if p == nil {
		return false
	}

	realmID := rand.Uint32()
	wait12 := make(chan scanOutcome, 4)

	t.scanMu.Lock()
	t.scanWait[realmID] = wait12
	t.scanMu.Unlock()

	defer func() {
		t.scanMu.Lock()
		delete(t.scanWait, realmID)
		t.scanMu.Unlock()

		p := t.getPrimary()
		if p != nil && !t.useTCPPath {
			discPkt := make([]byte, 16)
			discPkt[0] = 0x12
			binary.BigEndian.PutUint32(discPkt[4:8], realmID)
			copy(discPkt[12:], "DISC")
			p.RequestPTCP(discPkt)
		}
	}()

	bindPkt := make([]byte, 20)
	bindPkt[0] = 0x11
	binary.BigEndian.PutUint32(bindPkt[4:8], realmID)
	binary.BigEndian.PutUint32(bindPkt[12:16], uint32(targetPort))
	bindPkt[16] = 0x7F
	bindPkt[19] = 0x01

	for attempt := 0; attempt < 2; attempt++ {
		t.bindReqMu.Lock()
		p = t.getPrimary()
		if p == nil {
			t.bindReqMu.Unlock()
			return false
		}
		p.RequestPTCP(bindPkt)
		time.Sleep(3 * time.Millisecond)
		t.bindReqMu.Unlock()

		select {
		case outcome := <-wait12:
			if outcome == scanOutcomeDisc {
				t.logf("Scan port %d: received DISC (closed)", targetPort)
				return false
			}
			t.logf("Scan port %d: received CONN (open)", targetPort)
			return true
		case <-time.After(1500 * time.Millisecond):
			if attempt == 0 {
				t.logf("Scan port %d: timeout waiting for 0x12, retrying BIND", targetPort)
			}
		case <-t.done:
			return false
		}
	}

	t.logf("Scan port %d: no response after retries (closed/unreachable)", targetPort)
	return false
}

func (t *Tunnel) scanSinglePort(targetPort int) bool {
	return t.ScanSinglePort(targetPort)
}
