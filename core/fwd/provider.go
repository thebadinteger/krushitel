package fwd

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os/exec"
	"strings"
	"sync"
	"time"

	"krushitel/core/i18n"
)

var ErrExhausted = errors.New("provider: serials exhausted")

type TunnelHandle interface {
	Local(port int) string
	Dial(port int) (net.Conn, error)
	Alive() bool
	IsRelay() bool
	Close()
}

type Binding struct {
	Serial  string
	Tunnel  TunnelHandle
	Login   string
	Pass    string
	Dtype   int
	IsRelay bool

	CamHTTP int
	CamPriv int
	CamRTSP int
}

func (b Binding) HasPort(port int) bool {
	return true
}

type Provider interface {
	Acquire(ctx context.Context) (Binding, error)
	Done(serial string)
	ReQueue() int
	DeadCount() int
	Shutdown()
}

var defaultTunnelPorts = []int{37777, 5000, 80, 554}

func portSpecs(ports []int) []PortSpec {
	out := make([]PortSpec, len(ports))
	for i, p := range ports {
		out[i] = PortSpec{Local: 0, Remote: p}
	}
	return out
}

type InProcessProvider struct {
	mu       sync.Mutex
	serials  []string
	idx      int
	dead     []string
	onLog    func(string)
	attempts map[string]int

	OnDead func(serial, reason string)
}

var maxAcquireAttempts = 2

func NewInProcess(serials []string, onLog func(string)) *InProcessProvider {
	return &InProcessProvider{
		serials:  serials,
		onLog:    onLog,
		attempts: make(map[string]int),
	}
}

func (p *InProcessProvider) logf(format string, args ...any) {
	if p.onLog != nil {
		p.onLog(fmt.Sprintf(format, args...))
	}
}

func (p *InProcessProvider) Acquire(ctx context.Context) (Binding, error) {
	for {
		p.mu.Lock()
		if p.idx >= len(p.serials) {
			if len(p.dead) > 0 {
				p.serials = p.dead
				p.dead = nil
				p.idx = 0
				p.logf(i18n.Tr("ре-очередь: запуск 2-го круга для %d недоступных серийников"), len(p.serials))
			} else {
				p.mu.Unlock()
				return Binding{}, ErrExhausted
			}
		}
		serial := p.serials[p.idx]
		p.idx++
		p.mu.Unlock()

		if err := ctx.Err(); err != nil {
			return Binding{}, err
		}

		if alive, _, verr := VerifyDevice(serial, p.logf); verr == nil && !alive {
			if p.OnDead != nil {
				p.OnDead(serial, "offline (verify)")
			}
			p.logf("%s — offline (verify)", serial)
			continue
		}

		time.Sleep(time.Duration(20+rand.Intn(60)) * time.Millisecond)

		f, err := StartSupervised(ctx, serial, portSpecs(defaultTunnelPorts), func(line string) {
			p.logf("%s", line)
		})
		if err != nil {
			if ctx.Err() != nil {
				return Binding{}, ctx.Err()
			}
			p.mu.Lock()
			if errors.Is(err, ErrDeviceNotFound) {
				if p.OnDead != nil {
					p.OnDead(serial, "offline (404)")
				}
				p.logf("%s — offline (404)", serial)
			} else if errors.Is(err, ErrNoDeviceLife) {
				if p.OnDead != nil {
					p.OnDead(serial, fmt.Sprintf("нет ответа за %v", zombieTimeout))
				}
				p.logf(i18n.Tr("%s — нет ответа за %v — из очереди исключён"), serial, zombieTimeout)
			} else if errors.Is(err, ErrAuthRequired) || isAuthError(err) {
				if p.OnDead != nil {
					p.OnDead(serial, "нужны креды (type 1)")
				}
				p.logf(i18n.Tr("%s — устройство требует Type 1 auth"), serial)
			} else {
				p.attempts[serial]++
				if p.attempts[serial] >= maxAcquireAttempts {
					p.logf(i18n.Tr("%s — исчерпан (%d туннель-подъёма за прогон)"), serial, p.attempts[serial])
					if p.OnDead != nil {
						p.OnDead(serial, fmt.Sprintf("туннель: %v", err))
					}
				} else {
					p.logf(i18n.Tr("%s — туннель не встал (%v) — в ре-очередь (попытка %d/%d)"), serial, err, p.attempts[serial], maxAcquireAttempts)
					p.dead = append(p.dead, serial)
				}
			}
			p.mu.Unlock()
			continue
		}

		camHTTP, camPriv, camRTSP := f.t.DevicePorts()
		if camHTTP != 0 && camHTTP != 80 || camPriv != 0 && camPriv != 37777 || camRTSP != 0 && camRTSP != 554 {
			p.logf(i18n.Tr("%s — порты из Info: http=%d priv=%d rtsp=%d"), serial, camHTTP, camPriv, camRTSP)
		}
		return Binding{
			Serial:  serial,
			Tunnel:  fwdTunnel{f: f},
			Login:   f.User,
			Pass:    f.Pass,
			Dtype:   f.Dtype,
			IsRelay: f.IsRelay(),
			CamHTTP: camHTTP,
			CamPriv: camPriv,
			CamRTSP: camRTSP,
		}, nil
	}
}

func (p *InProcessProvider) Done(serial string) {}

func (p *InProcessProvider) ReQueue() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := len(p.dead)
	if n == 0 {
		return 0
	}
	p.serials = append(p.serials, p.dead...)
	p.dead = nil
	return n
}

func (p *InProcessProvider) DeadCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.dead)
}

func (p *InProcessProvider) Shutdown() {}

type fwdTunnel struct {
	f *Forwarder
}

func (w fwdTunnel) Local(port int) string { return w.f.Local(port) }

func (w fwdTunnel) Dial(port int) (net.Conn, error) { return w.f.DialCamera(port) }

func (w fwdTunnel) Alive() bool   { return w.f.Alive() }
func (w fwdTunnel) IsRelay() bool { return w.f.IsRelay() }
func (w fwdTunnel) Close()        { w.f.Stop() }

type dhEvent struct {
	Event   string        `json:"event"`
	Serial  string        `json:"serial"`
	Phase   string        `json:"phase"`
	Detail  string        `json:"detail"`
	Reason  string        `json:"reason"`
	Version string        `json:"version"`
	Attempt int           `json:"attempt"`
	Max     int           `json:"max"`
	Ports   []dhEventPort `json:"ports"`
}

type dhEventPort struct {
	Local  int `json:"local"`
	Remote int `json:"remote"`
}

func parseDhEvent(line string) *dhEvent {
	line = strings.TrimSpace(line)
	if line == "" || line[0] != '{' {
		return nil
	}
	var ev dhEvent
	if err := json.Unmarshal([]byte(line), &ev); err != nil {
		return nil
	}
	if ev.Event == "" {
		return nil
	}
	return &ev
}

type dhTunnel struct {
	svc     *DhFwdService
	mu      sync.Mutex
	serial  string
	ports   map[int]int
	alive   bool
	isRelay bool
}

func (t *dhTunnel) Local(port int) string {
	t.mu.Lock()
	defer t.mu.Unlock()
	if p, ok := t.ports[port]; ok {
		return fmt.Sprintf("127.0.0.1:%d", p)
	}
	return ""
}

func (t *dhTunnel) Dial(port int) (net.Conn, error) {
	t.mu.Lock()
	local, ok := t.ports[port]
	t.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("нет форварда для порта %d", port)
	}
	return net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", local), 10*time.Second)
}

func (t *dhTunnel) Alive() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.alive
}

func (t *dhTunnel) IsRelay() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.isRelay
}

func (t *dhTunnel) Close() {
	t.svc.closeSerial(t.serial)
	t.mu.Lock()
	t.alive = false
	t.mu.Unlock()
}

type DhFwdService struct {
	exePath string
	ports   []int
	batchSz int
	onLog   func(string)

	OnDead func(serial, reason string)

	mu          sync.Mutex
	stdin       io.WriteCloser
	cmd         *exec.Cmd
	remaining   []string
	batch       map[string]bool
	resolved    map[string]bool
	taken       map[string]*dhTunnel
	dead        []string
	relay       map[string]bool
	exhausted   bool
	shutdown    bool
	bindBuf     []Binding
	spawnedOnce bool
}

func NewDhFwdService(exePath string, serials []string, batchSize int, onLog func(string)) (*DhFwdService, error) {
	s := &DhFwdService{
		exePath:   exePath,
		ports:     defaultTunnelPorts,
		batchSz:   batchSize,
		onLog:     onLog,
		remaining: append([]string{}, serials...),
		batch:     map[string]bool{},
		resolved:  map[string]bool{},
		taken:     map[string]*dhTunnel{},
		relay:     map[string]bool{},
	}
	if err := s.spawn(); err != nil {
		return nil, err
	}
	s.sendQueue(s.remaining)
	s.mu.Lock()
	s.remaining = nil
	s.mu.Unlock()
	s.sendRecv()
	return s, nil
}

func (s *DhFwdService) logf(format string, args ...any) {
	if s.onLog != nil {
		s.onLog(fmt.Sprintf(format, args...))
	}
}

func (s *DhFwdService) portsArg() string {
	locals := make([]string, len(s.ports))
	cams := make([]string, len(s.ports))
	for i, p := range s.ports {
		locals[i] = "0"
		cams[i] = fmt.Sprintf("%d", p)
	}
	return strings.Join(locals, ",") + ":" + strings.Join(cams, ",")
}

func (s *DhFwdService) spawn() error {
	cmd := exec.Command(s.exePath,
		"--service",
		"-p", s.portsArg(),
		"-threads", "1",
		"--pool", "50",
	)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	s.mu.Lock()
	s.cmd = cmd
	s.stdin = stdin
	s.mu.Unlock()

	go func() {
		_, _ = io.Copy(io.Discard, stderr)
	}()
	go s.readLoop(stdout)
	s.logf("сервис dh-fwd запущен (%s)", s.exePath)
	return nil
}

func (s *DhFwdService) sendCmd(raw string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stdin == nil {
		return errors.New("service stdin closed")
	}
	_, err := io.WriteString(s.stdin, raw+"\n")
	return err
}

func (s *DhFwdService) sendQueue(serials []string) {
	if len(serials) == 0 {
		return
	}
	b, _ := json.Marshal(map[string]any{"cmd": "queue", "serials": serials})
	if err := s.sendCmd(string(b)); err != nil {
		s.logf("queue: %v", err)
	}
}

func (s *DhFwdService) sendRecv() {
	if err := s.sendCmd(fmt.Sprintf(`{"cmd":"recv","count":%d}`, s.batchSz)); err != nil {
		s.logf("recv: %v", err)
	}
}

func (s *DhFwdService) closeSerial(serial string) {
	b, _ := json.Marshal(map[string]any{"cmd": "close", "serial": serial})
	if err := s.sendCmd(string(b)); err != nil {
		s.logf("close: %v", err)
	}
}

func (s *DhFwdService) readLoop(r io.ReadCloser) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		ev := parseDhEvent(sc.Text())
		if ev != nil {
			s.handleEvent(ev)
		}
	}
	s.mu.Lock()
	dying := !s.shutdown
	s.mu.Unlock()
	if !dying {
		return
	}
	s.logf("сервис dh-fwd умер (%v) — перезапуск", sc.Err())
	s.kill()
	time.Sleep(time.Second)

	s.mu.Lock()
	for _, t := range s.taken {
		t.mu.Lock()
		t.alive = false
		t.mu.Unlock()
	}
	var reopen []string
	for sn := range s.batch {
		if !s.resolved[sn] {
			reopen = append(reopen, sn)
		}
	}
	reopen = append(reopen, s.remaining...)
	s.batch = map[string]bool{}
	s.resolved = map[string]bool{}
	s.taken = map[string]*dhTunnel{}
	s.mu.Unlock()

	if err := s.spawn(); err != nil {
		s.logf("перезапуск сервиса не удался: %v", err)
		s.mu.Lock()
		s.exhausted = true
		s.mu.Unlock()
		return
	}
	s.sendQueue(reopen)
	s.sendRecv()
}

func (s *DhFwdService) handleEvent(ev *dhEvent) {
	switch ev.Event {
	case "fwdStarted":
		s.logf("сервис dh-fwd v%s готов", ev.Version)
	case "fwdConnecting":
		s.mu.Lock()
		s.batch[ev.Serial] = true
		s.mu.Unlock()
		s.logf("%s — установление (%s)", ev.Serial, "туннель")
	case "fwdPhase":
		s.logf("[dbg] %s: %s — %s", ev.Serial, ev.Phase, ev.Detail)
		if strings.Contains(strings.ToLower(ev.Phase), "relay") || strings.Contains(strings.ToLower(ev.Detail), "relay") {
			s.mu.Lock()
			s.relay[ev.Serial] = true
			s.mu.Unlock()
		}
	case "fwdPortsOpened":
		ports := map[int]int{}
		for _, p := range ev.Ports {
			ports[p.Remote] = p.Local
		}
		s.mu.Lock()
		isRelay := s.relay[ev.Serial]
		_, wasTaken := s.taken[ev.Serial]
		unresolved := s.batch[ev.Serial] && !s.resolved[ev.Serial]
		tun := &dhTunnel{svc: s, serial: ev.Serial, ports: ports, alive: true, isRelay: isRelay}
		if !wasTaken && unresolved {
			s.taken[ev.Serial] = tun
		}
		s.mu.Unlock()
		if wasTaken {
			s.logf("%s — переразвёрнут сервисом, биндинг уже отработан", ev.Serial)
			return
		}
		if !unresolved {
			return
		}
		s.pushBinding(Binding{Serial: ev.Serial, Tunnel: tun, IsRelay: isRelay})
	case "fwdError":
		s.mu.Lock()
		s.dead = append(s.dead, ev.Serial)
		s.resolved[ev.Serial] = true
		s.mu.Unlock()
		if s.OnDead != nil {
			s.OnDead(ev.Serial, ev.Reason)
		}
		s.logf("%s — offline (%s)", ev.Serial, ev.Reason)
		s.checkBatch()
	case "fwdTunnelDied":
		s.mu.Lock()
		t, wasTaken := s.taken[ev.Serial]
		if wasTaken {
			t.mu.Lock()
			t.alive = false
			t.mu.Unlock()
		}
		s.mu.Unlock()
		if wasTaken {
			s.mu.Lock()
			s.dead = append(s.dead, ev.Serial)
			s.resolved[ev.Serial] = true
			s.mu.Unlock()
			s.logf("%s — туннель умер (%s)", ev.Serial, ev.Reason)
			s.checkBatch()
		} else {
			s.logf("%s — туннель умер до выдачи (%s), сервис переразворачивает", ev.Serial, ev.Reason)
		}
	case "fwdClosed":
		s.logf("%s — закрыт", ev.Serial)
	case "fwdQueueEmpty":
		s.mu.Lock()
		s.exhausted = true
		s.mu.Unlock()
		s.logf("очередь сервиса пуста")
	case "fwdRetry":
		s.logf("%s — retry %d/%d: %s", ev.Serial, ev.Attempt, 0, ev.Reason)
	}
}

func (s *DhFwdService) pushBinding(b Binding) {
	s.mu.Lock()
	s.bindBuf = append(s.bindBuf, b)
	s.mu.Unlock()
}

func (s *DhFwdService) checkBatch() {
	s.mu.Lock()
	need := len(s.batch) > 0 && len(s.resolved) >= len(s.batch)
	if need {
		s.batch = map[string]bool{}
		s.resolved = map[string]bool{}
	}
	s.mu.Unlock()
	if need {
		if err := s.sendCmd(`{"cmd":"nextbatch"}`); err != nil {
			s.logf("nextbatch: %v", err)
		}
	}
}

func (s *DhFwdService) Acquire(ctx context.Context) (Binding, error) {
	for {
		s.mu.Lock()
		if len(s.bindBuf) > 0 {
			b := s.bindBuf[0]
			s.bindBuf = s.bindBuf[1:]
			s.mu.Unlock()
			return b, nil
		}
		exh := s.exhausted
		s.mu.Unlock()
		if exh {
			return Binding{}, ErrExhausted
		}
		select {
		case <-ctx.Done():
			return Binding{}, ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func (s *DhFwdService) Done(serial string) {
	s.mu.Lock()
	if !s.batch[serial] || s.resolved[serial] {
		s.mu.Unlock()
		return
	}
	s.resolved[serial] = true
	need := len(s.resolved) >= len(s.batch)
	if need {
		s.batch = map[string]bool{}
		s.resolved = map[string]bool{}
	}
	s.mu.Unlock()
	if need {
		if err := s.sendCmd(`{"cmd":"nextbatch"}`); err != nil {
			s.logf("nextbatch: %v", err)
		}
	}
}

func (s *DhFwdService) ReQueue() int {
	s.mu.Lock()
	dead := s.dead
	s.dead = nil
	exh := s.exhausted
	s.mu.Unlock()
	if len(dead) == 0 {
		return 0
	}
	s.sendQueue(dead)
	if exh {
		s.mu.Lock()
		s.exhausted = false
		s.mu.Unlock()
		s.sendRecv()
	}
	return len(dead)
}

func (s *DhFwdService) DeadCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.dead)
}

func (s *DhFwdService) kill() {
	s.mu.Lock()
	cmd := s.cmd
	s.stdin = nil
	s.mu.Unlock()
	if cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
}

func (s *DhFwdService) Shutdown() {
	s.mu.Lock()
	s.shutdown = true
	s.mu.Unlock()
	_ = s.sendCmd(`{"cmd":"shutdown"}`)
	time.Sleep(500 * time.Millisecond)
	s.kill()
}
