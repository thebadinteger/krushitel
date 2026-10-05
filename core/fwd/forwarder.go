package fwd

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"krushitel/core/i18n"
)

type Forwarder struct {
	t     *Tunnel
	Ports map[int]int
	Err   chan error
	mu    sync.Mutex
	done  chan struct{}
	User  string
	Pass  string
	Dtype int
}

var ErrDeviceNotFound = errDeviceNotFound

var DefaultPoolSize = 50

var (
	defaultCredsMu   sync.RWMutex
	DefaultLogin     = "admin"
	DefaultPasswords = []string{
		"admin",
		"admin123",
		"123456",
		"password",
		"tlJwpbo6",
		"admin777",
		"888888",
		"dahua",
	}
	LockoutCooldown = 8 * time.Second
)

func SetDefaultCreds(login string, passwords []string) {
	defaultCredsMu.Lock()
	defer defaultCredsMu.Unlock()
	if login != "" {
		DefaultLogin = login
	}
	if len(passwords) > 0 {
		DefaultPasswords = make([]string, len(passwords))
		copy(DefaultPasswords, passwords)
	}
}

func GetDefaultCreds() (string, []string) {
	defaultCredsMu.RLock()
	defer defaultCredsMu.RUnlock()
	login := DefaultLogin
	passwords := make([]string, len(DefaultPasswords))
	copy(passwords, DefaultPasswords)
	return login, passwords
}

func getDefaultCreds() (string, []string) {
	return GetDefaultCreds()
}

func LoadPasswordsFromFile(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []string
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		out = append(out, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func Start(serial string, specs []PortSpec, dtype int, user, pass string) (*Forwarder, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	return StartContext(ctx, serial, specs, dtype, user, pass)
}

func StartContext(ctx context.Context, serial string, specs []PortSpec, dtype int, user, pass string) (*Forwarder, error) {
	idxs := make([]int, len(specs))
	for i := range specs {
		idxs[i] = i
	}
	g := specGroup{idxs: idxs, specs: specs}
	t := newTunnel(serial, dtype, user, pass, "", Debug, false, DefaultPoolSize, g)

	u := NewUDP(t.profile.mainServer, t.profile.mainPort, Debug, t.profile)
	ensureClockSync(u)
	u.Close()

	f := &Forwarder{
		t:     t,
		Err:   make(chan error, 1),
		done:  make(chan struct{}),
		User:  user,
		Pass:  pass,
		Dtype: dtype,
	}
	errCh := make(chan error, 1)

	go func() {
		runWithRetries(t, func(err error) { errCh <- err })
	}()

	select {
	case err := <-errCh:
		t.Terminate()
		return nil, fmt.Errorf("tunnel: %w", err)
	case <-ctx.Done():
		t.Terminate()
		return nil, ctx.Err()
	case <-t.Ready():
		f.Ports = t.LocalPorts()
		go func() {
			select {
			case err := <-errCh:
				select {
				case f.Err <- err:
				default:
				}
			case <-f.done:
			}
		}()
		return f, nil
	}
}

func (f *Forwarder) Local(remotePort int) string {
	if f != nil && f.t != nil {
		live := f.t.LocalPorts()
		if p, ok := live[remotePort]; ok && p > 0 {
			return fmt.Sprintf("127.0.0.1:%d", p)
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if p, ok := f.Ports[remotePort]; ok {
		return fmt.Sprintf("127.0.0.1:%d", p)
	}
	return ""
}

func (f *Forwarder) DialCamera(remotePort int) (net.Conn, error) {
	return f.t.DialCamera(remotePort)
}

func (f *Forwarder) Alive() bool {
	return !f.t.isStopped() && f.t.Failure() == nil
}

func (f *Forwarder) IsRelay() bool {
	return f != nil && f.t != nil && f.t.IsRelay()
}

func (f *Forwarder) Stop() {
	select {
	case <-f.done:
		return
	default:
		close(f.done)
	}
	f.t.Terminate()
}

func StartWithAuth(serial, user, pass string, specs []PortSpec) (*Forwarder, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 240*time.Second)
	defer cancel()
	return StartWithAuthContext(ctx, serial, user, pass, specs)
}

func StartWithAuthContext(ctx context.Context, serial, user, pass string, specs []PortSpec) (*Forwarder, error) {
	targetSerial := serial

	f, err0 := StartContext(ctx, targetSerial, specs, 0, "", "")
	if err0 == nil {
		f.User = user
		f.Pass = pass
		f.Dtype = 0
		return f, nil
	}

	if user != "" && pass != "" {
		f1, err1 := StartContext(ctx, targetSerial, specs, 1, user, pass)
		if err1 == nil {
			f1.User = user
			f1.Pass = pass
			f1.Dtype = 1
			return f1, nil
		}
		return nil, err1
	}

	if isAuthError(err0) {
		login, passwords := getDefaultCreds()
		if len(passwords) > 0 {
			for i, p := range passwords {
				if err := ctx.Err(); err != nil {
					return nil, err
				}
				if i > 0 {
					time.Sleep(LockoutCooldown)
				}
				u := login
				pw := p
				if idx := strings.Index(p, ":"); idx != -1 {
					u = p[:idx]
					pw = p[idx+1:]
				}
				f1, err1 := StartContext(ctx, targetSerial, specs, 1, u, pw)
				if err1 == nil {
					f1.User = u
					f1.Pass = pw
					f1.Dtype = 1
					return f1, nil
				}
				if errors.Is(err1, ErrDeviceNotFound) {
					return nil, err1
				}
			}
		}
		return nil, ErrAuthRequired
	}

	return nil, err0
}

func StartSupervised(ctx context.Context, serial string, specs []PortSpec, onEvent func(string)) (*Forwarder, error) {
	return StartSupervisedWithAuth(ctx, serial, "", "", specs, onEvent)
}

func StartSupervisedWithAuth(ctx context.Context, serial, user, pass string, specs []PortSpec, onEvent func(string)) (*Forwarder, error) {
	const maxAttempts = 3
	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if attempt > 1 && onEvent != nil {
			onEvent(fmt.Sprintf(i18n.Tr("туннель: переподключение (попытка %d)"), attempt))
		}
		f, err := StartWithAuthContext(ctx, serial, user, pass, specs)
		if err == nil {
			if attempt > 1 && onEvent != nil {
				onEvent(fmt.Sprintf(i18n.Tr("туннель поднят с %d-й попытки"), attempt))
			}
			return f, nil
		}
		lastErr = err
		if errors.Is(err, ErrDeviceNotFound) || errors.Is(err, ErrAuthRequired) || errors.Is(err, ErrNoDeviceLife) || isAuthError(err) {
			return nil, err
		}
		if onEvent != nil {
			onEvent(fmt.Sprintf(i18n.Tr("туннель: попытка %d не удалась (%v)"), attempt, err))
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Second):
		}
	}
	return nil, lastErr
}
