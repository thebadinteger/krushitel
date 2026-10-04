package rtsp

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	rtsnap "github.com/thebadinteger/rtsnap"
)

var (
	ErrNoVideoTrack = errors.New("rtsp: H264/H265-трек не обнаружен в SDP")
	ErrTimeout      = errors.New("rtsp: таймаут ожидания декодированного кадра")
)

// Snapshot получает JPEG-кадр с канала 1.
func Snapshot(addr, user, pass string, timeout time.Duration) ([]byte, error) {
	return SnapshotChannel(addr, user, pass, 1, timeout)
}

// SnapshotChannel получает JPEG-кадр с указанного канала через RTSP.
//
// StdoutSink оставлен для совместимости (раньше сюда глушились
// stdout-принты декодера hi264). rtsnap в stdout не пишет, переменная
// больше ни на что не влияет — ставится из головного пакета, убирать
// присваивание там не обязательно.
//
// Deprecated: ни на что не влияет, rtsnap не шумит в stdout.
var StdoutSink *os.File //nolint:revive // совместимость со старым API

func SnapshotChannel(addr, user, pass string, channel int, timeout time.Duration) ([]byte, error) {
	if channel <= 0 {
		channel = 1
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	var lastErr error
	for _, subtype := range []int{1, 0} {
		rtspURL := fmt.Sprintf("rtsp://%s/cam/realmonitor?channel=%d&subtype=%d", addr, channel, subtype)
		data, err := snapshotURL(rtspURL, user, pass, timeout)
		if err == nil {
			return data, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("rtsp: не удалось")
	}
	return nil, lastErr
}

func snapshotURL(rtspURL, user, pass string, timeout time.Duration) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return rtsnap.SnapshotJPEG(ctx, rtspURL, 85,
		rtsnap.WithAuth(user, pass),
		rtsnap.WithTimeout(timeout),
	)
}

// ProbeChannel проверяет активность видеопотока на канале (RTSP DESCRIBE).
// Возвращает true, если в SDP описан валидный видео-трек.
func ProbeChannel(addr, user, pass string, channel int, timeout time.Duration) bool {
	if channel <= 0 {
		channel = 1
	}
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	rtspURL := fmt.Sprintf("rtsp://%s/cam/realmonitor?channel=%d&subtype=0", addr, channel)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	info, err := rtsnap.Query(ctx, rtspURL,
		rtsnap.WithAuth(user, pass),
		rtsnap.WithTimeout(timeout),
	)
	if err != nil || info == nil {
		return false
	}
	return len(info.Tracks) > 0
}

// FindActiveChannels опрашивает каналы 1..totalChannels и возвращает срез только активных каналов.
// Опрос выполняется параллельно пулом воркеров (до 4 параллельных проверок) с таймаутом timeout на канал.
func FindActiveChannels(addr, user, pass string, totalChannels int, timeout time.Duration) []int {
	if totalChannels <= 1 {
		return []int{1}
	}
	if timeout <= 0 {
		timeout = 2 * time.Second
	}

	type probeRes struct {
		ch int
		ok bool
	}
	resCh := make(chan probeRes, totalChannels)
	sem := make(chan struct{}, 8)

	var wg sync.WaitGroup
	for ch := 1; ch <= totalChannels; ch++ {
		wg.Add(1)
		go func(c int) {
			defer wg.Done()
			sem <- struct{}{}
			ok := ProbeChannel(addr, user, pass, c, timeout)
			<-sem
			resCh <- probeRes{ch: c, ok: ok}
		}(ch)
	}

	wg.Wait()
	close(resCh)

	activeMap := make(map[int]bool)
	for r := range resCh {
		if r.ok {
			activeMap[r.ch] = true
		}
	}

	var active []int
	for ch := 1; ch <= totalChannels; ch++ {
		if activeMap[ch] {
			active = append(active, ch)
		}
	}

	// Если ни один канал не ответил (например, строгий фаервол или RTSP требует нестандартных прав),
	// чтобы не потерять снап, пробуем канал 1 по умолчанию.
	if len(active) == 0 {
		return []int{1}
	}
	return active
}
