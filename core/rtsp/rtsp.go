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

func Snapshot(addr, user, pass string, timeout time.Duration) ([]byte, error) {
	return SnapshotChannel(addr, user, pass, 1, timeout)
}

var StdoutSink *os.File

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

	if len(active) == 0 {
		return []int{1}
	}
	return active
}
