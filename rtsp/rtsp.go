package rtsp

import (
	"errors"
	"fmt"
	"net/url"
	"sync"
	"time"

	"github.com/bluenviron/gortsplib/v5"
	"github.com/bluenviron/gortsplib/v5/pkg/base"
	"github.com/bluenviron/gortsplib/v5/pkg/description"
	"github.com/bluenviron/gortsplib/v5/pkg/format"
	"github.com/pion/rtp"
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
func SnapshotChannel(addr, user, pass string, channel int, timeout time.Duration) ([]byte, error) {
	if channel <= 0 {
		channel = 1
	}
	var lastErr error
	for _, subtype := range []int{1, 0} {
		u, err := base.ParseURL(fmt.Sprintf("rtsp://%s/cam/realmonitor?channel=%d&subtype=%d", addr, channel, subtype))
		if err != nil {
			return nil, err
		}
		u.User = url.UserPassword(user, pass)

		data, err := snapshotSub(u, timeout)
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

// ProbeChannel проверяет активность видеопотока на канале (RTSP DESCRIBE).
// Возвращает true, если в SDP описан валидный H264/H265 видео-трек.
func ProbeChannel(addr, user, pass string, channel int, timeout time.Duration) bool {
	if channel <= 0 {
		channel = 1
	}
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	u, err := base.ParseURL(fmt.Sprintf("rtsp://%s/cam/realmonitor?channel=%d&subtype=0", addr, channel))
	if err != nil {
		return false
	}
	u.User = url.UserPassword(user, pass)

	proto := gortsplib.ProtocolTCP
	c := &gortsplib.Client{
		Scheme:        u.Scheme,
		Host:          u.Host,
		ReadTimeout:   timeout,
		WriteTimeout:  timeout,
		Protocol:      &proto,
		OnPacketsLost: func(uint64) {},
	}
	if err := c.Start(); err != nil {
		return false
	}
	defer c.Close()

	session, _, err := c.Describe(u)
	if err != nil {
		return false
	}
	for _, m := range session.Medias {
		for _, f := range m.Formats {
			switch f.(type) {
			case *format.H264, *format.H265:
				return true
			}
		}
	}
	return false
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

// rtpADecoder — общий интерфейс RTP-депакетизаторов H264/HEVC: Decode
// возвращает NAL-юниты (без Annex-B старт-кодов) собранного доступ-юнита.
type rtpADecoder interface {
	Decode(*rtp.Packet) ([][]byte, error)
}

func snapshotSub(u *base.URL, timeout time.Duration) ([]byte, error) {
	proto := gortsplib.ProtocolTCP
	c := &gortsplib.Client{
		Scheme:       u.Scheme,
		Host:         u.Host,
		ReadTimeout:  timeout,
		WriteTimeout: timeout,
		Protocol:     &proto,
		// дефолтный хендлер gortsplib логирует "N RTP packets lost" через
		// стандартный log — а тот в TUI уходит в ленту прогона. Для снапа
		// потери RTP (пропуски sequence number, обычно камера дропает
		// кадры) — шум, глушим
		OnPacketsLost: func(uint64) {},
	}

	if err := c.Start(); err != nil {
		return nil, err
	}
	// порядок закрытия важен: СНАЧАЛА c.Close() (останавливает RTP-горутину),
	// ПОТОМ jdec.close() — иначе callback может дернуть feed() по уже
	// освобожденному декодеру (nil deref / use-after-free на cgo)
	var jdec *jpegDecoder
	defer func() {
		c.Close()
		if jdec != nil {
			jdec.close()
		}
	}()

	session, _, err := c.Describe(u)
	if err != nil {
		return nil, err
	}

	// ищем H264 или H265 трек; параметр-сеты из SDP пойдут преамбулой
	var (
		media   *description.Media
		rtpFmt  format.Format
		rtpDec  rtpADecoder
		codec   string
		params  [][]byte // Annex-B: [VPS] SPS PPS
	)

	for _, m := range session.Medias {
		for _, f := range m.Formats {
			switch ff := f.(type) {
			case *format.H264:
				media, rtpFmt, codec = m, ff, "h264"
				if ff.SPS != nil {
					params = append(params, ff.SPS)
				}
				if ff.PPS != nil {
					params = append(params, ff.PPS)
				}
			case *format.H265:
				media, rtpFmt, codec = m, ff, "hevc"
				if ff.VPS != nil {
					params = append(params, ff.VPS)
				}
				if ff.SPS != nil {
					params = append(params, ff.SPS)
				}
				if ff.PPS != nil {
					params = append(params, ff.PPS)
				}
			}
			if media != nil {
				break
			}
		}
		if media != nil {
			break
		}
	}
	if media == nil {
		return nil, ErrNoVideoTrack
	}

	switch ff := rtpFmt.(type) {
	case *format.H264:
		rtpDec, err = ff.CreateDecoder()
	case *format.H265:
		rtpDec, err = ff.CreateDecoder()
	default:
		return nil, ErrNoVideoTrack
	}
	if err != nil {
		return nil, fmt.Errorf("create rtp decoder: %w", err)
	}

	jdec, err = newJPEGDecoder(codec)
	if err != nil {
		return nil, err
	}

	frameCh := make(chan []byte, 1)
	errCh := make(chan error, 1)
	sentParams := false

	_, err = c.Setup(session.BaseURL, media, 0, 0)
	if err != nil {
		return nil, err
	}

	c.OnPacketRTP(media, rtpFmt, func(pkt *rtp.Packet) {
		aus, err := rtpDec.Decode(pkt)
		if err != nil || len(aus) == 0 {
			return // ErrMorePacketsNeeded / битый пакет — не фатально
		}

		// первый AU: подкладываем параметр-сеты из SDP, чтобы декодер
		// стартовал даже если камера шлёт их только в SDP
		nalus := aus
		if !sentParams && len(params) > 0 {
			sentParams = true
			nalus = make([][]byte, 0, len(params)+len(aus))
			nalus = append(nalus, params...)
			nalus = append(nalus, aus...)
		}

		size := 4
		for _, n := range nalus {
			size += 4 + len(n)
		}
		au := make([]byte, 0, size)
		for _, n := range nalus {
			au = append(au, 0, 0, 0, 1)
			au = append(au, n...)
		}

		jpeg, err := jdec.feed(au)
		if err != nil {
			select {
			case errCh <- err:
			default:
			}
			return
		}
		if jpeg != nil {
			select {
			case frameCh <- jpeg:
			default:
			}
		}
	})

	_, err = c.Play(nil)
	if err != nil {
		return nil, err
	}

	select {
	case frame := <-frameCh:
		return frame, nil
	case <-time.After(timeout):
		// таймаут: если был декод — отдаём его ошибку, она информативнее
		select {
		case err := <-errCh:
			return nil, fmt.Errorf("rtsp: decode: %w", err)
		default:
			return nil, ErrTimeout
		}
	}
}

// annexb — NAL-юнит с Annex-B старт-кодом (00 00 00 01).
func annexb(nalu []byte) []byte {
	out := make([]byte, 4+len(nalu))
	out[0], out[1], out[2], out[3] = 0x00, 0x00, 0x00, 0x01
	copy(out[4:], nalu)
	return out
}
