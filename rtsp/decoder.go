// decoder.go — декодирование H.264 и H.265 (HEVC) в JPEG на чистом Go (без CGO / libavcodec).
// Используются библиотеки github.com/Eyevinn/hi264 и github.com/gen2brain/h265.
// Работает поверх доступ-юнитов (AU) из gortsplib: депакетизатор отдаёт NAL-юниты,
// мы собираем Annex-B и скармливаем декодеру. Полученный кадр сжимается стандартным image/jpeg.

package rtsp

import (
	"bytes"
	"errors"
	"fmt"
	"image"
	"image/jpeg"
	"sync"

	"github.com/Eyevinn/hi264/pkg/decoder"
	"github.com/Eyevinn/hi264/pkg/frame"
	"github.com/gen2brain/h265/hevc"
)

// jpegDecoder — H.264 / HEVC → YCbCr → JPEG на чистом Go.
type jpegDecoder struct {
	mu      sync.Mutex
	codec   string
	h264Dec *decoder.Decoder
	hevcDec *hevc.Decoder
	closed  bool
}

func newJPEGDecoder(codec string) (*jpegDecoder, error) {
	switch codec {
	case "h264":
		return &jpegDecoder{
			codec:   codec,
			h264Dec: decoder.New(),
		}, nil
	case "hevc":
		dec := &hevc.Decoder{}
		dec.Threads(1)
		return &jpegDecoder{
			codec:   codec,
			hevcDec: dec,
		}, nil
	default:
		return nil, fmt.Errorf("rtsp: неподдерживаемый кодек %q", codec)
	}
}

func (d *jpegDecoder) close() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.closed = true
	d.h264Dec = nil
	d.hevcDec = nil
}

// feed — один доступ-юнит в формате Annex-B.
// Возвращает готовые байты JPEG, когда кадр успешно декодирован.
// До первого ключевого кадра (IDR) или при неполном NAL возвращает nil, nil.
func (d *jpegDecoder) feed(au []byte) ([]byte, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.closed || len(au) == 0 {
		return nil, nil
	}

	switch d.codec {
	case "h264":
		return d.feedH264(au)
	case "hevc":
		return d.feedHEVC(au)
	default:
		return nil, errors.New("rtsp: неизвестный кодек декодера")
	}
}

func (d *jpegDecoder) feedH264(au []byte) ([]byte, error) {
	if d.h264Dec == nil {
		return nil, nil
	}
	// DecodeIDRAnnexB парсит SPS/PPS и декодирует IDR-кадры,
	// пропуская P-кадры до первого ключевого
	frames, err := d.h264Dec.DecodeIDRAnnexB(au)
	if err != nil {
		// Ошибка на промежуточном/неполном NALU — не фатально, ждём следующий AU
		return nil, nil
	}
	if len(frames) == 0 {
		return nil, nil
	}
	return encodeH264(frames[0])
}

func encodeH264(f *frame.Frame) ([]byte, error) {
	if f == nil || f.Width <= 0 || f.Height <= 0 {
		return nil, nil
	}
	img := &image.YCbCr{
		Y:              f.Y,
		Cb:             f.Cb,
		Cr:             f.Cr,
		YStride:        f.StrideY,
		CStride:        f.StrideC,
		SubsampleRatio: image.YCbCrSubsampleRatio420,
		Rect:           image.Rect(0, 0, f.Width, f.Height),
	}
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: 85}); err != nil {
		return nil, fmt.Errorf("rtsp: encode h264 jpeg: %w", err)
	}
	return buf.Bytes(), nil
}

func (d *jpegDecoder) feedHEVC(au []byte) ([]byte, error) {
	if d.hevcDec == nil {
		return nil, nil
	}
	nals := hevc.SplitAnnexB(au)
	for _, nal := range nals {
		pics, err := d.hevcDec.DecodeNAL(nal)
		if err != nil {
			continue
		}
		for i, pic := range pics {
			if i == 0 {
				jpegBytes, encErr := encodeHEVC(pic)
				pic.Release()
				if encErr == nil && len(jpegBytes) > 0 {
					for _, rest := range pics[1:] {
						rest.Release()
					}
					return jpegBytes, nil
				}
			} else {
				pic.Release()
			}
		}
	}
	return nil, nil
}

func encodeHEVC(pic *hevc.Picture) ([]byte, error) {
	if pic == nil || pic.Width <= 0 || pic.Height <= 0 {
		return nil, nil
	}
	var y, cb, cr []uint8
	yStride, cStride := pic.StrideY, pic.StrideC

	if len(pic.Y) > 0 {
		y = pic.Y
		cb = pic.Cb
		cr = pic.Cr
	} else if len(pic.Y16) > 0 {
		shift := uint(pic.BitDepth - 8)
		if shift > 8 {
			shift = 2
		}
		y = make([]uint8, len(pic.Y16))
		for i, v := range pic.Y16 {
			y[i] = uint8(v >> shift)
		}
		cb = make([]uint8, len(pic.Cb16))
		for i, v := range pic.Cb16 {
			cb[i] = uint8(v >> shift)
		}
		cr = make([]uint8, len(pic.Cr16))
		for i, v := range pic.Cr16 {
			cr[i] = uint8(v >> shift)
		}
	} else {
		return nil, nil
	}

	img := &image.YCbCr{
		Y:              y,
		Cb:             cb,
		Cr:             cr,
		YStride:        yStride,
		CStride:        cStride,
		SubsampleRatio: image.YCbCrSubsampleRatio420,
		Rect:           image.Rect(0, 0, pic.Width, pic.Height),
	}

	var src image.Image = img
	if pic.CropW > 0 && pic.CropH > 0 &&
		pic.CropX+pic.CropW <= pic.Width && pic.CropY+pic.CropH <= pic.Height {
		src = img.SubImage(image.Rect(pic.CropX, pic.CropY, pic.CropX+pic.CropW, pic.CropY+pic.CropH))
	}

	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, src, &jpeg.Options{Quality: 85}); err != nil {
		return nil, fmt.Errorf("rtsp: encode hevc jpeg: %w", err)
	}
	return buf.Bytes(), nil
}
