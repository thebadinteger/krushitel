package fwd

// checker.go — быстрый авторитетный чек жизни серийника.
//
// /online/p2psrv/<SN> — НЕ проверка живости: облако Dahua это hash-routed
// кластер, p2psrv отвечает 200+US на любой серийник. ProbeOnline, который
// смотрел только p2psrv, — мёртвый код (ни одного вызова) и вдобавок
// сломанный критерий. Единственный авторитетный сигнал жизни — ack
// САМОГО УСТРОЙСТВА на p2p-channel запрос, отправленный через облако:
//
//	200 (+LocalAddr)  → камера жива
//	401/403 при Type 0 → камера жива, но требует Type-1 auth (2024+)
//	404               → камеры нет / оффлайн (авторитетный dead)
//	тишина            → не авторитетно (облако молча дропает)
//
// VerifyDevice — это фазы discover+p2p-channel из establish(), вырезанные
// из полного flow: без relay lookup, без relay agent, без STUN/PTCP,
// без листенеров. Цена: 1 UDP-сокет, 3-5 датаграмм, ~1-2с на живую,
// ~1с на 404, до ~10с на полную тишину.

import (
	"context"
	"fmt"
	"math/rand"
	"strings"
	"sync"
	"time"
)

// checkReadTimeout — чтение ack устройства мимо early-окна (см.
// waitChannelEarlyAck). var, а не const — тесты подменяют на миллисекунды.
var checkReadTimeout = 8 * time.Second

// VerifyDevice — быстрый чек серийника через p2p-channel round-trip.
// Возвращает (alive, needsAuth, err):
//
//	(true, false, nil)  — устройство ответило 2xx (+LocalAddr)
//	(true, true, nil)   — устройство живо, но требует Type-1 auth
//	(false, false, nil) — авторитетный dead (404)
//	(false, false, err) — тишина/ошибка: НЕ вердикт, серийник нельзя хоронить
//
// logf — куда писать протокол (nil = молча).
func VerifyDevice(serial string, logf func(string, ...any)) (bool, bool, error) {
	return verifyDeviceOn(serial, smartpssProfile.mainServer, smartpssProfile.mainPort, smartpssProfile, logf)
}

// verifyDeviceOn — VerifyDevice против явного хоста:порта (тесты).
func verifyDeviceOn(serial, host string, port int, prof *appProfile, logf func(string, ...any)) (bool, bool, error) {
	if prof == nil {
		prof = smartpssProfile
	}
	if logf == nil {
		logf = func(string, ...any) {}
	}
	u := NewUDP(host, port, false, prof)
	defer u.Close()
	if u.initErr != nil {
		return false, false, fmt.Errorf("verify socket: %w", u.initErr)
	}

	// 1. warmup — ответ читаем и выбрасываем (факт сессии), как в
	// establish: непрочитанный reply отравил бы следующее чтение
	// (сокет один, Read не мэтчит CSeq).
	u.RequestEx(prof.warmupPath, "", prof.warmupAuth, true, reqOpts{warmup: true})

	// 2. p2psrv — нужен body/US (маршрут), НЕ живость.
	// RequestEx конвертит 4xx в Go-error — 404 ловим по строке,
	// как Phase 1 в establish().
	res, err := u.RequestEx(fmt.Sprintf("/online/p2psrv/%s", serial), "", true, true, reqOpts{})
	if err != nil {
		if strings.Contains(err.Error(), "404") {
			return false, false, nil
		}
		return false, false, fmt.Errorf("verify p2psrv silent: %w", err)
	}
	if res == nil {
		return false, false, fmt.Errorf("verify p2psrv: empty response")
	}
	if res.Code == 404 {
		return false, false, nil
	}
	if res.Body["body/US"] == "" {
		return false, false, fmt.Errorf("verify p2psrv: no route (US empty)")
	}

	// 3. p2p-channel Type 0 — запрос уходит НА УСТРОЙСТВО через облако.
	aid := make([]byte, 8)
	rand.Read(aid)
	xchg := newChannelSender(u, serial, prof, 0, "", "", "", u.lport, 37777, aid)
	xchg.send(false)

	// 4. ack устройства: сначала early-окно с ретрансмитами (1.8с),
	// потом обычное чтение — как Phase 4 в establish().
	var ack *DHResponse
	if prof.channelRetransmit {
		ack = waitChannelEarlyAck(u, xchg, logf, channelAckWindow)
	}
	if ack == nil {
		var rerr error
		ack, rerr = u.Read(true, checkReadTimeout)
		if rerr == nil && ack.Code < 200 {
			// provisional (100 Trying) — ждём финальный, как establish.
			ack, rerr = u.Read(true, checkReadTimeout)
		}
		if rerr != nil {
			return false, false, fmt.Errorf("verify channel silent: %w", rerr)
		}
	}
	if ack.Code == 404 {
		return false, false, nil
	}
	if ack.Code == 401 || ack.Code == 403 {
		return true, true, nil
	}
	if ack.Code >= 400 {
		return false, false, fmt.Errorf("verify channel: code=%d %s", ack.Code, ack.Status)
	}
	return true, false, nil
}

// CheckSerials — быстрый батч-чекер с пулом воркеров: каждый воркер держит
// 1 UDP-сокет и гоняет VerifyDevice. concurrency <= 0 → 32 (облако тянет
// 32 одновременных p2p-channel, больше — рискованно). onResult вызывается
// ровно раз на серийник; тишина (err != nil) — не вердикт, хоронить нельзя.
func CheckSerials(ctx context.Context, serials []string, concurrency int, onResult func(serial string, alive, needsAuth bool, err error)) {
	checkSerialsOn(ctx, serials, concurrency, smartpssProfile.mainServer, smartpssProfile.mainPort, onResult)
}

// checkSerialsOn — CheckSerials против явного хоста:порта (тесты).
func checkSerialsOn(ctx context.Context, serials []string, concurrency int, host string, port int, onResult func(serial string, alive, needsAuth bool, err error)) {
	if concurrency < 1 {
		concurrency = 32
	}
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for _, sn := range serials {
		if ctx.Err() != nil {
			break
		}
		sem <- struct{}{}
		wg.Add(1)
		go func(serial string) {
			defer wg.Done()
			defer func() { <-sem }()
			// джиттер против UDP-шторма на старте пула
			time.Sleep(time.Duration(rand.Intn(50)) * time.Millisecond)
			alive, needsAuth, err := verifyDeviceOn(serial, host, port, smartpssProfile, nil)
			onResult(serial, alive, needsAuth, err)
		}(sn)
	}
	wg.Wait()
}
