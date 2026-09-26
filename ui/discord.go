package ui

// discord.go — Discord Rich Presence purely for fun. Работает всегда,
// пока запущен бинарник (хоть в меню, хоть в прогоне), если
// в настройках включён тогл. App ID зашит в бинарь, руками ничего
// вставлять не надо. Клиента дискорда рядом нет — тихо молчим,
// всё остальное идёт как обычно.
//
// Правила безопасности:
//   - троттлинг апдейтов 15с (лимит дискорда), смена текста пушится сразу;
//   - ретрай коннекта не чаще раза в 15с (не спамим пайп каждые 200мс);
//   - любой чих либы гасится recover — RPC никогда не роняет программу;
//   - Logout только если Login прошёл (там внутри паника на ошибке).

import (
	"fmt"
	"os"
	"sync"
	"time"

	"krushitel/update"
)

// appVersion — алиас единственного источника версии (пакет update:
// туда же смотрят проверка обновлений, баннер и краш-сплеш).
const appVersion = update.CurrentVersion

// discordState — вторая строка presence, общая для всех режимов и языков.
const discordState = "t.me/kkrushitel | discord: .gg/hysJP23fAn"

// discordPushEvery — пауза между SET_ACTIVITY (лимит API).
const discordPushEvery = 15 * time.Second

// discordAppID — зашитый App ID (discord.com/developers → New Application).
// Тогл в настройках его только включает/выключает, менять не надо.
const discordAppID = "1550655836777353216"

var (
	rpcMu          sync.Mutex
	rpcConn        discordConn
	rpcOn          bool
	rpcStarted     int64 // unix старта presence (таймер от запуска, не от прогона)
	rpcLastPush    time.Time
	rpcNextRetry   time.Time
	rpcLastDetails string
	rpcLastState   string
)

// discordEnabled — только тогл, id всегда на месте (хардкод).
func discordEnabled() bool {
	return cfg.DiscordRPC && discordAppID != ""
}

// discordStart — один хендшейк до первого успеха. false = дискорда рядом
// нет, молчим. rpcStarted выставляется один раз (таймер от запуска
// бинарника), на переподключениях не сбрасывается.
func discordStart() (ok bool) {
	defer func() { _ = recover() }()
	if !discordEnabled() {
		return false
	}
	rpcMu.Lock()
	defer rpcMu.Unlock()
	if rpcOn {
		return true
	}
	conn, err := discordDial()
	if err != nil {
		return false
	}
	if err := discordHandshake(conn, discordAppID); err != nil {
		_ = conn.Close()
		return false
	}
	rpcConn = conn
	rpcOn = true
	if rpcStarted == 0 {
		rpcStarted = time.Now().Unix()
	}
	return true
}

// discordStop — закрываем сокет, присутствие гаснет само.
func discordStop() {
	defer func() { _ = recover() }()
	rpcMu.Lock()
	defer rpcMu.Unlock()
	if !rpcOn {
		return
	}
	rpcOn = false
	if rpcConn != nil {
		_ = rpcConn.Close()
		rpcConn = nil
	}
	rpcLastDetails = ""
	rpcLastState = ""
}

// discordPush — один SET_ACTIVITY. Вызывает тот, кто держит троттлинг.
func discordPush(details, state string) {
	defer func() { _ = recover() }()
	rpcMu.Lock()
	defer rpcMu.Unlock()
	if !rpcOn || rpcConn == nil {
		return
	}
	if err := discordSetActivity(rpcConn, int(os.Getpid()), discordActivity{
		Details:   details,
		State:     state,
		LargeText: "krushitel v" + appVersion,
		Start:     rpcStarted,
		Buttons: []discordButton{
			{Label: "Telegram", URL: "https://t.me/kkrushitel"},
			{Label: "Discord", URL: "https://discord.gg/hysJP23fAn"},
		},
	}); err != nil {
		// Сокет сдох (дискорд закрыли) — молча отваливаемся, ретрай через 15с.
		rpcOn = false
		_ = rpcConn.Close()
		rpcConn = nil
		rpcNextRetry = time.Now().Add(discordPushEvery)
	}
}

// discordTick — дёргается из тика TUI (200мс) в ЛЮБОМ состоянии:
// коннектится при старте бинарника, раз в 15с пушит статус,
// при смене текста (меню ↔ скан) пушит сразу без троттлинга.
// r == nil или финиш = idle-статус, активный прогон = скан-статус.
func discordTick(r *runState) {
	defer func() { _ = recover() }()
	if !discordEnabled() {
		if isRpcOn() {
			discordStop()
		}
		return
	}
	if !isRpcOn() {
		rpcMu.Lock()
		wait := time.Now().Before(rpcNextRetry)
		rpcMu.Unlock()
		if wait {
			return
		}
		if !discordStart() {
			rpcMu.Lock()
			rpcNextRetry = time.Now().Add(discordPushEvery)
			rpcMu.Unlock()
			return
		}
	}
	details, state := discordText(r)
	rpcMu.Lock()
	same := details == rpcLastDetails && state == rpcLastState
	throttled := time.Since(rpcLastPush) < discordPushEvery && !rpcLastPush.IsZero()
	rpcMu.Unlock()
	if same && throttled {
		return
	}
	if details == "" {
		return
	}
	discordPush(details, state)
	rpcMu.Lock()
	if rpcOn {
		rpcLastPush = time.Now()
		rpcLastDetails = details
		rpcLastState = state
	}
	rpcMu.Unlock()
}

// isRpcOn — чтение флага без гонки.
func isRpcOn() bool {
	rpcMu.Lock()
	defer rpcMu.Unlock()
	return rpcOn
}

// discordText — скан-статус в прогоне, иначе idle-статус меню.
// Версия подставляется из appVersion, перевод — через словарь.
func discordText(r *runState) (details, state string) {
	if r != nil && !r.finished() {
		return fmt.Sprintf(tr("сканит камеры через крушитель v%s"), appVersion), discordState
	}
	return tr("в меню"), discordState
}
