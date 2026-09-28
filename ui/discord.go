package ui

// discord.go — Discord Rich Presence purely for fun. Работает всегда,
// пока запущен бинарник (хоть в меню, хоть в прогоне), если
// в настройках включён тогл. App ID зашит в бинарь, руками ничего
// вставлять не надо. Клиента дискорда рядом нет — тихо молчим,
// всё остальное идёт как обычно.
//
// Нить безопасности: ВСЯ работа с пайпом (dial/handshake/write/close) —
// только в фоновой горутине discordWorker. Пайп дискорда синхронный и
// без дедлайнов: полудохлый Discord (висит, буфер забит) подвешивает
// Write навсегда. Раньше эти операции жили на TUI-потоке (discordTick
// дёргался из тика bubbletea) — такой висяк замораживал весь интерфейс
// «по невьебической причине». Теперь TUI-поток только кладёт последний
// статус под мьютекс и мгновенно возвращается; подвиснуть может
// максимум воркер — и то до закрытия процесса.
//
// Прочие правила:
//   - троттлинг апдейтов 15с (лимит дискорда), смена текста пушится сразу;
//   - коннект/реконнект не чаще раза в 15с (не спамим пайп каждые 500мс);
//   - любой чих гасится recover — RPC никогда не роняет программу.

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

// discordConnectRetry — пауза между попытками коннекта/реконнекта.
const discordConnectRetry = 15 * time.Second

// discordAppID — зашитый App ID (discord.com/developers → New Application).
// Тогл в настройках его только включает/выключает, менять не надо.
const discordAppID = "1550655836777353216"

// ── запрос воркеру: TUI-поток пишет, воркер читает ───────────────────

var (
	reqMu      sync.Mutex
	reqEnabled bool   // желаемое состояние (тогл настроек)
	reqDetails string // последний желаемый статус
	reqState   string
)

// workerOnce — воркер стартует один раз при первом включённом тике.
var workerOnce sync.Once

// discordEnabled — только тогл, id всегда на месте (хардкод).
func discordEnabled() bool {
	return cfg.DiscordRPC && discordAppID != ""
}

// discordReqSnapshot — снимок запроса (без пайп-операций под замком).
func discordReqSnapshot() (enabled bool, details, state string) {
	reqMu.Lock()
	defer reqMu.Unlock()
	return reqEnabled, reqDetails, reqState
}

// discordTick — дёргается из тика TUI (200мс) в ЛЮБОМ состоянии.
// Пайп НЕ трогает (он может виснуть): фиксирует желаемый статус и
// стартует воркер. r == nil или финиш = idle-статус.
func discordTick(r *runState) {
	defer func() { _ = recover() }()
	enabled := discordEnabled()
	var details, state string
	if enabled {
		details, state = discordText(r)
		if details == "" {
			enabled = false
		}
	}
	reqMu.Lock()
	reqDetails, reqState, reqEnabled = details, state, enabled
	reqMu.Unlock()
	if enabled {
		workerOnce.Do(func() { go discordWorker() })
	}
}

// discordStop — гасим presence: воркер увидит enabled=false и закроет
// пайп у себя, в своей горутине. Никто снаружи не блокируется.
func discordStop() {
	defer func() { _ = recover() }()
	reqMu.Lock()
	reqEnabled = false
	reqDetails, reqState = "", ""
	reqMu.Unlock()
}

// ── воркер: единственный владелец пайпа ──────────────────────────────

// discordWorker — фоновой владелец discord-соединения. Все блокирующие
// операции (dial, handshake, write, close) живут только здесь: зависший
// пайп подвешивает максимум эту горутину, TUI и headless продолжают.
func discordWorker() {
	defer func() { _ = recover() }()
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	var (
		conn     discordConn
		started  int64             // unix старта presence (не прогона)
		lastPush time.Time
		pushedD  string            // что реально запушено в последний раз
		pushedS  string
		lastTry  time.Time // последняя попытка коннекта (ретрай раз в 15с)
	)
	for range ticker.C {
		// чих воркера гасим локально — горутина живёт дальше
		func() {
			defer func() { _ = recover() }()
			enabled, details, state := discordReqSnapshot()
			if !enabled {
				if conn != nil {
					_ = conn.Close()
					conn = nil
				}
				pushedD, pushedS = "", ""
				lastPush = time.Time{}
				return
			}
			// коннект по необходимости (пайпа нет = CreateFile/Dial падает
			// сразу, без виса; висячий пайп подвесит воркер — не интерфейс)
			if conn == nil {
				if time.Since(lastTry) < discordConnectRetry {
					return
				}
				lastTry = time.Now()
				c, err := discordDial()
				if err != nil {
					return
				}
				if err := discordHandshake(c, discordAppID); err != nil {
					_ = c.Close()
					return
				}
				conn = c
				if started == 0 {
					started = time.Now().Unix()
				}
				lastPush, pushedD, pushedS = time.Time{}, "", ""
			}
			// пушим при смене текста сразу, иначе — раз в 15с (лимит API)
			if details == pushedD && state == pushedS &&
				!lastPush.IsZero() && time.Since(lastPush) < discordPushEvery {
				return
			}
			if err := discordSetActivity(conn, int(os.Getpid()), discordActivity{
				Details:   details,
				State:     state,
				LargeText: "krushitel v" + appVersion,
				Start:     started,
				Buttons: []discordButton{
					{Label: "Telegram", URL: "https://t.me/kkrushitel"},
					{Label: "Discord", URL: "https://discord.gg/hysJP23fAn"},
				},
			}); err != nil {
				// Сокет сдох (дискорд закрыли/подвес) — реконнект по ретраю.
				_ = conn.Close()
				conn = nil
				lastTry = time.Now()
				return
			}
			lastPush, pushedD, pushedS = time.Now(), details, state
		}()
	}
}

// discordText — скан-статус в прогоне, иначе idle-статус меню.
// Версия подставляется из appVersion, перевод — через словарь.
func discordText(r *runState) (details, state string) {
	if r != nil && !r.finished() {
		return fmt.Sprintf(tr("сканит камеры через крушитель v%s"), appVersion), discordState
	}
	return tr("в меню"), discordState
}
