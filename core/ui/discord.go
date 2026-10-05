package ui

import (
	"fmt"
	"os"
	"sync"
	"time"

	"krushitel/core/update"
)

const appVersion = update.CurrentVersion

const discordState = "t.me/kkrushitel | discord: .gg/hysJP23fAn"

const discordPushEvery = 15 * time.Second

const discordConnectRetry = 15 * time.Second

const discordAppID = "1550655836777353216"

var (
	reqMu      sync.Mutex
	reqEnabled bool
	reqDetails string
	reqState   string
)

var workerOnce sync.Once

func discordEnabled() bool {
	return cfg.DiscordRPC && discordAppID != ""
}

func discordReqSnapshot() (enabled bool, details, state string) {
	reqMu.Lock()
	defer reqMu.Unlock()
	return reqEnabled, reqDetails, reqState
}

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

func discordStop() {
	defer func() { _ = recover() }()
	reqMu.Lock()
	reqEnabled = false
	reqDetails, reqState = "", ""
	reqMu.Unlock()
}

func discordWorker() {
	defer func() { _ = recover() }()
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	var (
		conn     discordConn
		started  int64
		lastPush time.Time
		pushedD  string
		pushedS  string
		lastTry  time.Time
	)
	for range ticker.C {
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
				_ = conn.Close()
				conn = nil
				lastTry = time.Now()
				return
			}
			lastPush, pushedD, pushedS = time.Now(), details, state
		}()
	}
}

func discordText(r *runState) (details, state string) {
	if r != nil && !r.finished() {
		return fmt.Sprintf(tr("сканит камеры через крушитель v%s"), appVersion), discordState
	}
	return tr("в меню"), discordState
}
