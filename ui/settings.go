package ui

import (
	"encoding/json"
	"os"

	"krushitel/fwd"
	"krushitel/i18n"
	"krushitel/scanner"
)

// Settings — как в krushitel (config.json), но без dummy-полей: тут только
// то, что трогает UI.
type Settings struct {
	Snaps     bool `json:"snaps"`
	XML       bool `json:"xml"`
	Titles    bool `json:"titles"`
	Preflight bool `json:"preflight"` // пре-флайт перед боем (33044/33045/39943/6117)

	// Destructive — разрешить деструктивные оверфлоу (CVE-2025-31700 /
	// CVE-2017-3223): крашат auth-сервис камеры. По умолчанию выключено.
	Destructive bool `json:"destructive"`

	// WipeUsers — после PWNED/ADDED вычистить всех юзеров кроме admin
	// и активного логина.
	WipeUsers bool `json:"wipe_users"`

	// Последний заход: предзаполняем формы, чтобы не переписывать
	// targets.txt каждый раз (просьба из тг-чата).
	LastInput   string `json:"last_input"`
	LastOut     string `json:"last_out"`
	LastThreads int    `json:"last_threads"`

	Lang        string `json:"lang"`        // "ru" | "en"
	IsActivated bool   `json:"isActivated"` // приветствие пройдено

	Debug bool `json:"debug"` // лог-режим: дампы протокола облака в ленту логов

	// Титры (логика osd.py): ChannelTitle и CustomTitle — независимые
	// конфиги, каждый на свежем коннекте. Пустое поле = слот не
	// используется (на камере очистится).
	ChannelText string    `json:"channel_text"` // имя канала, огр 32 симв.
	CustomTexts [4]string `json:"custom_texts"` // слоты OSD 1-4, огр 22 симв.

	// legacy: старый единый текст; мигрируется в loadSettings.
	Text string `json:"text,omitempty"`

	DummyLogin string `json:"dummy_login"`
	DummyPass  string `json:"dummy_pass"`

	// Discord RPC (pure fun): тогл вкл/выкл, app id зашит в бинарь.
	DiscordRPC bool `json:"discord_rpc"`

	// ForceAppRelay (аналог dh-fwd -ar): сразу идти апп-диалектом релея —
	// без 0x17 token-обмена. Для камер/релеев, где токен-канал не живёт.
	ForceAppRelay bool `json:"force_app_relay"`

	// Governor (scan mode): AIMD-губернатор UDP-скана — сам находит
	// предел канала/роутера и держится у него. Off = максимум скорости,
	// но шквал датаграмм забивает аплинк (лаги инета).
	Governor bool `json:"governor"`
	// GovernorCap — ручной потолок PPS (0 = авто/AIMD).
	GovernorCap int `json:"governor_cap"`

	// Profile оставлен для совместимости старых config.json; всегда smartpss.
	Profile string `json:"profile"`
}

const configFile = "config.json"

var cfg = Settings{
	Snaps:       true,
	XML:         false,
	Titles:      false,
	Lang:        "ru",
	IsActivated: false,
	ChannelText: "",
	CustomTexts: [4]string{},
	DummyLogin:  "krushitel",
	DummyPass:   "TancuiPantera1337",
	Profile:     "smartpss",
	Governor:    true,
	GovernorCap: 0,
}

func loadSettings() {
	data, err := os.ReadFile(configFile)
	if err != nil {
		return
	}
	_ = json.Unmarshal(data, &cfg)
	if cfg.Lang == "" {
		cfg.Lang = "ru"
	}
	// Dolynk/DMSS удалены: профиль всегда smartpss, что бы ни лежало в конфиге.
	cfg.Profile = "smartpss"
	_ = fwd.SetProfile(cfg.Profile)
	// -ar из dh-fwd: форс апп-диалекта на релее (глобаль fwd-пакета).
	fwd.ForceAppRelay = cfg.ForceAppRelay
	// Губернатор скана (scan mode): тумблер + ручной потолок PPS.
	scanner.GovernorOn = cfg.Governor
	scanner.GovernorCap = cfg.GovernorCap
	// Миграция старого единого текста: уходит в канал + слот 1, поле чистим.
	if cfg.ChannelText == "" && cfg.Text != "" {
		cfg.ChannelText = cfg.Text
		cfg.CustomTexts[0] = cfg.Text
		cfg.Text = ""
	}
}

// LoadSettings — чтение config.json для headless-режима (до старта CLI).
func LoadSettings() { loadSettings() }

// Config — снимок настроек для headless-режима.
func Config() Settings { return cfg }

// ApplyLang — выставить язык i18n из конфига (headless не проходит через
// ui.Run, где это делается само).
func ApplyLang() { i18n.SetLang(cfg.Lang) }

// RememberRun — запомнить параметры последнего захода в config.json.
func RememberRun(inFile, outDir string, threads int) {
	if inFile != "" {
		cfg.LastInput = inFile
	}
	if outDir != "" {
		cfg.LastOut = outDir
	}
	if threads > 0 {
		cfg.LastThreads = threads
	}
	saveSettings()
}

func saveSettings() {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(configFile, data, 0644)
}
