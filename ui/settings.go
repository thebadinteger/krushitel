package ui

import (
	"encoding/json"
	"os"

	"krushitel/fwd"
)

// Settings — как в krushitel (config.json), но без dummy-полей: тут только
// то, что трогает UI.
type Settings struct {
	Snaps     bool `json:"snaps"`
	XML       bool `json:"xml"`
	Titles    bool `json:"titles"`
	Preflight bool `json:"preflight"` // пре-флайт перед боем (33044/33045/39943/6117)

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
	// Миграция старого единого текста: уходит в канал + слот 1, поле чистим.
	if cfg.ChannelText == "" && cfg.Text != "" {
		cfg.ChannelText = cfg.Text
		cfg.CustomTexts[0] = cfg.Text
		cfg.Text = ""
	}
}

func saveSettings() {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(configFile, data, 0644)
}
