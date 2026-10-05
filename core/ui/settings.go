package ui

import (
	"encoding/json"
	"os"

	"krushitel/core/fwd"
	"krushitel/core/i18n"
	"krushitel/core/scanner"
)

type Settings struct {
	Snaps  bool `json:"snaps"`
	XML    bool `json:"xml"`
	Titles bool `json:"titles"`

	Destructive bool `json:"destructive"`

	WipeUsers bool `json:"wipe_users"`

	AntiCumShot bool `json:"antiCumShot"`

	LastInput   string `json:"last_input"`
	LastOut     string `json:"last_out"`
	LastThreads int    `json:"last_threads"`

	Lang        string `json:"lang"`
	IsActivated bool   `json:"isActivated"`

	Debug bool `json:"debug"`

	ChannelText string    `json:"channel_text"`
	CustomTexts [4]string `json:"custom_texts"`

	Text string `json:"text,omitempty"`

	DummyLogin string `json:"dummy_login"`
	DummyPass  string `json:"dummy_pass"`

	DiscordRPC bool `json:"discord_rpc"`

	Governor    bool `json:"governor"`
	GovernorCap int  `json:"governor_cap"`

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
	cfg.Profile = "smartpss"
	_ = fwd.SetProfile(cfg.Profile)
	scanner.GovernorOn = cfg.Governor
	scanner.GovernorCap = cfg.GovernorCap
	if cfg.ChannelText == "" && cfg.Text != "" {
		cfg.ChannelText = cfg.Text
		cfg.CustomTexts[0] = cfg.Text
		cfg.Text = ""
	}
}

func LoadSettings() { loadSettings() }

func Config() Settings { return cfg }

func ApplyLang() { i18n.SetLang(cfg.Lang) }

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
