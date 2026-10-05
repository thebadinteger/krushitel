package fwd

import (
	"crypto/rand"
	"fmt"
)

type appProfile struct {
	name        string
	mainServer  string
	mainPort    int
	wsseUser    string
	wsseUserKey string
	verbGet     string
	verbPost    string
	createdNow  func() string

	toUType  string
	version  string
	sversion string

	appHeaderOrder bool
	randomCSeq     bool

	pcsRequestID      bool
	extendedBody      bool
	channelRetransmit bool
	localChannel      bool
	autoSalt          bool
	noRelayAuth       bool

	relayAgentOptional bool

	warmupPath string
	warmupAuth bool
}

var smartpssProfile = &appProfile{
	name:              "smartpss",
	mainServer:        MAIN_SERVER,
	mainPort:          MAIN_PORT,
	wsseUser:          WSSE_USERNAME,
	wsseUserKey:       WSSE_USERKEY,
	verbGet:           "DHGET",
	verbPost:          "DHPOST",
	createdNow:        func() string { return nowUTC().Format("2006-01-02T15:04:05Z") },
	warmupPath:        "/probe/p2psrv",
	warmupAuth:        true,
	channelRetransmit: true,
}

var activeProfile = smartpssProfile

func ActiveProfile() *appProfile { return activeProfile }

func SetProfile(name string) error {
	if name != "" && name != "smartpss" {
		return fmt.Errorf("unknown app profile %q (only smartpss supported)", name)
	}
	activeProfile = smartpssProfile
	return nil
}

func profileByName(name string) (*appProfile, error) {
	if name == "" || name == "smartpss" {
		return smartpssProfile, nil
	}
	return nil, fmt.Errorf("unknown app profile %q (only smartpss supported)", name)
}

func randomHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}
