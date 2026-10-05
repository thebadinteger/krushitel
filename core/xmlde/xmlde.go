package xmlde

import (
	"encoding/xml"
	"fmt"

	"krushitel/core/smartpss"
)

func DecodeBlob(blob string) (string, error) {
	return smartpss.Decode(blob)
}

func EncodeBlob(password string) string {
	return smartpss.Encode(password)
}

type Cred struct {
	Username string
	Password string
	Domain   string
	Port     string
	Serial   string
}

type deviceXML struct {
	Name     string `xml:"name,attr"`
	Domain   string `xml:"domain,attr"`
	Port     string `xml:"port,attr"`
	Username string `xml:"username,attr"`
	Password string `xml:"password,attr"`
}

type deviceManagerXML struct {
	Version string      `xml:"version,attr"`
	Devices []deviceXML `xml:"Device"`
}

func DecodeXML(data []byte) ([]Cred, error) {
	var dm deviceManagerXML
	var devices []deviceXML
	if err := xml.Unmarshal(data, &dm); err != nil {
		var d deviceXML
		if err2 := xml.Unmarshal(data, &d); err2 != nil {
			return nil, err
		}
		devices = []deviceXML{d}
	} else {
		devices = dm.Devices
	}

	var creds []Cred
	for _, dev := range devices {
		plain, err := smartpss.Decode(dev.Password)
		if err != nil {
			continue
		}
		creds = append(creds, Cred{
			Username: dev.Username,
			Password: plain,
			Domain:   dev.Domain,
			Port:     dev.Port,
			Serial:   dev.Name,
		})
	}
	if len(creds) == 0 {
		return nil, fmt.Errorf("no decodable devices")
	}
	return creds, nil
}
