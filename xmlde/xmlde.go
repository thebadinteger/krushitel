// Package xmlde — расшифровка SmartPSS: base64-блоб пароля и XML-экспорт
// DeviceManager → креды. Формат: login:password@domain:port.
package xmlde

import (
	"encoding/xml"
	"fmt"

	"krushitel/smartpss"
)

// DecodeBlob расшифровывает base64-блоб пароля FastUnEnc.
func DecodeBlob(blob string) (string, error) {
	return smartpss.Decode(blob)
}

// EncodeBlob шифрует plaintext пароль в блоб (для roundtrip-проверок).
func EncodeBlob(password string) string {
	return smartpss.Encode(password)
}

// Cred — одна расшифрованная строка устройства.
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

// DecodeXML парсит SmartPSS DeviceManager XML (или одиночный <Device>) и
// расшифровывает каждый password-блоб, который смогла.
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
