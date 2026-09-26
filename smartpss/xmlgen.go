// xmlgen.go — bulk-запись DeviceManager-XML для импорта в SmartPSS.
// Реальные экспорты не любят больше 64 камер (<Device>) на файл — чанкуем
// так же, как PerDeviceFiles.
package smartpss

import (
	"fmt"
	"path/filepath"
	"strings"
)

// DeviceImport — камера для импорта в SmartPSS.
type DeviceImport struct {
	Serial, Login, Password string
}

// WriteXML — креды → DeviceManager-XML. Один чанк пишется ровно в path
// (без суффиксов); при переполнении 64 файлы получают суффиксы
// _1.xml, _2.xml… Возвращает число записанных файлов.
func WriteXML(path string, devices []DeviceImport) (int, error) {
	if len(devices) == 0 {
		return 0, fmt.Errorf("no devices")
	}
	if len(devices) <= 64 {
		if err := writeChunk(path, devices); err != nil {
			return 0, err
		}
		return 1, nil
	}
	base := strings.TrimSuffix(path, filepath.Ext(path))
	files := 0
	for first := 0; first < len(devices); first += 64 {
		last := first + 64
		if last > len(devices) {
			last = len(devices)
		}
		p := fmt.Sprintf("%s_%d.xml", strings.TrimSuffix(base, filepath.Ext(base)), files+1)
		if err := writeChunk(p, devices[first:last]); err != nil {
			return files, err
		}
		files++
	}
	return files, nil
}

func writeChunk(path string, devices []DeviceImport) error {
	var sb strings.Builder
	sb.WriteString(xmlHeader)
	sb.WriteString("<DeviceManager version=\"2.0\">\n")
	for _, d := range devices {
		sb.WriteString(DeviceRow(d.Serial, d.Login, Encode(d.Password)))
		sb.WriteString("\n")
	}
	sb.WriteString(xmlFooter)
	return writeFile(path, []byte(sb.String()))
}