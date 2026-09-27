package dhip

import (
	"time"
)

// ProbeDeviceDial — прямое опознание Dahua-девайса по адресу: логин
// (NetKeyboard-байпас → challenge-дефолты → loopback), затем
// magicBox.getSystemInfo → серийник + модель. Для IP-сканера: цель по
// прямому адресу (без облака). ok = девайс опознан как Dahua.
func ProbeDeviceDial(dial Dialer) (serial, model string, ok bool) {
	conn, err := dial()
	if err != nil {
		return "", "", false
	}
	defer conn.Close()
	time.Sleep(500 * time.Millisecond)

	sess, err := dhipLogin(conn, nil)
	if err != nil {
		return "", "", false
	}

	r, err := dhipCallCollectT(conn, "magicBox.getSystemInfo", map[string]any{}, sess, 30, nil, nil, nil, nil, CallTimeout)
	if err != nil {
		return "", "", false
	}
	p, _ := r["params"].(map[string]any)
	table, _ := p["table"].([]any)
	var m map[string]any
	if len(table) > 0 {
		m, _ = table[0].(map[string]any)
	} else {
		m = p
	}
	if m == nil {
		return "", "", false
	}
	serial, _ = m["serialNo"].(string)
	if s2, _ := m["sn"].(string); serial == "" {
		serial = s2
	}
	model, _ = m["deviceType"].(string)
	if model == "" {
		model, _ = m["deviceModel"].(string)
	}
	if serial == "" && model == "" {
		return "", "", false
	}
	return serial, model, true
}
