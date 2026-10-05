package dhip

import (
	"encoding/json"
	"fmt"
	"net"
	"time"
)

func DumpConfig(addr, password, name string, timeout time.Duration) (string, error) {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return "", fmt.Errorf("connect: %w", err)
	}
	defer conn.Close()

	sess, err := dhipLogin(conn, nil, password)
	if err != nil {
		return "", fmt.Errorf("login: %w", err)
	}
	table, err := configGetTable(conn, sess, 40, name)
	if err != nil {
		return "", err
	}
	raw, err := json.MarshalIndent(table, "", "  ")
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

func DumpConfigDial(dial Dialer, password, name string, timeout time.Duration) (string, error) {
	return DumpConfigUserDial(dial, "admin", password, name, timeout)
}

func DumpConfigUserDial(dial Dialer, user, pass, name string, timeout time.Duration) (string, error) {
	conn, err := dial()
	if err != nil {
		return "", fmt.Errorf("connect: %w", err)
	}
	defer conn.Close()

	var sess int
	if user != "" {
		sess, err = dhipLoginAs(conn, nil, user, pass)
	} else {
		sess, err = dhipLogin(conn, nil, pass)
	}
	if err != nil {
		return "", fmt.Errorf("login: %w", err)
	}
	table, err := configGetTable(conn, sess, 40, name)
	if err != nil {
		return "", err
	}
	raw, err := json.MarshalIndent(table, "", "  ")
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

func SetChannelTitle(addr, password, title string, timeout time.Duration) error {
	return SetChannelTitleDial(AddrDialer(addr, timeout), password, title)
}

func SetChannelTitleDial(dial Dialer, password, title string) error {
	return SetChannelTitleUserDial(dial, "admin", password, title)
}

func SetChannelTitleUserDial(dial Dialer, user, password, title string) error {
	conn, err := dial()
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer conn.Close()

	sess, err := dhipLoginAs(conn, nil, user, password)
	if err != nil {
		return fmt.Errorf("login: %w", err)
	}

	name := title
	if n := len([]rune(name)); n > 32 {
		r := []rune(name)
		name = string(r[:32])
	}

	table, err := configGetTable(conn, sess, 20, "ChannelTitle")
	if err != nil {
		flatParams := make(map[string]any)
		for ch := 0; ch < 16; ch++ {
			flatParams[fmt.Sprintf("ChannelTitle[%d].Name", ch)] = name
		}
		r, ferr := dhipCallCollectT(conn, "configManager.setConfig", flatParams, sess, 21, nil, nil, nil, nil, CallTimeout)
		if ferr != nil {
			return fmt.Errorf("setConfig flat: %w", ferr)
		}
		if ok, _ := r["result"].(bool); !ok {
			return fmt.Errorf("setConfig flat: result=false")
		}
		return nil
	}

	for i := range table {
		if entry, ok := table[i].(map[string]any); ok {
			entry["Name"] = name
		}
	}
	if _, err := configSetTable(conn, sess, 22, "ChannelTitle", table); err != nil {
		return err
	}
	return nil
}

func SetCustomTitle(addr, password, title string, timeout time.Duration) (bool, error) {
	return SetCustomTitleTexts(addr, password, []string{title}, timeout)
}

func SetCustomTitleRect(addr, password, title string, rect []int, timeout time.Duration) (bool, error) {
	return SetCustomTitleRectTexts(addr, password, []string{title}, rect, timeout)
}

func SetCustomTitleTexts(addr, password string, texts []string, timeout time.Duration) (bool, error) {
	return SetCustomTitleRectTexts(addr, password, texts, nil, timeout)
}

func SetCustomTitleRectTexts(addr, password string, texts []string, rect []int, timeout time.Duration) (bool, error) {
	return SetCustomTitleRectTextsDial(AddrDialer(addr, timeout), password, texts, rect)
}

func SetCustomTitleRectTextsDial(dial Dialer, password string, texts []string, rect []int) (bool, error) {
	return SetCustomTitleRectTextsUserDial(dial, "admin", password, texts, rect)
}

func defaultSlotRect(slot int) []int {
	y1 := 1000 + slot*600
	y2 := y1 + 500
	return []int{200, y1, 4500, y2}
}

func isZeroRect(r any) bool {
	if r == nil {
		return true
	}
	switch v := r.(type) {
	case []any:
		if len(v) == 4 {
			for _, val := range v {
				switch n := val.(type) {
				case float64:
					if n != 0 {
						return false
					}
				case int:
					if n != 0 {
						return false
					}
				}
			}
			return true
		}
	case []int:
		if len(v) == 4 {
			return v[0] == 0 && v[1] == 0 && v[2] == 0 && v[3] == 0
		}
	}
	return true
}

func sendFlatVideoWidget(conn net.Conn, sess int, texts []string, rect []int) (bool, error) {
	flatParams := make(map[string]any)
	for ch := 0; ch < 32; ch++ {
		for j := 0; j < 4; j++ {
			prefix := fmt.Sprintf("VideoWidget[%d].CustomTitle[%d]", ch, j)
			if j < len(texts) {
				flatParams[prefix+".Text"] = texts[j]
				flatParams[prefix+".EncodeBlend"] = true
				flatParams[prefix+".PreviewBlend"] = true
				r := rect
				if r == nil || len(r) != 4 {
					r = defaultSlotRect(j)
				}
				flatParams[prefix+".Rect[0]"] = r[0]
				flatParams[prefix+".Rect[1]"] = r[1]
				flatParams[prefix+".Rect[2]"] = r[2]
				flatParams[prefix+".Rect[3]"] = r[3]
			} else {
				flatParams[prefix+".EncodeBlend"] = false
				flatParams[prefix+".PreviewBlend"] = false
			}
		}
	}
	r, ferr := dhipCallCollectT(conn, "configManager.setConfig", flatParams, sess, 31, nil, nil, nil, nil, CallTimeout)
	if ferr != nil {
		if isRetryableConnErr(ferr) {
			return false, nil
		}
		return false, fmt.Errorf("setConfig flat VideoWidget: %w", ferr)
	}
	if ok, _ := r["result"].(bool); !ok {
		return false, fmt.Errorf("setConfig flat VideoWidget: result=false")
	}
	return true, nil
}

func SetCustomTitleRectTextsUserDial(dial Dialer, user, password string, texts []string, rect []int) (bool, error) {
	conn, err := dial()
	if err != nil {
		return false, fmt.Errorf("connect: %w", err)
	}
	defer conn.Close()

	sess, err := dhipLoginAs(conn, nil, user, password)
	if err != nil {
		return false, fmt.Errorf("login: %w", err)
	}

	table, err := configGetTable(conn, sess, 30, "VideoWidget")
	if err != nil {
		return sendFlatVideoWidget(conn, sess, texts, rect)
	}

	changed := false
	for i := range table {
		entry, ok := table[i].(map[string]any)
		if !ok {
			continue
		}
		ct, ok := entry["CustomTitle"].([]any)
		if !ok || len(ct) == 0 {
			ct = make([]any, 4)
			for j := range ct {
				defR := defaultSlotRect(j)
				ct[j] = map[string]any{
					"Text":         "",
					"EncodeBlend":  false,
					"PreviewBlend": false,
					"Rect":         []any{defR[0], defR[1], defR[2], defR[3]},
					"FrontColor":   []any{255, 255, 255, 255},
					"BackColor":    []any{0, 0, 0, 128},
				}
			}
			entry["CustomTitle"] = ct
		}
		for j := range ct {
			c, ok := ct[j].(map[string]any)
			if !ok {
				continue
			}
			if j < len(texts) {
				c["Text"] = texts[j]
				c["EncodeBlend"] = true
				c["PreviewBlend"] = true
				if rect != nil && len(rect) == 4 {
					c["Rect"] = []any{rect[0], rect[1], rect[2], rect[3]}
				} else if isZeroRect(c["Rect"]) {
					defR := defaultSlotRect(j)
					c["Rect"] = []any{defR[0], defR[1], defR[2], defR[3]}
				}
			} else {
				c["EncodeBlend"] = false
				c["PreviewBlend"] = false
			}
			changed = true
		}
	}
	if !changed {
		return sendFlatVideoWidget(conn, sess, texts, rect)
	}
	applied, err := configSetTable(conn, sess, 31, "VideoWidget", table)
	if err != nil {
		if fapplied, ferr := sendFlatVideoWidget(conn, sess, texts, rect); ferr == nil {
			return fapplied, nil
		}
		return applied, err
	}
	return applied, nil
}

func configGetTable(conn net.Conn, sess, id int, name string) ([]any, error) {
	r, err := dhipCallCollectT(conn, "configManager.getConfig", map[string]any{
		"name": name,
	}, sess, id, nil, nil, nil, nil, CallTimeout)
	if err != nil {
		return nil, err
	}
	if ok, _ := r["result"].(bool); !ok {
		return nil, fmt.Errorf("getConfig %s: result=false", name)
	}
	params, _ := r["params"].(map[string]any)
	if params == nil {
		return nil, fmt.Errorf("getConfig %s: нет params", name)
	}
	table, _ := params["table"].([]any)
	if table == nil {
		return nil, fmt.Errorf("getConfig %s: нет table", name)
	}
	return table, nil
}

func configSetTable(conn net.Conn, sess, id int, name string, table any) (bool, error) {
	r, err := dhipCallCollectT(conn, "configManager.setConfig", map[string]any{
		"name":  name,
		"table": table,
	}, sess, id, nil, nil, nil, nil, CallTimeout)
	if err != nil {
		if isRetryableConnErr(err) {
			return false, nil
		}
		return false, fmt.Errorf("setConfig %s: %w", name, err)
	}
	if ok, _ := r["result"].(bool); !ok {
		return false, fmt.Errorf("setConfig %s: result=false", name)
	}
	return true, nil
}

func GetChannelCountDial(dial Dialer, user, password string) int {
	conn, err := dial()
	if err != nil {
		return 1
	}
	defer conn.Close()

	sess, err := dhipLoginAs(conn, nil, user, password)
	if err != nil {
		return 1
	}

	table, err := configGetTable(conn, sess, 20, "ChannelTitle")
	if err == nil && len(table) > 1 {
		return len(table)
	}

	info, err := dhipCallCollectT(conn, "magicBox.getSystemInfo", nil, sess, 21, nil, nil, nil, nil, 3*time.Second)
	if err == nil {
		if params, ok := info["params"].(map[string]any); ok {
			if ch, ok := params["videoInputChannels"].(float64); ok && ch > 1 {
				return int(ch)
			}
		}
		if result, ok := info["result"].(map[string]any); ok {
			if ch, ok := result["videoInputChannels"].(float64); ok && ch > 1 {
				return int(ch)
			}
		}
	}
	return 1
}
