package dhip

import (
	"fmt"
	"net"
	"time"
)

// ClearCustomOSDUserDial вычищает OSD и приватные маски: тексты CustomTitle
// в "", бленды в false, каверам (Covers) бленды тоже в false.
// Имя канала не трогаем. Возвращает число вычищенных текстов+масок.
// Пишем с verify чтением назад и ретраями — молча не уходим.
func ClearCustomOSDUserDial(dial Dialer, user, password string) (int, error) {
	conn, err := dial()
	if err != nil {
		return 0, fmt.Errorf("connect: %w", err)
	}
	defer conn.Close()

	sess, err := dhipLoginAs(conn, nil, user, password)
	if err != nil {
		return 0, fmt.Errorf("login: %w", err)
	}

	var err2 error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			time.Sleep(2 * time.Second)
		}
		var n int
		n, err2 = clearOSDPass(conn, sess)
		if err2 == nil {
			return n, nil
		}
	}
	return 0, err2
}

func clearOSDPass(conn net.Conn, sess int) (int, error) {
	table, err := configGetTable(conn, sess, 32, "VideoWidget")
	if err != nil {
		return 0, err
	}
	cleaned := 0
	scrub := func(raw any) {
		m, ok := raw.(map[string]any)
		if !ok {
			return
		}
		if ct, ok := m["CustomTitle"].([]any); ok {
			for _, c := range ct {
				cm, ok := c.(map[string]any)
				if !ok {
					continue
				}
				if t, _ := cm["Text"].(string); t != "" {
					cm["Text"] = ""
					cleaned++
				}
				cm["EncodeBlend"] = false
				cm["PreviewBlend"] = false
			}
		}
		if covers, ok := m["Covers"].([]any); ok {
			for _, c := range covers {
				cm, ok := c.(map[string]any)
				if !ok {
					continue
				}
				if onBlend(cm["EncodeBlend"]) || onBlend(cm["PreviewBlend"]) {
					cleaned++
				}
				cm["EncodeBlend"] = false
				cm["PreviewBlend"] = false
			}
		}
	}
	for _, raw := range table {
		if nested, ok := raw.([]any); ok {
			for _, item := range nested {
				scrub(item)
			}
			continue
		}
		scrub(raw)
	}
	if _, err := configSetTable(conn, sess, 33, "VideoWidget", table); err != nil {
		return 0, err
	}
	return cleaned, verifyCleanOSD(conn, sess)
}

// verifyCleanOSD читает назад: тексты пустые, бленды каверов выкл.
func verifyCleanOSD(conn net.Conn, sess int) error {
	table, err := configGetTable(conn, sess, 34, "VideoWidget")
	if err != nil {
		return err
	}
	check := func(raw any) error {
		m, ok := raw.(map[string]any)
		if !ok {
			return nil
		}
		if ct, ok := m["CustomTitle"].([]any); ok {
			for _, c := range ct {
				cm, ok := c.(map[string]any)
				if !ok {
					continue
				}
				if t, _ := cm["Text"].(string); t != "" {
					return fmt.Errorf("текст не стёрся: %q", t)
				}
			}
		}
		if covers, ok := m["Covers"].([]any); ok {
			for _, c := range covers {
				cm, ok := c.(map[string]any)
				if !ok {
					continue
				}
				if onBlend(cm["EncodeBlend"]) || onBlend(cm["PreviewBlend"]) {
					return fmt.Errorf("маска осталась включена")
				}
			}
		}
		return nil
	}
	for _, raw := range table {
		if nested, ok := raw.([]any); ok {
			for _, item := range nested {
				if err := check(item); err != nil {
					return err
				}
			}
			continue
		}
		if err := check(raw); err != nil {
			return err
		}
	}
	return nil
}

func onBlend(v any) bool {
	switch b := v.(type) {
	case bool:
		return b
	case float64:
		return b != 0
	case int:
		return b != 0
	}
	return false
}
