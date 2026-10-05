// videofix.go — анти-камшот фаза 2: откат «белого экрана». Камшот-тулы
// ставят Brightness/Gamma=100 на активном профиле VideoColor[0][0] —
// картинка выжигается. Возвращаем 50 и верифицируем чит-беком.
//
// Транспорт — веб-CGI (digest) поверх туннельного HTTP-диалера. Запись
// по ОДНОМУ параметру за запрос: эта семья прошивок 400-ет комбинированные
// шейпы setConfig. 400-флап на валидных запросах ретраится внутри
// cgiDigestGet (configdump.go).
package dhip

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

// cgividKey — ключ активного профиля в плоском CGI-дампе VideoColor.
const cgividKey = "[0][0]."

// CGIClientOverDial — HTTP-клиент, ходящий через туннельный диалер
// (dial открывает net.Conn на веб-порт камеры). Timeout — на весь запрос.
func CGIClientOverDial(dial Dialer, timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dial()
			},
		},
	}
}

// SetVideoColorParam — одиночная CGI-запись VideoColor[0][0].<param>=val.
// Имя таблицы в URL литералом: CGI не ест %5B-энкодинг индексов.
func SetVideoColorParam(client *http.Client, user, pass, param string, val int) error {
	body, err := cgiDigestGet(client,
		fmt.Sprintf("http://dahua/cgi-bin/configManager.cgi?action=setConfig&VideoColor[0][0].%s=%d", param, val),
		user, pass)
	if err != nil {
		return err
	}
	b := strings.ToUpper(strings.TrimSpace(body))
	if strings.Contains(b, "ERROR") || strings.Contains(b, "BAD REQUEST") {
		return fmt.Errorf("rejected: %s", strings.TrimSpace(body))
	}
	if !strings.Contains(b, "OK") {
		return fmt.Errorf("no OK: %s", strings.TrimSpace(body))
	}
	return nil
}

// readVideoColor — getConfig VideoColor → map("[0][0].Brightness" → "59").
func readVideoColor(client *http.Client, user, pass string) (map[string]string, error) {
	body, err := cgiDigestGet(client,
		"http://dahua/cgi-bin/configManager.cgi?action=getConfig&name=VideoColor",
		user, pass)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, ln := range strings.Split(body, "\n") {
		ln = strings.TrimSpace(strings.TrimRight(ln, "\r"))
		if ln == "" || !strings.HasPrefix(ln, "table.VideoColor") {
			continue
		}
		kv := strings.SplitN(ln, "=", 2)
		if len(kv) != 2 {
			continue
		}
		out[strings.TrimPrefix(kv[0], "table.VideoColor")] = kv[1]
	}
	return out, nil
}

// FixVideoWhiteout — откат белого экрана на 50/50. Здоровую камеру
// (уже 50/50 по дампу) записями не дёргаем. Read-back verify: true
// только когда финальный дамп читается ровно 50/50. detail — текст
// для ноты при провале.
func FixVideoWhiteout(client *http.Client, user, pass string) (bool, string) {
	m0, err := readVideoColor(client, user, pass)
	if err == nil &&
		m0[cgividKey+"Brightness"] == "50" &&
		m0[cgividKey+"Gamma"] == "50" {
		return true, ""
	}
	for _, p := range []struct {
		name string
		val  int
	}{
		{"Brightness", 50},
		{"Gamma", 50},
	} {
		if err := SetVideoColorParam(client, user, pass, p.name, p.val); err != nil {
			return false, fmt.Sprintf("set %s: %v", p.name, err)
		}
	}
	m, err := readVideoColor(client, user, pass)
	if err != nil {
		return false, fmt.Sprintf("verify read: %v", err)
	}
	if br, ok1 := m[cgividKey+"Brightness"]; ok1 && br == "50" {
		if ga, ok2 := m[cgividKey+"Gamma"]; ok2 && ga == "50" {
			return true, ""
		}
	}
	return false, fmt.Sprintf("verify mismatch: Brightness=%s Gamma=%s",
		m[cgividKey+"Brightness"], m[cgividKey+"Gamma"])
}

// FixVideoWhiteoutDial — то же на свежем клиенте поверх туннельного
// диалера (эксплойт-путь: httpDial живого туннеля).
func FixVideoWhiteoutDial(dial Dialer, user, pass string) (bool, string) {
	return FixVideoWhiteout(CGIClientOverDial(dial, 15*time.Second), user, pass)
}
