// configdump.go — полный дамп конфига камеры по DHIP. Фаза 1 антикамшота:
// эталонный снапшот настроек (по диффу видно, что именно портит вандал
// через 5000-й порт — титры, OSD, настройки картинки).
package dhip

import (
	"encoding/json"
	"fmt"
	"time"
)

// globalTables — глобальные (не канальные) таблицы.
var globalTables = []string{
	"General",
	"ChannelTitle",
	"VideoEncode",
	"VideoInMode",
	"Detect",
	"VideoInLayer",
}

// channelTables — канально-индексированные таблицы (имя[i], i с нуля):
// именно их портят камшот-тулы (OSD, картинка, виджеты).
var channelTables = []string{
	"VideoInOsd",
	"VideoWidget",
	"VideoInTitle",
	"ImageParam",
	"VideoColor",
}

// DumpAllConfigDial — логин по DHIP (challenge с переданным паролем) и
// выгрузка конфига: глобальные таблицы + канальные (VideoInOsd[0]…
// по числу каналов). Возврат:
//
//	{"software": ..., "channels": N, "tables": {"VideoInOsd[0]": {...}, ...}}
//
// таблица, которую камера отказалась отдать, попадает как {"error": "..."}.
func DumpAllConfigDial(dial Dialer, user, pass string, timeout time.Duration) (map[string]any, error) {
	conn, err := dial()
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	sess, err := dhipLoginAs(conn, nil, user, pass)
	if err != nil {
		return nil, fmt.Errorf("login: %w", err)
	}

	out := map[string]any{
		"tables": map[string]any{},
	}
	outTables := out["tables"].(map[string]any)
	id := 10
	// get — сырой getConfig с чисткой обёртки: камеры отдают содержимое
	// в разных формах (table[] / table{} / params / плоские ключи), нужна
	// та форма, что реально пришла, минус result/session/id мусор.
	get := func(name string) any {
		r, err := dhipCall(conn, "configManager.getConfig", map[string]any{"name": name}, sess, id, nil)
		id++
		if err != nil {
			return map[string]any{"error": err.Error()}
		}
		if ok, _ := r["result"].(bool); !ok {
			if e, ok := r["error"]; ok {
				return map[string]any{"error": e}
			}
			return map[string]any{"error": "result=false"}
		}
		clean := map[string]any{}
		for k, v := range r {
			switch k {
			case "result", "session", "id":
				continue
			default:
				clean[k] = v
			}
		}
		return clean
	}

	// мета: версия прошивки — где камера её ни спрятала в ответе
	if r, err := dhipCall(conn, "magicBox.getSoftwareVersion", nil, sess, id, nil); err == nil {
		if v := findVersion(r); v != "" {
			out["software"] = v
		}
	}
	id++

	// число каналов: канальные таблицы именуются name[i], i с нуля
	channels := 1
	if r, err := dhipCall(conn, "magicBox.getChannelCount", nil, sess, id, nil); err == nil {
		if n, ok := r["count"].(float64); ok && n >= 1 {
			channels = int(n)
		}
	}
	out["channels"] = channels
	id++

	for _, name := range globalTables {
		outTables[name] = get(name)
	}
	for _, name := range channelTables {
		for ch := 0; ch < channels; ch++ {
			// разные fw нумеруют по-разному: name[0], name[1] (с единицы),
			// без индекса — берём первый вариант, что камера согласилась отдать
			for _, full := range []string{
				fmt.Sprintf("%s[%d]", name, ch),
				fmt.Sprintf("%s[%d]", name, ch+1),
				name,
			} {
				v := get(full)
				if _, bad := v.(map[string]any)["error"]; !bad {
					key := fmt.Sprintf("%s[%d]", name, ch)
					outTables[key] = v
					break
				}
				if ch == 0 {
					outTables[key0(name)] = v // последний (ошибочный) вариант — для диффа
				}
			}
		}
	}

	return out, nil
}

// key0 — канонический ключ дампа для канальной таблицы (name[ch]).
func key0(name string) string { return name + "[0]" }

// findVersion — первое строковое "version" на любой глубине ответа.
func findVersion(v any) string {
	switch x := v.(type) {
	case map[string]any:
		if s, ok := x["version"].(string); ok {
			return s
		}
		for _, vv := range x {
			if s := findVersion(vv); s != "" {
				return s
			}
		}
	case []any:
		for _, vv := range x {
			if s := findVersion(vv); s != "" {
				return s
			}
		}
	}
	return ""
}

// DumpAllConfigJSON — то же, сразу pretty-JSON (для снапшотов на диск).
func DumpAllConfigJSON(dial Dialer, user, pass string, timeout time.Duration) ([]byte, error) {
	dump, err := DumpAllConfigDial(dial, user, pass, timeout)
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(dump, "", "  ")
}
