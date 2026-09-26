package ui

// discord_ipc.go — минимальный Discord IPC-клиент (Rich Presence) без
// внешних зависимостей: хендшейк + SET_ACTIVITY поверх локального сокета.
// Fire-and-forget как в rich-go: ответы дискорда не читаем, блокировок нет.
// Любая ошибка = дискорда рядом нет, молча выходим (скан важнее рофла).

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
)

// discordConn — минимум для fire-and-forget: os.File (виндовый пайп)
// его удовлетворяет, как и net.Conn (unix-сокет).
type discordConn interface {
	Write([]byte) (int, error)
	Close() error
}

// discordFrame — фрейм IPC: opcode u32 LE + длина u32 LE + JSON.
func discordWriteFrame(conn discordConn, opcode uint32, payload any) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	hdr := make([]byte, 8)
	binary.LittleEndian.PutUint32(hdr[0:4], opcode)
	binary.LittleEndian.PutUint32(hdr[4:8], uint32(len(raw)))
	_, err = conn.Write(append(hdr, raw...))
	return err
}

// discordNonce — случайный nonce для фрейма.
func discordNonce() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

// discordActivity — тело presence (лимиты дискорда 128 символов на поле).
type discordActivity struct {
	Details   string          `json:"details,omitempty"`
	State     string          `json:"state,omitempty"`
	LargeText string          `json:"large_text,omitempty"`
	Start     int64           `json:"start,omitempty"`
	Buttons   []discordButton `json:"buttons,omitempty"`
}

// discordButton — кликабельная кнопка (макс 2, только https).
type discordButton struct {
	Label string `json:"label,omitempty"`
	URL   string `json:"url,omitempty"`
}

// discordHandshake — opcode 0: {"v":"1","client_id":"..."}.
func discordHandshake(conn discordConn, appID string) error {
	return discordWriteFrame(conn, 0, map[string]string{"v": "1", "client_id": appID})
}

// discordSetActivity — opcode 1: SET_ACTIVITY с pid и presence.
func discordSetActivity(conn discordConn, pid int, act discordActivity) error {
	return discordWriteFrame(conn, 1, map[string]any{
		"cmd":   "SET_ACTIVITY",
		"nonce": discordNonce(),
		"args": map[string]any{
			"pid": pid,
			"activity": map[string]any{
				"details": act.Details,
				"state":   act.State,
				"assets": map[string]string{
					"large_text": act.LargeText,
				},
				"timestamps": map[string]int64{
					"start": act.Start,
				},
			},
		},
	})
}
