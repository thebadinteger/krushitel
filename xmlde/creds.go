// creds.go — разбор txt-файлов с кредами (обратная сторона DecodeXML).
// Понимает форматы:
//
//	SN,login:pass      (creds.txt от pack_creds)
//	SN;login:pass      (любой из , ; таб/пробел)
//	login:pass@SN      (формат xmlde-экспорта без порта)
//	login:pass@SN:port
//
// Мусорные строки и # комменты пропускаются со счётчиком. Пароль может
// содержать ':' — рез по ПЕРВОМУ. Пароль не может содержать ',;\t '
// в форматах с разделителем (после него уже идёт конец строки).
package xmlde

import (
	"strings"

	"krushitel/ironscan"
)

// ParseCreds — разбор txt с кредами в []Cred. Возвращает разобранное и
// число пропущенных строк. SN валидируется через ironscan.SanitizeSerial
// (мусорные серийники в импорт-файлы SmartPSS не годятся).
func ParseCreds(data []byte) ([]Cred, int) {
	var creds []Cred
	skipped := 0
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(strings.TrimRight(line, "\r\x00"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// хвост " | модель | метод" из results.txt (exploit/dhip пишут
		// "SN,login:pass | MODEL | METHOD") — в пароль не входит.
		// Режем строку ДО разбора, как в exploit/titles.go: пароли Dahua
		// " | " не содержат, а пробелы внутри пароля сохраняются.
		if i := strings.Index(line, " | "); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		var user, pass, dom string
		if i := strings.IndexByte(line, '@'); i >= 0 {
			// login:pass@SN[:port]
			var ok bool
			user, pass, ok = splitUserPass(line[:i])
			if !ok {
				skipped++
				continue
			}
			dom = line[i+1:]
			if j := strings.IndexByte(dom, ':'); j >= 0 {
				dom = dom[:j] // порт не нужен — DeviceRow пишет 37777
			}
		} else {
			// SN<sep>login:pass
			i := strings.IndexAny(line, ",;\t ")
			if i < 0 {
				skipped++
				continue
			}
			dom = strings.TrimSpace(line[:i])
			var ok bool
			user, pass, ok = splitUserPass(strings.TrimSpace(line[i+1:]))
			if !ok {
				skipped++
				continue
			}
		}
		dom = ironscan.SanitizeSerial(dom)
		// защитный рез: хвост "|модель|метод", слепленный без пробелов
		// (пароли Dahua "|" не содержат) — как в exploit/titles.go.
		if i := strings.IndexByte(pass, '|'); i >= 0 {
			pass = strings.TrimSpace(pass[:i])
		}
		if dom == "" || user == "" || pass == "" {
			skipped++
			continue
		}
		creds = append(creds, Cred{Username: user, Password: pass, Domain: dom})
	}
	return creds, skipped
}

// splitUserPass — логин до первого ':' (пароль может содержать ':').
func splitUserPass(s string) (user, pass string, ok bool) {
	i := strings.IndexByte(s, ':')
	if i <= 0 || i == len(s)-1 {
		return "", "", false
	}
	return s[:i], s[i+1:], true
}