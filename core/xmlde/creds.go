package xmlde

import (
	"strings"

	"krushitel/core/ironscan"
)

func ParseCreds(data []byte) ([]Cred, int) {
	var creds []Cred
	skipped := 0
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(strings.TrimRight(line, "\r\x00"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if i := strings.Index(line, " | "); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		var user, pass, dom string
		if i := strings.IndexByte(line, '@'); i >= 0 {
			var ok bool
			user, pass, ok = splitUserPass(line[:i])
			if !ok {
				skipped++
				continue
			}
			dom = line[i+1:]
			if j := strings.IndexByte(dom, ':'); j >= 0 {
				dom = dom[:j]
			}
		} else {
			i := strings.IndexAny(line, ",;\t ")
			if i < 0 {
				skipped++
				continue
			}
			dom = strings.TrimSpace(line[:i])
			rest := strings.TrimSpace(line[i+1:])
			var ok bool
			user, pass, ok = splitUserPass(rest)
			if !ok && strings.IndexByte(rest, ':') < 0 && strings.Contains(rest, ",") {
				parts := strings.Split(rest, ",")
				if len(parts) >= 2 && parts[0] != "" && parts[1] != "" {
					user, pass, ok = parts[0], parts[1], true
				}
			}
			if !ok {
				skipped++
				continue
			}
		}
		dom = ironscan.SanitizeSerial(dom)
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

func splitUserPass(s string) (user, pass string, ok bool) {
	i := strings.IndexByte(s, ':')
	if i <= 0 || i == len(s)-1 {
		return "", "", false
	}
	return s[:i], s[i+1:], true
}
