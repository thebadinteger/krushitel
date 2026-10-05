package dhip

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var globalTables = []string{
	"General",
	"ChannelTitle",
	"VideoEncode",
	"VideoInMode",
	"Detect",
	"VideoInLayer",
}

var channelTables = []string{
	"VideoInOsd",
	"VideoWidget",
	"VideoInTitle",
	"ImageParam",
	"VideoColor",
}

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

	if r, err := dhipCall(conn, "magicBox.getSoftwareVersion", nil, sess, id, nil); err == nil {
		if v := findVersion(r); v != "" {
			out["software"] = v
		}
	}
	id++

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
					outTables[key0(name)] = v
				}
			}
		}
	}

	return out, nil
}

func key0(name string) string { return name + "[0]" }

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

func DumpAllConfigJSON(dial Dialer, user, pass string, timeout time.Duration) ([]byte, error) {
	dump, err := DumpAllConfigDial(dial, user, pass, timeout)
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(dump, "", "  ")
}

func cgiDigestGet(client *http.Client, urlStr, user, pass string) (string, error) {
	do := func(auth string) (int, string, http.Header, error) {
		req, err := http.NewRequest("GET", urlStr, nil)
		if err != nil {
			return 0, "", nil, err
		}
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		resp, err := client.Do(req)
		if err != nil {
			return 0, "", nil, err
		}
		defer resp.Body.Close()
		b, err := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b), resp.Header, err
	}

	digestAuth := func(head http.Header) (string, bool) {
		h := head.Get("WWW-Authenticate")
		if !strings.HasPrefix(strings.ToLower(h), "digest") {
			return "", false
		}
		params := map[string]string{}
		for _, part := range strings.Split(h, ",") {
			kv := strings.SplitN(part, "=", 2)
			if len(kv) != 2 {
				continue
			}
			params[strings.ToLower(strings.TrimSpace(kv[0]))] = strings.Trim(strings.TrimSpace(kv[1]), `"`)
		}
		realm, nonce, qop := params["realm"], params["nonce"], params["qop"]
		if nonce == "" {
			return "", false
		}
		u, err := url.Parse(urlStr)
		if err != nil {
			return "", false
		}
		uri := u.RequestURI()
		ha1 := fmt.Sprintf("%x", md5.Sum([]byte(user+":"+realm+":"+pass)))
		ha2 := fmt.Sprintf("%x", md5.Sum([]byte("GET:"+uri)))
		cnonce, nc := "0a4f113d", "00000001"
		var response string
		if qop != "" {
			response = fmt.Sprintf("%x", md5.Sum([]byte(ha1+":"+nonce+":"+nc+":"+cnonce+":"+qop+":"+ha2)))
		} else {
			response = fmt.Sprintf("%x", md5.Sum([]byte(ha1+":"+nonce+":"+ha2)))
		}
		auth := fmt.Sprintf("Digest username=%q, realm=%q, nonce=%q, uri=%q, response=%q", user, realm, nonce, uri, response)
		if qop != "" {
			auth += fmt.Sprintf(", qop=%s, nc=%s, cnonce=%q", qop, nc, cnonce)
		}
		return auth, true
	}

	for attempt := 0; attempt < 3; attempt++ {
		code, body, head, err := do("")
		if err != nil {
			return "", err
		}
		if code == 401 {
			auth, ok := digestAuth(head)
			if !ok {
				return "", fmt.Errorf("cgi: digest not offered")
			}
			code, body, _, err = do(auth)
			if err != nil {
				return "", err
			}
		}
		if code == 200 {
			return body, nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return "", fmt.Errorf("cgi: table keeps failing (fw flaps 400)")
}

var httpVideoTables = []string{
	"VideoColor",
	"VideoWidget",
	"ImageParam",
	"VideoInOsd",
	"VideoInTitle",
}

func DumpHTTPVideoConfig(webAddr, user, pass string, timeout time.Duration) (map[string]any, error) {
	client := &http.Client{Timeout: timeout}
	out := map[string]any{}
	for _, name := range httpVideoTables {
		body, err := cgiDigestGet(client,
			fmt.Sprintf("http://%s/cgi-bin/configManager.cgi?action=getConfig&name=%s", webAddr, name),
			user, pass)
		if err != nil {
			out[name] = map[string]any{"error": err.Error()}
			continue
		}
		table := map[string]any{}
		prefix := "table." + name
		for _, ln := range strings.Split(body, "\n") {
			ln = strings.TrimSpace(strings.TrimRight(ln, "\r"))
			if ln == "" || strings.HasPrefix(ln, "Error") || !strings.HasPrefix(ln, prefix) {
				continue
			}
			rest := strings.TrimPrefix(ln, prefix)
			rest = strings.TrimLeft(rest, ".")
			rest = strings.TrimPrefix(rest, "[0].")
			kv := strings.SplitN(rest, "=", 2)
			if len(kv) == 2 {
				table[kv[0]] = kv[1]
			}
		}
		out[name] = table
	}
	return out, nil
}
