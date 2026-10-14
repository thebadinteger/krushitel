package main

import (
	"context"
	"flag"
	"fmt"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"krushitel/core/fwd"
)

func main() {
	serial := flag.String("serial", "", "серийник камеры (обязательно)")
	login := flag.String("login", "", "логин (из results.csv)")
	pass := flag.String("pass", "", "пароль (из results.csv)")
	channel := flag.Int("channel", 1, "канал")
	subtype := flag.Int("subtype", 0, "0 = подпоток (лёгкий), 1 = основной")
	timeout := flag.Duration("timeout", 180*time.Second, "сколько ждать подъёма туннеля")
	flag.Parse()

	if *serial == "" {
		fmt.Fprintln(os.Stderr, "нужен -serial. пример:")
		fmt.Fprintln(os.Stderr, "  watch -serial 3F0506EPAG30A4A -login admin -pass debi447799")
		os.Exit(2)
	}
	if *channel <= 0 {
		*channel = 1
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	fmt.Fprintf(os.Stderr, "[*] поднимаю туннель %s (554)...\n", *serial)
	f, err := fwd.StartSupervisedWithAuth(ctx, *serial, *login, *pass,
		[]fwd.PortSpec{{Local: 0, Remote: 554}},
		func(line string) { fmt.Fprintf(os.Stderr, "  %s\n", line) })
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] туннель не встал: %v\n", err)
		os.Exit(1)
	}
	defer f.Stop()

	rtspAddr := f.Local(554)
	if rtspAddr == "" {
		fmt.Fprintln(os.Stderr, "[!] туннель встал, но порт 554 не замаппился")
		os.Exit(1)
	}

	user := url.UserPassword(*login, *pass)
	u := &url.URL{
		Scheme:   "rtsp",
		User:     user,
		Host:     rtspAddr,
		Path:     "/cam/realmonitor",
		RawQuery: fmt.Sprintf("channel=%d&subtype=%d", *channel, *subtype),
	}
	// Без кредов — без userinfo.
	if *login == "" && *pass == "" {
		u.User = nil
	}
	streamURL := u.String()

	fmt.Fprintf(os.Stderr, "[+] туннель жив (relay=%v). смотри поток, для выхода Ctrl+C\n", f.IsRelay())
	fmt.Printf("ffplay -rtsp_transport tcp -stimeout 10000000 -fflags nobuffer -flags low_delay %q\n", streamURL)
	fmt.Printf("mpv --no-cache --untimed --rtsp-transport=tcp %q\n", streamURL)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	fmt.Fprintln(os.Stderr, "\n[*] гашу туннель")
}
