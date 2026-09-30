// dumpcfg — CLI-обёртка дамперов конфига камеры. Антикамшот, фаза 1:
// эталонный снапшот настроек для будущего диффа (что вандал поменял —
// титры, OSD, картинка).
//
//	dumpcfg [-web host:port] <dhip:port> <user> <pass> [out.json]
//
// -web — веб-CGI камеры (порт 80/1380): через него добираются видео-таблицы
// (ImageParam/VideoInOsd/VideoInTitle/VideoColor), которые DHIP на части
// прошивок не отдаёт. Пример:
//
//	dumpcfg -web 127.0.0.1:1380 127.0.0.1:1337 admin admin
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	"krushitel/dhip"
)

func main() {
	fs := flag.NewFlagSet("dumpcfg", flag.ContinueOnError)
	web := fs.String("web", "", "веб-CGI камеры (host:port) — видео-таблицы через HTTP")
	if err := fs.Parse(os.Args[1:]); err != nil {
		os.Exit(2)
	}
	rest := fs.Args()
	if len(rest) < 3 {
		fmt.Fprintln(os.Stderr, "usage: dumpcfg [-web host:port] <dhip:port> <user> <pass> [out.json]")
		os.Exit(2)
	}
	addr, user, pass := rest[0], rest[1], rest[2]
	out := "cfg_dump.json"
	if len(rest) > 3 {
		out = rest[3]
	}

	dump, err := dhip.DumpAllConfigDial(func() (net.Conn, error) {
		return net.DialTimeout("tcp", addr, 10*time.Second)
	}, user, pass, 120*time.Second)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] %v\n", err)
		os.Exit(1)
	}

	// веб-CGI: добор видео-таблиц, которых DHIP не отдал (или перезапись —
	// CGI-версия полнее по параметрам картинки)
	if *web != "" {
		httpTables, err := dhip.DumpHTTPVideoConfig(*web, user, pass, 30*time.Second)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] web: %v\n", err)
		} else {
			tables := dump["tables"].(map[string]any)
			for name, t := range httpTables {
				tables[name] = t
			}
		}
	}

	b, err := json.MarshalIndent(dump, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] marshal: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(out, b, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "[-] write: %v\n", err)
		os.Exit(1)
	}

	tables := dump["tables"].(map[string]any)
	fmt.Printf("[+] dumped %d tables -> %s (%d bytes)\n", len(tables), out, len(b))
	for name := range tables {
		fmt.Printf("    %s\n", name)
	}
}
