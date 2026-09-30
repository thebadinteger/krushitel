// dumpcfg — CLI-обёртка dhip.DumpConfigDial: дамп конфига камеры по DHIP.
// Антикамшот, фаза 1: эталонный снапшот настроек для будущего диффа
// (что вандал поменял через 5000-й порт — титры, OSD, картинка).
//
//	dumpcfg <host:port> <user> <pass> [out.json]
//
// Пример:
//
//	dumpcfg 127.0.0.1:1337 admin admin
package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"time"

	"krushitel/dhip"
)

func main() {
	if len(os.Args) < 4 {
		fmt.Fprintln(os.Stderr, "usage: dumpcfg <host:port> <user> <pass> [out.json]")
		os.Exit(2)
	}
	addr, user, pass := os.Args[1], os.Args[2], os.Args[3]
	out := "cfg_dump.json"
	if len(os.Args) > 4 {
		out = os.Args[4]
	}

	dump, err := dhip.DumpAllConfigDial(func() (net.Conn, error) {
		return net.DialTimeout("tcp", addr, 10*time.Second)
	}, user, pass, 120*time.Second)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] %v\n", err)
		os.Exit(1)
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
