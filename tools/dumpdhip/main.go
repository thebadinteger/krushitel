// dumpdhip — одноразовый дамп конфига регистратора по DHIP через
// локальный туннель (127.0.0.1:1337 → 5000). Использует dhip.DumpAllConfigDial.
package main

import (
	"fmt"
	"os"
	"time"

	"krushitel/core/dhip"
)

func main() {
	addr := "127.0.0.1:1337"
	user := "kronaphasia"
	pass := "TancuiPantera1337"
	out := "dvr_dump.json"
	if len(os.Args) > 1 {
		addr = os.Args[1]
	}
	if len(os.Args) > 2 {
		user = os.Args[2]
	}
	if len(os.Args) > 3 {
		pass = os.Args[3]
	}
	if len(os.Args) > 4 {
		out = os.Args[4]
	}

	model := dhip.DeviceModelDial(dhip.AddrDialer(addr, 15*time.Second), 15*time.Second)
	fmt.Println("device:", model)

	data, err := dhip.DumpAllConfigJSON(dhip.AddrDialer(addr, 30*time.Second), user, pass, 30*time.Second)
	if err != nil {
		fmt.Fprintln(os.Stderr, "dump failed:", err)
		os.Exit(1)
	}
	if err := os.WriteFile(out, data, 0644); err != nil {
		fmt.Fprintln(os.Stderr, "write:", err)
		os.Exit(1)
	}
	fmt.Printf("dumped %d bytes -> %s\n", len(data), out)
}
