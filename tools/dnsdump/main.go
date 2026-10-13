// Command dnsdump prints the A records for a hostname as a Go string slice,
// ready to paste into core/cloudip.FallbackIPs.
//
//	go run ./tools/dnsdump www.easy4ipcloud.com
package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

func main() {
	host := "www.easy4ipcloud.com"
	if len(os.Args) > 1 {
		host = os.Args[1]
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", host)
	if err != nil {
		fmt.Fprintf(os.Stderr, "lookup %s: %v\n", host, err)
		os.Exit(1)
	}

	uniq := map[string]bool{}
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			uniq[v4.String()] = true
		}
	}
	list := make([]string, 0, len(uniq))
	for ip := range uniq {
		list = append(list, ip)
	}
	sort.Slice(list, func(i, j int) bool {
		a := strings.Split(list[i], ".")
		b := strings.Split(list[j], ".")
		for k := 0; k < 4; k++ {
			x, _ := strconv.Atoi(a[k])
			y, _ := strconv.Atoi(b[k])
			if x != y {
				return x < y
			}
		}
		return false
	})

	fmt.Printf("// %s — %d A records (%s)\n", host, len(list), time.Now().Format("2006-01-02"))
	fmt.Println("var FallbackIPs = []string{")
	for _, ip := range list {
		fmt.Printf("\t%q,\n", ip)
	}
	fmt.Println("}")
}
