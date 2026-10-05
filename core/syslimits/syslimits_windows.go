//go:build windows

package syslimits

func Ensure() Report {
	return Report{MaxWorkers: WindowsWorkers}
}

func SocketHint() string {
	return "netsh int ipv4 set dynamicport udp start=1024 num=64511"
}
