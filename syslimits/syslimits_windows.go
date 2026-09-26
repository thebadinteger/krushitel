//go:build windows

package syslimits

// Ensure — на Windows лимиты из процесса не поднять (нужны netsh + админ),
// так что только фиксированный кап: сокеты воркеров переиспользуются из пула,
// эфемерные порты на каждую пробу не тратим — 512 с запасом под хендлы.
func Ensure() Report {
	return Report{MaxWorkers: WindowsWorkers}
}

// SocketHint — готовая команда на случай ошибок создания сокетов:
// расширяет пул динамических UDP-портов (нужен админ; после применения
// обычно хватает переоткрытия сокетов, без ребута).
func SocketHint() string {
	return "netsh int ipv4 set dynamicport udp start=1024 num=64511"
}
