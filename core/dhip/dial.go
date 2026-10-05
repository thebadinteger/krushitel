package dhip

import (
	"fmt"
	"net"
	"time"
)

type Dialer func() (net.Conn, error)

func AddrDialer(addr string, timeout time.Duration) Dialer {
	return func() (net.Conn, error) { return net.DialTimeout("tcp", addr, timeout) }
}

func ExtractCredsDial(dial Dialer, timeout time.Duration) ([]DhipUser, error) {
	users, err := tryExtractCredsDial(dial, timeout)
	if err == nil {
		return users, nil
	}
	if isRetryableConnErr(err) {
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

func DeviceModelDial(dial Dialer, timeout time.Duration) string {
	return DeviceModelDialAs(dial, "", "", timeout)
}

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
