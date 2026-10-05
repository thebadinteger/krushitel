package dhip

import (
	"fmt"
	"net"
	"time"
)

func ListUsersDHIP(conn net.Conn, sess int) []DhipUser {
	r, err := dhipCallCollectT(conn, "userManager.getUserInfoAll", map[string]any{}, sess, 20, nil, nil, nil, nil, CallTimeout)
	if err != nil {
		return nil
	}
	if res, _ := r["result"].(bool); !res {
		return nil
	}
	p, _ := r["params"].(map[string]any)
	usersRaw, _ := p["users"].([]any)
	var out []DhipUser
	for _, u := range usersRaw {
		m, ok := u.(map[string]any)
		if !ok {
			continue
		}
		name, _ := m["Name"].(string)
		if name == "" {
			continue
		}
		out = append(out, DhipUser{Name: name})
	}
	return out
}

func DeleteUserDHIP(conn net.Conn, sess int, name string) bool {
	r, err := dhipCallCollectT(conn, "userManager.deleteUser", map[string]any{"name": name}, sess, 21, nil, nil, nil, nil, CallTimeout)
	if err != nil {
		return false
	}
	res, _ := r["result"].(bool)
	return res
}

func WipeUsersDial(dial Dialer, login, pass string, keep map[string]bool) ([]string, error) {
	conn, err := dial()
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()
	time.Sleep(500 * time.Millisecond)

	sess, err := dhipLoginAs(conn, nil, login, pass)
	if err != nil {
		return nil, fmt.Errorf("login: %w", err)
	}

	users := ListUsersDHIP(conn, sess)
	if len(users) == 0 {
		return nil, fmt.Errorf("список юзеров пуст или не читается")
	}

	var deleted []string
	for _, u := range users {
		if keep[u.Name] {
			continue
		}
		if DeleteUserDHIP(conn, sess, u.Name) {
			deleted = append(deleted, u.Name)
		}
	}
	return deleted, nil
}
