#!/usr/bin/env python3
import curses
import subprocess
import os
import re
import select
import shutil
import signal
import time
import datetime
from collections import defaultdict, Counter

LOG_DIR = os.path.expanduser("~/.secaudit")
LOG_FILE = os.path.join(LOG_DIR, "events.log")
os.makedirs(LOG_DIR, exist_ok=True)

IP_RE = re.compile(r'(?:\d{1,3}\.){3}\d{1,3}')
FAIL_RE = re.compile(r'Failed password for (invalid user )?(\S+) from ([\d.]+) port \d+')
ACCEPT_RE = re.compile(r'Accepted (password|publickey) for (\S+) from ([\d.]+) port \d+')
ANSI_RE = re.compile(r'\x1b\[[0-9;]*[a-zA-Z]|\x1b\][^\x07]*\x07')

QUIT_CHARS = ('q', 'Q', 'й', 'Й')
DROP_TARGETS = ("DROP", "REJECT")

MAX_PAD_LINES = 20000
MAX_PAD_COLS = 1000
LIVE_REDRAW_INTERVAL = 0.1

OTHER_CMDS = {
    "users": "journalctl --since today 2>/dev/null | grep -Ei 'useradd|userdel|usermod|groupadd|passwd' | tail -50",
    "ports": "ss -tulpn 2>/dev/null",
}

MAIN_MENU = [
    ("IP-отчёт по попыткам входа", "ip_report"),
    ("Сессии пользователей (bash_history)", "sessions"),
    ("Изменения пользователей/групп", "users"),
    ("Слушающие порты", "ports"),
    ("Аудит sshd_config", "sshd_audit"),
    ("rkhunter (руткиты)", "rkhunter"),
    ("Firewall / fail2ban", "firewall"),
    ("Экспорт отчёта в txt", "export"),
]

FIREWALL_MENU = [
    ("ufw status", "ufw status verbose", 15, "ufw", "ufw", False),
    ("fail2ban status", "fail2ban-client status", 15, "fail2ban-client", "fail2ban", False),
    ("fail2ban status sshd", "fail2ban-client status sshd", 15, "fail2ban-client", "fail2ban", False),
    ("iptables -L", "iptables -L -n --line-numbers", 15, None, None, False),
]

RKHUNTER_MENU = [
    ("Запустить полную проверку (может занять пару минут)",
     "rkhunter --check --skip-keypress --report-warnings-only", 900, "rkhunter", "rkhunter", True),
    ("Последний лог проверки",
     "tail -n 200 /var/log/rkhunter.log 2>/dev/null || echo 'лог не найден, запусти проверку'",
     15, "rkhunter", "rkhunter", False),
    ("Обновить базы сигнатур (--update)", "rkhunter --update", 120, "rkhunter", "rkhunter", True),
    ("Обновить снимок файловых свойств (--propupd)", "rkhunter --propupd", 120, "rkhunter", "rkhunter", True),
]

DEPENDENCY_GROUPS = [
    ("Важные", [
        ("ssh/sshd", ("sshd", "ssh")),
        ("ss", ("ss",)),
        ("journalctl", ("journalctl",)),
    ]),
    ("Опциональные", [
        ("whois", ("whois",)),
        ("rkhunter", ("rkhunter",)),
    ]),
    ("Фаервол", [
        ("iptables", ("iptables",)),
        ("ufw", ("ufw",)),
        ("fail2ban", ("fail2ban-client",)),
    ]),
]

_which_cache = {}
_whois_cache = {}
_deps_box_cache = None
_backend_cache = None
_ssh_unit_cache = None


def strip_ansi(s):
    return ANSI_RE.sub('', s).replace('\r', '')


def run(cmd, timeout=30):
    try:
        out = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        text = out.stdout.strip()
        if out.stderr.strip() and not text:
            text = "[stderr] " + out.stderr.strip()
        return strip_ansi(text)
    except Exception as e:
        return f"ошибка выполнения: {e}"


def log_event(action):
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        with open(LOG_FILE, "a") as f:
            f.write(f"{ts}  {action}\n")
    except OSError:
        pass


def which(name):
    if name not in _which_cache:
        _which_cache[name] = shutil.which(name) is not None
    return _which_cache[name]


def safe_addstr(win, y, x, text, attr=curses.A_NORMAL):
    h, w = win.getmaxyx()
    if y < 0 or y >= h or x >= w:
        return
    try:
        win.addstr(y, x, text[:max(w - x - 1, 0)], attr)
    except curses.error:
        pass


def get_key(stdscr):
    try:
        return stdscr.get_wch()
    except curses.error:
        return -1


def is_quit(k):
    return isinstance(k, str) and k in QUIT_CHARS


def is_escape(k):
    return isinstance(k, str) and k == '\x1b'


def is_enter(k):
    if isinstance(k, str):
        return k in ('\n', '\r')
    return k in (curses.KEY_ENTER, 10, 13)


def prompt_input(stdscr, prompt):
    curses.curs_set(1)
    buf = ""
    while True:
        h, w = stdscr.getmaxyx()
        safe_addstr(stdscr, h - 1, 0, " " * (w - 1))
        line = (prompt + buf)[:w - 1]
        safe_addstr(stdscr, h - 1, 0, line)
        try:
            stdscr.move(h - 1, min(len(line), w - 1))
        except curses.error:
            pass
        stdscr.refresh()
        k = get_key(stdscr)
        if is_enter(k):
            break
        if is_escape(k):
            buf = None
            break
        if isinstance(k, int) and k in (curses.KEY_BACKSPACE, 127, 8):
            buf = buf[:-1]
        elif isinstance(k, str) and k in ('\x7f', '\b'):
            buf = buf[:-1]
        elif isinstance(k, str) and k.isprintable():
            buf += k
    curses.curs_set(0)
    return buf


# ---------- сбор данных по SSH попыткам ----------

def ssh_unit():
    global _ssh_unit_cache
    if _ssh_unit_cache is None:
        probe = run("journalctl -u ssh -n 1 --no-pager 2>/dev/null")
        _ssh_unit_cache = "ssh" if probe and "-- No entries" not in probe else "sshd"
    return _ssh_unit_cache


def collect_ip_data(date_obj):
    since = date_obj.strftime("%Y-%m-%d 00:00:00")
    until = (date_obj + datetime.timedelta(days=1)).strftime("%Y-%m-%d 00:00:00")
    unit = ssh_unit()
    raw = run(f"journalctl -u {unit} --since '{since}' --until '{until}' -o short-iso 2>/dev/null", timeout=60)

    data = defaultdict(lambda: {
        "fail_users": Counter(),
        "success_users": Counter(),
        "fail_count": 0,
        "success_count": 0,
        "first": None,
        "last": None,
    })

    for line in raw.splitlines():
        ts = line[:25]
        m = FAIL_RE.search(line)
        if m:
            user, ip = m.group(2), m.group(3)
            e = data[ip]
            e["fail_users"][user] += 1
            e["fail_count"] += 1
            e["first"] = e["first"] or ts
            e["last"] = ts
            continue
        m = ACCEPT_RE.search(line)
        if m:
            user, ip = m.group(2), m.group(3)
            e = data[ip]
            e["success_users"][user] += 1
            e["success_count"] += 1
            e["first"] = e["first"] or ts
            e["last"] = ts

    return data


def whois_lookup(ip):
    if ip in _whois_cache:
        return _whois_cache[ip]
    if not which("whois"):
        return "whois не установлен - поставь через свой пакетный менеджер (apt/dnf/pacman/...): whois"

    out = run(f"whois {ip}", timeout=10)
    if not out:
        result = "нет данных"
    else:
        wanted = ("orgname", "org-name", "netname", "country", "descr", "abuse")
        seen = set()
        picked = []
        for l in out.splitlines():
            if l.strip().lower().startswith(wanted) and l not in seen:
                seen.add(l)
                picked.append(l)
        result = "\n".join(picked[:12]) if picked else "нет полезных полей (whois вернул нестандартный формат)"

    _whois_cache[ip] = result
    return result


def ip_detail_text(ip, entry, blocked_ips):
    lines = [f"IP: {ip}", f"первая попытка: {entry['first']}", f"последняя попытка: {entry['last']}", ""]
    lines.append(f"неудачных входов: {entry['fail_count']}")
    if entry["fail_users"]:
        lines.append("логины, которые перебирались (пароли sshd не логирует):")
        for user, cnt in entry["fail_users"].most_common(20):
            lines.append(f"  {user}: {cnt}")
    lines.append("")
    lines.append(f"успешных входов: {entry['success_count']}")
    if entry["success_users"]:
        lines.append("успешные логины:")
        for user, cnt in entry["success_users"].most_common(20):
            lines.append(f"  {user}: {cnt}")
    lines.append("")
    lines.append("--- whois ---")
    lines.append(whois_lookup(ip))
    lines.append("")
    lines.append(f"статус блокировки: {'ЗАБЛОКИРОВАН' if ip in blocked_ips else 'не заблокирован'}")
    return "\n".join(lines)


# ---------- блокировка IP ----------

def firewall_backend():
    global _backend_cache
    if _backend_cache is None:
        if which("ufw") and "Status: active" in run("ufw status"):
            _backend_cache = "ufw"
        elif which("iptables"):
            _backend_cache = "iptables"
        else:
            _backend_cache = "none"
    return None if _backend_cache == "none" else _backend_cache


def parse_ufw_denied(out):
    ips = set()
    for line in out.splitlines():
        upper = line.upper()
        if "DENY" in upper or "REJECT" in upper:
            ips |= set(IP_RE.findall(line))
    return ips


def parse_iptables_dropped(out):
    ips = set()
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 5 and parts[0] in DROP_TARGETS:
            src = parts[3]
            if IP_RE.fullmatch(src.split("/")[0]) and not src.startswith("0.0.0.0"):
                ips.add(src.split("/")[0])
    return ips


def get_blocked_ips():
    ips = set()

    if which("ufw"):
        out = run("ufw status")
        if "Status: active" in out:
            ips |= parse_ufw_denied(out)

    if which("iptables"):
        ips |= parse_iptables_dropped(run("iptables -L INPUT -n"))

    if which("fail2ban-client"):
        jout = run("fail2ban-client status")
        m = re.search(r'Jail list:\s*(.*)', jout)
        if m:
            for jail in [j.strip() for j in re.split(r'[,\s]+', m.group(1)) if j.strip()]:
                if not re.fullmatch(r'[\w.-]+', jail):
                    continue
                bm = re.search(r'Banned IP list:\s*(.*)', run(f"fail2ban-client status {jail}"))
                if bm:
                    ips |= set(IP_RE.findall(bm.group(1)))

    return ips


def block_ip(ip):
    backend = firewall_backend()
    if backend == "ufw":
        return run(f"ufw deny from {ip} to any")
    if backend == "iptables":
        return run(f"iptables -I INPUT -s {ip} -j DROP")
    return "не найден ни ufw (активный), ни iptables - блокировка недоступна"


def unblock_ip(ip):
    backend = firewall_backend()
    if backend == "ufw":
        return run(f"ufw delete deny from {ip} to any")
    if backend == "iptables":
        return run(f"iptables -D INPUT -s {ip} -j DROP")
    return "не найден ни ufw (активный), ни iptables - разблокировка недоступна"


# ---------- сессии пользователей / bash_history ----------

def get_user_homes():
    users = []
    try:
        with open("/etc/passwd") as f:
            for line in f:
                parts = line.strip().split(":")
                if len(parts) < 7:
                    continue
                name, uid, home, shell = parts[0], parts[2], parts[5], parts[6]
                try:
                    uid_int = int(uid)
                except ValueError:
                    continue
                if shell.endswith(("nologin", "false")):
                    continue
                if uid_int < 1000 and name != "root":
                    continue
                users.append((name, home))
    except OSError:
        pass
    return users


def parse_bash_history(path):
    try:
        with open(path, errors="replace") as f:
            raw = f.read().splitlines()
    except PermissionError:
        return None, "нет доступа к файлу (нужен root)"
    except FileNotFoundError:
        return None, None
    except OSError as e:
        return None, f"ошибка чтения: {e}"

    entries = []
    pending_ts = None
    for line in raw:
        if line.startswith("#") and line[1:].isdigit():
            pending_ts = int(line[1:])
            continue
        if not line.strip():
            continue
        ts_str = None
        if pending_ts is not None:
            try:
                ts_str = datetime.datetime.fromtimestamp(pending_ts).strftime("%Y-%m-%d %H:%M:%S")
            except (OSError, OverflowError, ValueError):
                ts_str = None
        entries.append((ts_str, line))
        pending_ts = None
    return entries, None


def format_history(entries):
    if not entries:
        return "история пуста"
    return "\n".join(
        f"{i:>4}  {f'[{ts}] ' if ts else ''}{cmd}" for i, (ts, cmd) in enumerate(entries, 1)
    )


def sessions_screen(stdscr):
    users = get_user_homes()
    if not users:
        show_text(stdscr, "Сессии пользователей", "не удалось прочитать /etc/passwd")
        return

    items = []
    for name, home in users:
        mark = "история есть" if os.path.exists(os.path.join(home, ".bash_history")) else "нет .bash_history"
        items.append(f"{name:<15} {home:<22} {mark}")

    while True:
        choice = pick_from_list(stdscr, "Сессии пользователей (bash_history)", items)
        if choice is None:
            return
        name, home = users[choice]
        entries, err = parse_bash_history(os.path.join(home, ".bash_history"))
        if err:
            show_text(stdscr, f"{name} - bash_history", err)
        elif entries is None:
            show_text(stdscr, f"{name} - bash_history", "файл .bash_history не найден")
        else:
            show_text(stdscr, f"{name} - bash_history ({len(entries)} команд)", format_history(entries))


# ---------- аудит sshd_config ----------

def get_effective_sshd_config():
    out = run("sshd -T 2>&1")
    conf = {}
    for line in out.splitlines():
        parts = line.strip().split(None, 1)
        if not parts:
            continue
        conf[parts[0].lower()] = parts[1] if len(parts) == 2 else ""
    if len(conf) > 5:
        return conf, True
    return None, False


def get_raw_sshd_config():
    conf = {}
    try:
        with open("/etc/ssh/sshd_config") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(None, 1)
                conf[parts[0].lower()] = parts[1].strip() if len(parts) == 2 else ""
    except OSError:
        return None
    return conf


def audit_sshd_config():
    conf, effective = get_effective_sshd_config()
    if conf is None:
        conf = get_raw_sshd_config()
        effective = False
    if conf is None:
        return "не удалось прочитать sshd_config (нет доступа или файл отсутствует)"

    lines = []
    if effective:
        lines.append("источник: эффективная конфигурация (sshd -T), учитывает значения по умолчанию")
    else:
        lines.append("источник: сырой файл /etc/ssh/sshd_config - незаданные параметры показаны как "
                     "'default', запусти под root для точной проверки через sshd -T")
    lines.append("")

    get = conf.get
    checks = []

    v = get("permitrootlogin")
    if v == "yes":
        checks.append(("[!]", "PermitRootLogin=yes - root может логиниться по SSH, рекомендуется 'no' или 'prohibit-password'"))
    elif v in ("without-password", "prohibit-password"):
        checks.append(("[i]", f"PermitRootLogin={v} - root вход разрешён только по ключу"))
    elif v == "no":
        checks.append(("[v]", "PermitRootLogin=no"))
    else:
        checks.append(("[i]", f"PermitRootLogin: {v or 'default'}"))

    v = get("passwordauthentication")
    if v == "yes":
        checks.append(("[!]", "PasswordAuthentication=yes - вход по паролю разрешён, уязвимо к брутфорсу"))
    elif v == "no":
        checks.append(("[v]", "PasswordAuthentication=no"))
    else:
        checks.append(("[i]", f"PasswordAuthentication: {v or 'default'}"))

    v = get("permitemptypasswords")
    if v == "yes":
        checks.append(("[!]", "PermitEmptyPasswords=yes - критично, разрешены пустые пароли"))
    else:
        checks.append(("[v]", f"PermitEmptyPasswords={v or 'no'}"))

    v = get("pubkeyauthentication")
    if v == "no":
        checks.append(("[!]", "PubkeyAuthentication=no - аутентификация по ключу выключена"))
    else:
        checks.append(("[v]", f"PubkeyAuthentication={v or 'yes'}"))

    v = get("maxauthtries")
    try:
        if v and int(v) > 4:
            checks.append(("[!]", f"MaxAuthTries={v} - рекомендуется 3-4"))
        else:
            checks.append(("[v]", f"MaxAuthTries={v or '6 (default)'}"))
    except ValueError:
        checks.append(("[i]", f"MaxAuthTries: {v}"))

    v = get("permituserenvironment")
    if v == "yes":
        checks.append(("[!]", "PermitUserEnvironment=yes - риск повышения привилегий через переменные окружения"))
    else:
        checks.append(("[v]", f"PermitUserEnvironment={v or 'no'}"))

    v = get("x11forwarding")
    if v == "yes":
        checks.append(("[i]", "X11Forwarding=yes - отключи, если не используется"))
    else:
        checks.append(("[v]", f"X11Forwarding={v or 'no'}"))

    v = get("allowtcpforwarding")
    if v and v != "no":
        checks.append(("[i]", f"AllowTcpForwarding={v} - может использоваться для туннелирования"))

    v = get("port")
    if v in (None, "22"):
        checks.append(("[i]", f"Port={v or '22'} - стандартный порт активнее сканируют ботами"))
    else:
        checks.append(("[v]", f"Port={v} (нестандартный)"))

    v = get("allowusers") or get("allowgroups")
    if v:
        checks.append(("[v]", f"ограничение по пользователям/группам задано: {v}"))
    else:
        checks.append(("[i]", "AllowUsers/AllowGroups не заданы - войти может любой валидный пользователь"))

    checks.append(("[i]", f"LoginGraceTime={get('logingracetime') or '120 (default)'}"))

    for mark, text in checks:
        lines.append(f"{mark}  {text}")

    lines.append("")
    lines.append(f"предупреждений: {sum(1 for m, _ in checks if m == '[!]')}")
    return "\n".join(lines)


# ---------- экспорт отчёта ----------

def build_full_report():
    today = datetime.date.today()
    ip_data = collect_ip_data(today)
    blocked = get_blocked_ips()

    parts = [f"=== Отчёт по безопасности - {datetime.datetime.now().strftime('%d.%m.%Y %H:%M')} ===", ""]

    parts.append("--- IP-попытки входа (сегодня) ---")
    if not ip_data:
        parts.append("попыток не найдено")
    else:
        for ip in sorted(ip_data, key=lambda i: ip_data[i]["fail_count"], reverse=True):
            e = ip_data[ip]
            mark = " [BLOCKED]" if ip in blocked else ""
            users = ", ".join(e["fail_users"].keys()) or "-"
            parts.append(f"{ip}{mark}: fail={e['fail_count']} ok={e['success_count']} логины={users}")
    parts.append("")

    parts.append("--- Изменения пользователей/групп (сегодня) ---")
    parts.append(run(OTHER_CMDS["users"]) or "нет записей")
    parts.append("")

    parts.append("--- Слушающие порты ---")
    parts.append(run(OTHER_CMDS["ports"]) or "нет данных")
    parts.append("")

    parts.append("--- Аудит sshd_config ---")
    parts.append(audit_sshd_config())
    parts.append("")

    parts.append("--- Firewall / fail2ban ---")
    for label, cmd, timeout, req_bin, package, _live in FIREWALL_MENU:
        if req_bin and not which(req_bin):
            parts.append(f"[{label}] - не установлено ({package})")
            continue
        parts.append(f"[{label}]")
        parts.append(run(cmd, timeout=timeout))
        parts.append("")

    return "\n".join(parts)


def export_report_screen(stdscr):
    stdscr.erase()
    safe_addstr(stdscr, 0, 2, "формирую отчёт...")
    stdscr.refresh()
    text = build_full_report()

    out_dir = os.path.join(LOG_DIR, "reports")
    try:
        os.makedirs(out_dir, exist_ok=True)
        path = os.path.join(out_dir, datetime.datetime.now().strftime("report_%Y%m%d_%H%M%S.txt"))
        with open(path, "w") as f:
            f.write(text)
    except OSError as e:
        show_text(stdscr, "Ошибка экспорта", f"не удалось записать отчёт: {e}\n\n{text}")
        return

    log_event(f"экспорт отчёта: {path}")
    show_text(stdscr, "Отчёт сохранён", f"файл: {path}\n\n{text}")


# ---------- зависимости ----------

def deps_box_lines():
    global _deps_box_cache
    if _deps_box_cache is not None:
        return _deps_box_cache

    content = ["Зависимости", ""]
    for group_name, items in DEPENDENCY_GROUPS:
        content.append(f"{group_name}:")
        for label, bins in items:
            mark = "v" if any(which(b) for b in bins) else "x"
            content.append(f"    [{mark}] - {label}")

    width = max(len(c) for c in content) + 4
    box = ["-" * width]
    for c in content:
        if c == "Зависимости":
            pad = width - 2 - len(c)
            left = pad // 2
            box.append("|" + " " * left + c + " " * (pad - left) + "|")
        else:
            box.append("|" + c.ljust(width - 2) + "|")
    box.append("-" * width)

    _deps_box_cache = box
    return box


def missing_tool_text(tool_name, package):
    return (
        f"{tool_name} не установлен.\n\n"
        f"поставь через пакетный менеджер своего дистрибутива, например:\n"
        f"  Debian/Ubuntu: sudo apt install {package}\n"
        f"  Fedora/RHEL:   sudo dnf install {package}\n"
        f"  Arch:          sudo pacman -S {package}"
    )


# ---------- curses UI ----------

def show_text(stdscr, title, text, footer="q/й - назад, Ctrl+F - поиск", hotkeys=()):
    full_lines = text.split("\n") if text else ["(пусто)"]
    if len(full_lines) > MAX_PAD_LINES:
        full_lines = full_lines[:MAX_PAD_LINES] + [f"... вывод обрезан до {MAX_PAD_LINES} строк"]

    view_lines = full_lines
    query = None

    def build_pad(lines):
        h, w = stdscr.getmaxyx()
        pad_h = max(len(lines) + 1, h)
        longest = max((len(l) for l in lines), default=0) + 1
        pad_w = max(min(longest, MAX_PAD_COLS), w)
        pad = curses.newpad(pad_h, pad_w)
        for i, line in enumerate(lines):
            try:
                pad.addstr(i, 0, line[:pad_w - 1])
            except curses.error:
                pass
        return pad, pad_h, pad_w

    pad, pad_h, _pad_w = build_pad(view_lines)
    top = 0

    while True:
        h, w = stdscr.getmaxyx()
        stdscr.erase()
        label = f"{title} [поиск: {query}]" if query else title
        safe_addstr(stdscr, 0, 0, f" {label} - {footer} ", curses.A_REVERSE)
        stdscr.refresh()
        if h > 1 and w > 1:
            try:
                pad.refresh(top, 0, 1, 0, h - 1, w - 1)
            except curses.error:
                pass

        k = get_key(stdscr)

        if k == curses.KEY_RESIZE:
            pad, pad_h, _pad_w = build_pad(view_lines)
            top = 0
        elif k == '\x06':
            q = prompt_input(stdscr, "поиск: ")
            if q:
                query = q
                view_lines = [l for l in full_lines if q.lower() in l.lower()] or ["ничего не найдено"]
            else:
                query = None
                view_lines = full_lines
            pad, pad_h, _pad_w = build_pad(view_lines)
            top = 0
        elif is_quit(k) or is_escape(k):
            if query:
                query = None
                view_lines = full_lines
                pad, pad_h, _pad_w = build_pad(view_lines)
                top = 0
            else:
                return None
        elif hotkeys and isinstance(k, str) and k.lower() in hotkeys:
            return k.lower()
        elif k == curses.KEY_DOWN and top < pad_h - h:
            top += 1
        elif k == curses.KEY_UP and top > 0:
            top -= 1
        elif k == curses.KEY_NPAGE:
            top = min(top + (h - 2), max(pad_h - h, 0))
        elif k == curses.KEY_PPAGE:
            top = max(top - (h - 2), 0)


def pick_from_list(stdscr, title, items, footer="Enter - выбрать, q/й - назад"):
    idx = 0
    top = 0
    while True:
        stdscr.erase()
        h, w = stdscr.getmaxyx()
        visible_rows = max(h - 3, 1)
        safe_addstr(stdscr, 0, 0, f" {title} - {footer} ", curses.A_REVERSE)

        if idx < top:
            top = idx
        elif idx >= top + visible_rows:
            top = idx - visible_rows + 1

        for row, label in enumerate(items[top:top + visible_rows]):
            attr = curses.A_REVERSE if top + row == idx else curses.A_NORMAL
            safe_addstr(stdscr, 2 + row, 2, label, attr)

        if items:
            safe_addstr(stdscr, h - 1, 0, f" {idx + 1}/{len(items)} ", curses.A_DIM)
        stdscr.refresh()

        k = get_key(stdscr)
        if is_quit(k) or is_escape(k):
            return None
        elif k == curses.KEY_UP and items:
            idx = (idx - 1) % len(items)
        elif k == curses.KEY_DOWN and items:
            idx = (idx + 1) % len(items)
        elif k == curses.KEY_NPAGE:
            idx = min(idx + visible_rows, max(len(items) - 1, 0))
        elif k == curses.KEY_PPAGE:
            idx = max(idx - visible_rows, 0)
        elif is_enter(k) and items:
            return idx


def ip_report_screen(stdscr):
    current_date = datetime.date.today()
    blocked_ips = get_blocked_ips()
    state = {"data": {}, "ips": []}

    def load(date_obj):
        stdscr.erase()
        safe_addstr(stdscr, 0, 2, f"собираю данные за {date_obj.strftime('%d.%m.%Y')}...")
        stdscr.refresh()
        data = collect_ip_data(date_obj)
        state["data"] = data
        state["ips"] = sorted(data.keys(), key=lambda ip: data[ip]["fail_count"], reverse=True)
        log_event(f"IP-отчёт: сбор данных за {date_obj.strftime('%d.%m.%Y')}")

    load(current_date)
    idx = 0
    top = 0

    while True:
        data = state["data"]
        ips_sorted = state["ips"]
        h, w = stdscr.getmaxyx()
        visible_rows = max(h - 4, 1)
        stdscr.erase()

        title = f"IP-отчёт - {current_date.strftime('%d.%m.%Y')}"
        safe_addstr(stdscr, 0, 0, f" {title} - ←/→ - день, Enter - детали, q/й - назад ", curses.A_REVERSE)

        if not ips_sorted:
            safe_addstr(stdscr, 2, 2, "за этот день попыток входа не найдено")
        else:
            if idx < top:
                top = idx
            elif idx >= top + visible_rows:
                top = idx - visible_rows + 1
            for row, ip in enumerate(ips_sorted[top:top + visible_rows]):
                label = (
                    f"{ip:<16} fail={data[ip]['fail_count']:<4} ok={data[ip]['success_count']:<3} "
                    f"{'[BLOCKED]' if ip in blocked_ips else ''}"
                )
                attr = curses.A_REVERSE if top + row == idx else curses.A_NORMAL
                safe_addstr(stdscr, 2 + row, 2, label, attr)
            safe_addstr(stdscr, h - 1, 0, f" {idx + 1}/{len(ips_sorted)} ", curses.A_DIM)
        stdscr.refresh()

        k = get_key(stdscr)
        if is_quit(k) or is_escape(k):
            return
        elif k == curses.KEY_LEFT:
            current_date -= datetime.timedelta(days=1)
            load(current_date)
            idx, top = 0, 0
        elif k == curses.KEY_RIGHT:
            current_date += datetime.timedelta(days=1)
            load(current_date)
            idx, top = 0, 0
        elif k == curses.KEY_UP and ips_sorted:
            idx = (idx - 1) % len(ips_sorted)
        elif k == curses.KEY_DOWN and ips_sorted:
            idx = (idx + 1) % len(ips_sorted)
        elif k == curses.KEY_NPAGE:
            idx = min(idx + visible_rows, max(len(ips_sorted) - 1, 0))
        elif k == curses.KEY_PPAGE:
            idx = max(idx - visible_rows, 0)
        elif is_enter(k) and ips_sorted:
            ip = ips_sorted[idx]
            while True:
                key = show_text(
                    stdscr, f"Детали {ip} ({current_date.strftime('%d.%m.%Y')})",
                    ip_detail_text(ip, data[ip], blocked_ips),
                    footer="b - блок, u - разблок, q/й - назад, Ctrl+F - поиск",
                    hotkeys=('b', 'u'),
                )
                if key == 'b':
                    res = block_ip(ip)
                    log_event(f"блокировка IP {ip}: {res or 'ok'}")
                    blocked_ips = get_blocked_ips()
                    show_text(stdscr, "Блокировка", f"{ip}\n\n{res or 'выполнено'}")
                elif key == 'u':
                    res = unblock_ip(ip)
                    log_event(f"разблокировка IP {ip}: {res or 'ok'}")
                    blocked_ips = get_blocked_ips()
                    show_text(stdscr, "Разблокировка", f"{ip}\n\n{res or 'выполнено'}")
                else:
                    break


def kill_process_group(proc):
    """Убивает shell вместе с его потомками, иначе дети переживают kill и виснут зомби."""
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    except (ProcessLookupError, PermissionError, OSError):
        proc.kill()
        return
    try:
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except OSError:
            proc.kill()


def render_live(stdscr, title, lines):
    stdscr.erase()
    h, _w = stdscr.getmaxyx()
    safe_addstr(stdscr, 0, 0, f" {title} - выполняется, подожди... ", curses.A_REVERSE)
    for i, line in enumerate(lines[-(h - 2):]):
        safe_addstr(stdscr, 1 + i, 0, line)
    stdscr.refresh()


def run_live(stdscr, title, cmd, timeout=900):
    proc = subprocess.Popen(
        cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1,
        start_new_session=True,
    )
    lines = []
    start = time.time()
    last_draw = 0.0
    timed_out = False

    try:
        while True:
            ready, _, _ = select.select([proc.stdout], [], [], 0.2)
            if ready:
                line = proc.stdout.readline()
                if line:
                    clean = strip_ansi(line.rstrip("\r\n"))
                    if clean.strip():
                        lines.append(clean)
                        now = time.time()
                        if now - last_draw >= LIVE_REDRAW_INTERVAL:
                            render_live(stdscr, title, lines)
                            last_draw = now
                    continue
                if proc.poll() is not None:
                    break
            elif proc.poll() is not None:
                break

            if time.time() - start > timeout:
                kill_process_group(proc)
                timed_out = True
                break
    finally:
        try:
            proc.stdout.close()
        except OSError:
            pass
        proc.wait()

    elapsed = time.time() - start
    lines.append("")
    if timed_out:
        lines.append(f"=== ПРЕРВАНО ПО ТАЙМАУТУ ({timeout} сек) ===")
    else:
        lines.append(f"=== СКАН ЗАВЕРШЁН (заняло {elapsed:.0f} сек, код выхода {proc.returncode}) ===")
    render_live(stdscr, title, lines)
    time.sleep(1)
    return "\n".join(lines)


def command_menu_screen(stdscr, title, menu):
    while True:
        choice = pick_from_list(stdscr, title, [label for label, *_ in menu])
        if choice is None:
            return
        label, cmd, timeout, req_bin, package, live = menu[choice]
        if req_bin and not which(req_bin):
            show_text(stdscr, label, missing_tool_text(package, package))
            continue
        stdscr.erase()
        safe_addstr(stdscr, 0, 2, f"выполняю: {label}...")
        stdscr.refresh()
        output = run_live(stdscr, label, cmd, timeout=timeout) if live else run(cmd, timeout=timeout)
        show_text(stdscr, label, output)
        log_event(f"проверка: {label}")


def firewall_screen(stdscr):
    command_menu_screen(stdscr, "Firewall / fail2ban", FIREWALL_MENU)


def rkhunter_screen(stdscr):
    if not which("rkhunter"):
        show_text(stdscr, "rkhunter", missing_tool_text("rkhunter", "rkhunter"))
        return
    command_menu_screen(stdscr, "rkhunter (проверка на руткиты)", RKHUNTER_MENU)


def main(stdscr):
    curses.curs_set(0)
    idx = 0
    while True:
        stdscr.erase()
        h, _w = stdscr.getmaxyx()
        safe_addstr(stdscr, 0, 2, "host-security", curses.A_BOLD)
        safe_addstr(stdscr, 1, 2, "стрелки - выбор, Enter - выполнить, q - выход")

        for i, (label, _) in enumerate(MAIN_MENU):
            y = 3 + i
            if y >= h - 1:
                break
            safe_addstr(stdscr, y, 4, label, curses.A_REVERSE if i == idx else curses.A_NORMAL)

        deps_y = 3 + len(MAIN_MENU) + 1
        for j, line in enumerate(deps_box_lines()):
            y = deps_y + j
            if y >= h - 1:
                break
            safe_addstr(stdscr, y, 4, line, curses.A_DIM)
        stdscr.refresh()

        k = get_key(stdscr)
        if is_quit(k):
            break
        elif k == curses.KEY_UP:
            idx = (idx - 1) % len(MAIN_MENU)
        elif k == curses.KEY_DOWN:
            idx = (idx + 1) % len(MAIN_MENU)
        elif is_enter(k):
            label, action_key = MAIN_MENU[idx]
            if action_key == "ip_report":
                ip_report_screen(stdscr)
            elif action_key == "firewall":
                firewall_screen(stdscr)
            elif action_key == "rkhunter":
                rkhunter_screen(stdscr)
            elif action_key == "sessions":
                sessions_screen(stdscr)
            elif action_key == "sshd_audit":
                log_event(label)
                show_text(stdscr, label, audit_sshd_config())
            elif action_key == "export":
                export_report_screen(stdscr)
            else:
                log_event(label)
                show_text(stdscr, label, run(OTHER_CMDS[action_key]))


if __name__ == "__main__":
    curses.wrapper(main)