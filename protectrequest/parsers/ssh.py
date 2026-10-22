"""Linux auth.log / secure parser (sshd lines)."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Optional

from ..models import LogEvent
from .base import Parser, parse_time

# "Mar 14 09:00:00 host sshd[123]: msg"  or  "2026-03-14T09:00:00+00:00 host sshd[123]: msg"
_PREFIX = re.compile(
    r'^(?P<time>[A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}T\S+)\s+'
    r'(?P<host>\S+)\s+(?P<prog>[\w\-/.]+)(?:\[\d+\])?:\s+(?P<msg>.*)$'
)
_IP = r'(?P<ip>[0-9a-fA-F:.]+)'
_RULES = [
    ("auth_failed", re.compile(r'Failed (?:password|publickey|keyboard-interactive/pam) for (?:invalid user )?(?P<user>\S*) from ' + _IP)),
    ("auth_success", re.compile(r'Accepted (?:password|publickey|keyboard-interactive/pam) for (?P<user>\S+) from ' + _IP)),
    ("invalid_user", re.compile(r'Invalid user (?P<user>\S*) from ' + _IP)),
    ("auth_failed", re.compile(r'authentication failure;.*rhost=' + _IP + r'(?:\s+user=(?P<user>\S+))?')),
    ("disconnect_preauth", re.compile(r'(?:Disconnected from|Connection closed by) (?:invalid user |authenticating user )?(?:(?P<user>\S+) )?' + _IP + r' port \d+ \[preauth\]')),
    ("max_auth", re.compile(r'maximum authentication attempts exceeded for (?:invalid user )?(?P<user>\S+) from ' + _IP)),
]


class SSHAuthParser(Parser):
    name = "ssh"
    description = "Linux auth.log / secure (sshd login events)"

    def __init__(self, year: Optional[int] = None):
        self.year = year or datetime.now().year

    def parse(self, line: str, line_no: int = 0) -> Optional[LogEvent]:
        m = _PREFIX.match(line.strip())
        if not m or "sshd" not in m.group("prog"):
            return None
        raw_time = m.group("time")
        if raw_time[0].isdigit():
            ts = parse_time(raw_time)
        else:  # syslog has no year
            ts = parse_time(f"{self.year} {' '.join(raw_time.split())}", "%Y %b %d %H:%M:%S")
        msg = m.group("msg")
        action, user, ip = "other", None, None
        for name, rx in _RULES:
            hit = rx.search(msg)
            if hit:
                action, user, ip = name, hit.group("user"), hit.group("ip")
                break
        return LogEvent(
            source=self.name, raw=line.rstrip("\n"), line_no=line_no,
            ip=ip, timestamp=ts, user=user, action=action, message=msg,
            extra={"host": m.group("host")},
        )
