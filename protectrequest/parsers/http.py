"""Web server access/error log parsers: Apache, Nginx, RequestShield."""

from __future__ import annotations

import re
from typing import Optional

from ..models import LogEvent
from .base import Parser, parse_time, to_int

CLF_TIME = "%d/%b/%Y:%H:%M:%S %z"

# IP ident user [time] "METHOD PATH PROTO" STATUS SIZE ["REFERER" "UA"]
_COMBINED = re.compile(
    r'^(?P<ip>\S+)\s+(?P<ident>\S+)\s+(?P<user>\S+)\s+'
    r'\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<request>[^"]*)"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\d+|-)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)")?'
)

# Original RequestShield format: IP DOMAIN - [time] "REQ" STATUS SIZE "REF" "UA" | TLS | ...
_REQUESTSHIELD = re.compile(
    r'^(?P<ip>\S+)\s+(?P<domain>\S+)\s+\S+\s+'
    r'\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<request>[^"]*)"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\d+)\s+'
    r'"[^"]*"\s+"(?P<ua>[^"]*)"\s+'
    r'\|\s*(?P<tls>\S+)\s*\|\s*(?P<rest>.*)$'
)

# 2026/03/14 09:00:00 [error] 12#12: *5 message, client: 1.2.3.4, server: x, request: "GET / HTTP/1.1"
_NGINX_ERROR = re.compile(
    r'^(?P<time>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) \[(?P<level>\w+)\] '
    r'\d+#\d+: (?:\*\d+ )?(?P<msg>.*?)'
    r'(?:, client: (?P<ip>[^,\s]+))?'
    r'(?:, server: (?P<server>[^,]*))?'
    r'(?:, request: "(?P<request>[^"]*)")?'
    r'(?:, .*)?$'
)


def _split_request(request: str):
    parts = (request or "").split()
    if len(parts) >= 2:
        return parts[0], parts[1]
    # Garbage request lines (binary probes, "-") are interesting too.
    return None, request or None


class CombinedParser(Parser):
    name = "combined"
    description = "Apache / Nginx access log (Combined or Common Log Format)"

    def parse(self, line: str, line_no: int = 0) -> Optional[LogEvent]:
        m = _COMBINED.match(line.strip())
        if not m:
            return None
        method, path = _split_request(m.group("request"))
        user = m.group("user")
        return LogEvent(
            source=self.name, raw=line.rstrip("\n"), line_no=line_no,
            ip=m.group("ip"),
            timestamp=parse_time(m.group("time"), CLF_TIME),
            method=method, path=path,
            status=to_int(m.group("status")),
            size=to_int(m.group("size"), 0) or 0,
            user_agent=m.group("ua"),
            user=None if user == "-" else user,
            extra={"referer": m.group("referer")},
        )


class RequestShieldParser(Parser):
    name = "requestshield"
    description = "Original RequestShield custom format (with TLS/cache fields)"

    def parse(self, line: str, line_no: int = 0) -> Optional[LogEvent]:
        m = _REQUESTSHIELD.match(line.strip())
        if not m:
            return None
        method, path = _split_request(m.group("request"))
        return LogEvent(
            source=self.name, raw=line.rstrip("\n"), line_no=line_no,
            ip=m.group("ip"),
            timestamp=parse_time(m.group("time"), CLF_TIME),
            method=method, path=path,
            status=to_int(m.group("status")),
            size=to_int(m.group("size"), 0) or 0,
            user_agent=m.group("ua"),
            extra={"domain": m.group("domain"), "tls": m.group("tls")},
        )


class NginxErrorParser(Parser):
    name = "nginx_error"
    description = "Nginx error.log"

    def parse(self, line: str, line_no: int = 0) -> Optional[LogEvent]:
        m = _NGINX_ERROR.match(line.strip())
        if not m:
            return None
        method, path = _split_request(m.group("request") or "")
        return LogEvent(
            source=self.name, raw=line.rstrip("\n"), line_no=line_no,
            ip=m.group("ip"),
            timestamp=parse_time(m.group("time"), "%Y/%m/%d %H:%M:%S"),
            method=method, path=path,
            action="error",
            message=m.group("msg"),
            extra={"level": m.group("level")},
        )
