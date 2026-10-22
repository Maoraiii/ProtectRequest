"""JSON-lines parser (one JSON object per line).

Works with Nginx/Caddy/Traefik JSON logs, cloud load balancers and most
app loggers, because it looks for many common key names.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from ..models import LogEvent
from .base import Parser, parse_time, to_int

CLF_TIME = "%d/%b/%Y:%H:%M:%S %z"

KEYS = {
    "ip": ["ip", "remote_addr", "client_ip", "clientip", "src_ip", "remote_ip",
           "request.remote_ip", "httpRequest.remoteIp", "ClientHost"],
    "path": ["path", "uri", "request_uri", "url", "request.uri", "httpRequest.requestUrl",
             "RequestPath"],
    "method": ["method", "request_method", "request.method", "httpRequest.requestMethod",
               "RequestMethod"],
    "status": ["status", "status_code", "response_code", "httpRequest.status",
               "DownstreamStatus"],
    "size": ["bytes", "body_bytes_sent", "size", "bytes_sent", "httpRequest.responseSize"],
    "user_agent": ["user_agent", "http_user_agent", "agent", "ua", "request.headers.User-Agent",
                   "httpRequest.userAgent", "request_User-Agent"],
    "time": ["time", "timestamp", "@timestamp", "time_local", "ts", "time_iso8601", "StartUTC"],
    "user": ["user", "username", "remote_user"],
}


def _lookup(obj: Dict[str, Any], dotted: str):
    if dotted in obj:
        return obj[dotted]
    cur: Any = obj
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def _first(obj: Dict[str, Any], field: str):
    for key in KEYS[field]:
        val = _lookup(obj, key)
        if val not in (None, ""):
            if isinstance(val, list) and val:  # Caddy stores headers as lists
                val = val[0]
            return val
    return None


class JSONLinesParser(Parser):
    name = "json"
    description = "JSON lines (Nginx/Caddy/Traefik/cloud LB/app logs)"

    def parse(self, line: str, line_no: int = 0) -> Optional[LogEvent]:
        line = line.strip()
        if not line.startswith("{"):
            return None
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            return None
        if not isinstance(obj, dict):
            return None
        ip = _first(obj, "ip")
        path = _first(obj, "path")
        if ip is None and path is None:
            return None
        if isinstance(ip, str) and ip.count(":") == 1 and "." in ip:
            ip = ip.split(":")[0]  # "1.2.3.4:5678"
        raw_time = _first(obj, "time")
        ts = None
        if isinstance(raw_time, (int, float)):
            secs = raw_time if raw_time < 1e11 else raw_time / 1000  # ms epoch
            ts = datetime.fromtimestamp(secs, timezone.utc).replace(tzinfo=None)
        elif raw_time:
            ts = parse_time(str(raw_time), CLF_TIME)
        return LogEvent(
            source=self.name, raw=line, line_no=line_no,
            ip=str(ip) if ip else None, timestamp=ts,
            method=_first(obj, "method"), path=str(path) if path else None,
            status=to_int(_first(obj, "status")),
            size=to_int(_first(obj, "size"), 0) or 0,
            user_agent=_first(obj, "user_agent"),
            user=_first(obj, "user"),
        )
