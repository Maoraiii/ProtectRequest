"""Microsoft IIS W3C Extended log parser.

IIS logs declare their columns in a "#Fields:" header, so this parser keeps
state: it reads the header, then maps each data line by column name.
"""

from __future__ import annotations

from typing import List, Optional

from ..models import LogEvent
from .base import Parser, parse_time, to_int

DEFAULT_FIELDS = ("date time s-ip cs-method cs-uri-stem cs-uri-query s-port "
                  "cs-username c-ip cs(User-Agent) cs(Referer) sc-status "
                  "sc-substatus sc-win32-status time-taken").split()


class IISParser(Parser):
    name = "iis"
    description = "Microsoft IIS W3C Extended log"

    def __init__(self):
        self.fields: List[str] = list(DEFAULT_FIELDS)

    def matches(self, line: str) -> bool:
        if line.startswith("#Software: Microsoft Internet Information Services") \
                or line.startswith("#Fields:"):
            return True
        return super().matches(line)

    def parse(self, line: str, line_no: int = 0) -> Optional[LogEvent]:
        line = line.strip()
        if not line:
            return None
        if line.startswith("#"):
            if line.startswith("#Fields:"):
                self.fields = line[len("#Fields:"):].split()
            return None
        parts = line.split()
        if len(parts) != len(self.fields):
            return None
        row = dict(zip(self.fields, parts))
        if "c-ip" not in row or "cs-uri-stem" not in row:
            return None
        ts = parse_time(f"{row.get('date', '')} {row.get('time', '')}", "%Y-%m-%d %H:%M:%S")
        if ts is None:
            return None
        query = row.get("cs-uri-query", "-")
        path = row["cs-uri-stem"] + ("" if query in ("-", "") else "?" + query)
        ua = row.get("cs(User-Agent)", "-").replace("+", " ")
        user = row.get("cs-username", "-")
        return LogEvent(
            source=self.name, raw=line, line_no=line_no,
            ip=row["c-ip"], timestamp=ts,
            method=row.get("cs-method"), path=path,
            status=to_int(row.get("sc-status")),
            size=to_int(row.get("sc-bytes"), 0) or 0,
            user_agent=None if ua == "-" else ua,
            user=None if user == "-" else user,
        )
