"""Parser base class + small helpers."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from ..models import LogEvent


class Parser:
    """A parser turns one raw line into a LogEvent (or None if no match).

    Subclasses set `name` and `description` and implement `parse`.
    A new instance is made per file, so parsers may keep state (IIS does).
    """

    name = "base"
    description = ""

    def parse(self, line: str, line_no: int = 0) -> Optional[LogEvent]:
        raise NotImplementedError

    def matches(self, line: str) -> bool:
        """Used by auto-detect. Default: does parse() succeed?"""
        try:
            return self.parse(line) is not None
        except Exception:
            return False


def to_naive_utc(dt: Optional[datetime]) -> Optional[datetime]:
    """Make every timestamp comparable: aware -> UTC naive."""
    if dt is None:
        return None
    if dt.tzinfo is not None:
        return dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


def parse_time(value: str, *formats: str) -> Optional[datetime]:
    value = (value or "").strip()
    if not value:
        return None
    for fmt in formats:
        try:
            return to_naive_utc(datetime.strptime(value, fmt))
        except ValueError:
            continue
    try:  # ISO 8601 fallback (handles "Z" too on 3.11+)
        return to_naive_utc(datetime.fromisoformat(value.replace("Z", "+00:00")))
    except ValueError:
        return None


def to_int(value, default: Optional[int] = None) -> Optional[int]:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default
