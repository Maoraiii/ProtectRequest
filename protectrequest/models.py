"""Core data types shared by every module."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import IntEnum
from typing import Any, Dict, Optional


class Severity(IntEnum):
    INFO = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5

    @property
    def label(self) -> str:
        return self.name.capitalize()


@dataclass
class LogEvent:
    """One normalised log line, whatever format it came from."""

    source: str                      # parser name, e.g. "combined", "ssh"
    raw: str
    line_no: int = 0
    ip: Optional[str] = None
    timestamp: Optional[datetime] = None
    method: Optional[str] = None
    path: Optional[str] = None
    status: Optional[int] = None
    size: int = 0
    user_agent: Optional[str] = None
    user: Optional[str] = None       # login name (SSH, IIS)
    action: Optional[str] = None     # e.g. "auth_failed", "auth_success", "error"
    message: Optional[str] = None    # free text (error logs, SSH)
    extra: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Finding:
    """One thing a detector thinks is bad."""

    rule: str
    category: str
    severity: Severity
    description: str
    ip: Optional[str]
    event: Optional[LogEvent] = None
    evidence: str = ""

    def to_dict(self) -> Dict[str, Any]:
        ev = self.event
        return {
            "rule": self.rule,
            "category": self.category,
            "severity": self.severity.label,
            "description": self.description,
            "ip": self.ip,
            "evidence": self.evidence,
            "timestamp": ev.timestamp.isoformat() if ev and ev.timestamp else None,
            "path": ev.path if ev else None,
            "status": ev.status if ev else None,
            "user_agent": ev.user_agent if ev else None,
            "source": ev.source if ev else None,
            "line_no": ev.line_no if ev else None,
        }
