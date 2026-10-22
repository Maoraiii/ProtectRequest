"""Live watch mode: follow a log like `tail -F` and alert in real time."""

from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone
from typing import Dict, Optional, Tuple

from .analyzer import Analyzer, IPProfile
from .colors import C
from .config import Settings
from .models import Finding, Severity
from .parsers import detect_format, get_parser

SEV_COLOR = {Severity.CRITICAL: "MAGENTA", Severity.HIGH: "RED", Severity.MEDIUM: "YELLOW",
             Severity.LOW: "CYAN", Severity.INFO: "DIM"}


class Alerter:
    def __init__(self, settings: Settings, quiet_seconds: int = 60):
        self.min_sev = Severity[settings.min_severity.upper()] \
            if settings.min_severity.upper() in Severity.__members__ else Severity.MEDIUM
        self.webhook = settings.webhook_url
        self.alert_file = settings.alert_file
        self.quiet = quiet_seconds
        self._last: Dict[Tuple[str, str], float] = {}
        self.sent = 0

    def __call__(self, f: Finding, prof: Optional[IPProfile]) -> None:
        if f.severity < self.min_sev:
            return
        key = (f.ip or "", f.rule)
        now = time.time()
        if now - self._last.get(key, 0) < self.quiet:  # de-duplicate floods
            return
        self._last[key] = now
        self.sent += 1
        if f.event and f.event.timestamp:  # stored as UTC; show the viewer's local time
            ts = f.event.timestamp.replace(tzinfo=timezone.utc).astimezone()
        else:
            ts = datetime.now()
        col = getattr(C, SEV_COLOR.get(f.severity, "RESET"))
        where = (f.event.path or f.event.message or "") if f.event else ""
        print(f"{C.DIM}{ts:%H:%M:%S}{C.RESET} {col}{f.severity.label.upper():<8}{C.RESET} "
              f"{f.ip or '-':<16} {f.description}  {C.DIM}{where[:90]}{C.RESET}", flush=True)
        payload = f.to_dict()
        if prof:
            payload["country"] = prof.info.country
        if self.alert_file:
            try:
                self.alert_file.parent.mkdir(parents=True, exist_ok=True)
                with self.alert_file.open("a", encoding="utf-8") as fh:
                    fh.write(json.dumps(payload, default=str) + "\n")
            except OSError as exc:
                print(C.RED + f"alert file write failed: {exc}" + C.RESET)
        if self.webhook:
            self._post(f, payload)

    def _post(self, f: Finding, payload: dict) -> None:
        text = f"[ProtectRequest] {f.severity.label}: {f.description} from {f.ip}"
        try:
            import requests
            # "text" = Slack/Mattermost/Teams-style, "content" = Discord.
            requests.post(self.webhook, json={"text": text, "content": text, "finding": payload},
                          timeout=5)
        except Exception as exc:
            print(C.RED + f"webhook failed: {exc}" + C.RESET)


def follow(path: str, from_start: bool, interval: float):
    """Yield new lines forever. Handles log rotation and truncation."""
    fh = None
    inode = None
    while fh is None:
        try:
            fh = open(path, encoding="utf-8", errors="replace")
        except FileNotFoundError:
            time.sleep(interval)
    inode = os.fstat(fh.fileno()).st_ino
    if not from_start:
        fh.seek(0, os.SEEK_END)
    buf = ""
    while True:
        chunk = fh.readline()
        if chunk:
            buf += chunk
            if buf.endswith("\n"):
                yield buf
                buf = ""
            continue
        time.sleep(interval)
        try:
            st = os.stat(path)
        except FileNotFoundError:
            continue
        if st.st_ino != inode or st.st_size < fh.tell():  # rotated or truncated
            fh.close()
            fh = open(path, encoding="utf-8", errors="replace")
            inode = os.fstat(fh.fileno()).st_ino
            buf = ""


def run_watch(path: str, settings: Settings, fmt: str = "auto", from_start: bool = False,
              interval: float = 1.0, use_abuse: bool = True) -> Analyzer:
    alerter = Alerter(settings)
    analyzer = Analyzer(settings, use_abuse=use_abuse, on_finding=alerter)
    if fmt == "auto":
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                fmt = detect_format(fh)
        except (FileNotFoundError, ValueError):
            fmt = "combined"
            print(C.YELLOW + "Could not detect format yet, assuming 'combined'. "
                             "Use --format to set it." + C.RESET)
    parser = get_parser(fmt)
    print(C.BOLD + f"Watching {path} [{fmt}]" + C.RESET +
          f"  alerts >= {alerter.min_sev.label}. Ctrl+C to stop.")
    n = 0
    try:
        for line in follow(path, from_start, interval):
            n += 1
            analyzer.feed_line(parser, line, n)
    except KeyboardInterrupt:
        print(f"\nStopped. {analyzer.parsed} events, {len(analyzer.findings)} findings, "
              f"{alerter.sent} alerts.")
    return analyzer
