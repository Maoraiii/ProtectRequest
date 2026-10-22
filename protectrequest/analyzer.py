"""Analysis engine: feed events in, get per-IP profiles + findings out."""

from __future__ import annotations

import math
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable, Dict, Iterable, Iterator, List, Optional, Set

from .config import Settings
from .detectors import build_detectors
from .enrich import Enricher, IPInfo
from .models import Finding, LogEvent, Severity
from .parsers import Parser, detect_format, get_parser


@dataclass
class IPProfile:
    ip: str
    requests: int = 0
    bytes: int = 0
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    statuses: Counter = field(default_factory=Counter)
    paths: Counter = field(default_factory=Counter)
    user_agents: Set[str] = field(default_factory=set)
    users: Set[str] = field(default_factory=set)
    sources: Set[str] = field(default_factory=set)
    findings: List[Finding] = field(default_factory=list)
    info: IPInfo = field(default_factory=IPInfo)
    score: float = 0.0
    level: str = "None"

    @property
    def rule_counts(self) -> Counter:
        return Counter(f.rule for f in self.findings)

    @property
    def categories(self) -> List[str]:
        return sorted({f.category for f in self.findings})

    @property
    def max_severity(self) -> Optional[Severity]:
        return max((f.severity for f in self.findings), default=None)

    def to_dict(self) -> dict:
        return {
            "ip": self.ip, "score": round(self.score, 1), "level": self.level,
            "requests": self.requests, "bytes": self.bytes,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "country": self.info.country, "country_code": self.info.country_code,
            "abuse_score": self.info.abuse_score, "abuse_reports": self.info.total_reports,
            "isp": self.info.isp, "categories": self.categories,
            "rules": dict(self.rule_counts), "statuses": dict(self.statuses),
            "top_paths": self.paths.most_common(10),
            "user_agents": sorted(self.user_agents)[:10],
            "users": sorted(self.users)[:20],
            "sources": sorted(self.sources),
        }


def level_for(score: float) -> str:
    if score >= 70:
        return "Critical"
    if score >= 40:
        return "High"
    if score >= 15:
        return "Medium"
    if score > 0:
        return "Low"
    return "None"


class Analyzer:
    def __init__(self, settings: Settings, use_abuse: bool = True,
                 on_finding: Optional[Callable[[Finding, IPProfile], None]] = None):
        self.settings = settings
        self.enricher = Enricher(settings, use_abuse=use_abuse)
        self.detectors = build_detectors(settings)
        self.on_finding = on_finding
        self.profiles: Dict[str, IPProfile] = {}
        self.findings: List[Finding] = []
        self.total_lines = 0
        self.parsed = 0
        self.skipped_whitelist = 0
        self.unparsed_samples: List[str] = []
        self.files: List[dict] = []
        self.status_counts: Counter = Counter()
        self.path_counts: Counter = Counter()
        self.timeline: Dict[str, Counter] = defaultdict(Counter)  # hour -> {requests, findings}
        self.total_bytes = 0
        self.first_ts: Optional[datetime] = None
        self.last_ts: Optional[datetime] = None
        self._geo_flagged: Set[str] = set()

    # ---------- input ----------
    def analyze_file(self, path: str, fmt: str = "auto",
                     progress: Optional[Callable[[int], None]] = None) -> str:
        with open(path, encoding="utf-8", errors="replace") as fh:
            if fmt == "auto":
                fmt = detect_format(fh)
                fh.seek(0)
            parser = get_parser(fmt)
            # Fresh sliding windows per file: files are not in time order
            # relative to each other.
            self.detectors = build_detectors(self.settings)
            before = self.parsed
            n = 0
            for n, line in enumerate(fh, start=1):
                self.feed_line(parser, line, n)
                if progress and n % 200 == 0:
                    progress(n)
            if progress:
                progress(n)
        self.files.append({"path": str(path), "format": fmt, "lines": n,
                           "parsed": self.parsed - before})
        return fmt

    def feed_line(self, parser: Parser, line: str, line_no: int = 0) -> List[Finding]:
        if not line.strip() or line.startswith("#"):
            if line.startswith("#"):
                parser.parse(line, line_no)  # IIS reads its #Fields header
            return []
        self.total_lines += 1
        try:
            ev = parser.parse(line, line_no)
        except Exception:
            ev = None
        if ev is None:
            if len(self.unparsed_samples) < 5:
                self.unparsed_samples.append(line.strip()[:200])
            return []
        self.parsed += 1
        return self.process(ev)

    # ---------- core ----------
    def process(self, ev: LogEvent) -> List[Finding]:
        if ev.ip and ev.ip in self.enricher.whitelist:
            self.skipped_whitelist += 1
            return []
        hour = ev.timestamp.strftime("%Y-%m-%d %H:00") if ev.timestamp else "unknown"
        if ev.timestamp:
            self.first_ts = min(self.first_ts or ev.timestamp, ev.timestamp)
            self.last_ts = max(self.last_ts or ev.timestamp, ev.timestamp)
        self.timeline[hour]["events"] += 1
        if ev.status is not None:
            self.status_counts[ev.status] += 1
        if ev.path:
            self.path_counts[ev.path.split("?", 1)[0]] += 1
        self.total_bytes += ev.size or 0

        prof = None
        if ev.ip:
            prof = self.profiles.get(ev.ip) or IPProfile(ip=ev.ip)
            self.profiles[ev.ip] = prof
            prof.requests += 1
            prof.bytes += ev.size or 0
            prof.sources.add(ev.source)
            if ev.timestamp:
                prof.first_seen = min(prof.first_seen or ev.timestamp, ev.timestamp)
                prof.last_seen = max(prof.last_seen or ev.timestamp, ev.timestamp)
            if ev.status is not None:
                prof.statuses[ev.status] += 1
            if ev.path:
                prof.paths[ev.path] += 1
            if ev.user_agent:
                prof.user_agents.add(ev.user_agent)
            if ev.user:
                prof.users.add(ev.user)

        new: List[Finding] = []
        for det in self.detectors:
            new.extend(det.check(ev))
        if prof and new and ev.ip not in self._geo_flagged:
            new.extend(self._geo_check(prof, ev))
        for f in new:
            self.findings.append(f)
            self.timeline[hour]["findings"] += 1
            if prof:
                prof.findings.append(f)
            if self.on_finding:
                self.on_finding(f, prof)
        return new

    def _geo_check(self, prof: IPProfile, ev: LogEvent) -> List[Finding]:
        """Enrich an IP the first time it does something suspicious."""
        self._geo_flagged.add(prof.ip)
        prof.info = self.enricher.info(prof.ip)
        risky = self.settings.risky_countries
        if risky and (prof.info.country.lower() in risky
                      or prof.info.country_code.lower() in risky):
            return [Finding("RISKY_COUNTRY", "Geo Risk", Severity.LOW,
                            f"Traffic from watch-listed country {prof.info.country}",
                            prof.ip, ev, evidence=prof.info.country)]
        return []

    # ---------- results ----------
    def score(self, prof: IPProfile) -> float:
        pts = self.settings.severity_points
        total = 0.0
        sev_by_rule = {}
        for f in prof.findings:
            sev_by_rule[f.rule] = max(sev_by_rule.get(f.rule, f.severity), f.severity)
        for rule, count in prof.rule_counts.items():
            base = pts[sev_by_rule[rule].name.lower()]
            total += base * (1 + math.log2(count))  # repeats add, but slowly
        if prof.info.abuse_score:
            total += prof.info.abuse_score * self.settings.abuse_weight
        if any(f.rule == "RISKY_COUNTRY" for f in prof.findings):
            total += self.settings.geo_points
        # A single critical finding (RCE, compromise) is enough on its own.
        if prof.max_severity == Severity.CRITICAL:
            total = max(total, 70.0)
        return min(100.0, total)

    def finalize(self) -> "Report":
        for prof in self.profiles.values():
            if prof.ip not in self.enricher._seen:
                # Geo for everyone (local DB, free). AbuseIPDB only for flagged IPs.
                if prof.findings:
                    prof.info = self.enricher.info(prof.ip)
                else:
                    country, code = self.enricher.geo.lookup(prof.ip)
                    prof.info = IPInfo(country=country, country_code=code)
            else:
                prof.info = self.enricher.info(prof.ip)
            prof.score = self.score(prof)
            prof.level = level_for(prof.score)
        self.enricher.close()
        return Report(self)


class Report:
    """Read-only view used by every output writer."""

    def __init__(self, a: Analyzer):
        self.generated = datetime.now()
        self.files = a.files
        self.total_lines = a.total_lines
        self.parsed = a.parsed
        self.unparsed = a.total_lines - a.parsed
        self.unparsed_samples = a.unparsed_samples
        self.skipped_whitelist = a.skipped_whitelist
        self.total_bytes = a.total_bytes
        self.first_ts, self.last_ts = a.first_ts, a.last_ts
        self.findings = a.findings
        self.status_counts = a.status_counts
        self.path_counts = a.path_counts
        self.timeline = dict(sorted(a.timeline.items()))
        self.profiles = sorted(a.profiles.values(), key=lambda p: (-p.score, -p.requests))
        # INFO-only IPs (e.g. a curl user) stay in the findings list but are not 'flagged'.
        self.flagged = [p for p in self.profiles
                        if any(f.severity > Severity.INFO for f in p.findings)]
        self.category_counts = Counter(f.category for f in a.findings)
        self.severity_counts = Counter(f.severity.label for f in a.findings)
        self.geo_note = a.enricher.geo.error
        self.abuse_note = a.enricher.abuse.disabled_reason
        self.abuse_calls = a.enricher.abuse.calls

    @property
    def unique_ips(self) -> int:
        return len(self.profiles)

    def to_dict(self) -> dict:
        return {
            "generated": self.generated.isoformat(timespec="seconds"),
            "files": self.files,
            "summary": {
                "lines": self.total_lines, "parsed": self.parsed, "unparsed": self.unparsed,
                "whitelisted": self.skipped_whitelist, "unique_ips": self.unique_ips,
                "flagged_ips": len(self.flagged), "findings": len(self.findings),
                "bytes": self.total_bytes,
                "first_seen": self.first_ts.isoformat() if self.first_ts else None,
                "last_seen": self.last_ts.isoformat() if self.last_ts else None,
                "by_severity": dict(self.severity_counts),
                "by_category": dict(self.category_counts),
                "status_codes": {str(k): v for k, v in self.status_counts.items()},
            },
            "notes": [n for n in (self.geo_note, self.abuse_note) if n],
            "ips": [p.to_dict() for p in self.flagged],
            "findings": [f.to_dict() for f in self.findings],
        }


def iter_files(paths: Iterable[str]) -> Iterator[Path]:
    """Expand folders to the log files inside them."""
    for p in paths:
        path = Path(p)
        if path.is_dir():
            for child in sorted(path.rglob("*")):
                if child.is_file() and child.suffix.lower() in (".log", ".txt", ".json", ".jsonl", "") \
                        and not child.name.startswith("."):
                    yield child
        else:
            yield path
