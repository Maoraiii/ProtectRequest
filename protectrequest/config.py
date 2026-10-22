"""Configuration: defaults + config.ini + environment variables.

Order of priority (highest wins):
    1. environment variables (e.g. ABUSEIPDB_API_KEY)
    2. config.ini
    3. DEFAULTS below

Relative paths in config.ini are resolved against the folder holding the
config file, so the tool works the same on Windows, Linux and in Docker.
"""

from __future__ import annotations

import configparser
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Set

DEFAULT_CONFIG_TEXT = """\
# ProtectRequest configuration.
# Relative paths are resolved against this file's folder.

[general]
geoip_db = GeoLite2-Country.mmdb
# Where AbuseIPDB results are cached between runs (saves API quota).
cache_file = .cache/abuseipdb.json
cache_ttl_hours = 24

[api]
# Leave empty and set the ABUSEIPDB_API_KEY environment variable instead.
# Never commit a real key to git.
abuseipdb_api_key =
abuseipdb_max_age_days = 90

[detection]
# Sliding-window rate limit per IP.
rate_window_seconds = 60
max_requests_per_window = 120
# Brute force: failed logins from one IP inside the window.
bruteforce_window_seconds = 300
bruteforce_threshold = 5
# 404 scanning: many not-found responses from one IP inside the window.
scan_window_seconds = 120
scan_404_threshold = 15
# Comma-separated ISO country codes or names, e.g. KP, RU, Iran
risky_countries =
# Comma-separated HTTP status codes to flag, e.g. 500, 502, 418
unusual_status_codes =
# Extra paths considered sensitive (prefix match), comma-separated.
extra_sensitive_paths =

[whitelist]
# IPs or CIDR ranges that are never flagged, comma-separated.
ips = 127.0.0.1, ::1

[scoring]
# Points per finding severity, summed per IP then capped at 100.
info = 1
low = 3
medium = 8
high = 15
critical = 30
# How much of the AbuseIPDB confidence score (0-100) to add.
abuse_weight = 0.5
# Points added when the IP is from a risky country.
geo_points = 10

[alerts]
# Watch mode: also POST alerts as JSON to this URL (Slack/Discord/webhook).
webhook_url =
# Watch mode: append alerts as JSON lines to this file.
alert_file =
# Only alert at or above this severity: info, low, medium, high, critical
min_severity = medium
"""


def _split(value: str) -> List[str]:
    return [v.strip() for v in value.split(",") if v.strip()]


@dataclass
class Settings:
    base_dir: Path = field(default_factory=Path.cwd)
    geoip_db: Optional[Path] = None
    cache_file: Optional[Path] = None
    cache_ttl_hours: float = 24

    abuseipdb_api_key: str = ""
    abuseipdb_max_age_days: int = 90

    rate_window_seconds: int = 60
    max_requests_per_window: int = 120
    bruteforce_window_seconds: int = 300
    bruteforce_threshold: int = 5
    scan_window_seconds: int = 120
    scan_404_threshold: int = 15
    risky_countries: Set[str] = field(default_factory=set)
    unusual_status_codes: Set[int] = field(default_factory=set)
    extra_sensitive_paths: List[str] = field(default_factory=list)

    whitelist: List[str] = field(default_factory=lambda: ["127.0.0.1", "::1"])

    severity_points: dict = field(default_factory=lambda: {
        "info": 1, "low": 3, "medium": 8, "high": 15, "critical": 30})
    abuse_weight: float = 0.5
    geo_points: float = 10

    webhook_url: str = ""
    alert_file: Optional[Path] = None
    min_severity: str = "medium"


def load_settings(config_path: Optional[str] = None) -> Settings:
    """Load settings. Missing file = defaults (no crash)."""
    parser = configparser.ConfigParser()
    parser.read_string(DEFAULT_CONFIG_TEXT)

    path = Path(config_path) if config_path else Path("config.ini")
    base = path.resolve().parent if path.exists() else Path.cwd()
    if path.exists():
        parser.read(path, encoding="utf-8")

    def p(section: str, key: str) -> Optional[Path]:
        raw = parser.get(section, key, fallback="").strip()
        if not raw:
            return None
        candidate = Path(os.path.expanduser(raw))
        return candidate if candidate.is_absolute() else base / candidate

    g, d, s, a = "general", "detection", "scoring", "alerts"
    st = Settings(base_dir=base)
    st.geoip_db = p(g, "geoip_db")
    st.cache_file = p(g, "cache_file")
    st.cache_ttl_hours = parser.getfloat(g, "cache_ttl_hours")

    st.abuseipdb_api_key = (os.environ.get("ABUSEIPDB_API_KEY")
                            or parser.get("api", "abuseipdb_api_key", fallback="").strip())
    st.abuseipdb_max_age_days = parser.getint("api", "abuseipdb_max_age_days")

    for key in ("rate_window_seconds", "max_requests_per_window",
                "bruteforce_window_seconds", "bruteforce_threshold",
                "scan_window_seconds", "scan_404_threshold"):
        setattr(st, key, parser.getint(d, key))
    st.risky_countries = {c.lower() for c in _split(parser.get(d, "risky_countries"))}
    st.unusual_status_codes = {int(c) for c in _split(parser.get(d, "unusual_status_codes"))}
    st.extra_sensitive_paths = _split(parser.get(d, "extra_sensitive_paths"))

    st.whitelist = _split(parser.get("whitelist", "ips"))

    st.severity_points = {k: parser.getfloat(s, k)
                          for k in ("info", "low", "medium", "high", "critical")}
    st.abuse_weight = parser.getfloat(s, "abuse_weight")
    st.geo_points = parser.getfloat(s, "geo_points")

    st.webhook_url = parser.get(a, "webhook_url").strip()
    st.alert_file = p(a, "alert_file")
    st.min_severity = parser.get(a, "min_severity").strip().lower() or "medium"
    return st


def write_default_config(path: str, force: bool = False) -> bool:
    target = Path(path)
    if target.exists() and not force:
        return False
    target.write_text(DEFAULT_CONFIG_TEXT, encoding="utf-8")
    return True
