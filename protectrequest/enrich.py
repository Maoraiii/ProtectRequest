"""IP enrichment: whitelist, GeoIP country, AbuseIPDB reputation.

AbuseIPDB results are cached per IP (in memory + on disk) so each IP is
looked up at most once per TTL - the old version called the API once per
log LINE and burned the free 1000/day quota fast.
"""

from __future__ import annotations

import ipaddress
import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

from .config import Settings


@dataclass
class IPInfo:
    country: str = "Unknown"
    country_code: str = ""
    abuse_score: Optional[int] = None   # None = not checked
    total_reports: int = 0
    isp: str = ""
    usage_type: str = ""
    is_private: bool = False


def _parse_ip(ip: str):
    try:
        return ipaddress.ip_address(ip)
    except (ValueError, TypeError):
        return None


class Whitelist:
    def __init__(self, entries: List[str]):
        self.nets = []
        for e in entries:
            try:
                self.nets.append(ipaddress.ip_network(e, strict=False))
            except ValueError:
                pass

    def __contains__(self, ip: Optional[str]) -> bool:
        addr = _parse_ip(ip) if ip else None
        return bool(addr) and any(addr in n for n in self.nets if n.version == addr.version)


class GeoIP:
    def __init__(self, db_path: Optional[Path]):
        self.reader = None
        self.error = ""
        if not db_path:
            self.error = "no GeoIP database configured"
            return
        if not Path(db_path).exists():
            self.error = f"GeoIP database not found: {db_path}"
            return
        try:
            import geoip2.database  # optional dependency
            self.reader = geoip2.database.Reader(str(db_path))
        except ImportError:
            self.error = "geoip2 package not installed"
        except Exception as exc:  # corrupt DB etc.
            self.error = f"GeoIP load failed: {exc}"

    def lookup(self, ip: str):
        if not self.reader:
            return "Unknown", ""
        try:
            r = self.reader.country(ip)
            return r.country.name or "Unknown", r.country.iso_code or ""
        except Exception:
            return "Unknown", ""


class AbuseIPDB:
    URL = "https://api.abuseipdb.com/api/v2/check"

    def __init__(self, settings: Settings, enabled: bool = True):
        self.key = settings.abuseipdb_api_key
        self.max_age = settings.abuseipdb_max_age_days
        self.ttl = settings.cache_ttl_hours * 3600
        self.cache_file = settings.cache_file
        self.enabled = enabled and bool(self.key)
        self.cache: Dict[str, dict] = {}
        self.calls = 0
        self.errors = 0
        self.disabled_reason = "" if self.enabled else (
            "disabled by --no-abuse" if not enabled else "no API key (set ABUSEIPDB_API_KEY)")
        self._load()

    def _load(self):
        if self.cache_file and self.cache_file.exists():
            try:
                self.cache = json.loads(self.cache_file.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                self.cache = {}

    def save(self):
        if not self.cache_file or not self.cache:
            return
        try:
            self.cache_file.parent.mkdir(parents=True, exist_ok=True)
            self.cache_file.write_text(json.dumps(self.cache), encoding="utf-8")
        except OSError:
            pass

    def check(self, ip: str) -> Optional[dict]:
        hit = self.cache.get(ip)
        if hit and time.time() - hit.get("_ts", 0) < self.ttl:
            return hit
        if not self.enabled:
            return None
        if self.errors >= 3:  # API down / quota hit: stop trying
            return None
        try:
            import requests
            resp = requests.get(self.URL, timeout=6,
                                headers={"Accept": "application/json", "Key": self.key},
                                params={"ipAddress": ip, "maxAgeInDays": str(self.max_age)})
            self.calls += 1
            if resp.status_code == 429:
                self.errors = 3
                self.disabled_reason = "AbuseIPDB rate limit reached (HTTP 429)"
                return None
            resp.raise_for_status()
            data = resp.json().get("data", {})
        except Exception as exc:
            self.errors += 1
            if self.errors >= 3:
                self.disabled_reason = f"AbuseIPDB unreachable: {exc}"
            return None
        result = {
            "score": int(data.get("abuseConfidenceScore", 0) or 0),
            "reports": int(data.get("totalReports", 0) or 0),
            "isp": data.get("isp") or "",
            "usage": data.get("usageType") or "",
            "_ts": time.time(),
        }
        self.cache[ip] = result
        return result


class Enricher:
    def __init__(self, settings: Settings, use_abuse: bool = True):
        self.whitelist = Whitelist(settings.whitelist)
        self.geo = GeoIP(settings.geoip_db)
        self.abuse = AbuseIPDB(settings, enabled=use_abuse)
        self._seen: Dict[str, IPInfo] = {}

    def info(self, ip: str) -> IPInfo:
        if ip in self._seen:
            return self._seen[ip]
        addr = _parse_ip(ip)
        info = IPInfo()
        if addr is None:
            info.country = "Invalid IP"
        elif addr.is_private or addr.is_loopback or addr.is_reserved or addr.is_link_local:
            info.is_private = True
            info.country = "Private / Reserved"
        else:
            info.country, info.country_code = self.geo.lookup(ip)
            res = self.abuse.check(ip)
            if res:
                info.abuse_score = res["score"]
                info.total_reports = res["reports"]
                info.isp = res["isp"]
                info.usage_type = res["usage"]
        self._seen[ip] = info
        return info

    def close(self):
        self.abuse.save()
