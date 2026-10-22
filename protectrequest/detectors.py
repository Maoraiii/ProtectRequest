"""Threat detectors.

Two kinds:
  * SignatureDetector - looks at ONE event (regex rules on path / user-agent).
  * Stateful detectors - remember events per IP in a sliding time window
    (rate limit, brute force, 404 scanning).

Every detector has `check(event) -> list[Finding]`.
"""

from __future__ import annotations

import re
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Deque, Dict, List, Optional, Pattern
from urllib.parse import unquote_plus

from .config import Settings
from .models import Finding, LogEvent, Severity


def normalise(text: Optional[str]) -> str:
    """URL-decode twice (beats double encoding) and lowercase."""
    if not text:
        return ""
    out = text
    for _ in range(2):
        decoded = unquote_plus(out)
        if decoded == out:
            break
        out = decoded
    return out.lower()


@dataclass
class Rule:
    rule_id: str
    category: str
    severity: Severity
    description: str
    pattern: Pattern
    target: str = "path"  # "path", "ua" or "both"


def _rx(*parts: str) -> Pattern:
    return re.compile("|".join(parts), re.IGNORECASE)


SIGNATURES: List[Rule] = [
    Rule("SQLI", "SQL Injection", Severity.HIGH,
         "SQL injection attempt",
         _rx(r"union(\s|/\*.*?\*/)+(all\s+)?select", r"'\s*or\s*'?\d+'?\s*=\s*'?\d",
             r"\bor\s+1\s*=\s*1\b", r"sleep\s*\(\s*\d", r"benchmark\s*\(", r"waitfor\s+delay",
             r"information_schema", r"\bselect\b.+\bfrom\b", r"(;|')\s*(drop|insert|update|delete)\s",
             r"'\s*--", r"\bxp_cmdshell\b", r"extractvalue\s*\(", r"updatexml\s*\("),
         "both"),
    Rule("XSS", "Cross-Site Scripting", Severity.HIGH,
         "Cross-site scripting (XSS) payload",
         _rx(r"<\s*script", r"javascript\s*:", r"\bon(error|load|mouseover|focus|click)\s*=",
             r"<\s*(svg|img|iframe|body)[^>]*\bon\w+", r"document\.(cookie|location)",
             r"\balert\s*\(", r"<\s*iframe"),
         "both"),
    Rule("TRAVERSAL", "Path Traversal / LFI", Severity.HIGH,
         "Directory traversal or local file inclusion",
         _rx(r"\.\./", r"\.\.\\", r"/etc/(passwd|shadow|hosts)", r"c:\\windows", r"win\.ini",
             r"boot\.ini", r"php://(filter|input)", r"file://", r"/proc/self/"),
         "path"),
    Rule("CMDI", "Command Injection", Severity.CRITICAL,
         "OS command injection / RCE attempt",
         _rx(r"[;|`]\s*(cat|id|whoami|uname|ls|wget|curl|nc|bash|sh|ping)\b",
             r"\$\((\s*)(id|whoami|cat|curl|wget)", r"/bin/(ba)?sh", r"\bnc\s+-e\b",
             r"cmd\.exe", r"powershell", r"\bwget\s+https?://", r"\bcurl\s+https?://"),
         "both"),
    Rule("LOG4SHELL", "Remote Code Execution", Severity.CRITICAL,
         "Log4Shell (CVE-2021-44228) JNDI lookup",
         _rx(r"\$\{\s*jndi\s*:", r"\$\{\s*\$\{.*?\}\s*ndi"),
         "both"),
    Rule("SHELLSHOCK", "Remote Code Execution", Severity.CRITICAL,
         "Shellshock (CVE-2014-6271) payload",
         _rx(r"\(\)\s*\{\s*:;\s*\}"), "both"),
    Rule("SENSITIVE_FILE", "Sensitive File Access", Severity.MEDIUM,
         "Probe for secrets / config / backup files",
         _rx(r"/\.env\b", r"/\.git(/|$)", r"/\.svn/", r"/\.aws/", r"/\.ssh/", r"id_rsa",
             r"\.htpasswd", r"\.htaccess", r"wp-config\.php", r"/config\.(php|json|yml|yaml)\b",
             r"\.(bak|old|backup|sql|swp)(\?|$)", r"/phpinfo\.php", r"/server-status",
             r"/actuator(/|$)", r"/web\.config", r"\.ds_store"),
         "path"),
    Rule("ADMIN_PROBE", "Admin / Login Probe", Severity.LOW,
         "Request to admin or login endpoint",
         _rx(r"^/(admin|administrator|login|signin|wp-login\.php|wp-admin|phpmyadmin|pma|"
             r"manager/html|user/login|xmlrpc\.php|cpanel|webadmin)(/|\?|$)"),
         "path"),
    Rule("SCANNER_UA", "Scanner / Attack Tool", Severity.MEDIUM,
         "Known security scanner or attack tool user-agent",
         _rx(r"sqlmap", r"nikto", r"nmap", r"masscan", r"zgrab", r"gobuster", r"dirbuster",
             r"\bdirb\b", r"wpscan", r"nuclei", r"acunetix", r"nessus", r"openvas", r"\bhydra\b",
             r"\bffuf\b", r"wfuzz", r"burp", r"zmeu", r"jorgee", r"censys", r"netsparker"),
         "ua"),
    Rule("SCRIPTED_UA", "Automated Client", Severity.INFO,
         "Scripted HTTP client (not a browser)",
         _rx(r"^curl/", r"^wget/", r"python-requests", r"python-urllib", r"go-http-client",
             r"^java/", r"libwww-perl", r"^okhttp", r"httpclient", r"aiohttp"),
         "ua"),
]

BAD_METHODS = {"TRACE": Severity.MEDIUM, "TRACK": Severity.MEDIUM, "CONNECT": Severity.MEDIUM,
               "DEBUG": Severity.MEDIUM, "PROPFIND": Severity.LOW, "PUT": Severity.LOW,
               "DELETE": Severity.LOW}

LOGIN_PATH = re.compile(r"(login|signin|auth|wp-login|xmlrpc|session|token)", re.IGNORECASE)


class SignatureDetector:
    name = "signatures"
    ONCE_PER_IP = {"SCANNER_UA", "SCRIPTED_UA", "EMPTY_UA"}

    def __init__(self, settings: Settings):
        self.settings = settings
        self.extra_paths = [p.lower() for p in settings.extra_sensitive_paths]
        # Client-type rules describe the IP, not the request: report once per IP.
        self._once_seen = set()

    def check(self, ev: LogEvent) -> List[Finding]:
        out: List[Finding] = []
        path = normalise(ev.path)
        ua = (ev.user_agent or "").lower()
        ua_norm = normalise(ev.user_agent)
        path_only = path.split("?", 1)[0]

        for rule in SIGNATURES:
            if rule.target == "ua":
                hit = rule.pattern.search(ua)
            elif rule.target == "path":
                target = path_only if rule.rule_id == "ADMIN_PROBE" else path
                hit = rule.pattern.search(target)
            else:
                hit = rule.pattern.search(path) or rule.pattern.search(ua_norm)
            if hit and rule.rule_id in self.ONCE_PER_IP:
                if (ev.ip, rule.rule_id) in self._once_seen:
                    continue
                self._once_seen.add((ev.ip, rule.rule_id))
            if hit:
                out.append(Finding(rule.rule_id, rule.category, rule.severity,
                                   rule.description, ev.ip, ev,
                                   evidence=hit.group(0)[:120]))

        for prefix in self.extra_paths:
            if path_only.startswith(prefix):
                out.append(Finding("CUSTOM_PATH", "Sensitive File Access", Severity.MEDIUM,
                                   f"Access to configured sensitive path {prefix}", ev.ip, ev,
                                   evidence=path_only))
                break

        if ev.method and ev.method.upper() in BAD_METHODS:
            out.append(Finding("BAD_METHOD", "Unusual HTTP Method",
                               BAD_METHODS[ev.method.upper()],
                               f"Unusual HTTP method {ev.method.upper()}", ev.ip, ev,
                               evidence=ev.method))

        if ev.source != "ssh" and ev.method is not None and ev.user_agent in ("", "-") \
                and (ev.ip, "EMPTY_UA") not in self._once_seen:
            self._once_seen.add((ev.ip, "EMPTY_UA"))
            out.append(Finding("EMPTY_UA", "Automated Client", Severity.LOW,
                               "Empty user-agent", ev.ip, ev))

        if ev.status is not None and ev.status in self.settings.unusual_status_codes:
            out.append(Finding("UNUSUAL_STATUS", "Unusual Response", Severity.LOW,
                               f"Configured unusual status code {ev.status}", ev.ip, ev,
                               evidence=str(ev.status)))

        if ev.source == "ssh" and ev.action == "invalid_user":
            out.append(Finding("SSH_INVALID_USER", "Brute Force", Severity.LOW,
                               f"SSH login for non-existent user '{ev.user}'", ev.ip, ev,
                               evidence=ev.user or ""))
        return out


class _Window:
    """Per-IP sliding window of timestamps.

    Alerts escalate: first at the threshold, then each time the count in the
    window doubles (5, 10, 20, 40...). Long attacks score higher without
    flooding the report with one finding per line.
    """

    def __init__(self, seconds: int, threshold: int):
        self.span = timedelta(seconds=seconds)
        self.threshold = max(1, threshold)
        self.hits: Dict[str, Deque[datetime]] = defaultdict(deque)
        self.next_alert: Dict[str, int] = {}

    def add(self, ip: str, ts: datetime) -> int:
        q = self.hits[ip]
        q.append(ts)
        while q and ts - q[0] > self.span:
            q.popleft()
        if len(q) < self.threshold:
            self.next_alert.pop(ip, None)  # attack burst over: reset escalation
        return len(q)

    def should_alert(self, ip: str, count: int) -> bool:
        if count >= self.next_alert.get(ip, self.threshold):
            self.next_alert[ip] = count * 2
            return True
        return False


class RateDetector:
    name = "rate"

    def __init__(self, settings: Settings):
        self.limit = settings.max_requests_per_window
        self.window = _Window(settings.rate_window_seconds, self.limit + 1)
        self.secs = settings.rate_window_seconds

    def check(self, ev: LogEvent) -> List[Finding]:
        if not ev.ip or ev.source == "ssh" or ev.timestamp is None:
            return []
        count = self.window.add(ev.ip, ev.timestamp)
        if self.window.should_alert(ev.ip, count):
            return [Finding("RATE_LIMIT", "High Request Volume", Severity.HIGH,
                            f"{count} requests in {self.secs}s (limit {self.limit})",
                            ev.ip, ev, evidence=str(count))]
        return []


class BruteForceDetector:
    name = "bruteforce"

    def __init__(self, settings: Settings):
        self.threshold = settings.bruteforce_threshold
        self.secs = settings.bruteforce_window_seconds
        self.window = _Window(self.secs, self.threshold)
        self.flagged: Dict[str, int] = {}

    @staticmethod
    def is_failure(ev: LogEvent) -> bool:
        if ev.source == "ssh":
            return ev.action in ("auth_failed", "invalid_user", "max_auth")
        if not ev.path or not LOGIN_PATH.search(ev.path.split("?", 1)[0]):
            return False
        # 401/403 = rejected. POST answered with 200 = login form shown again
        # (most web apps re-render the form on a wrong password).
        is_post = (ev.method or "").upper() == "POST"
        return ev.status in (401, 403) or (is_post and ev.status == 200)

    @staticmethod
    def is_success(ev: LogEvent) -> bool:
        if ev.source == "ssh":
            return ev.action == "auth_success"
        # POST to login answered with a redirect = usually logged in.
        return bool((ev.method or "").upper() == "POST" and ev.path
                    and LOGIN_PATH.search(ev.path) and ev.status in (302, 303))

    def check(self, ev: LogEvent) -> List[Finding]:
        if not ev.ip or ev.timestamp is None:
            return []
        if self.is_failure(ev):
            count = self.window.add(ev.ip, ev.timestamp)
            if self.window.should_alert(ev.ip, count):
                self.flagged[ev.ip] = count
                target = "SSH" if ev.source == "ssh" else "web login"
                return [Finding("BRUTE_FORCE", "Brute Force", Severity.HIGH,
                                f"{count} failed {target} attempts in {self.secs}s",
                                ev.ip, ev, evidence=ev.user or ev.path or "")]
        elif self.is_success(ev) and ev.ip in self.flagged:
            fails = self.flagged.pop(ev.ip)
            who = f" as '{ev.user}'" if ev.user else ""
            return [Finding("BRUTE_FORCE_SUCCESS", "Account Compromise", Severity.CRITICAL,
                            f"Successful login{who} after {fails}+ failures - likely compromise",
                            ev.ip, ev, evidence=ev.user or ev.path or "")]
        return []


class NotFoundScanDetector:
    name = "scan404"

    def __init__(self, settings: Settings):
        self.threshold = settings.scan_404_threshold
        self.secs = settings.scan_window_seconds
        self.window = _Window(self.secs, self.threshold)

    def check(self, ev: LogEvent) -> List[Finding]:
        if not ev.ip or ev.status != 404 or ev.timestamp is None:
            return []
        count = self.window.add(ev.ip, ev.timestamp)
        if self.window.should_alert(ev.ip, count):
            return [Finding("SCAN_404", "Reconnaissance", Severity.MEDIUM,
                            f"{count} not-found responses in {self.secs}s (forced browsing)",
                            ev.ip, ev, evidence=str(count))]
        return []


def build_detectors(settings: Settings):
    return [SignatureDetector(settings), RateDetector(settings),
            BruteForceDetector(settings), NotFoundScanDetector(settings)]
