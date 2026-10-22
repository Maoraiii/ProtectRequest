"""Run with:  python -m pytest -q"""

from datetime import datetime, timedelta
from pathlib import Path

import pytest

from protectrequest.analyzer import Analyzer
from protectrequest.cli import main
from protectrequest.config import Settings, load_settings
from protectrequest.detectors import SignatureDetector, normalise
from protectrequest.enrich import Whitelist
from protectrequest.html_report import generate_html
from protectrequest.models import LogEvent, Severity
from protectrequest.parsers import detect_format, get_parser

ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "samples"
T = datetime(2026, 3, 14, 9, 0, 0)


def settings(**kw) -> Settings:
    s = Settings()
    s.geoip_db = None
    s.cache_file = None
    s.abuseipdb_api_key = ""
    for k, v in kw.items():
        setattr(s, k, v)
    return s


def ev(path="/", ip="203.0.113.1", ua="Mozilla/5.0", status=200, method="GET", ts=T, **kw):
    return LogEvent(source="combined", raw="", ip=ip, path=path, user_agent=ua,
                    status=status, method=method, timestamp=ts, **kw)


def rules(findings):
    return {f.rule for f in findings}


# ---------- parsers ----------

def test_combined_parser():
    line = ('203.0.113.42 - bob [14/Mar/2026:09:00:00 +0000] "GET /a?b=1 HTTP/1.1" 200 400 '
            '"-" "Mozilla/5.0"')
    e = get_parser("combined").parse(line)
    assert (e.ip, e.method, e.path, e.status, e.size, e.user) == \
        ("203.0.113.42", "GET", "/a?b=1", 200, 400, "bob")
    assert e.timestamp == T


def test_common_log_format_without_ua():
    e = get_parser("combined").parse('1.2.3.4 - - [14/Mar/2026:09:00:00 +0530] "GET / HTTP/1.0" 404 -')
    assert e.status == 404 and e.size == 0
    assert e.timestamp == T - timedelta(hours=5, minutes=30)  # normalised to UTC


def test_ssh_parser():
    p = get_parser("ssh")
    e = p.parse("Mar 14 09:00:01 web01 sshd[99]: Failed password for invalid user admin "
                "from 203.0.113.5 port 4000 ssh2")
    assert (e.action, e.user, e.ip) == ("auth_failed", "admin", "203.0.113.5")
    e = p.parse("Mar 14 09:00:02 web01 sshd[99]: Accepted publickey for deploy from 198.51.100.1 port 1 ssh2")
    assert e.action == "auth_success"
    assert p.parse("Mar 14 09:00:02 web01 cron[1]: something") is None


def test_iis_parser_reads_fields_header():
    p = get_parser("iis")
    p.parse("#Fields: date time c-ip cs-method cs-uri-stem cs-uri-query sc-status cs(User-Agent)")
    e = p.parse("2026-03-14 09:00:00 203.0.113.9 GET /x a=1 404 curl/8.0")
    assert (e.ip, e.path, e.status, e.user_agent) == ("203.0.113.9", "/x?a=1", 404, "curl/8.0")


def test_json_parser_nested_and_epoch():
    p = get_parser("json")
    e = p.parse('{"ts": 1773478800, "request": {"remote_ip": "203.0.113.3", "uri": "/z", '
                '"method": "POST", "headers": {"User-Agent": ["x"]}}, "status": 401}')
    assert (e.ip, e.path, e.method, e.status, e.user_agent) == ("203.0.113.3", "/z", "POST", 401, "x")
    assert e.timestamp == datetime(2026, 3, 14, 9, 0, 0)


@pytest.mark.parametrize("name,fmt", [
    ("web_access.log", "combined"), ("auth.log", "ssh"), ("iis_u_ex260314.log", "iis"),
    ("nginx_json.log", "json"), ("nginx_error.log", "nginx_error"),
])
def test_autodetect_samples(name, fmt):
    with open(SAMPLES / name, encoding="utf-8") as fh:
        assert detect_format(fh) == fmt


# ---------- detectors ----------

def test_double_url_encoding_is_decoded():
    assert normalise("/%252e%252e%252fetc%252fpasswd") == "/../etc/passwd"


@pytest.mark.parametrize("path,rule", [
    ("/p?id=1%27%20OR%20%271%27=%271", "SQLI"),
    ("/p?id=1+UNION+SELECT+a,b+FROM+users", "SQLI"),
    ("/s?q=%3Cscript%3Ealert(1)%3C/script%3E", "XSS"),
    ("/d?f=..%2f..%2fetc%2fpasswd", "TRAVERSAL"),
    ("/ping?h=1;cat%20/etc/passwd", "CMDI"),
    ("/.env", "SENSITIVE_FILE"),
    ("/.git/config", "SENSITIVE_FILE"),
    ("/wp-login.php", "ADMIN_PROBE"),
])
def test_signatures_hit(path, rule):
    assert rule in rules(SignatureDetector(settings()).check(ev(path)))


@pytest.mark.parametrize("path", ["/", "/products/42", "/selection?from=menu", "/administration-guide.pdf",
                                  "/blog/union-station-review", "/assets/app.js"])
def test_signatures_no_false_positive(path):
    found = SignatureDetector(settings()).check(ev(path))
    assert not [f for f in found if f.severity >= Severity.MEDIUM], found


def test_log4shell_in_user_agent():
    assert "LOG4SHELL" in rules(SignatureDetector(settings()).check(ev(ua="${jndi:ldap://x/a}")))


def test_scanner_ua_reported_once_per_ip():
    det = SignatureDetector(settings())
    hits = sum(len(det.check(ev(ua="sqlmap/1.8"))) for _ in range(5))
    assert hits == 1


def test_whitelist_cidr():
    wl = Whitelist(["10.0.0.0/8", "::1"])
    assert "10.2.3.4" in wl and "::1" in wl and "11.0.0.1" not in wl


# ---------- behaviour (analyzer) ----------

def test_rate_limit_and_escalation():
    a = Analyzer(settings(max_requests_per_window=10, rate_window_seconds=60), use_abuse=False)
    for i in range(45):
        a.process(ev(ip="192.0.2.1", ts=T + timedelta(seconds=i)))
    rl = [f for f in a.findings if f.rule == "RATE_LIMIT"]
    # alert at 11, then each time the count doubles: 22, 44
    assert [f.evidence for f in rl] == ["11", "22", "44"]


def test_slow_traffic_is_not_rate_limited():
    a = Analyzer(settings(max_requests_per_window=10, rate_window_seconds=60), use_abuse=False)
    for i in range(50):
        a.process(ev(ip="192.0.2.1", ts=T + timedelta(seconds=i * 10)))
    assert not [f for f in a.findings if f.rule == "RATE_LIMIT"]


def test_web_bruteforce_then_success_is_critical():
    a = Analyzer(settings(bruteforce_threshold=5), use_abuse=False)
    for i in range(6):
        a.process(ev("/login", ip="198.51.100.9", method="POST", status=401, ts=T + timedelta(seconds=i)))
    a.process(ev("/login", ip="198.51.100.9", method="POST", status=302, ts=T + timedelta(seconds=30)))
    report = a.finalize()
    assert {"BRUTE_FORCE", "BRUTE_FORCE_SUCCESS"} <= rules(a.findings)
    assert report.flagged[0].level == "Critical"


def test_whitelisted_ip_ignored():
    a = Analyzer(settings(whitelist=["203.0.113.0/24"]), use_abuse=False)
    a.process(ev("/.env"))
    assert not a.findings and a.skipped_whitelist == 1


def test_full_sample_run_finds_every_attacker():
    a = Analyzer(settings(), use_abuse=False)
    a.analyze_file(str(SAMPLES / "web_access.log"))
    a.analyze_file(str(SAMPLES / "auth.log"))
    flagged = {p.ip: p for p in a.finalize().flagged}
    for ip in ["203.0.113.66", "198.51.100.200", "192.0.2.150", "203.0.113.77",
               "198.51.100.99", "192.0.2.201", "203.0.113.5", "192.0.2.44"]:
        assert ip in flagged, ip
    assert flagged["192.0.2.44"].level == "Critical"     # SSH brute force + success
    assert "198.51.100.17" not in flagged                 # normal user


# ---------- output ----------

def test_html_escapes_attacker_input(tmp_path):
    a = Analyzer(settings(), use_abuse=False)
    a.process(ev("/s?q=<script>alert('pwned')</script>"))
    out = tmp_path / "r.html"
    generate_html(a.finalize(), str(out))
    page = out.read_text(encoding="utf-8")
    assert "<script>alert('pwned')" not in page
    assert "&lt;script&gt;" in page


def test_cli_end_to_end(tmp_path):
    rc = main(["analyze", str(SAMPLES / "web_access.log"), "--no-abuse", "-q", "--no-color",
               "-c", str(tmp_path / "none.ini"),
               "-o", str(tmp_path / "r.html"), "--json", str(tmp_path / "r.json"),
               "--csv", str(tmp_path / "r.csv"), "--fail-on", "critical"])
    assert rc == 2  # critical IPs present
    for name in ("r.html", "r.json", "r.csv", "r_findings.csv"):
        assert (tmp_path / name).stat().st_size > 0


def test_config_env_key_wins(tmp_path, monkeypatch):
    ini = tmp_path / "c.ini"
    ini.write_text("[api]\nabuseipdb_api_key = fromfile\n[general]\ngeoip_db = db.mmdb\n")
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "fromenv")
    s = load_settings(str(ini))
    assert s.abuseipdb_api_key == "fromenv"
    assert s.geoip_db == tmp_path / "db.mmdb"  # relative to config file
