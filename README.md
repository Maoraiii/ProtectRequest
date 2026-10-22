# ProtectRequest

Multi-format log threat analyzer. Reads web server, SSH, IIS and JSON logs,
finds attacks, scores each IP and writes HTML / JSON / CSV reports. It can
also follow a log live and send alerts.

Cybersecurity honours mini-project.

## Features

- **6 log formats, auto-detected**: Apache/Nginx access (Combined + Common),
  Nginx error log, Linux `auth.log` (sshd), Microsoft IIS W3C, JSON lines
  (Nginx/Caddy/Traefik/cloud LBs), and the original RequestShield format.
- **Attack detection**:
  - payloads: SQL injection, XSS, path traversal / LFI, command injection,
    Log4Shell, Shellshock
  - probes for secrets (`.env`, `.git`, backups) and admin/login pages
  - scanner tools (sqlmap, nikto, gobuster, nuclei and more)
  - behaviour: request floods, web + SSH brute force, **brute force followed
    by a successful login**, 404 scanning, unusual HTTP methods
- **Threat intel**: GeoIP country (offline MaxMind DB) and AbuseIPDB
  reputation, cached per IP to save API quota.
- **Risk score 0-100 per IP**, levels Low / Medium / High / Critical.
- **Reports**: one HTML file with charts and search (works offline), plus
  JSON and CSV exports.
- **Live watch mode**: follows the log like `tail -F` and survives log
  rotation. Alerts go to the console, a JSON-lines file, or a
  Slack/Discord webhook.
- CI-friendly: `--fail-on high` exits with code 2. Use it in cron or pipelines.

## Quick start

```bash
pip install -r requirements.txt

# try it on the bundled demo logs (offline, no API key needed)
python run.py analyze samples/ --no-abuse
# open report.html
```

### Presentation demo (Windows)

Double-click `demo.bat`. It runs 10 steps in order and pauses between them:
setup, formats and rules, tests, web log report, SSH brute force, all
formats with JSON/CSV export, the XSS-safety check, **live watch mode**
(a second window shows alerts while attacks are fed in), the CI exit code,
and IP lookup. Use `demo.bat auto` to skip the pauses. Outputs go to
`demo_output\`.

Optional install as a command:

```bash
pip install -e .
protectrequest analyze /var/log/nginx/access.log
```

### AbuseIPDB key (optional)

Get a free key at abuseipdb.com, then set it as an environment variable.
**Do not put it in `config.ini` if the repo is public.**

```powershell
# Windows PowerShell
$env:ABUSEIPDB_API_KEY = "your-key"
```
```bash
# Linux / macOS
export ABUSEIPDB_API_KEY="your-key"
```

With no key, the tool still works. It just skips reputation scores.

## Commands

| Command | What it does |
|---|---|
| `analyze FILES/FOLDERS...` | Analyse logs, print summary, write reports |
| `watch FILE` | Follow a log live and alert |
| `check-ip IP...` | GeoIP + AbuseIPDB lookup for some IPs |
| `formats` | List supported log formats |
| `rules` | List detection rules |
| `init [config.ini]` | Write a default config file |

### Examples

```bash
# several files, all exports
python run.py analyze logs/access.log logs/auth.log --json out.json --csv out.csv

# force a format, only show serious IPs
python run.py analyze u_ex260314.log -f iis --min-score 40

# cron / CI: run only if the log changed; exit code 2 on high-risk IPs
python run.py analyze /var/log/nginx/access.log --skip-unchanged --fail-on high -q

# live monitoring with a Discord/Slack webhook, report on Ctrl+C
python run.py watch /var/log/auth.log --webhook https://discord.com/api/webhooks/... --report live.html
```

## Architecture

```
            ┌───────────┐   LogEvent   ┌────────────┐  Finding  ┌──────────┐
 log file ─▶│  parsers  │─────────────▶│  detectors │──────────▶│ analyzer │
            │ (6 types, │              │ signatures │           │ per-IP   │
            │ auto-pick)│              │ rate/brute │           │ profiles │
            └───────────┘              │ 404 scan   │           └────┬─────┘
                                       └────────────┘                │
                         ┌────────────┐  GeoIP, AbuseIPDB (cached)   │
                         │  enrich    │◀─────────────────────────────┤
                         └────────────┘                              ▼
                                                    score ─▶ Report ─▶ HTML / JSON / CSV
                                                                    └▶ watch: alerts
```

| Module | Job |
|---|---|
| `protectrequest/parsers/` | One parser per format. Each turns a raw line into a `LogEvent`. `detect_format()` tries every parser on the first 25 lines and picks the best. |
| `protectrequest/models.py` | `LogEvent`, `Finding`, `Severity`, the shared data types. |
| `protectrequest/detectors.py` | `SignatureDetector` (regex rules on URL-decoded path and user-agent) plus stateful sliding-window detectors (rate, brute force, 404 scan). |
| `protectrequest/enrich.py` | Whitelist (IPs/CIDR), GeoIP, AbuseIPDB with memory + disk cache. Private IPs are never sent to the API. |
| `protectrequest/analyzer.py` | Runs events through detectors, builds per-IP profiles, scores them, makes the `Report`. |
| `protectrequest/html_report.py` | Self-contained HTML report. All log data is HTML-escaped and a strict CSP is set, so attack payloads cannot run in the report. |
| `protectrequest/output.py` | JSON, CSV and console summary. |
| `protectrequest/watch.py` | Live tail with rotation handling, alert de-duplication and webhooks. |
| `protectrequest/config.py` | Defaults → `config.ini` → environment variables. |
| `protectrequest/cli.py` | argparse subcommands. |

### How scoring works

Each finding has a severity. Each severity gives points (set in `[scoring]`):
info 1, low 3, medium 8, high 15, critical 30.

```
per rule:  points(severity) × (1 + log2(times hit))     # repeats count, but slowly
IP score = Σ rules + AbuseIPDB% × abuse_weight + geo_points (if risky country)
           any CRITICAL finding → at least 70; capped at 100
level:     ≥70 Critical, ≥40 High, ≥15 Medium, >0 Low
```

Sliding-window detectors alert at the threshold, then again each time the
count doubles (5 → 10 → 20 …). Long attacks score higher without one
finding per line.

## Configuration

Run `python run.py init` for a commented `config.ini`. Main settings:

| Section | Key | Default | Meaning |
|---|---|---|---|
| general | `geoip_db` | `GeoLite2-Country.mmdb` | Path, relative to the config file |
| detection | `max_requests_per_window` / `rate_window_seconds` | 120 / 60 | Flood threshold |
| detection | `bruteforce_threshold` / `bruteforce_window_seconds` | 5 / 300 | Failed logins |
| detection | `scan_404_threshold` / `scan_window_seconds` | 15 / 120 | Forced browsing |
| detection | `risky_countries` | empty | e.g. `KP, RU, Iran` |
| detection | `unusual_status_codes` | empty | e.g. `500, 418` |
| detection | `extra_sensitive_paths` | empty | e.g. `/internal, /debug` |
| whitelist | `ips` | `127.0.0.1, ::1` | IPs or CIDR, never flagged |
| alerts | `webhook_url`, `alert_file`, `min_severity` | — | Watch mode |

## Extending

**New log format**: subclass `Parser` in `protectrequest/parsers/`,
implement `parse(line, line_no) -> LogEvent | None`, then add it to `PARSERS`
in `parsers/__init__.py`.

**New signature**: add a `Rule(...)` to `SIGNATURES` in `detectors.py`.

**New behaviour rule**: write a class with `check(event) -> list[Finding]`
and add it to `build_detectors()`.

## Tests

```bash
pip install pytest
python -m pytest -q
```

36 tests cover parsers, auto-detect, every signature, false positives,
sliding windows, brute force → compromise, whitelist, XSS-safe HTML, CLI,
and config. `python tools/make_samples.py` rebuilds the demo logs. All demo
IPs come from documentation ranges (RFC 5737), so they show as
"Private / Reserved" and are never sent to AbuseIPDB.

## Limits

- Regex signatures can be evaded by heavy obfuscation. This is not a WAF.
- Web brute-force detection is a heuristic: `401/403` or a `POST` to a
  login URL answered with `200` counts as a failure, and `302/303` counts
  as a success.
- Syslog lines have no year, so the current year is assumed.
- Scores are heuristics. Check before you block an IP.

## Changes from v1

v1 (`legacy/protectrequest_v1.py`) handled one Combined-format file and
flagged only `/admin` and `/login`. v2 fixes:

- API key was hardcoded in the repo → now read from an env var
- AbuseIPDB was called once per line → now once per IP, cached
- "requests per minute" was a running total → now a real sliding window
- HTML report was not escaped, so a log line could inject a script (XSS) → now escaped, with a CSP
- Docker-only `/app/...` paths → paths resolve relative to the config file
- unused whitelist and status-code settings → now work
- dependency check ran after imports → removed (use `requirements.txt`)

Uses GeoLite2 data by MaxMind (https://www.maxmind.com).
