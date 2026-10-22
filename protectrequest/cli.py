"""Command-line interface.

    python -m protectrequest analyze logs/access.log
    python -m protectrequest watch /var/log/auth.log
    python -m protectrequest --help
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import List, Optional

from . import __version__
from . import colors
from .colors import C
from .config import load_settings, write_default_config

BANNER = r"""
 ___         _          _   ___                       _
| _ \_ _ ___| |_ ___ __| |_| _ \___ __ _ _  _ ___ __| |_
|  _/ '_/ _ \  _/ -_) _|  _|   / -_) _` | || / -_|_-<  _|
|_| |_| \___/\__\___\__|\__|_|_\___\__, |\_,_\___/__/\__|
                                      |_|"""

LEVELS = ["low", "medium", "high", "critical"]


def _banner():
    print(C.CYAN + BANNER + C.RESET)
    print(C.DIM + f"  v{__version__}  multi-format log threat analyzer\n" + C.RESET)


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(65536), b""):
            h.update(block)
    return h.hexdigest()


def cmd_analyze(args) -> int:
    from .analyzer import Analyzer, iter_files
    from .html_report import generate_html
    from .output import print_summary, write_csv, write_json

    settings = load_settings(args.config)
    files = list(iter_files(args.logs))
    missing = [f for f in files if not f.is_file()]
    if missing:
        for f in missing:
            print(C.RED + f"Not found or not a file: {f}" + C.RESET, file=sys.stderr)
        return 1
    if not files:
        print(C.RED + "No log files found." + C.RESET, file=sys.stderr)
        return 1

    state_path = settings.base_dir / ".cache" / "hashes.json"
    hashes = {}
    if args.skip_unchanged:
        try:
            hashes = json.loads(state_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            hashes = {}
        changed = [f for f in files if hashes.get(str(f.resolve())) != _sha256(f)]
        if not changed:
            print("No changes since last run. Nothing to do.")
            return 0
        files = changed

    analyzer = Analyzer(settings, use_abuse=not args.no_abuse)
    for f in files:
        def progress(n, name=f.name):
            if not args.quiet and sys.stdout.isatty():
                print(f"\r  {name}: {n:,} lines", end="", flush=True)
        try:
            fmt = analyzer.analyze_file(str(f), args.format, progress)
        except ValueError as exc:
            print(C.RED + f"\n{f}: {exc}" + C.RESET, file=sys.stderr)
            return 1
        if not args.quiet:
            print(f"\r  {f.name}: {analyzer.files[-1]['lines']:,} lines  [{fmt}]")

    report = analyzer.finalize()
    if args.min_score:
        report.flagged = [p for p in report.flagged if p.score >= args.min_score]

    if not args.quiet:
        print_summary(report, top=args.top)
    print()
    if not args.no_html:
        generate_html(report, args.output)
        print(C.GREEN + f"HTML report: {Path(args.output).resolve()}" + C.RESET)
    if args.json:
        write_json(report, args.json)
        print(C.GREEN + f"JSON report: {Path(args.json).resolve()}" + C.RESET)
    if args.csv:
        write_csv(report, args.csv)
        print(C.GREEN + f"CSV reports: {Path(args.csv).resolve()} (+ _findings)" + C.RESET)

    if args.skip_unchanged:
        for f in files:
            hashes[str(f.resolve())] = _sha256(f)
        state_path.parent.mkdir(parents=True, exist_ok=True)
        state_path.write_text(json.dumps(hashes, indent=1), encoding="utf-8")

    if args.fail_on:
        need = LEVELS.index(args.fail_on)
        worst = max((LEVELS.index(p.level.lower()) for p in report.flagged
                     if p.level.lower() in LEVELS), default=-1)
        if worst >= need:
            print(C.RED + f"Exit 2: found IPs at level >= {args.fail_on}" + C.RESET)
            return 2
    return 0


def cmd_watch(args) -> int:
    from .watch import run_watch
    settings = load_settings(args.config)
    if args.min_severity:
        settings.min_severity = args.min_severity
    if args.webhook:
        settings.webhook_url = args.webhook
    if args.alert_file:
        settings.alert_file = Path(args.alert_file)
    analyzer = run_watch(args.log, settings, args.format, args.from_start,
                         args.interval, use_abuse=not args.no_abuse)
    if args.report:
        from .html_report import generate_html
        generate_html(analyzer.finalize(), args.report)
        print(C.GREEN + f"HTML report: {Path(args.report).resolve()}" + C.RESET)
    return 0


def cmd_formats(_args) -> int:
    from .parsers import PARSERS
    print(C.BOLD + "Supported log formats (--format):" + C.RESET)
    for name, cls in PARSERS.items():
        print(f"  {name:<14} {cls.description}")
    print(f"  {'auto':<14} detect from the first lines (default)")
    return 0


def cmd_rules(_args) -> int:
    from .detectors import SIGNATURES
    print(C.BOLD + "Signature rules:" + C.RESET)
    for r in SIGNATURES:
        print(f"  {r.rule_id:<15} {r.severity.label:<9} {r.category:<24} [{r.target}]")
    print(C.BOLD + "\nBehaviour rules:" + C.RESET)
    for rid, sev, text in [
        ("RATE_LIMIT", "High", "too many requests per IP in a sliding window"),
        ("BRUTE_FORCE", "High", "many failed SSH / web logins per IP"),
        ("BRUTE_FORCE_SUCCESS", "Critical", "successful login after a brute force"),
        ("SCAN_404", "Medium", "burst of 404s = forced browsing / dir scan"),
        ("BAD_METHOD", "Low-Med", "TRACE, CONNECT, PUT, DELETE, PROPFIND..."),
        ("EMPTY_UA", "Low", "request with no user-agent"),
        ("SSH_INVALID_USER", "Low", "SSH login for a user that does not exist"),
        ("RISKY_COUNTRY", "Low", "IP from a country in risky_countries"),
        ("UNUSUAL_STATUS", "Low", "status code listed in unusual_status_codes"),
    ]:
        print(f"  {rid:<20} {sev:<9} {text}")
    return 0


def cmd_init(args) -> int:
    if write_default_config(args.path, force=args.force):
        print(C.GREEN + f"Wrote {args.path}" + C.RESET)
        print("Set your AbuseIPDB key with the ABUSEIPDB_API_KEY environment variable.")
        return 0
    print(C.YELLOW + f"{args.path} exists. Use --force to overwrite." + C.RESET)
    return 1


def cmd_check_ip(args) -> int:
    from .enrich import Enricher
    settings = load_settings(args.config)
    enr = Enricher(settings)
    for ip in args.ips:
        info = enr.info(ip)
        abuse = "not checked" if info.abuse_score is None else \
            f"{info.abuse_score}% confidence, {info.total_reports} reports"
        print(f"{C.BOLD}{ip}{C.RESET}")
        print(f"  country : {info.country} {info.country_code}")
        print(f"  abuse   : {abuse}")
        if info.isp:
            print(f"  isp     : {info.isp} ({info.usage_type})")
        print(f"  listed  : {'whitelisted' if ip in enr.whitelist else 'no'}")
    for note in (enr.geo.error, enr.abuse.disabled_reason):
        if note:
            print(C.DIM + f"note: {note}" + C.RESET)
    enr.close()
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="protectrequest",
        description="Find attacks in web server, SSH, IIS and JSON logs.")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    p.add_argument("--no-color", action="store_true", help="disable colours")
    sub = p.add_subparsers(dest="command", metavar="COMMAND")

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("-c", "--config", default="config.ini", help="config file (default: config.ini)")
    common.add_argument("-f", "--format", default="auto",
                        help="log format: auto, combined, requestshield, nginx_error, ssh, iis, json")
    common.add_argument("--no-abuse", action="store_true", help="skip AbuseIPDB lookups (offline)")
    common.add_argument("--no-color", action="store_true", default=argparse.SUPPRESS,
                        help="disable colours")

    a = sub.add_parser("analyze", parents=[common], help="analyse log files and write reports")
    a.add_argument("logs", nargs="+", help="log files or folders")
    a.add_argument("-o", "--output", default="report.html", help="HTML report path")
    a.add_argument("--no-html", action="store_true", help="do not write the HTML report")
    a.add_argument("--json", metavar="PATH", help="also write a JSON report")
    a.add_argument("--csv", metavar="PATH", help="also write CSV reports")
    a.add_argument("--top", type=int, default=10, help="IPs to list in the console")
    a.add_argument("--min-score", type=float, default=0, help="hide IPs below this score")
    a.add_argument("--skip-unchanged", action="store_true", help="skip files unchanged since last run")
    a.add_argument("--fail-on", choices=LEVELS, help="exit code 2 if any IP reaches this level")
    a.add_argument("-q", "--quiet", action="store_true", help="less console output")
    a.set_defaults(func=cmd_analyze)

    w = sub.add_parser("watch", parents=[common], help="follow a log live and alert")
    w.add_argument("log", help="log file to follow")
    w.add_argument("--from-start", action="store_true", help="read existing lines first")
    w.add_argument("--interval", type=float, default=1.0, help="poll seconds (default 1)")
    w.add_argument("--min-severity", choices=["info"] + LEVELS, help="alert threshold")
    w.add_argument("--webhook", help="POST alerts to this URL (Slack/Discord/etc.)")
    w.add_argument("--alert-file", help="append alerts as JSON lines")
    w.add_argument("--report", metavar="PATH", help="write HTML report on Ctrl+C")
    w.set_defaults(func=cmd_watch)

    sub.add_parser("formats", help="list supported log formats").set_defaults(func=cmd_formats)
    sub.add_parser("rules", help="list detection rules").set_defaults(func=cmd_rules)

    i = sub.add_parser("init", help="write a default config.ini")
    i.add_argument("path", nargs="?", default="config.ini")
    i.add_argument("--force", action="store_true")
    i.set_defaults(func=cmd_init)

    c = sub.add_parser("check-ip", help="look up IPs (GeoIP + AbuseIPDB)")
    c.add_argument("ips", nargs="+")
    c.add_argument("-c", "--config", default="config.ini")
    c.set_defaults(func=cmd_check_ip)
    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    colors.init(force_off=args.no_color)
    if not args.command:
        _banner()
        parser.print_help()
        return 0
    if args.command in ("analyze", "watch") and not getattr(args, "quiet", False):
        _banner()
    try:
        return args.func(args)
    except KeyboardInterrupt:
        return 130
