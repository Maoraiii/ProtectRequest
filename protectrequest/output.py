"""Report writers: JSON, CSV and console summary. HTML lives in html_report.py."""

from __future__ import annotations

import csv
import json
from pathlib import Path

from .analyzer import Report
from .colors import C


def write_json(report: Report, path: str) -> None:
    Path(path).write_text(json.dumps(report.to_dict(), indent=2, default=str), encoding="utf-8")


def write_csv(report: Report, path: str) -> None:
    """Two CSVs: <name>.csv (one row per IP) and <name>_findings.csv."""
    base = Path(path)
    with base.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["ip", "score", "level", "country", "abuse_score", "requests",
                    "first_seen", "last_seen", "categories", "rules", "top_paths"])
        for p in report.flagged:
            w.writerow([p.ip, round(p.score, 1), p.level, p.info.country,
                        "" if p.info.abuse_score is None else p.info.abuse_score,
                        p.requests, p.first_seen or "", p.last_seen or "",
                        "; ".join(p.categories),
                        "; ".join(f"{k}x{v}" for k, v in p.rule_counts.items()),
                        "; ".join(path for path, _ in p.paths.most_common(5))])
    fpath = base.with_name(base.stem + "_findings" + base.suffix)
    with fpath.open("w", newline="", encoding="utf-8") as fh:
        rows = [f.to_dict() for f in report.findings]
        cols = ["timestamp", "ip", "severity", "rule", "category", "description",
                "evidence", "path", "status", "user_agent", "source", "line_no"]
        w = csv.DictWriter(fh, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)


LEVEL_COLOR = {"Critical": "MAGENTA", "High": "RED", "Medium": "YELLOW", "Low": "CYAN",
               "None": "DIM"}


def print_summary(report: Report, top: int = 10) -> None:
    print()
    print(C.BOLD + "=== Summary ===" + C.RESET)
    for f in report.files:
        print(f"  {f['path']}  [{f['format']}]  {f['parsed']}/{f['lines']} lines parsed")
    span = ""
    if report.first_ts and report.last_ts:
        span = f"  ({report.first_ts:%Y-%m-%d %H:%M} -> {report.last_ts:%Y-%m-%d %H:%M})"
    print(f"  Events: {report.parsed}{span}")
    print(f"  Unique IPs: {report.unique_ips}   Flagged IPs: {len(report.flagged)}   "
          f"Findings: {len(report.findings)}")
    if report.unparsed:
        print(C.YELLOW + f"  Unparsed lines: {report.unparsed}" + C.RESET)
    for note in (report.geo_note, report.abuse_note):
        if note:
            print(C.DIM + f"  note: {note}" + C.RESET)

    if report.category_counts:
        print()
        print(C.BOLD + "=== Findings by category ===" + C.RESET)
        for cat, n in report.category_counts.most_common():
            print(f"  {n:>5}  {cat}")

    if report.flagged:
        print()
        print(C.BOLD + f"=== Top {min(top, len(report.flagged))} risky IPs ===" + C.RESET)
        shown = report.flagged[:top]
        w = max(15, max(len(p.ip) for p in shown))  # IPv4 stays narrow, IPv6 still fits
        print(f"  {'IP':<{w}} {'Score':>5}  {'Level':<8} {'Reqs':>6}  {'Country':<18} Categories")
        for p in shown:
            col = getattr(C, LEVEL_COLOR.get(p.level, "RESET"))
            print(f"  {p.ip:<{w}} {col}{p.score:>5.0f}  {p.level:<8}{C.RESET} {p.requests:>6}  "
                  f"{p.info.country[:18]:<18} {', '.join(p.categories)}")
    else:
        print(C.GREEN + "\n  No threats found." + C.RESET)
