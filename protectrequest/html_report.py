"""Self-contained HTML report (no internet needed, charts are inline SVG).

Every value that came from a log line goes through esc(), because log lines
are attacker-controlled: an XSS payload in a URL must not run in the report.
"""

from __future__ import annotations

import html
from pathlib import Path
from typing import List, Sequence, Tuple

from . import __version__
from .analyzer import Report

SEV_ORDER = ["Critical", "High", "Medium", "Low", "Info"]


def esc(value) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def _fmt_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def svg_timeline(timeline: dict) -> str:
    items = [(k, v) for k, v in timeline.items() if k != "unknown"]
    if not items:
        return '<p class="muted">No timestamps in these logs.</p>'
    w, h, pad_l, pad_b = 900, 220, 44, 34
    n = len(items)
    peak = max(v.get("events", 0) for _, v in items) or 1
    bw = (w - pad_l - 10) / n
    bars: List[str] = []
    for i, (hour, v) in enumerate(items):
        x = pad_l + i * bw
        ev, fi = v.get("events", 0), v.get("findings", 0)
        eh = (h - pad_b - 10) * ev / peak
        fh = (h - pad_b - 10) * min(fi, ev or fi) / peak
        bars.append(
            f'<g><title>{esc(hour)}: {ev} events, {fi} findings</title>'
            f'<rect class="b-ev" x="{x + 1:.1f}" y="{h - pad_b - eh:.1f}" '
            f'width="{max(bw - 2, 1):.1f}" height="{eh:.1f}" rx="2"/>'
            f'<rect class="b-fi" x="{x + 1:.1f}" y="{h - pad_b - fh:.1f}" '
            f'width="{max(bw - 2, 1):.1f}" height="{fh:.1f}" rx="2"/></g>')
    step = max(1, n // 8)
    labels = "".join(
        f'<text class="axis" x="{pad_l + i * bw + bw / 2:.1f}" y="{h - 12}" '
        f'text-anchor="middle">{esc(items[i][0][5:])}</text>'
        for i in range(0, n, step))
    grid = "".join(
        f'<line class="grid" x1="{pad_l}" x2="{w - 10}" y1="{y:.1f}" y2="{y:.1f}"/>'
        f'<text class="axis" x="{pad_l - 6}" y="{y + 4:.1f}" text-anchor="end">{val}</text>'
        for val, y in ((round(peak * f), h - pad_b - (h - pad_b - 10) * f) for f in (0, .5, 1)))
    return (f'<svg viewBox="0 0 {w} {h}" class="chart" role="img" '
            f'aria-label="Events and findings per hour">{grid}{"".join(bars)}{labels}</svg>'
            '<div class="legend"><span><i class="sw ev"></i>Events</span>'
            '<span><i class="sw fi"></i>Findings</span></div>')


def svg_hbars(rows: Sequence[Tuple[str, int]], cls: str = "b-cat") -> str:
    if not rows:
        return '<p class="muted">Nothing to show.</p>'
    peak = max(v for _, v in rows) or 1
    row_h, w, label_w = 28, 520, 190
    h = row_h * len(rows) + 4
    out = []
    for i, (label, val) in enumerate(rows):
        y = i * row_h + 4
        bw = (w - label_w - 50) * val / peak
        out.append(
            f'<text class="lbl" x="{label_w - 8}" y="{y + 15}" text-anchor="end">{esc(label[:28])}</text>'
            f'<rect class="{cls}" x="{label_w}" y="{y + 3}" width="{max(bw, 2):.1f}" height="16" rx="3"/>'
            f'<text class="val" x="{label_w + bw + 6:.1f}" y="{y + 15}">{val}</text>')
    return f'<svg viewBox="0 0 {w} {h}" class="chart hb">{"".join(out)}</svg>'


def _sev_badge(level: str) -> str:
    return f'<span class="badge {esc(level.lower())}">{esc(level)}</span>'


def generate_html(report: Report, path: str, max_findings: int = 2000) -> None:
    d = report
    sev_cards = "".join(
        f'<div class="sev {s.lower()}"><b>{d.severity_counts.get(s, 0)}</b>{s}</div>'
        for s in SEV_ORDER)
    files = "".join(f'<li><code>{esc(f["path"])}</code> &middot; {esc(f["format"])} &middot; '
                    f'{f["parsed"]}/{f["lines"]} lines</li>' for f in d.files)
    notes = "".join(f'<li>{esc(n)}</li>' for n in (d.geo_note, d.abuse_note) if n)
    if d.unparsed:
        notes += f'<li>{d.unparsed} lines did not match the format.</li>'

    ip_rows = []
    for p in d.flagged:
        abuse = "-" if p.info.abuse_score is None else f"{p.info.abuse_score}%"
        rules = ", ".join(f"{esc(k)} &times;{v}" for k, v in p.rule_counts.most_common())
        paths = "".join(f"<li><code>{esc(pp)}</code> &times;{c}</li>"
                        for pp, c in p.paths.most_common(8))
        uas = "".join(f"<li>{esc(u)}</li>" for u in sorted(p.user_agents)[:5])
        users = ", ".join(esc(u) for u in sorted(p.users)[:15])
        statuses = ", ".join(f"{k}: {v}" for k, v in sorted(p.statuses.items()))
        span = ""
        if p.first_seen:
            span = f"{p.first_seen:%Y-%m-%d %H:%M:%S} &rarr; {p.last_seen:%Y-%m-%d %H:%M:%S}"
        ip_rows.append(f"""
<tr class="ip-row" data-level="{esc(p.level)}">
  <td><button class="exp" aria-expanded="false">&#9656;</button><code>{esc(p.ip)}</code></td>
  <td><div class="meter"><span style="width:{p.score:.0f}%" class="{esc(p.level.lower())}"></span></div>
      <span class="num">{p.score:.0f}</span></td>
  <td>{_sev_badge(p.level)}</td>
  <td>{esc(p.info.country)}</td><td class="num">{p.requests}</td><td class="num">{abuse}</td>
  <td>{esc(", ".join(p.categories))}</td>
</tr>
<tr class="detail" hidden><td colspan="7"><div class="dgrid">
  <div><h4>Rules hit</h4><p>{rules}</p><h4>Seen</h4><p>{span or "-"}</p>
       <h4>Status codes</h4><p>{statuses or "-"}</p>
       {f"<h4>Usernames tried</h4><p>{users}</p>" if users else ""}
       {f"<h4>ISP</h4><p>{esc(p.info.isp)}</p>" if p.info.isp else ""}</div>
  <div><h4>Top paths</h4><ul>{paths or "<li>-</li>"}</ul>
       <h4>User-agents</h4><ul>{uas or "<li>-</li>"}</ul></div>
</div></td></tr>""")

    sev_rank = {s: i for i, s in enumerate(SEV_ORDER)}
    fs = sorted(d.findings, key=lambda f: (sev_rank.get(f.severity.label, 9),
                                           f.event.timestamp.isoformat() if f.event and f.event.timestamp else ""))
    f_rows = []
    for f in fs[:max_findings]:
        ev = f.event
        f_rows.append(
            f'<tr data-sev="{esc(f.severity.label)}"><td>{_sev_badge(f.severity.label)}</td>'
            f'<td class="nowrap">{esc(ev.timestamp.strftime("%Y-%m-%d %H:%M:%S") if ev and ev.timestamp else "-")}</td>'
            f'<td><code>{esc(f.ip)}</code></td><td>{esc(f.category)}</td>'
            f'<td>{esc(f.description)}</td>'
            f'<td class="ev"><code>{esc((ev.path if ev and ev.path else ev.message if ev else "") or "")[:160]}</code></td>'
            f'<td class="num">{esc(ev.status if ev and ev.status is not None else "")}</td></tr>')
    trunc = (f'<p class="muted">Showing {max_findings} of {len(fs)} findings. '
             f'Use JSON/CSV export for the full list.</p>') if len(fs) > max_findings else ""

    top_ips = [(p.ip, round(p.score)) for p in d.flagged[:10]]
    status_rows = sorted(((str(k), v) for k, v in d.status_counts.items()),
                         key=lambda kv: -kv[1])[:10]
    span = (f"{d.first_ts:%Y-%m-%d %H:%M} &rarr; {d.last_ts:%Y-%m-%d %H:%M}"
            if d.first_ts and d.last_ts else "no timestamps")

    page = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:">
<title>ProtectRequest Report</title>
<style>
:root{{--bg:#f6f7f9;--card:#fff;--ink:#14171c;--muted:#5d6673;--line:#e2e5ea;--accent:#2f5bea;
--crit:#9b1c6c;--high:#c4321f;--med:#b26b00;--low:#2577a8;--info:#6b7280;--ev:#c9d3e6;--fi:#c4321f}}
@media (prefers-color-scheme:dark){{:root{{--bg:#0f1115;--card:#171a20;--ink:#e7e9ee;--muted:#9aa3b2;
--line:#2a2f38;--accent:#7c9cff;--crit:#e05aa8;--high:#ff6b57;--med:#f0a83a;--low:#5bb5ea;--info:#9aa3b2;--ev:#2f3a52;--fi:#ff6b57}}}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--ink);font:14px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}}
main{{max-width:1180px;margin:0 auto;padding:28px 16px 60px}}
header{{display:flex;justify-content:space-between;align-items:flex-end;gap:16px;flex-wrap:wrap;margin-bottom:22px}}
h1{{margin:0;font-size:26px;letter-spacing:-.02em}}h1 span{{color:var(--accent)}}
h2{{font-size:16px;margin:0 0 12px}}h4{{margin:10px 0 4px;font-size:12px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted)}}
.muted{{color:var(--muted)}}code{{font:12.5px ui-monospace,SFMono-Regular,Consolas,monospace;word-break:break-all}}
.card{{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:18px;margin-bottom:16px}}
.kpis{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:16px}}
.kpi{{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px}}
.kpi b{{display:block;font-size:24px;font-variant-numeric:tabular-nums}}.kpi span{{color:var(--muted);font-size:12px}}
.sevs{{display:grid;grid-template-columns:repeat(5,1fr);gap:8px}}
.sev{{border-radius:10px;padding:10px;text-align:center;border:1px solid var(--line);font-size:12px;color:var(--muted)}}
.sev b{{display:block;font-size:20px;color:var(--ink)}}
.sev.critical b{{color:var(--crit)}}.sev.high b{{color:var(--high)}}.sev.medium b{{color:var(--med)}}.sev.low b{{color:var(--low)}}
.two{{display:grid;grid-template-columns:1fr 1fr;gap:16px}}@media(max-width:820px){{.two{{grid-template-columns:1fr}}.sevs{{grid-template-columns:repeat(3,1fr)}}}}
.chart{{width:100%;height:auto}}.b-ev{{fill:var(--ev)}}.b-fi{{fill:var(--fi)}}.b-cat{{fill:var(--accent)}}.b-ip{{fill:var(--high)}}.b-st{{fill:var(--low)}}
.grid{{stroke:var(--line)}}.axis,.val{{fill:var(--muted);font-size:11px}}.lbl{{fill:var(--ink);font-size:12px}}
.legend{{display:flex;gap:16px;font-size:12px;color:var(--muted)}}.sw{{display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:6px}}
.sw.ev{{background:var(--ev)}}.sw.fi{{background:var(--fi)}}
.tablewrap{{overflow-x:auto}}.tablewrap.tall{{max-height:640px;overflow-y:auto}}.tall thead th{{position:sticky;top:0;background:var(--card)}}
.ip-row td:nth-child(-n+2),#ft td:nth-child(3){{white-space:nowrap}}table{{width:100%;border-collapse:collapse}}
th{{text-align:left;font-size:12px;color:var(--muted);font-weight:600;border-bottom:1px solid var(--line);padding:8px}}
td{{border-bottom:1px solid var(--line);padding:8px;vertical-align:top}}.num{{text-align:right;font-variant-numeric:tabular-nums}}
.nowrap{{white-space:nowrap}}td.ev{{max-width:340px}}
.badge{{display:inline-block;padding:1px 8px;border-radius:99px;font-size:11.5px;font-weight:600;border:1px solid currentColor}}
.badge.critical{{color:var(--crit)}}.badge.high{{color:var(--high)}}.badge.medium{{color:var(--med)}}.badge.low{{color:var(--low)}}.badge.info,.badge.none{{color:var(--info)}}
.meter{{display:inline-block;width:70px;height:6px;border-radius:3px;background:var(--line);vertical-align:middle;margin-right:6px;overflow:hidden}}
.meter span{{display:block;height:100%}}.meter .critical{{background:var(--crit)}}.meter .high{{background:var(--high)}}.meter .medium{{background:var(--med)}}.meter .low{{background:var(--low)}}
.exp{{background:none;border:0;color:var(--muted);cursor:pointer;font-size:13px;width:22px;padding:0}}
.exp[aria-expanded=true]{{transform:rotate(90deg)}}
.dgrid{{display:grid;grid-template-columns:1fr 1fr;gap:20px;padding:4px 8px 8px 30px}}.dgrid ul{{margin:0;padding-left:18px}}
.toolbar{{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:10px}}
.toolbar input,.toolbar select{{background:var(--bg);color:var(--ink);border:1px solid var(--line);border-radius:8px;padding:7px 10px;font:inherit}}
.toolbar input{{flex:1;min-width:180px}}ul.files{{margin:0;padding-left:18px}}
footer{{color:var(--muted);font-size:12px;text-align:center;margin-top:30px}}
</style></head><body><main>
<header><div><h1>Protect<span>Request</span> report</h1>
<div class="muted">Generated {d.generated:%Y-%m-%d %H:%M:%S} &middot; log window {span}</div></div></header>

<div class="kpis">
 <div class="kpi"><b>{d.parsed:,}</b><span>events analysed</span></div>
 <div class="kpi"><b>{d.unique_ips:,}</b><span>unique IPs</span></div>
 <div class="kpi"><b>{len(d.flagged):,}</b><span>flagged IPs</span></div>
 <div class="kpi"><b>{len(d.findings):,}</b><span>findings</span></div>
 <div class="kpi"><b>{_fmt_bytes(d.total_bytes)}</b><span>data served</span></div>
</div>

<div class="card"><h2>Findings by severity</h2><div class="sevs">{sev_cards}</div></div>
<div class="card"><h2>Activity over time</h2>{svg_timeline(d.timeline)}</div>
<div class="two">
 <div class="card"><h2>Attack categories</h2>{svg_hbars(d.category_counts.most_common(10))}</div>
 <div class="card"><h2>Top risky IPs (score)</h2>{svg_hbars(top_ips, "b-ip")}</div>
</div>

<div class="card"><h2>Flagged IPs</h2>
<div class="toolbar"><input id="ipq" placeholder="Filter IPs, country, category..." aria-label="Filter IPs">
<select id="ipl" aria-label="Level"><option value="">All levels</option><option>Critical</option><option>High</option><option>Medium</option><option>Low</option></select></div>
<div class="tablewrap"><table id="ipt"><thead><tr><th>IP</th><th>Risk</th><th>Level</th><th>Country</th><th class="num">Requests</th><th class="num">AbuseIPDB</th><th>Categories</th></tr></thead>
<tbody>{"".join(ip_rows) or '<tr><td colspan="7" class="muted">No suspicious IPs.</td></tr>'}</tbody></table></div></div>

<div class="card"><h2>All findings</h2>
<div class="toolbar"><input id="fq" placeholder="Search findings..." aria-label="Search findings">
<select id="fs" aria-label="Severity"><option value="">All severities</option>{"".join(f"<option>{s}</option>" for s in SEV_ORDER)}</select></div>
<div class="tablewrap tall"><table id="ft"><thead><tr><th>Severity</th><th>Time</th><th>IP</th><th>Category</th><th>Description</th><th>Request / message</th><th class="num">Status</th></tr></thead>
<tbody>{"".join(f_rows) or '<tr><td colspan="7" class="muted">No findings.</td></tr>'}</tbody></table></div>{trunc}</div>

<div class="two">
 <div class="card"><h2>Status codes</h2>{svg_hbars(status_rows, "b-st")}</div>
 <div class="card"><h2>Inputs</h2><ul class="files">{files}</ul>
 {f'<h4>Notes</h4><ul class="files">{notes}</ul>' if notes else ''}</div>
</div>
<footer>ProtectRequest v{esc(__version__)} &middot; Scores are heuristics &mdash; verify before blocking.</footer>
</main>
<script>
document.querySelectorAll('#ipt .exp').forEach(b=>b.addEventListener('click',()=>{{
 const r=b.closest('tr').nextElementSibling, o=b.getAttribute('aria-expanded')==='true';
 b.setAttribute('aria-expanded',String(!o)); r.hidden=o;}}));
function filt(inp,sel,rows,attr){{const q=inp.value.toLowerCase(),s=sel.value;
 rows().forEach(r=>{{const ok=(!q||r.textContent.toLowerCase().includes(q))&&(!s||r.dataset[attr]===s);
 r.style.display=ok?'':'none'; if(!ok&&r.nextElementSibling&&r.nextElementSibling.classList.contains('detail')) r.nextElementSibling.hidden=true;}});}}
const ipq=document.getElementById('ipq'),ipl=document.getElementById('ipl'),fq=document.getElementById('fq'),fsel=document.getElementById('fs');
const ipr=()=>document.querySelectorAll('#ipt tr.ip-row'),fr=()=>document.querySelectorAll('#ft tbody tr[data-sev]');
[ipq,ipl].forEach(e=>e.addEventListener('input',()=>filt(ipq,ipl,ipr,'level')));
[fq,fsel].forEach(e=>e.addEventListener('input',()=>filt(fq,fsel,fr,'sev')));
</script></body></html>"""
    Path(path).write_text(page, encoding="utf-8")
