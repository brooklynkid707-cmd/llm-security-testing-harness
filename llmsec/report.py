"""Reporting: console table, JSON, Markdown and a self-contained HTML report.

Reports map every category to its OWASP LLM Top 10 remediation and the MITRE
ATLAS technique ids, so a reader can act on the results without the harness.
"""

from __future__ import annotations

import html
import json
from pathlib import Path

from llmsec.mappings import ATLAS, OWASP, OWASP_TO_ATLAS, atlas_label
from llmsec.models import CATEGORY_TITLES, ScanResult

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def risk_band(score: float) -> str:
    if score >= 75:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "NONE"


# --------------------------------------------------------------------- console
def console_report(scan: ScanResult, show_cases: int = 12) -> str:
    """Human-readable summary for stdout."""
    lines: list[str] = []
    lines.append(f"llmsec {scan.harness_version} - target={scan.target}  ({scan.started_at})")
    lines.append(
        f"cases={scan.total}  succeeded={scan.successes}  "
        f"ASR={scan.asr * 100:.1f}%  risk={scan.risk_score:.1f}/100 [{risk_band(scan.risk_score)}]  "
        f"time={scan.duration_s:.2f}s"
    )
    lines.append("")
    lines.append(f"{'CATEGORY':<8}  {'TITLE':<30}  {'CASES':>5}  {'HIT':>4}  {'ASR':>7}")
    lines.append(f"{'-' * 8}  {'-' * 30}  {'-' * 5}  {'-' * 4}  {'-' * 7}")
    for cat in sorted(scan.categories.values(), key=lambda c: c.category):
        lines.append(
            f"{cat.category:<8}  {CATEGORY_TITLES.get(cat.category, cat.category):<30}  "
            f"{cat.total:>5}  {cat.successes:>4}  {cat.asr * 100:>6.1f}%"
        )
    lines.append("")
    hits = sorted(
        (r for r in scan.results if r.verdict.success),
        key=lambda r: (_SEV_ORDER.get(r.case.severity.value, 9), r.case.id),
    )
    lines.append(f"Top findings (attacks that SUCCEEDED, {min(show_cases, len(hits))} of {len(hits)}):")
    lines.append(f"{'SEV':<9} {'ID':<20} {'TECHNIQUE':<22} FINDING")
    lines.append("-" * 92)
    for r in hits[:show_cases]:
        lines.append(
            f"{r.case.severity.value:<9} {r.case.id:<20} {r.case.technique[:22]:<22} {r.case.name[:30]}"
        )
    if len(hits) > show_cases:
        lines.append(f"... {len(hits) - show_cases} more (see JSON/Markdown report)")
    if scan.notes:
        lines.append("")
        for n in scan.notes:
            lines.append(f"[note] {n}")
    return "\n".join(lines)


# ------------------------------------------------------------------------ JSON
def json_report(scan: ScanResult) -> str:
    return json.dumps(scan.as_dict(), indent=2)


# -------------------------------------------------------------------- Markdown
def _remediation_rows(scan: ScanResult) -> list[str]:
    rows = []
    for cat in sorted(scan.categories.values(), key=lambda c: c.category):
        info = OWASP.get(cat.category, {})
        atlas_ids = " ".join(OWASP_TO_ATLAS.get(cat.category, ()))
        rows.append(
            f"| {cat.category} {info.get('title', '')} | {cat.successes}/{cat.total} "
            f"({cat.asr * 100:.0f}%) | {atlas_ids} | {info.get('remediation', '')} |"
        )
    return rows


def markdown_report(scan: ScanResult) -> str:
    md: list[str] = []
    md.append(f"# llmsec report - `{scan.target}`")
    md.append("")
    md.append(f"- Harness version: `{scan.harness_version}`")
    md.append(f"- Started: `{scan.started_at}`  (duration {scan.duration_s:.2f}s)")
    md.append(f"- Cases: **{scan.total}**  Succeeded: **{scan.successes}**  "
              f"ASR: **{scan.asr * 100:.1f}%**")
    md.append(f"- Severity-weighted risk score: **{scan.risk_score:.1f}/100** ({risk_band(scan.risk_score)})")
    md.append("")
    md.append("## Attack success rate by OWASP LLM category")
    md.append("")
    md.append("| Category | Title | Cases | Succeeded | ASR |")
    md.append("|---|---|---:|---:|---:|")
    for cat in sorted(scan.categories.values(), key=lambda c: c.category):
        md.append(
            f"| {cat.category} | {CATEGORY_TITLES.get(cat.category, cat.category)} | "
            f"{cat.total} | {cat.successes} | {cat.asr * 100:.0f}% |"
        )
    md.append("")
    md.append("## Remediation guidance (OWASP LLM Top 10 + MITRE ATLAS)")
    md.append("")
    md.append("| Category | ASR | MITRE ATLAS | Remediation |")
    md.append("|---|---|---|---|")
    md.extend(_remediation_rows(scan))
    md.append("")
    md.append("## Findings (successful attacks)")
    md.append("")
    md.append("| Severity | ID | Category | Technique | ATLAS | Case |")
    md.append("|---|---|---|---|---|---|")
    hits = sorted(
        (r for r in scan.results if r.verdict.success),
        key=lambda r: (_SEV_ORDER.get(r.case.severity.value, 9), r.case.id),
    )
    for r in hits:
        md.append(
            f"| {r.case.severity.value} | `{r.case.id}` | {r.case.category} | {r.case.technique} | "
            f"{' '.join(r.case.atlas)} | {r.case.name} |"
        )
    if not hits:
        md.append("| - | - | - | - | - | No attacks succeeded |")
    md.append("")
    md.append("## All cases")
    md.append("")
    md.append("| ID | Result | Judge | Reason |")
    md.append("|---|---|---|---|")
    for r in scan.results:
        res = "SUCCESS" if r.verdict.success else "blocked"
        reason = r.verdict.reason.replace("|", "\\|")[:80]
        md.append(f"| `{r.case.id}` | {res} | {r.verdict.judge} | {reason} |")
    md.append("")
    if scan.notes:
        md.append("## Notes")
        md.append("")
        for n in scan.notes:
            md.append(f"- {n}")
        md.append("")
    md.append("## MITRE ATLAS techniques referenced")
    md.append("")
    referenced = sorted({t for r in scan.results for t in r.case.atlas})
    for tid in referenced:
        info = ATLAS.get(tid, {})
        md.append(f"- `{tid}` {info.get('name', '')} ({info.get('tactic', '')})")
    md.append("")
    return "\n".join(md)


# ------------------------------------------------------------------------ HTML
def html_report(scan: ScanResult) -> str:
    def esc(s: str) -> str:
        return html.escape(str(s))

    band = risk_band(scan.risk_score)
    rows_cat = "\n".join(
        f"<tr><td>{c.category}</td><td>{esc(CATEGORY_TITLES.get(c.category, c.category))}</td>"
        f"<td class='num'>{c.total}</td><td class='num'>{c.successes}</td>"
        f"<td class='num'><div class='bar'><span style='width:{c.asr * 100:.0f}%'></span>"
        f"<em>{c.asr * 100:.0f}%</em></div></td></tr>"
        for c in sorted(scan.categories.values(), key=lambda c: c.category)
    )
    rows_rem = "\n".join(
        f"<tr><td>{c.category} {esc(OWASP.get(c.category, {}).get('title', ''))}</td>"
        f"<td class='num'>{c.asr * 100:.0f}%</td>"
        f"<td>{esc(' '.join(atlas_label(t) for t in OWASP_TO_ATLAS.get(c.category, ())))}</td>"
        f"<td>{esc(OWASP.get(c.category, {}).get('remediation', ''))}</td></tr>"
        for c in sorted(scan.categories.values(), key=lambda c: c.category)
    )
    hits = sorted(
        (r for r in scan.results if r.verdict.success),
        key=lambda r: (_SEV_ORDER.get(r.case.severity.value, 9), r.case.id),
    )
    rows_find = "\n".join(
        f"<tr><td><span class='sev {r.case.severity.value}'>{r.case.severity.value}</span></td>"
        f"<td><code>{esc(r.case.id)}</code></td><td>{esc(r.case.technique)}</td>"
        f"<td>{esc(' '.join(r.case.atlas))}</td><td>{esc(r.case.name)}</td></tr>"
        for r in hits
    ) or "<tr><td colspan='5'>No attacks succeeded.</td></tr>"
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>llmsec report - {esc(scan.target)}</title>
<style>
:root{{--bg:#0f1420;--panel:#171e2e;--ink:#e6ebf5;--muted:#9aa7bd;--line:#273149;--accent:#4da3ff;
--crit:#ff5c6c;--high:#ff9f43;--med:#ffd166;--low:#4dd4ac;}}
*{{box-sizing:border-box}}
body{{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;padding:24px;}}
h1{{font-size:22px;margin:0 0 4px}} h2{{font-size:17px;margin:28px 0 10px;color:var(--accent)}}
.sub{{color:var(--muted);font-size:13px}}
.cards{{display:flex;flex-wrap:wrap;gap:12px;margin:18px 0}}
.card{{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px 18px;min-width:150px}}
.card .big{{font-size:26px;font-weight:700}}
.card .lbl{{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.04em}}
.badge{{display:inline-block;padding:3px 10px;border-radius:999px;font-weight:700;font-size:12px}}
.badge.CRITICAL{{background:var(--crit);color:#2a0008}} .badge.HIGH{{background:var(--high);color:#3a1f00}}
.badge.MEDIUM{{background:var(--med);color:#3a3000}} .badge.LOW{{background:var(--low);color:#003026}}
.badge.NONE{{background:#3a4660;color:#cdd6ea}}
table{{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line);border-radius:10px;overflow:hidden;margin-bottom:8px}}
th,td{{text-align:left;padding:9px 12px;border-bottom:1px solid var(--line);vertical-align:top;font-size:13px}}
th{{background:#1d2740;color:var(--muted);text-transform:uppercase;font-size:11px;letter-spacing:.04em}}
td.num{{text-align:right;white-space:nowrap}}
.bar{{position:relative;background:#223;border-radius:6px;height:18px;min-width:120px}}
.bar span{{position:absolute;left:0;top:0;bottom:0;background:linear-gradient(90deg,#4da3ff,#ff5c6c);border-radius:6px}}
.bar em{{position:relative;font-style:normal;font-size:11px;padding-left:6px;line-height:18px}}
code{{background:#0c1120;padding:1px 5px;border-radius:4px;font-size:12px}}
.sev{{padding:2px 8px;border-radius:999px;font-size:11px;font-weight:700;text-transform:uppercase}}
.sev.critical{{background:var(--crit);color:#2a0008}} .sev.high{{background:var(--high);color:#3a1f00}}
.sev.medium{{background:var(--med);color:#3a3000}} .sev.low{{background:var(--low);color:#003026}}
footer{{color:var(--muted);font-size:12px;margin-top:28px}}
</style></head><body>
<h1>LLM Security Testing Harness - report</h1>
<div class="sub">Target <code>{esc(scan.target)}</code> &middot; {esc(scan.started_at)} &middot; harness {esc(scan.harness_version)} &middot; authorized testing only</div>
<div class="cards">
  <div class="card"><div class="lbl">Cases</div><div class="big">{scan.total}</div></div>
  <div class="card"><div class="lbl">Succeeded</div><div class="big">{scan.successes}</div></div>
  <div class="card"><div class="lbl">Attack success rate</div><div class="big">{scan.asr * 100:.1f}%</div></div>
  <div class="card"><div class="lbl">Risk score</div><div class="big">{scan.risk_score:.0f}<span style="font-size:14px">/100</span></div>
    <div><span class="badge {band}">{band}</span></div></div>
</div>
<h2>Attack success rate by OWASP LLM category</h2>
<table><thead><tr><th>Category</th><th>Title</th><th>Cases</th><th>Hit</th><th>ASR</th></tr></thead>
<tbody>{rows_cat}</tbody></table>
<h2>Remediation (OWASP LLM Top 10 &amp; MITRE ATLAS)</h2>
<table><thead><tr><th>Category</th><th>ASR</th><th>MITRE ATLAS</th><th>Remediation</th></tr></thead>
<tbody>{rows_rem}</tbody></table>
<h2>Findings (successful attacks)</h2>
<table><thead><tr><th>Severity</th><th>ID</th><th>Technique</th><th>ATLAS</th><th>Case</th></tr></thead>
<tbody>{rows_find}</tbody></table>
<footer>Generated by llmsec. All targets and data are synthetic; goals are benign and measurable. See SCOPE.md.</footer>
</body></html>"""


# ----------------------------------------------------------------- file output
def write_reports(scan: ScanResult, out_dir: Path, stem: str | None = None) -> dict[str, Path]:
    """Write JSON + Markdown + HTML into ``out_dir``; return the paths."""
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = scan.started_at.replace(":", "").replace("-", "").replace("+0000", "").replace("T", "-")
    stem = stem or f"scan-{scan.target}-{ts}"
    paths = {
        "json": out_dir / f"{stem}.json",
        "md": out_dir / f"{stem}.md",
        "html": out_dir / f"{stem}.html",
    }
    paths["json"].write_text(json_report(scan), encoding="utf-8")
    paths["md"].write_text(markdown_report(scan), encoding="utf-8")
    paths["html"].write_text(html_report(scan), encoding="utf-8")
    return paths


def diff_reports(a: dict, b: dict) -> str:
    """Compare two JSON report dicts (``a`` baseline, ``b`` candidate)."""
    lines: list[str] = []
    lines.append(f"diff: {a.get('target')} ({a.get('asr', 0) * 100:.1f}% ASR) -> "
                 f"{b.get('target')} ({b.get('asr', 0) * 100:.1f}% ASR)")
    lines.append(
        f"  overall ASR {a.get('asr', 0) * 100:.1f}% -> {b.get('asr', 0) * 100:.1f}%"
        f"  ({(b.get('asr', 0) - a.get('asr', 0)) * 100:+.1f} pts)"
    )
    lines.append(
        f"  risk score  {a.get('risk_score', 0):.1f} -> {b.get('risk_score', 0):.1f}"
        f"  ({b.get('risk_score', 0) - a.get('risk_score', 0):+.1f})"
    )
    lines.append("")
    lines.append(f"{'CATEGORY':<8}  {'ASR A':>7}  {'ASR B':>7}  {'DELTA':>8}")
    lines.append(f"{'-' * 8}  {'-' * 7}  {'-' * 7}  {'-' * 8}")
    cats = sorted(set(a.get("categories", {})) | set(b.get("categories", {})))
    for c in cats:
        ca = a.get("categories", {}).get(c, {}).get("asr", 0) * 100
        cb = b.get("categories", {}).get(c, {}).get("asr", 0) * 100
        lines.append(f"{c:<8}  {ca:>6.1f}%  {cb:>6.1f}%  {cb - ca:>+7.1f}")
    # Per-case regressions / fixes.
    a_cases = {r["id"]: r["success"] for r in a.get("results", [])}
    b_cases = {r["id"]: r["success"] for r in b.get("results", [])}
    fixed = sorted(i for i in a_cases if a_cases[i] and not b_cases.get(i, False))
    regressed = sorted(i for i in b_cases if b_cases[i] and not a_cases.get(i, False))
    lines.append("")
    lines.append(f"fixed (succeeded in A, blocked in B): {len(fixed)}")
    for i in fixed:
        lines.append(f"  + {i}")
    lines.append(f"regressed (blocked in A, succeeded in B): {len(regressed)}")
    for i in regressed:
        lines.append(f"  - {i}")
    return "\n".join(lines)
