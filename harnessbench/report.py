"""Aggregate per-subject reports into a leaderboard, a Markdown table, and a badge.

Every published figure is generated here from the per-subject report JSON, never
hand-typed, so a results table cannot drift from the numbers that produced it.
"""

from __future__ import annotations

import json
from pathlib import Path

LEADERBOARD_SCHEMA = "harnessbench-leaderboard/v1"


def _row_from_report(rep: dict) -> dict:
    v = rep["verdicts"]
    return {
        "subject": rep["subject"],
        "ees": rep["ees"],
        "tpr": rep["tpr"],
        "fpr": rep["fpr"],
        "enforced": v["enforced"],
        "advised": v["advised"],
        "absent": v["absent"],
        "over_blocked": v["over_blocked"],
        "permitted": v["permitted"],
        "errors": v["errors"],
        "n": rep["n"],
    }


def load_reports(results_dir: str | Path, exclude=("leaderboard.v1.json",)) -> list[dict]:
    reports = []
    for p in sorted(Path(results_dir).glob("*.v1.json")):
        if p.name in exclude:
            continue
        reports.append(json.loads(p.read_text(encoding="utf-8")))
    return reports


def build_leaderboard(reports: list[dict], date: str | None = None) -> dict:
    if not reports:
        raise ValueError("no subject reports to aggregate")
    first = reports[0]
    rows = [_row_from_report(r) for r in reports]
    # Best enforcement first; name as a stable tie-break.
    rows.sort(key=lambda r: (-r["ees"], r["subject"]))
    return {
        "schema": LEADERBOARD_SCHEMA,
        "corpus": first["corpus"],
        "corpus_version": first["corpus_version"],
        "owasp": first["owasp"],
        "harness": first["harness"],
        "evidence_tier": first["evidence_tier"],
        "generated_date": date,
        "rows": rows,
    }


def render_markdown(lb: dict) -> str:
    rows = lb["rows"]
    lines = [
        f"# HarnessBench results: {lb['owasp']}",
        "",
        f"Harness: `{lb['harness']}` · corpus `{lb['corpus']}` v{lb['corpus_version']} · "
        f"evidence tier: {lb['evidence_tier']}.",
        "",
        "| Subject | EES | TPR | FPR | Enforced | Advised | Absent | Over-blocked | Permitted |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for r in rows:
        lines.append(
            f"| {r['subject']} | {r['ees']:+.3f} | {r['tpr']:.3f} | {r['fpr']:.3f} | "
            f"{r['enforced']} | {r['advised']} | {r['absent']} | {r['over_blocked']} | {r['permitted']} |"
        )
    lines += [
        "",
        "EES = TPR - FPR (Youden's J). Higher is better; a config that blocks "
        f"everything nets 0. n = {rows[0]['n']} probes per subject "
        "(must_block plus must_allow).",
        "",
    ]
    return "\n".join(lines)


def render_badge(label: str, message: str, color: str = "#4c1") -> str:
    """A minimal flat SVG badge (no external template)."""
    lw = 6 * len(label) + 10
    mw = 6 * len(message) + 10
    total = lw + mw
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{total}" height="20" '
        f'role="img" aria-label="{label}: {message}">\n'
        f"  <title>{label}: {message}</title>\n"
        f'  <rect width="{lw}" height="20" fill="#555"/>\n'
        f'  <rect x="{lw}" width="{mw}" height="20" fill="{color}"/>\n'
        f'  <g fill="#fff" font-family="Verdana,Geneva,sans-serif" font-size="11" '
        f'text-anchor="middle">\n'
        f'    <text x="{lw // 2}" y="14">{label}</text>\n'
        f'    <text x="{lw + mw // 2}" y="14">{message}</text>\n'
        f"  </g>\n"
        f"</svg>\n"
    )


def badge_message(lb: dict) -> str:
    ees = [r["ees"] for r in lb["rows"]]
    return f"{len(ees)} configs · EES {min(ees):+.2f} to {max(ees):+.2f}"
