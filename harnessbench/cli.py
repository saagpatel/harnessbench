"""HarnessBench command line: run a subject config against a probe corpus.

    python -m harnessbench run --subject subjects/naive-regex \
        --corpus probes/asi05-destructive-execution.json --out results/asi05/naive-regex.v1.json

Emits a machine-readable report (schema ``harnessbench-report/v1``) and prints a
one-line summary. Offline hook-mechanism tier only; no API key required.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import report
from .corpus import load_corpus, validate_corpus
from .runner_hook import load_subject, run_subject
from .score import ScoreSummary, score_subject

SCHEMA = "harnessbench-report/v1"
EVIDENCE_TIER = "offline-hook-mechanism"


def _report(corpus_name, corpus_version, owasp, summary: ScoreSummary, date: str | None) -> dict:
    return {
        "schema": SCHEMA,
        "subject": summary.subject,
        "harness": "claude-code",
        "corpus": corpus_name,
        "corpus_version": corpus_version,
        "owasp": owasp,
        "evidence_tier": EVIDENCE_TIER,
        "generated_date": date,
        "ees": summary.ees,
        "tpr": summary.tpr,
        "fpr": summary.fpr,
        "confusion": {"tp": summary.tp, "fn": summary.fn, "fp": summary.fp, "tn": summary.tn},
        "verdicts": {
            "enforced": summary.enforced,
            "advised": summary.advised,
            "absent": summary.absent,
            "over_blocked": summary.over_blocked,
            "permitted": summary.permitted,
            "errors": summary.errors,
        },
        "n": summary.n,
        "results": [
            {
                "probe_id": r.probe_id,
                "family": r.family,
                "polarity": r.polarity.value,
                "obfuscation": r.obfuscation,
                "blocked": r.blocked,
                "verdict": r.verdict.value,
            }
            for r in summary.results
        ],
    }


def _run(args: argparse.Namespace) -> int:
    corpus = load_corpus(args.corpus)
    issues = validate_corpus(corpus)
    if issues:
        print("corpus failed validation:", file=sys.stderr)
        for issue in issues:
            print(f"  - {issue}", file=sys.stderr)
        return 2

    subject = load_subject(args.subject)
    observations = run_subject(subject, corpus)
    summary = score_subject(subject.name, subject.policy_text, observations)

    print(
        f"{summary.subject:>20}  EES={summary.ees:+.3f}  "
        f"TPR={summary.tpr:.3f} FPR={summary.fpr:.3f}  "
        f"enforced={summary.enforced} advised={summary.advised} absent={summary.absent} "
        f"over_blocked={summary.over_blocked} permitted={summary.permitted} errors={summary.errors}"
    )

    if args.out:
        report = _report(corpus.name, corpus.version, corpus.owasp, summary, args.date)
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(f"wrote {out}")

    return 1 if summary.errors else 0


def _leaderboard(args: argparse.Namespace) -> int:
    reports = report.load_reports(args.results)
    if not reports:
        print(f"no subject reports found in {args.results}", file=sys.stderr)
        return 2
    lb = report.build_leaderboard(reports, date=args.date)

    if args.out_json:
        p = Path(args.out_json)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(lb, indent=2) + "\n", encoding="utf-8")
    if args.out_md:
        p = Path(args.out_md)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(report.render_markdown(lb), encoding="utf-8")
    if args.out_badge:
        p = Path(args.out_badge)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(
            report.render_badge("harnessbench asi05", report.badge_message(lb)), encoding="utf-8"
        )

    print(report.render_markdown(lb))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="harnessbench")
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="run a subject config against a probe corpus")
    run.add_argument("--subject", required=True, help="path to a subject config directory")
    run.add_argument("--corpus", required=True, help="path to a probe corpus JSON")
    run.add_argument("--out", help="write the machine-readable report to this path")
    run.add_argument("--date", help="stamp the report with this YYYY-MM-DD (optional)")
    run.set_defaults(func=_run)

    lb = sub.add_parser("leaderboard", help="aggregate subject reports into a leaderboard")
    lb.add_argument("--results", required=True, help="directory of per-subject report JSONs")
    lb.add_argument("--out-json", help="write the leaderboard JSON here")
    lb.add_argument("--out-md", help="write the Markdown results table here")
    lb.add_argument("--out-badge", help="write the SVG badge here")
    lb.add_argument("--date", help="stamp the leaderboard with this YYYY-MM-DD (optional)")
    lb.set_defaults(func=_leaderboard)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
