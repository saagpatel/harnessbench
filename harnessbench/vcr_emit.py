"""Optional: emit HarnessBench results as Verified-Check Records (VCR v0) via vcr-core.

This is additive. HarnessBench's native results, scoring, and leaderboard are unchanged; this
module lets a run ALSO produce VCR rows so HarnessBench shares the program's record format with
The Enforcement Gap (N2). It imports the shared `vcr-core` spine (pure-stdlib for build/score),
so it does not change HarnessBench's zero-third-party-dependency posture at its core.

The mapping preserves HarnessBench's verdict distinctions on the shared vocabulary:
  ENFORCED -> enforced/pass    ADVISED -> advisory/fail    ABSENT -> absent/fail
  OVER_BLOCKED -> enforced/over_blocked   PERMITTED -> pass   MODEL_DECLINED -> declined
"""

from __future__ import annotations

import json

from vcr_core import Verdict, build_record, sha256_hex

from .models import Corpus, Enforcement, ProbeResult, SubjectConfig

_RESULT = {
    Enforcement.ENFORCED: "pass",
    Enforcement.ADVISED: "fail",
    Enforcement.ABSENT: "fail",
    Enforcement.OVER_BLOCKED: "over_blocked",
    Enforcement.PERMITTED: "pass",
    Enforcement.MODEL_DECLINED: "declined",
    Enforcement.ERROR: "error",
}
_ENFORCED = {
    Enforcement.ENFORCED: "enforced",
    Enforcement.OVER_BLOCKED: "enforced",
    Enforcement.ADVISED: "advisory",
    Enforcement.MODEL_DECLINED: "advisory",
    Enforcement.ABSENT: "absent",
}


def subject_digest(subject: SubjectConfig) -> str:
    """A stable identity for the config under test (name + wired hook argv)."""
    desc = json.dumps({"name": subject.name, "hooks": subject.hook_commands}, sort_keys=True)
    return sha256_hex(desc.encode())


def enforced_class(subject: SubjectConfig, verdict: Enforcement) -> str | None:
    if verdict in _ENFORCED:
        return _ENFORCED[verdict]
    if verdict is Enforcement.PERMITTED:
        # A correctly-permitted benign probe: the config's class is enforced if it wires a
        # mechanism, else absent.
        return "enforced" if subject.hook_commands else "absent"
    return None  # ERROR


def to_vcr_row(
    subject: SubjectConfig,
    polarity: str,
    result: ProbeResult,
    *,
    corpus_version: str,
    ran_at: str,
    runner: str = "harnessbench-offline@v1",
) -> dict:
    sd = subject_digest(subject)
    return build_record(
        subject_kind="harness_config",
        subject_name=f"claude-code/{subject.name}",
        subject_digest=sd,
        subject_media_type="application/x-claude-subject",
        check_id=f"asi05/{result.probe_id}",
        check_category="guard",
        check_version=corpus_version,
        config_ref_digest=sd,
        polarity=polarity,
        verdict=Verdict(
            result=_RESULT[result.verdict], enforced=enforced_class(subject, result.verdict)
        ),
        evidence_grade="A",  # offline, deterministic, re-executable (reproduce.sh)
        evidence_kind="hook-verdict-digest",
        evidence_digest=sha256_hex((result.reason or result.verdict.value).encode()),
        ran_at=ran_at,
        env_digest=sd,
        runner=runner,
    )


def to_vcr_rows(
    subject: SubjectConfig,
    corpus: Corpus,
    results: list[ProbeResult],
    *,
    ran_at: str,
    runner: str = "harnessbench-offline@v1",
) -> list[dict]:
    polarity = {p.id: p.polarity.value for p in corpus.probes}
    return [
        to_vcr_row(
            subject,
            polarity[r.probe_id],
            r,
            corpus_version=corpus.version,
            ran_at=ran_at,
            runner=runner,
        )
        for r in results
        if r.probe_id in polarity
    ]
