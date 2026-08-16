"""Core data types for HarnessBench.

A probe is an action attempt paired with the polarity of the correct outcome:
``must_block`` (the harness should stop it) or ``must_allow`` (the harness should
let it run). Enforcement is always judged on a mechanical observable, never on
model text.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Polarity(str, Enum):
    """The correct outcome for a probe."""

    MUST_BLOCK = "must_block"
    MUST_ALLOW = "must_allow"


class Enforcement(str, Enum):
    """The verdict for a single probe against a single subject config."""

    # A must_block probe that a mechanism actually blocked.
    ENFORCED = "enforced"
    # A must_block probe that was NOT blocked, but the config states a policy
    # against it. Words, not a mechanism.
    ADVISED = "advised"
    # A must_block probe that was NOT blocked and no policy is stated.
    ABSENT = "absent"
    # A must_allow probe that a mechanism wrongly blocked.
    OVER_BLOCKED = "over_blocked"
    # A must_allow probe correctly allowed to run.
    PERMITTED = "permitted"
    # Live layer only: the model refused to attempt the action (no tool call was
    # issued). Never counted as enforcement.
    MODEL_DECLINED = "model_declined"
    # The measurement itself failed. Never silently treated as allow or deny.
    ERROR = "error"


@dataclass(frozen=True)
class FixtureFile:
    """A file the runner materializes before a probe runs.

    ``path`` is written with a ``$STAGE`` placeholder that the runner resolves to
    a disposable temp directory. Used by script-body-indirection probes, where
    the dangerous command lives in a script the harness command launches. The
    offline runner never executes these scripts; the guard under test only reads
    them, so they are inert.
    """

    path: str
    body: str
    mode: str = "0644"


@dataclass(frozen=True)
class Probe:
    """A single action attempt with the correct outcome and its provenance."""

    id: str
    family: str
    polarity: Polarity
    command: str
    # One of the cwd placeholders the runner resolves: ``$HOME``, ``$REPO`` (a
    # temp dir containing a ``.git``), or a ``$STAGE`` path.
    cwd: str
    obfuscation: str | None = None
    # For must_block probes: the policy prose the config would need to state for
    # a non-block to count as ADVISED rather than ABSENT. Always None for
    # must_allow probes.
    stated_policy_source: str | None = None
    provenance: str | None = None
    setup: tuple[FixtureFile, ...] = ()


@dataclass(frozen=True)
class Corpus:
    """A named, versioned set of probes for one OWASP category and harness."""

    name: str
    owasp: str
    harness: str
    version: str
    probes: tuple[Probe, ...]
    notes: str = ""
    # The semantic threat class this corpus proves enforcement against (e.g.
    # "destructive-execution"). A CheckSeal enforced check whose threat class does
    # not match this cannot cite a report from this corpus as its proof.
    threat_class: str = ""


@dataclass(frozen=True)
class SubjectConfig:
    """A harness configuration under test.

    A subject is a real Claude Code config directory: a ``settings.json`` that may
    wire one or more PreToolUse Bash hooks, and an optional ``CLAUDE.md`` carrying
    policy prose. ``hook_commands`` is empty when the config states rules but
    wires no enforcing mechanism (the advisory case); otherwise it holds each
    matching hook's argv, in declared order.
    """

    name: str
    hook_commands: tuple[tuple[str, ...], ...] = ()
    policy_text: str = ""


@dataclass(frozen=True)
class ProbeResult:
    """The observation and verdict for one probe against one subject."""

    probe_id: str
    family: str
    polarity: Polarity
    obfuscation: str | None
    # True = a mechanism blocked it, False = it was allowed, None = measurement
    # error.
    blocked: bool | None
    verdict: Enforcement
    reason: str = ""
