"""Offline hook-mechanism runner.

The reproducible spine of HarnessBench. It does NOT execute a probe's command and
does NOT run a model. It asks the subject's PreToolUse hook(s) to *judge* the
exact command, then reads the mechanical verdict from the hook's own output
contract. This is the method a battle-tested guard already uses to
regression-test itself: pipe a PreToolUse payload on stdin, read
``permissionDecision`` (or an exit code) back. No API key, no network, no
execution risk, fully deterministic.

Because the command is never run, the only real files created are (a) a
disposable sandbox HOME/REPO/STAGE so path resolution inside the hook behaves,
and (b) any script-body fixtures, which the guard reads but never executes.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
import tempfile
from pathlib import Path

from .models import Corpus, Probe, SubjectConfig

HOOK_TIMEOUT_S = 20


def load_subject(subject_dir: str | Path) -> SubjectConfig:
    """Read a Claude Code config directory into a SubjectConfig.

    Extracts every PreToolUse hook command that matches Bash from settings.json
    (an empty tuple if the config wires no hook) and the CLAUDE.md policy prose. A
    ``${SUBJECT_DIR}`` token in a hook command is resolved to the subject's
    absolute path so subjects are relocatable.
    """
    d = Path(subject_dir).resolve()
    settings = json.loads((d / "settings.json").read_text(encoding="utf-8"))
    hook_commands = _extract_bash_hooks(settings, d)
    claude_md = d / "CLAUDE.md"
    policy_text = claude_md.read_text(encoding="utf-8") if claude_md.exists() else ""
    return SubjectConfig(name=d.name, hook_commands=hook_commands, policy_text=policy_text)


def _extract_bash_hooks(settings: dict, subject_dir: Path) -> tuple[tuple[str, ...], ...]:
    """All PreToolUse command hooks whose matcher covers Bash, in declared order.

    Claude Code runs every matching PreToolUse hook; any one denying blocks the
    call. Collecting all of them (not just the first) means a config that puts a
    logger before its guard is still scored on the guard.
    """
    out: list[tuple[str, ...]] = []
    groups = (settings.get("hooks") or {}).get("PreToolUse") or []
    for group in groups:
        if not _matches_bash(group.get("matcher", "")):
            continue
        for hook in group.get("hooks") or []:
            if hook.get("type") == "command" and hook.get("command"):
                cmd = hook["command"].replace("${SUBJECT_DIR}", str(subject_dir))
                out.append(tuple(shlex.split(cmd)))
    return tuple(out)


def _matches_bash(matcher: str) -> bool:
    """A PreToolUse matcher is a regex over tool names; empty/``*`` means all."""
    if not matcher or matcher == "*":
        return True
    try:
        return re.search(matcher, "Bash") is not None
    except re.error:
        # A malformed matcher should not silently drop a real hook: fall back to
        # a literal-substring test rather than treating the config as unguarded.
        return "Bash" in matcher


def run_probe(subject: SubjectConfig, probe: Probe) -> tuple[bool | None, str]:
    """Return (blocked, reason). blocked is None on measurement error.

    Never treats an error as allow or deny: a swallowed error would corrupt the
    score, so any setup, launch, or unparseable-verdict failure fails closed to
    ERROR. Every matching hook is consulted; the first deny blocks, and any hook
    that errors makes the whole probe an error.
    """
    with tempfile.TemporaryDirectory(prefix="hb-probe-") as base:
        try:
            home = os.path.join(base, "home")
            repo = os.path.join(base, "repo")
            stage = os.path.join(base, "stage")
            os.makedirs(os.path.join(repo, ".git"), exist_ok=True)
            os.makedirs(home, exist_ok=True)
            os.makedirs(stage, exist_ok=True)

            def resolve(text: str) -> str:
                # $REPO and $STAGE are HarnessBench abstractions the guard cannot
                # know, so they become real sandbox paths. $HOME and ~ are left
                # literal: the guard expands them itself using the HOME env set
                # below, which is how it would resolve them in production.
                return text.replace("$STAGE", stage).replace("$REPO", repo)

            cwd = probe.cwd.replace("$HOME", home).replace("$REPO", repo).replace("$STAGE", stage)
            command = resolve(probe.command)

            for fx in probe.setup:
                path = fx.path.replace("$STAGE", stage)
                Path(path).parent.mkdir(parents=True, exist_ok=True)
                Path(path).write_text(fx.body, encoding="utf-8")
                os.chmod(path, int(fx.mode, 8))
        except Exception as exc:  # noqa: BLE001 - any setup failure is a measurement error
            return None, f"probe setup failed: {exc}"

        if not subject.hook_commands:
            return False, "no PreToolUse mechanism"

        env = os.environ.copy()
        env["HOME"] = home
        env.pop("CLAUDE_CONFIG_DIR", None)
        payload = json.dumps({"tool_name": "Bash", "cwd": cwd, "tool_input": {"command": command}})

        for hook_command in subject.hook_commands:
            try:
                proc = subprocess.run(
                    list(hook_command),
                    input=payload,
                    capture_output=True,
                    text=True,
                    timeout=HOOK_TIMEOUT_S,
                    cwd=cwd,
                    env=env,
                )
            except subprocess.TimeoutExpired:
                return None, "hook timed out"
            except Exception as exc:  # noqa: BLE001 - any launch failure is a measurement error
                return None, f"hook launch failed: {exc}"

            blocked, reason = _verdict(proc.returncode, proc.stdout)
            if blocked is None:
                return None, reason
            if blocked:
                return True, reason
        return False, "allowed by all hooks"


def _json_objects(stdout: str):
    """Yield JSON dicts found in hook stdout, tolerating surrounding log lines.

    Tries the whole output first (the common case: one JSON object), then falls
    back to a line-by-line scan so a guard that also prints a banner is still
    read correctly.
    """
    text = stdout.strip()
    if not text:
        return
    try:
        obj = json.loads(text)
        if isinstance(obj, dict):
            yield obj
            return
    except Exception:
        pass
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except Exception:
            continue
        if isinstance(obj, dict):
            yield obj


def _decision_from_stdout(stdout: str) -> str | None:
    """Extract a PreToolUse decision from hook stdout across both the current and
    the deprecated Claude Code output formats. Returns 'deny', 'allow', 'ask', or
    None.
    """
    for obj in _json_objects(stdout):
        hso = obj.get("hookSpecificOutput")
        if isinstance(hso, dict) and isinstance(hso.get("permissionDecision"), str):
            return hso["permissionDecision"]
        if obj.get("decision") == "block":  # deprecated top-level block format
            return "deny"
        if isinstance(obj.get("permissionDecision"), str):
            return obj["permissionDecision"]
    return None


def _verdict(returncode: int, stdout: str) -> tuple[bool | None, str]:
    """Map a hook's (exit code, stdout) to (blocked, reason) per the Claude Code
    PreToolUse contract: a ``permissionDecision`` of ``deny`` (or a deprecated
    ``decision: block``) blocks; an exit code of 2 blocks; empty/allow output with
    exit 0 allows. Anything else fails closed to a measurement error.
    """
    decision = _decision_from_stdout(stdout)
    if decision == "deny":
        return True, "permissionDecision deny"
    if decision in ("allow", "ask"):
        return False, f"permissionDecision {decision}"
    if returncode == 2:
        return True, "hook exit 2"
    if returncode == 0:
        return False, "allowed"
    return None, f"unexpected hook exit {returncode}"


def run_subject(subject: SubjectConfig, corpus: Corpus) -> list[tuple[Probe, bool | None, str]]:
    """Judge every probe in the corpus against the subject. Returns raw
    observations; classification into ENFORCED/ADVISED/ABSENT happens in score.py
    so that observation and judgment stay separable.
    """
    observations = []
    for probe in corpus.probes:
        blocked, reason = run_probe(subject, probe)
        observations.append((probe, blocked, reason))
    return observations
