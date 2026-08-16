"""Load and validate a HarnessBench probe corpus."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from .models import Corpus, FixtureFile, Polarity, Probe

# Placeholders the runner resolves to real sandbox paths at execution time.
CWD_PLACEHOLDERS = {"$HOME", "$REPO", "$STAGE"}


def load_corpus(path: str | Path) -> Corpus:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    probes = tuple(_probe(p) for p in data["probes"])
    return Corpus(
        name=data["corpus"],
        owasp=data["owasp"],
        harness=data["harness"],
        version=str(data["version"]),
        notes=data.get("notes", ""),
        threat_class=data.get("threat_class", ""),
        probes=probes,
    )


def _probe(p: dict) -> Probe:
    setup = tuple(
        FixtureFile(path=f["path"], body=f["body"], mode=f.get("mode", "0644"))
        for f in p.get("setup", [])
    )
    return Probe(
        id=p["id"],
        family=p["family"],
        polarity=Polarity(p["polarity"]),
        command=p["command"],
        cwd=p["cwd"],
        obfuscation=p.get("obfuscation"),
        stated_policy_source=p.get("stated_policy_source"),
        provenance=p.get("provenance"),
        setup=setup,
    )


def validate_corpus(corpus: Corpus) -> list[str]:
    """Return coherence problems; an empty list means the corpus is well formed.

    A probe whose polarity contradicts its fields is worse than a missing probe:
    it would silently corrupt a score. These checks fail closed at load time.
    """
    issues: list[str] = []
    seen: set[str] = set()
    for pr in corpus.probes:
        if pr.id in seen:
            issues.append(f"duplicate probe id: {pr.id}")
        seen.add(pr.id)
        if not pr.command.strip():
            issues.append(f"{pr.id}: empty command")
        base = pr.cwd.split("/", 1)[0]
        if base not in CWD_PLACEHOLDERS:
            issues.append(
                f"{pr.id}: cwd must start with one of {sorted(CWD_PLACEHOLDERS)}, got {pr.cwd!r}"
            )
        for fx in pr.setup:
            if not fx.path.startswith("$STAGE"):
                issues.append(f"{pr.id}: fixture path must be under $STAGE, got {fx.path!r}")
        if pr.polarity is Polarity.MUST_BLOCK and not pr.stated_policy_source:
            issues.append(f"{pr.id}: must_block probe needs a stated_policy_source")
        if pr.polarity is Polarity.MUST_ALLOW and pr.stated_policy_source:
            issues.append(f"{pr.id}: must_allow probe must not carry a stated_policy_source")
    return issues


def family_counts(corpus: Corpus) -> Counter:
    return Counter(pr.family for pr in corpus.probes)


def obfuscation_counts(corpus: Corpus) -> Counter:
    return Counter(pr.obfuscation for pr in corpus.probes if pr.obfuscation)


def polarity_counts(corpus: Corpus) -> Counter:
    return Counter(pr.polarity.value for pr in corpus.probes)
