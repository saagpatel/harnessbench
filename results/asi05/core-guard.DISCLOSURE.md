# core-guard.v1.json — disclosure

This report measures the operator's real `core-guard.py` PreToolUse guard against the
`asi05-destructive-execution` corpus. It exists to back a CheckSeal `enforced_proof`
(the `config_sha256` cryptographic binding), **not** as a comparative leaderboard entry,
and is intentionally not added to `leaderboard.v1.json`.

Read the `ees: 1.0` with three caveats:

1. **Measurement circularity.** The corpus is derived from `core-guard`'s own test suite
   (`core-guard-test.py`). Probing `core-guard` with it therefore measures
   *conformance to its own specification*, not independent robustness. The clean
   must-allow pass (22/22 permitted, 0 over-blocked) is still a real property: the guard
   does not over-block. But `EES 1.0` here is not an earned, independent ceiling the way an
   adversary-independent subject's score would be.

2. **What `config_sha256` covers.** The hash `0e7a1c…` is over a minimal subject:
   `settings.json` (wiring `core-guard.py` as a `PreToolUse` Bash guard) plus
   `hooks/core-guard.py`, whose bytes are **byte-identical to the operator's production
   guard**. The enforcement logic (the 791-line `core-guard.py`) is the real mechanism;
   the wrapper `settings.json` is a faithful minimal representation.

3. **Private-by-design; verification is hash-match.** `core-guard.py`'s bytes are **not**
   published (the guard is deliberately kept out of public history). Only its hash and the
   verdict appear here. A public verifier can confirm a seal cites the same
   `config_sha256` this report measured (hash continuity); a full manifest recompute
   requires the operator's private config. This is the intended private-safe boundary.
