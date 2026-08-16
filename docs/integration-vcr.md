# VCR emission (optional integration with vcr-core / N2)

HarnessBench can additionally emit its results as **Verified-Check Records (VCR v0)** so it
shares one record format with the sibling project [The Enforcement Gap (N2)](../../enforcement-gap).
This is **optional and additive** — native HarnessBench results, EES scoring, and the
leaderboard are unchanged.

## What it does

`harnessbench.vcr_emit.to_vcr_rows(subject, corpus, results, ran_at=...)` maps each
`ProbeResult` onto the shared VCR vocabulary from the `vcr-core` package:

| HarnessBench verdict | VCR `verdict.result` | VCR `verdict.enforced` |
|---|---|---|
| ENFORCED | pass | enforced |
| ADVISED | fail | advisory |
| ABSENT | fail | absent |
| OVER_BLOCKED | over_blocked | enforced |
| PERMITTED | pass | enforced if a hook is wired, else absent |
| MODEL_DECLINED | declined | advisory |

The EES metric is defined once in `vcr_core.score` and matches HarnessBench's `score.py`
formula (TPR − FPR), so both projects score identically.

## Dependency posture

`vcr-core`'s build/score path is **pure-stdlib**, so importing it does not change
HarnessBench's zero-third-party-dependency core. `vcr-core` is declared as the optional `vcr`
extra; only VCR *validation* (not emission) pulls `jsonschema`.

```bash
# install the optional extra (pulls vcr-core from PyPI), then run the emission tests:
pip install -e ".[vcr]"
pytest tests/test_vcr_emit.py
```

## Boundary note

VCR rows emitted here carry only HarnessBench's own subject descriptors (advisory /
naive-regex / semantic-clean-room) and probe ids — never the `hardened-reference` guard body
that the public branch deliberately keeps out of history.
