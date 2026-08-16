#!/usr/bin/env bash
# Reproduce the HarnessBench ASI05 offline results from scratch.
#
# Deterministic and model-free: no API key, no network, nothing is executed --
# each probe is only judged by the subject's own hook. Anyone can run this and
# get byte-identical results, which is what makes the leaderboard contestable
# with evidence rather than opinion.
set -euo pipefail
cd "$(dirname "$0")/.."

CORPUS="probes/asi05-destructive-execution.json"
RESULTS="results/asi05"

for s in advisory naive-regex semantic-clean-room; do
  python3 -m harnessbench run \
    --subject "subjects/$s" \
    --corpus "$CORPUS" \
    --out "$RESULTS/$s.v1.json"
done

python3 -m harnessbench leaderboard \
  --results "$RESULTS" \
  --out-json "$RESULTS/leaderboard.v1.json" \
  --out-md "docs/results-asi05.md" \
  --out-badge "$RESULTS/badge.svg"
