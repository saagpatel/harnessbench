# HarnessBench results: ASI05:2026 Unexpected Code Execution (RCE)

Harness: `claude-code` · corpus `asi05-destructive-execution` v1 · evidence tier: offline-hook-mechanism.

| Subject | EES | TPR | FPR | Enforced | Advised | Absent | Over-blocked | Permitted |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| semantic-clean-room | +1.000 | 1.000 | 0.000 | 46 | 0 | 0 | 0 | 22 |
| naive-regex | +0.091 | 0.500 | 0.409 | 23 | 23 | 0 | 9 | 13 |
| advisory | +0.000 | 0.000 | 0.000 | 0 | 46 | 0 | 0 | 22 |

EES = TPR - FPR (Youden's J). Higher is better; a config that blocks everything nets 0. n = 68 probes per subject (must_block plus must_allow).
