# Publishing HarnessBench v1

Publish prep runbook. Ordered because the site step depends on the repo step: the
saagarpatel.dev `/instruments` room, by its own contract, only names repos that
are already public, so the GitHub repo must be public **before** the site entry
is added. Nothing here has been executed; the repo is committed on
`feat/harnessbench-v1` and unpushed.

## Step 0 (done) — the public subject set

The repo is already in its final public shape: three independent subjects
(`advisory`, `naive-regex`, `semantic-clean-room`). The origin guard the corpus
was derived from is deliberately not included, so nothing circular and nothing
core-guard-derived ships. The ladder stands on its own: prose +0.000, regex
blocklist +0.091, independent semantic guard +1.000.

## Step 1 — push the repo public (operator)

The branch history includes earlier commits that added (then removed) the vendored
origin guard. `git rm` drops it from HEAD but NOT from history, so a plain push
would still expose `subjects/hardened-reference/hooks/guard.py` in `git log`.
Publish from a clean, single-commit snapshot so the origin guard never appears in
any public commit:

```
cd ~/Projects/harnessbench
git checkout --orphan public          # fresh root commit, current tree only
git add -A
git commit -m "HarnessBench v1: enforced-vs-advised benchmark (OWASP ASI05)"
gh repo create saagpatel/harnessbench --public --source=. --remote=origin --push
```

Confirm the vendored guard is absent from the entire public history:

```
git log --all --oneline -- 'subjects/hardened-reference/*'   # must print nothing
```

Then verify a stranger can reproduce with no API key:

```
cd /tmp && rm -rf hb-check && git clone https://github.com/saagpatel/harnessbench hb-check
cd hb-check && bash scripts/reproduce.sh      # must print the same ladder
```

## Step 2 — add the site entry (after the repo is public)

The site page is one ledger entry in the `graders` shelf of `/instruments`,
exactly like OPERANT. This adds no new page, so it does NOT change the signed
`mcp.json` page count and needs NO re-signing, no sitemap/llms/corpus curation.

Work in a fresh worktree off current production, never on the shared checkout:

```
cd ~/Projects/portfolio-index            # the bare repo
git fetch origin
git worktree add ~/Projects/_claude-worktrees/hb-entry -b feat-harnessbench-entry origin/feat/portfolio-index
cd ~/Projects/_claude-worktrees/hb-entry
```

Paste this object as the first entry in the `graders` shelf of
`scripts/sources/instruments/instruments.json` (adjust `status`/`as_of` if the
numbers moved):

```json
{
  "name": "HarnessBench",
  "what": "Grades whether an agent harness's stated safety rules are mechanically enforced or merely advised. It fires destructive-command probes at a configuration and reads whether the mechanism actually blocked them, not whether the model said it would. Blocking everything and blocking nothing both score zero, so only a guard that discriminates passes.",
  "status": "OWASP ASI05 offline tier: stated-in-prose +0.00, a regex blocklist +0.09 (wrong in both directions), an independent semantic guard +1.00, across 68 probes. Reproducible with no API key.",
  "as_of": "2026-08-16",
  "run": "bash scripts/reproduce.sh",
  "href": "https://github.com/saagpatel/harnessbench",
  "links": [
    { "label": "harnessbench", "href": "https://github.com/saagpatel/harnessbench" },
    { "label": "methodology", "href": "https://github.com/saagpatel/harnessbench/blob/main/docs/methodology.md" }
  ]
}
```

## Step 3 — build, gate, deploy (operator-gated)

Run the FULL canonical build sequence (never a single generator) from
`AGENTS.md` "Full build sequence", then the gate, then deploy preview-first:

```
# ... full build sequence from AGENTS.md ...
bash scripts/verify.sh                    # 32-stage gate; never --no-verify
git commit -am "feat(instruments): add HarnessBench grader entry"

# deploy: build a git-free copy, preview, verify on bytes, THEN alias (never --prod a fresh build)
deploy_copy="/tmp/pidx-deploy-$(git rev-parse --short HEAD)"
bash scripts/make-vercel-deploy-copy.sh "$deploy_copy"
vercel deploy "$deploy_copy" --yes --scope "${VERCEL_TEAM_SCOPE:?}" --project portfolio-index
# verify the printed preview URL on bytes, then:
vercel alias set <preview-url> saagarpatel.dev --scope "${VERCEL_TEAM_SCOPE:?}"
# verify the LIVE alias, not the *.vercel.app URL
```

## Follow-up (not v1) — the standalone /harnessbench page

A bespoke `/harnessbench` page with the full leaderboard table (like `/operant`)
is a larger follow-up: a new `scripts/build-harnessbench.py` (copy
`build-instruments.py`, lift the table renderer from
`build-operant.py::cross_provider_html()`), a `templates/harnessbench.html` on
the Forge design tokens, a nav/build-sequence/AGENTS.md edit, and an
`mcp.json` re-sign because it adds a listed page. Do it once the entry is live and
the result has matured (more ASI categories, the live tier, more harnesses).
