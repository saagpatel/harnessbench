# Verification

Run commands from the repository root. Python 3.12+ is required; `python3` must
be on PATH because subject hooks invoke it. HarnessBench runs in place and is
not built or installed as a wheel (`tool.uv.package = false`). There is no
configured type checker, frontend build, or GitHub Actions workflow.

## Focused checks without dependencies

The offline core uses only the standard library. These checks read the public
corpus and committed reports without executing probe commands, contacting a
provider, or rewriting results:

```bash
python3 -m harnessbench --help
python3 -m unittest discover -s tests -p test_corpus.py
python3 -m unittest discover -s tests -p test_report.py
```

For hook-runner changes, use `-p test_runner_hook.py` instead. Those tests launch
small local hooks and create disposable fixtures; they do not launch an agent.
The existing script-body fixture assumes its temporary path has no whitespace.
If that fixture fails under a custom TMPDIR containing spaces, use a disposable
temporary root without whitespace; do not interpret that fixture failure as an
agent enforcement result.

## Full suite and optional VCR coverage

Create an isolated environment if one is not already available:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install pytest 'vcr-core>=0.1.0' 'ruff>=0.6'
python -m pytest -q
```

Installing dependencies requires package-index access; the tests themselves are
local. `pytest` runs both unittest classes and the function-based VCR tests.
`python -m unittest discover -s tests` alone imports the VCR test module (so it
still needs `vcr-core`) but does not execute its function-based tests. Focus the
optional integration with `python -m pytest -q tests/test_vcr_emit.py`; see
[VCR emission](integration-vcr.md) for the dependency boundary.

The live-runner tests use a local stub with disposable canaries. They do not
exercise Claude Code, credentials, or the real OS jail. Real destructive-agent
validation is a separate gated lane described in [LIVE.md](LIVE.md); it is not
a routine verification command for a developer workstation.

## Lint and format

Ruff is the configured development tool (`pyproject.toml`):

```bash
python -m ruff check --config pyproject.toml harnessbench tests
python -m ruff format --check --config pyproject.toml harnessbench tests
```

These commands only report findings and may expose existing lint or format debt.
Report those findings separately from verification of the files being changed.
Apply formatting to the files being changed
when appropriate; do not blanket-format unrelated work to make a check pass.

## Reproduction and report changes

In a clean disposable checkout, run `bash scripts/reproduce.sh`, then inspect
`git diff -- results/asi05 docs/results-asi05.md`. The script runs public subject
hooks and rewrites the report JSON, leaderboard, Markdown table, and SVG badge.
It does not execute the destructive probe commands or call a model/provider.
The private core-guard proof is excluded from the comparative leaderboard; its
historical private measurement cannot be reproduced from public subject files.

For changes to report rendering, review the generated Markdown and SVG in a
viewer as well as running `test_report.py`. If a downstream browser UI serves
them, verify that changed presentation there; this repository has no browser UI
or browser-test command. Pure documentation edits do not require browser checks.
