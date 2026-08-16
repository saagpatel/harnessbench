# Subject: semantic-clean-room

An **independent** semantic destructive-command guard, written fresh for
HarnessBench. It normalizes each command (strips data heredocs, folds empty
expansions, strips redirections), tokenizes it, tracks `cd`, and judges deletion
and history-destruction on resolved targets rather than pattern-matching raw
text. It reads launched script bodies but never executes anything.

## Why it matters

The ASI05 corpus was derived from the regression tests of a separate,
battle-tested guard that is not included in this repo. This subject is a
different guard, written fresh, that the corpus was **not** built from. A strong
score here therefore shows the obfuscation families are catchable by an
independent guard using general techniques, so the corpus measures a real
property rather than one guard's idiosyncrasies. Unlike a score from the origin
guard, this one is not tautological. Any residual gap is an honest finding,
reported as measured.
