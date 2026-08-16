"""End-to-end integration: run real subject hooks against the full corpus.

Unlike test_report (which reads committed result JSON), this actually invokes the
subject hooks, so it locks the two claims the benchmark rests on:

  1. An INDEPENDENT semantic guard (the corpus was not built from it) achieves a
     perfect score, so the ceiling is earned, not a corpus artifact.
  2. The naive pattern blocklist fails in both directions (low EES), which is the
     headline finding.

Slower than the unit tests (one subprocess per probe), but bounded to two
subjects.
"""

import unittest
from pathlib import Path

from harnessbench.corpus import load_corpus
from harnessbench.runner_hook import load_subject, run_subject
from harnessbench.score import score_subject

ROOT = Path(__file__).resolve().parent.parent
CORPUS = ROOT / "probes" / "asi05-destructive-execution.json"


def measure(subject_name: str):
    corpus = load_corpus(CORPUS)
    subject = load_subject(ROOT / "subjects" / subject_name)
    observations = run_subject(subject, corpus)
    return score_subject(subject.name, subject.policy_text, observations)


class TestIntegration(unittest.TestCase):
    def test_independent_guard_earns_the_ceiling(self):
        s = measure("semantic-clean-room")
        self.assertEqual(s.errors, 0)
        self.assertEqual(
            s.ees, 1.0, f"independent guard should block all and permit all, got {s.ees}"
        )
        self.assertEqual(s.over_blocked, 0)

    def test_naive_blocklist_fails_both_ways(self):
        s = measure("naive-regex")
        self.assertEqual(s.errors, 0)
        # Misses obfuscated attacks (TPR well below 1)...
        self.assertLess(s.tpr, 0.7)
        # ...and over-blocks legitimate work (FPR clearly positive).
        self.assertGreater(s.fpr, 0.2)
        # Net discrimination is barely above zero.
        self.assertLess(s.ees, 0.2)

    def test_advisory_enforces_nothing(self):
        s = measure("advisory")
        self.assertEqual(s.enforced, 0)
        self.assertEqual(s.ees, 0.0)


if __name__ == "__main__":
    unittest.main()
