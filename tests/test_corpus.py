"""Corpus coherence tests: the probe set must load, validate, and keep its
obfuscation richness. A silently thinned corpus would read as full coverage
while missing exactly the cases that separate a real guard from a naive one.
"""

import unittest
from pathlib import Path

from harnessbench.corpus import (
    load_corpus,
    obfuscation_counts,
    polarity_counts,
    validate_corpus,
)
from harnessbench.models import Polarity

CORPUS = Path(__file__).resolve().parent.parent / "probes" / "asi05-destructive-execution.json"


class TestCorpus(unittest.TestCase):
    def setUp(self):
        self.corpus = load_corpus(CORPUS)

    def test_loads_and_validates(self):
        self.assertEqual(validate_corpus(self.corpus), [])

    def test_metadata(self):
        self.assertEqual(self.corpus.name, "asi05-destructive-execution")
        self.assertEqual(self.corpus.harness, "claude-code")
        self.assertIn("ASI05", self.corpus.owasp)

    def test_has_both_polarities(self):
        pc = polarity_counts(self.corpus)
        self.assertGreaterEqual(pc["must_block"], 30)
        self.assertGreaterEqual(pc["must_allow"], 15)

    def test_families_present(self):
        fams = {pr.family for pr in self.corpus.probes}
        self.assertIn("destructive-deletion", fams)
        self.assertIn("history-destruction", fams)

    def test_covers_obfuscation_families(self):
        obf = set(obfuscation_counts(self.corpus))
        required = {
            "uppercase-recursive-flag",
            "empty-expansion-splice",
            "script-body-indirection",
            "heredoc-into-shell",
            "cd-vanishes",
            "subshell",
            "non-rm-verb",
            "pipeline-split",
            "plus-refspec",
        }
        self.assertEqual(required - obf, set(), f"missing obfuscation families: {required - obf}")

    def test_must_block_has_policy(self):
        for pr in self.corpus.probes:
            if pr.polarity is Polarity.MUST_BLOCK:
                self.assertTrue(pr.stated_policy_source, f"{pr.id} lacks a stated_policy_source")

    def test_must_allow_has_no_policy(self):
        for pr in self.corpus.probes:
            if pr.polarity is Polarity.MUST_ALLOW:
                self.assertIsNone(pr.stated_policy_source, f"{pr.id} carries a policy")

    def test_script_body_probes_carry_fixtures(self):
        script_probes = [
            p for p in self.corpus.probes if p.obfuscation == "script-body-indirection"
        ]
        self.assertTrue(script_probes)
        for pr in script_probes:
            self.assertTrue(pr.setup, f"{pr.id} is a script-body probe with no fixture")
            for fx in pr.setup:
                self.assertIn("rm -rf", fx.body)


if __name__ == "__main__":
    unittest.main()
