"""Report tests: enforce that every published figure is generated from the
results JSON and cannot drift. If a subject is re-measured, the committed
leaderboard, the generated table, and the methodology essay must all move with
it or these fail.
"""

import json
import unittest
from pathlib import Path

from harnessbench import report

ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "results" / "asi05"


class TestReport(unittest.TestCase):
    def setUp(self):
        self.reports = report.load_reports(RESULTS)
        self.lb = report.build_leaderboard(self.reports)

    def test_all_subjects_loaded(self):
        self.assertEqual(len(self.reports), 3)

    def test_committed_leaderboard_is_in_sync(self):
        committed = json.loads((RESULTS / "leaderboard.v1.json").read_text(encoding="utf-8"))
        self.assertEqual(self.lb, committed)

    def test_generated_table_is_in_sync(self):
        committed = (ROOT / "docs" / "results-asi05.md").read_text(encoding="utf-8")
        self.assertEqual(report.render_markdown(self.lb), committed)

    def test_rows_sorted_best_first(self):
        ees = [r["ees"] for r in self.lb["rows"]]
        self.assertEqual(ees, sorted(ees, reverse=True))

    def test_methodology_figures_match_results(self):
        # Every subject's EES, formatted, must appear verbatim in the essay.
        essay = (ROOT / "docs" / "methodology.md").read_text(encoding="utf-8")
        for r in self.lb["rows"]:
            self.assertIn(f"{r['ees']:+.3f}", essay, f"{r['subject']} EES missing from methodology")

    def test_markdown_contains_each_ees(self):
        md = report.render_markdown(self.lb)
        for r in self.lb["rows"]:
            self.assertIn(f"{r['ees']:+.3f}", md)

    def test_no_em_dashes_in_served_prose(self):
        # House rule for anything that may be published to the site.
        for name in ("methodology.md", "results-asi05.md"):
            text = (ROOT / "docs" / name).read_text(encoding="utf-8")
            self.assertNotIn("—", text, f"em dash in {name}")


if __name__ == "__main__":
    unittest.main()
