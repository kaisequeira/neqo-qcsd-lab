#!/usr/bin/env python3
"""Tests use fabricated values only; no plots are study findings."""
import csv
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest

import plot_results as plot


def table(path, rows):
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)


def fixture(root, status="complete", study_shape=False):
    root.mkdir(exist_ok=True)
    (root / "quality.json").write_text(json.dumps({
        "status": status, "extractor_errors": 0, "identity_or_other_flags": {},
        "accepted_metric_rows": 120000 if study_shape else 7200,
        "manifest_sessions": 120000 if study_shape else 7200,
        "manifest_sha256": "0" * 64 if study_shape else "synthetic",
        "metric_rows_content_sha256": "1" * 64 if study_shape else "synthetic",
    }))
    sums, rows = [], []
    for metric in plot.METRICS:
        for i, mode in enumerate(plot.MODES):
            vals = [-20 + i, 25 + i * 5, (2000 if metric == "observed_span" and i == 2 else 100 + i * 7)]
            if study_shape:
                vals = [vals[j % len(vals)] for j in range(50)]
            mean = sum(vals)/len(vals)
            sums.append({"metric": metric, "defense": mode, "domains": len(vals),
                         "macro_overhead_pct": mean, "macro_ci95_sessions_low": mean-10,
                         "macro_ci95_sessions_high": mean+20,
                         "pooled_cohort_mean_overhead_pct": mean+1,
                         "pooled_ci95_sessions_low": mean-8,
                         "pooled_ci95_sessions_high": mean+25,
                         "provisional": status != "complete"})
            for j, v in enumerate(vals):
                rows.append({"metric": metric, "defense": mode, "domain": f"synthetic-{j}.invalid",
                             "baseline_n": 399, "defense_n": 398, "baseline_expected_n": 400,
                             "defense_expected_n": 400, "overhead_pct": v})
    table(root / "overall-overheads.csv", sums)
    table(root / "domain-overheads.csv", rows)


class PlotTests(unittest.TestCase):
    def setUp(self):
        self.t = tempfile.TemporaryDirectory(prefix="synthetic-overhead-plot-test-")
        self.root = Path(self.t.name)
        self.src = self.root / "input"
        fixture(self.src)

    def tearDown(self):
        self.t.cleanup()

    def test_complete_and_counts(self):
        quality, summaries, domains, provisional = plot.load_results(self.src, synthetic_fixture=True)
        self.assertFalse(provisional)
        self.assertEqual(summaries[("ip_bytes", "front")]["domains"], 3)
        self.assertEqual(plot.counts(domains[("ip_bytes", "front")]), {
            "defense_n": 1194, "baseline_n": 1197,
            "defense_excluded": 6, "baseline_excluded": 3})

    def test_incomplete_must_be_explicit_and_is_marked(self):
        q = json.loads((self.src / "quality.json").read_text())
        q["status"] = "provisional_incomplete"
        (self.src / "quality.json").write_text(json.dumps(q))
        with self.assertRaisesRegex(ValueError, "incomplete"):
            plot.load_results(self.src, synthetic_fixture=True)
        self.assertTrue(plot.load_results(self.src, allow_incomplete=True, synthetic_fixture=True)[3])

    def test_reject_extractor_errors(self):
        q = json.loads((self.src / "quality.json").read_text())
        q["extractor_errors"] = 1
        (self.src / "quality.json").write_text(json.dumps(q))
        with self.assertRaisesRegex(ValueError, "errors"):
            plot.load_results(self.src, synthetic_fixture=True)

    def test_reject_mismatch_of_domain_and_summary(self):
        p = self.src / "domain-overheads.csv"
        with p.open(newline="") as f:
            rows = list(csv.DictReader(f))
        rows[0]["overhead_pct"] = "999999"
        table(p, rows)
        with self.assertRaisesRegex(ValueError, "mean mismatch"):
            plot.load_results(self.src, synthetic_fixture=True)

    def test_reject_missing_defense(self):
        p = self.src / "overall-overheads.csv"
        with p.open(newline="") as f:
            rows = list(csv.DictReader(f))
        table(p, rows[:-1])
        with self.assertRaisesRegex(ValueError, "all five defenses"):
            plot.load_results(self.src, synthetic_fixture=True)

    def test_reject_out_of_range_counts(self):
        p = self.src / "domain-overheads.csv"
        with p.open(newline="") as f:
            rows = list(csv.DictReader(f))
        rows[0]["defense_n"] = "401"
        table(p, rows)
        with self.assertRaisesRegex(ValueError, "exceeds expected"):
            plot.load_results(self.src, synthetic_fixture=True)

    def test_nonstudy_fixture_requires_explicit_flag(self):
        with self.assertRaisesRegex(ValueError, "120,000"):
            plot.load_results(self.src)
        plot.load_results(self.src, synthetic_fixture=True)

    def test_full_shaped_synthetic_input_exercises_production_gate(self):
        # Test the production validation with invented 50-domain data but do
        # not render or publish any figures from this temporary fixture.
        full = self.root / "full-shape-fixture"
        fixture(full, study_shape=True)
        q, s, d, provisional = plot.load_results(full)
        self.assertEqual(q["accepted_metric_rows"], 120000)
        self.assertEqual(s[("ip_bytes", "front")]["domains"], 50)
        self.assertFalse(provisional)

    def test_reject_different_domains_at_same_count(self):
        p = self.src / "domain-overheads.csv"
        with p.open(newline="") as f:
            rows = list(csv.DictReader(f))
        rows[0]["domain"] = "replacement.invalid"
        table(p, rows)
        with self.assertRaisesRegex(ValueError, "Different domains"):
            plot.load_results(self.src, synthetic_fixture=True)

    def test_synthetic_plots_and_provenance(self):
        out = self.root / "synthetic-figures"
        with contextlib.redirect_stdout(io.StringIO()):
            plot.main(["--results", str(self.src), "--output", str(out), "--synthetic-fixture"])
        for stem in ("01-overall-overheads", "02-domain-spread"):
            for ext in ("pdf", "svg", "png"):
                p = out / f"{stem}.{ext}"
                self.assertTrue(p.exists(), p)
                self.assertGreater(p.stat().st_size, 1000)
        meta = json.loads((out / "figure-provenance.json").read_text())
        self.assertEqual(meta["status"], "synthetic_fixture")
        self.assertEqual(meta["manifest_sha256"], "synthetic")
        self.assertIn("not application completion", meta["note"])
        self.assertIn("SYNTHETIC FIXTURE", (out / "01-overall-overheads.svg").read_text())
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
            plot.main(["--results", str(self.src), "--output", str(out), "--synthetic-fixture"])


if __name__ == "__main__":
    unittest.main()
