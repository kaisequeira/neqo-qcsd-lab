#!/usr/bin/env python3
"""Tests use fabricated numbers only; they are not study results."""
import csv
import json
import tempfile
import unittest
from pathlib import Path

import build_report as br


def write_csv(path, rows):
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.a, self.d, self.f = (self.root / x for x in ("aggregate", "descriptive", "figures"))
        for p in (self.a, self.d, self.f):
            p.mkdir()
        self.manifest = self.root / "manifest.csv"
        self.manifest.write_text("synthetic manifest fixture\n")
        self.hash_manifest, self.hash_rows, self.hash_agg = (br.sha(self.manifest), "b" * 64, "c" * 64)
        self.quality = {"status": "complete", "manifest_sessions": 36, "accepted_metric_rows": 36,
                        "extractor_errors": 0, "identity_or_other_flags": {},
                        "manifest_sha256": self.hash_manifest, "metric_rows_content_sha256": self.hash_rows,
                        "analysis_script_sha256": self.hash_agg, "bootstrap_replicates": 1000, "seed": 11,
                        "quality_by_condition": {mode: dict(rows=6, ip_valid_false=0, ip_valid_missing=0,
                                                           strict_timestamp_order_not_true=0, truncated_packets=0,
                                                           direction_complete=6) for mode in br.MODES}}
        self.write_quality()
        self.prov = {"status": "complete", "metric_rows": 36,
                     "manifest_sha256": self.hash_manifest, "metric_rows_content_sha256": self.hash_rows,
                     "aggregate_code_sha256": self.hash_agg, "descriptive_code_sha256": "d" * 64}
        self.write_desc()
        overall, detail, distributions, cohorts, offsets, shared, sens = [], [], [], [], [], [], []
        domains = ("example-a.test", "example-b.test")
        for mode_index, mode in enumerate(br.MODES):
            for metric in br.METRICS:
                base = 100.0 if metric == "ip_bytes" else 2.0
                mult = 1 + mode_index * .1
                vals = [base * (j + 1) * mult for j in range(2)]
                distributions.append(dict(defense=mode, metric=metric, n=6, excluded_n=0,
                                          mean=sum(vals) / 2, p50=sum(vals) / 2, p95=max(vals)))
                for j, domain in enumerate(domains):
                    cohorts.append(dict(defense=mode, domain=domain, metric=metric, n=3, excluded_n=0, mean=vals[j]))
        for mode_index, mode in enumerate(br.DEFENSES, start=1):
            for domain in domains:
                offsets.append(dict(defense=mode, domain=domain, median_offset_days=2, shared_utc_days=1))
            for metric in br.METRICS:
                b = 100.0 if metric == "ip_bytes" else 2.0
                ratios = []
                for j, domain in enumerate(domains):
                    baseline = b * (j + 1)
                    defended = baseline * (1 + mode_index * .1)
                    ratio = 100 * (defended / baseline - 1)
                    ratios.append(ratio)
                    detail.append(dict(defense=mode, metric=metric, domain=domain,
                                       baseline_expected_n=3, defense_expected_n=3,
                                       baseline_n=3, defense_n=3, baseline_mean=baseline,
                                       defense_mean=defended, overhead_pct=ratio,
                                       absolute_difference=defended - baseline))
                mean_base = b * 1.5
                mean_def = mean_base * (1 + mode_index * .1)
                mean_ratio = sum(ratios) / 2
                overall.append(dict(defense=mode, metric=metric, domains=2, provisional=False,
                                    bootstrap_draws=1000, macro_overhead_pct=mean_ratio,
                                    pooled_cohort_mean_overhead_pct=100 * (mean_def / mean_base - 1),
                                    baseline_equal_domain_mean=mean_base, defense_equal_domain_mean=mean_def,
                                    mean_absolute_difference=mean_def - mean_base,
                                    domain_median_pct=br.percentile(ratios, 50),
                                    domain_p05_pct=br.percentile(ratios, 5),
                                    domain_p95_pct=br.percentile(ratios, 95),
                                    macro_ci95_sessions_low=mean_ratio - 1, macro_ci95_sessions_high=mean_ratio + 1,
                                    macro_ci95_domain_cluster_low=mean_ratio - 2, macro_ci95_domain_cluster_high=mean_ratio + 2,
                                    macro_bootstrap_valid=1000, domain_cluster_bootstrap_valid=1000, pooled_bootstrap_valid=1000,
                                    pooled_ci95_sessions_low=mean_ratio - 1, pooled_ci95_sessions_high=mean_ratio + 1))
                shared.append(dict(defense=mode, metric=metric, eligible_domains=2, expected_domains=2,
                                   defense_sessions_in_eligible_domains=6, baseline_sessions_in_eligible_domains=6,
                                   equal_domain_mean_overhead_pct=mean_ratio))
                sens.append(dict(defense=mode, metric=metric, expected_domains=2,
                                 median_ratio_pct_domains=2, median_ratio_pct_equal_domain_mean=mean_ratio,
                                 upper_1pct_trimmed_mean_ratio_pct_domains=2,
                                 upper_1pct_trimmed_mean_ratio_pct_equal_domain_mean=mean_ratio))
        for path, rows in ((self.a / "overall-overheads.csv", overall), (self.a / "domain-overheads.csv", detail),
                           (self.d / "session-distributions-by-condition.csv", distributions),
                           (self.d / "session-distributions-by-cohort.csv", cohorts),
                           (self.d / "capture-epoch-offsets-by-domain.csv", offsets),
                           (self.d / "shared-utc-day-summary.csv", shared), (self.d / "sensitivity-overall.csv", sens)):
            write_csv(path, rows)
        for name in ("01-overall-overheads.svg", "01-overall-overheads.pdf",
                     "02-domain-spread.svg", "02-domain-spread.pdf"):
            (self.f / name).write_text("synthetic figure fixture\n")
        self.figure = {"status": "complete", "accepted_metric_rows": 36, "manifest_sessions": 36,
                       "manifest_sha256": self.hash_manifest, "metric_rows_content_sha256": self.hash_rows,
                       "script_sha256": "e" * 64}
        self.write_figure()

    def tearDown(self):
        self.tmp.cleanup()

    def write_quality(self):
        (self.a / "quality.json").write_text(json.dumps(self.quality))

    def write_desc(self):
        (self.d / "descriptive-provenance.json").write_text(json.dumps(self.prov))

    def write_figure(self):
        self.figure["inputs_sha256"] = {name: br.sha(self.a / name) for name in
                                        ("quality.json", "overall-overheads.csv", "domain-overheads.csv")}
        (self.f / "figure-provenance.json").write_text(json.dumps(self.figure))

    def build(self):
        return br.make_report(self.a, self.d, self.f, manifest=self.manifest,
                              expected_domains=2, sessions=3, synthetic=True)

    def test_complete_synthetic_report_is_visibly_marked_and_complete(self):
        report = self.build()
        self.assertIn("SYNTHETIC FIXTURE — NOT STUDY DATA", report)
        self.assertIn("application completion", report)
        for name in ("FRONT", "Tamaraw", "BuFLO", "CS-BuFLO", "WTF-PAD"):
            self.assertIn(name, report)
        self.assertIn("example-a.test", report)
        self.assertIn("shared-UTC-day", report)

    def test_reduced_real_data_cannot_be_reported(self):
        with self.assertRaises(ValueError):
            br.make_report(self.a, self.d, self.f, manifest=self.manifest, expected_domains=2, sessions=3)

    def test_manifest_tampering_rejected(self):
        self.manifest.write_text("different synthetic manifest\n")
        with self.assertRaises(ValueError):
            self.build()

    def test_incomplete_census_is_rejected(self):
        self.quality["accepted_metric_rows"] = 35
        self.write_quality()
        self.write_figure()
        with self.assertRaises(ValueError):
            self.build()

    def test_extractor_errors_rejected(self):
        self.quality["extractor_errors"] = 1
        self.write_quality()
        self.write_figure()
        with self.assertRaises(ValueError):
            self.build()

    def test_metrics_snapshot_mismatch_rejected(self):
        self.prov["metric_rows_content_sha256"] = "f" * 64
        self.write_desc()
        with self.assertRaises(ValueError):
            self.build()

    def test_figure_input_tampering_rejected(self):
        with (self.a / "overall-overheads.csv").open("a") as f:
            f.write("tampered")
        with self.assertRaises(ValueError):
            self.build()

    def test_missing_figure_rejected(self):
        (self.f / "02-domain-spread.pdf").unlink()
        with self.assertRaises(ValueError):
            self.build()

    def test_summary_inconsistency_rejected_even_with_refreshed_figure_hash(self):
        rows = br.read_csv(self.a / "overall-overheads.csv")
        rows[0]["macro_overhead_pct"] = "999"
        write_csv(self.a / "overall-overheads.csv", rows)
        self.write_figure()
        with self.assertRaises(ValueError):
            self.build()

    def test_domain_ratio_inconsistency_rejected(self):
        rows = br.read_csv(self.a / "domain-overheads.csv")
        rows[0]["overhead_pct"] = "999"
        write_csv(self.a / "domain-overheads.csv", rows)
        self.write_figure()
        with self.assertRaises(ValueError):
            self.build()

    def test_condition_count_inconsistency_rejected(self):
        rows = br.read_csv(self.d / "session-distributions-by-condition.csv")
        rows[0]["n"] = "5"
        write_csv(self.d / "session-distributions-by-condition.csv", rows)
        with self.assertRaises(ValueError):
            self.build()

    def test_missing_condition_quality_rejected(self):
        del self.quality["quality_by_condition"]["front"]
        self.write_quality()
        self.write_figure()
        with self.assertRaises(ValueError):
            self.build()

    def test_impossible_quality_count_rejected(self):
        self.quality["quality_by_condition"]["front"]["direction_complete"] = 7
        self.write_quality()
        self.write_figure()
        with self.assertRaises(ValueError):
            self.build()

    def test_inverted_percentiles_rejected(self):
        rows = br.read_csv(self.d / "session-distributions-by-condition.csv")
        rows[0]["p95"] = "0"
        write_csv(self.d / "session-distributions-by-condition.csv", rows)
        with self.assertRaises(ValueError):
            self.build()

    def test_bootstrap_draw_count_mismatch_rejected(self):
        rows = br.read_csv(self.a / "overall-overheads.csv")
        rows[0]["bootstrap_draws"] = "101"
        write_csv(self.a / "overall-overheads.csv", rows)
        self.write_figure()
        with self.assertRaises(ValueError):
            self.build()

    def test_percentiles_use_linear_interpolation(self):
        self.assertEqual(br.percentile([10, 20, 30], 95), 29)

    def test_empty_shared_day_is_not_a_zero_percent_result(self):
        rows = br.read_csv(self.d / "shared-utc-day-summary.csv")
        rows[0]["eligible_domains"] = "0"
        rows[0]["equal_domain_mean_overhead_pct"] = ""
        write_csv(self.d / "shared-utc-day-summary.csv", rows)
        self.assertIn("Unavailable", self.build())


if __name__ == "__main__":
    unittest.main()
