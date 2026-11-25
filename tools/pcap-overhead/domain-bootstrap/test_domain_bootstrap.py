import csv
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock
import numpy as np
import domain_bootstrap as db


class FixedRng:
    def __init__(self, outputs):
        self.outputs = iter(outputs)

    def integers(self, low, high, size):
        result = np.asarray(next(self.outputs), dtype=int)
        if result.shape != tuple(size):
            raise AssertionError((result.shape, size))
        return result


class DomainBootstrapTest(unittest.TestCase):
    def test_duplicate_domain_occurrences_get_fresh_session_draws(self):
        # One observed domain selected twice: defended resamples differ.
        rng = FixedRng([[[0]], [[0, 0]], [[0, 0]]])
        # First make explicit the usual one-domain design's fixed dimensions.
        draws, invalid = db.independent_occurrence_draws([([2, 2], [1, 1])], 1, rng)
        self.assertEqual(invalid, 0)
        self.assertEqual(draws.tolist(), [100.0])
        # A two-domain bootstrap can select domain 0 twice. Its two occurrences
        # select opposite sessions and average to 0%, impossible with reuse.
        rng = FixedRng([[[0, 0]], [[0, 0], [1, 1]], [[0], [0]]])
        draws, invalid = db.independent_occurrence_draws([([0, 2], [1]), ([0, 2], [1])], 1, rng)
        self.assertEqual(invalid, 0)
        self.assertEqual(draws.tolist(), [0.0])

    def test_zero_resampled_baseline_invalidates_whole_replicate(self):
        rng = FixedRng([[[0]], [[0]], [[0]]])
        draws, invalid = db.independent_occurrence_draws([([1], [0])], 1, rng)
        self.assertTrue(np.isnan(draws[0]))
        self.assertEqual(invalid, 1)

    def test_domain_only_samples_whole_domain_ratios(self):
        rng = FixedRng([[[0, 1], [1, 1]]])
        draws = db.domain_only_draws([([2], [1]), ([3], [3])], 2, rng)
        np.testing.assert_allclose(draws, [50, 0])

    def test_seed_reproducibility(self):
        cohorts = [([0, 1, 2], [1, 2, 3]), ([3, 4], [1, 4])]
        a, ai = db.independent_occurrence_draws(cohorts, 200, np.random.default_rng(47))
        b, bi = db.independent_occurrence_draws(cohorts, 200, np.random.default_rng(47))
        np.testing.assert_array_equal(a, b)
        self.assertEqual(ai, bi)

    def test_complete_cohort_point_and_unavailable_cohort(self):
        class FakeAggregate:
            CONDITIONS = ('undefended', 'front')

            @staticmethod
            def cohort_data(records, defense, domain, field, sessions, **kwargs):
                return np.asarray(records.get((defense, domain, field), []), dtype=float), {}, {}

        records = {}
        for field in ('ip_bytes', 'span_seconds'):
            records['undefended', 'a', field] = [1, 1]
            records['front', 'a', field] = [2, 2]
            records['undefended', 'b', field] = [2, 2]
            records['front', 'b', field] = [2, 2]
        rows = db.calculate(FakeAggregate, records, ['a', 'b'], 200, np.random.default_rng(48), sessions=2)
        self.assertEqual(len(rows), 2)
        for row in rows:
            self.assertEqual(row['status'], 'complete')
            self.assertAlmostEqual(row['macro_overhead_pct'], 50)
            self.assertEqual(row['valid_replicates'], 200)
            self.assertEqual(row['domain_only_valid_replicates'], 200)
        records['undefended', 'a', 'ip_bytes'] = [0, 0]
        rows = db.calculate(FakeAggregate, records, ['a', 'b'], 200, np.random.default_rng(48), sessions=2)
        self.assertEqual(rows[0]['status'], 'unavailable')
        self.assertEqual(json.loads(rows[0]['unavailable_domains']), ['a'])

    def test_reuse_and_independent_draws_have_distinct_synthetic_variance(self):
        n, reps = 50, 12000
        cohorts = [([0, 2], [1, 1])] * n
        fresh, invalid = db.independent_occurrence_draws(cohorts, reps, np.random.default_rng(31))
        rng = np.random.default_rng(32)
        # Reproduces the old algorithm: one inner draw per original domain,
        # copied unchanged for every duplicate outer selection.
        one_each = (rng.integers(0, 2, size=(n, reps, 2)).mean(axis=2) * 2 - 1) * 100
        choices = rng.integers(0, n, size=(n, reps))
        reused = np.take_along_axis(one_each, choices, axis=0).mean(axis=0)
        self.assertEqual(invalid, 0)
        self.assertTrue(1.3 < reused.std() / fresh.std() < 1.5)
        self.assertLess(db.domain_only_draws(cohorts, reps, np.random.default_rng(33)).std(), 1e-12)

    def test_quality_gate_rejects_incomplete_or_mismatched_inputs(self):
        valid = {'status': 'complete', 'manifest_sessions': 120000, 'accepted_metric_rows': 120000,
                 'extractor_errors': 0, 'identity_or_other_flags': {},
                 'manifest_sha256': db.MANIFEST_SHA, 'analysis_script_sha256': db.AGGREGATE_SHA}
        db.validate_quality(valid)
        for field, value in [('status', 'provisional'), ('accepted_metric_rows', 119999),
                             ('extractor_errors', 1), ('manifest_sha256', '0' * 64),
                             ('identity_or_other_flags', {'bad': 1})]:
            record = dict(valid); record[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                db.validate_quality(record)

    def test_primary_point_estimates_are_bound_and_tampering_rejected(self):
        results = [{'defense': 'front', 'metric': 'ip_bytes', 'expected_domains': 50,
                    'status': 'complete', 'macro_overhead_pct': 10.0}]
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'overall-overheads.csv'
            fields = ['defense', 'metric', 'domains', 'provisional', 'macro_overhead_pct']
            row = {'defense': 'front', 'metric': 'ip_bytes', 'domains': '50',
                   'provisional': 'False', 'macro_overhead_pct': '10'}
            def write():
                with path.open('w', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=fields); writer.writeheader(); writer.writerow(row)
            write(); db.validate_primary_points(results, path)
            row['macro_overhead_pct'] = '11'; write()
            with self.assertRaises(ValueError):
                db.validate_primary_points(results, path)

    def test_every_domain_count_mean_and_ratio_is_bound(self):
        class FakeAggregate:
            CONDITIONS = ('undefended', 'front')

            @staticmethod
            def cohort_data(records, defense, domain, field, sessions, **kwargs):
                return np.asarray(records.get((defense, domain, field), []), dtype=float), {}, {}

        records = {}
        rows = []
        for metric, (field, unit) in db.METRICS.items():
            for domain in ('a', 'b'):
                records['undefended', domain, field] = [1, 1]
                records['front', domain, field] = [2, 2]
                rows.append(dict(metric=metric, unit=unit, defense='front', domain=domain,
                                 baseline_n=2, defense_n=2, baseline_expected_n=2, defense_expected_n=2,
                                 baseline_mean=1, defense_mean=2, absolute_difference=1, overhead_pct=100))
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'domain-overheads.csv'
            def write():
                with path.open('w', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=list(rows[0])); writer.writeheader(); writer.writerows(rows)
            write()
            self.assertEqual(db.validate_primary_domains(FakeAggregate, records, ['a', 'b'], 2, path), (4, 0))
            for field, value in [('baseline_n', 1), ('defense_mean', 3), ('overhead_pct', 101), ('unit', 'invalid')]:
                old = rows[0][field]; rows[0][field] = value; write()
                with self.subTest(field=field), self.assertRaises(ValueError):
                    db.validate_primary_domains(FakeAggregate, records, ['a', 'b'], 2, path)
                rows[0][field] = old
            # Missing primary comparison is allowed only when the corresponding
            # cohort itself is unavailable; coverage is explicitly returned.
            records['undefended', 'a', 'ip_bytes'] = [0, 0]
            rows.pop(0); write()
            self.assertEqual(db.validate_primary_domains(FakeAggregate, records, ['a', 'b'], 2, path), (3, 1))

    def test_incomplete_database_does_not_create_output(self):
        valid = {'status': 'complete', 'manifest_sessions': 120000, 'accepted_metric_rows': 120000,
                 'extractor_errors': 0, 'identity_or_other_flags': {},
                 'manifest_sha256': db.MANIFEST_SHA, 'analysis_script_sha256': db.AGGREGATE_SHA}
        aggregate = mock.Mock()
        aggregate.read_manifest.return_value = ({}, [])
        aggregate.load_metrics.return_value = ({}, {}, 'snapshot', [])
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); (root / 'quality.json').write_text(json.dumps(valid))
            arguments = ['domain_bootstrap.py', '--manifest', str(root / 'manifest.csv'),
                         '--database', str(root / 'metrics.sqlite3'), '--quality', str(root / 'quality.json'),
                         '--aggregate', str(root / 'aggregate.py'), '--output', str(root / 'output')]
            with mock.patch.object(db, 'sha', return_value=db.MANIFEST_SHA), \
                 mock.patch.object(db, 'load_aggregate', return_value=aggregate), \
                 mock.patch('sys.argv', arguments), self.assertRaises(SystemExit):
                db.main()
            self.assertFalse((root / 'output').exists())


if __name__ == '__main__':
    unittest.main()
