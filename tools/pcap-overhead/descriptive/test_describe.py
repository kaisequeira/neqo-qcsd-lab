import hashlib
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest import mock

import describe
import numpy as np


class DescriptiveTests(unittest.TestCase):
    def test_percentiles_use_linear_interpolation_and_absolute_units(self):
        result = describe.describe([1, 2, 3, 4])
        self.assertEqual(result['n'], 4)
        self.assertEqual(result['sum'], 10)
        self.assertEqual(result['mean'], 2.5)
        self.assertEqual(result['p50'], 2.5)
        self.assertAlmostEqual(result['p95'], 3.85)
        self.assertIsNone(describe.describe([]))

    def test_independent_trim_is_order_invariant_and_removes_floor_one_percent(self):
        a = [2] * 99 + [102]
        b = [1] * 99 + [51]
        x = describe.compare(a, b)
        y = describe.compare(list(reversed(a)), list(reversed(b)))
        self.assertEqual(x, y)
        self.assertEqual((x['defense_trimmed_n'], x['baseline_trimmed_n']), (99, 99))
        self.assertEqual(x['upper_1pct_trimmed_mean_ratio_pct'], 100.0)
        self.assertEqual(x['median_ratio_pct'], 100.0)

    def test_zero_denominator_is_undefined_not_infinite(self):
        x = describe.compare([1, 3], [0, 0])
        self.assertIsNone(x['mean_ratio_pct'])
        self.assertIsNone(x['median_ratio_pct'])
        self.assertIsNone(x['upper_1pct_trimmed_mean_ratio_pct'])
        self.assertIsNone(describe.compare([], [1]))

    def test_epoch_overlap_gap_and_calendar_day_coverage(self):
        day = 86400
        x = describe.compare_epochs([day + 10, day * 3 + 10], [day + 20, day * 2 + 20])
        self.assertTrue(x['start_ranges_intersect'])
        self.assertEqual(x['shared_utc_days'], 1)
        self.assertEqual(x['defense_sessions_on_shared_utc_days'], 1)
        self.assertEqual(x['baseline_sessions_on_shared_utc_days'], 1)
        self.assertAlmostEqual(x['start_range_overlap_days'], 1)
        y = describe.compare_epochs([day * 5, day * 6], [day, day * 2])
        self.assertFalse(y['start_ranges_intersect'])
        self.assertEqual(y['start_range_gap_days'], 3)
        self.assertEqual(y['shared_utc_days'], 0)

    def test_touching_ranges_and_invalid_times(self):
        x = describe.compare_epochs([86400], [86400])
        self.assertTrue(x['start_ranges_intersect'])
        self.assertEqual(x['start_range_overlap_days'], 0)
        self.assertIsNone(describe.parse_epoch('not-a-time'))
        self.assertIsNone(describe.parse_epoch('nan'))
        self.assertIsNone(describe.epoch_summary([]))
        self.assertIsNone(describe.compare_epochs([], [1]))

    def test_shared_day_sensitivity_is_unpaired_and_excludes_nonshared_days(self):
        a = [(1, 10), (1, 20), (2, 200)]
        b = [(1, 5), (1, 10), (3, 1)]
        x = describe.shared_day_compare(a, b)
        self.assertEqual(x['shared_utc_days'], 1)
        self.assertEqual((x['defense_n'], x['baseline_n']), (2, 2))
        self.assertEqual(x['mean_ratio_pct'], 100.0)
        self.assertEqual(x, describe.shared_day_compare(list(reversed(a)), list(reversed(b))))
        self.assertEqual(describe.shared_day_compare([(1, 3)], [(2, 2)])['status'], 'no_shared_utc_day')
        self.assertEqual(describe.shared_day_compare([(1, 3)], [(1, 0)])['status'], 'zero_baseline_mean')

    def test_metric_value_matches_expected_pcap_quality_exclusions(self):
        good = {'ip_bytes': 500, 'ip_valid': True, 'span_seconds': 2.5, 'strict_order': 'True'}
        self.assertEqual(describe.metric_value(good, 'ip_bytes', 'ip_bytes'), 500)
        self.assertEqual(describe.metric_value(good, 'observed_span', 'span_seconds'), 2.5)
        self.assertIsNone(describe.metric_value({**good, 'ip_valid': False}, 'ip_bytes', 'ip_bytes'))
        self.assertIsNone(describe.metric_value({**good, 'strict_order': 'False'}, 'observed_span', 'span_seconds'))
        self.assertIsNone(describe.metric_value({**good, 'ip_bytes': True}, 'ip_bytes', 'ip_bytes'))

    def test_incomplete_quality_cannot_create_outputs(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            quality = root / 'quality.json'
            quality.write_text(json.dumps({'status': 'provisional_incomplete'}))
            out = root / 'results'
            args = ['describe.py', '--manifest', str(root/'manifest'), '--database', str(root/'db'),
                    '--quality', str(quality), '--aggregate', str(root/'aggregate.py'), '--output', str(out)]
            with mock.patch.object(sys, 'argv', args), self.assertRaisesRegex(ValueError, 'complete'):
                describe.main()
            self.assertFalse(out.exists())

    def test_mismatched_manifest_rejected_before_loading_database(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            manifest, agg, quality = root/'m.csv', root/'aggregate.py', root/'quality.json'
            manifest.write_text('not the pinned manifest')
            agg.write_text('not the pinned aggregator')
            quality.write_text(json.dumps({'status':'complete', 'manifest_sessions':120000,
                                          'accepted_metric_rows':120000, 'extractor_errors':0,
                                          'identity_or_other_flags':{}, 'manifest_sha256':'0'*64,
                                          'analysis_script_sha256':hashlib.sha256(agg.read_bytes()).hexdigest()}))
            args = ['describe.py', '--manifest', str(manifest), '--database', str(root/'missing.sqlite3'),
                    '--quality', str(quality), '--aggregate', str(agg), '--output', str(root/'out')]
            with mock.patch.object(sys, 'argv', args), self.assertRaisesRegex(ValueError, 'Manifest or aggregate'):
                describe.main()
            self.assertFalse((root/'out').exists())

    def test_completed_synthetic_pipeline_writes_all_expected_tables(self):
        class Records:
            def __len__(self):
                return 120000
            def __getitem__(self, key):
                value = 1.0 if key[0] == 'undefended' else 2.0
                return {'first_epoch': '1700000000.25', 'ip_bytes': value, 'ip_valid': True,
                        'span_seconds': value, 'strict_order': 'True'}

        modes = ('undefended', 'front', 'tamaraw', 'buflo', 'cs-buflo', 'wtf-pad')
        fake = types.SimpleNamespace(
            CONDITIONS=modes,
            read_manifest=lambda path, domain_count, sessions: ({}, [f'domain{i:02d}' for i in range(50)]),
            load_metrics=lambda path, manifest: (Records(), {}, 'snapshot', []),
            cohort_data=lambda records, mode, domain, field, sessions, strict_order=False:
                (np.full(400, 1.0 if mode == 'undefended' else 2.0), {}, {}),
        )
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            quality = root / 'quality.json'
            quality.write_text(json.dumps({'status':'complete', 'manifest_sessions':120000,
                                          'accepted_metric_rows':120000, 'extractor_errors':0,
                                          'identity_or_other_flags':{}, 'manifest_sha256':'hash',
                                          'analysis_script_sha256':'hash',
                                          'metric_rows_content_sha256':'snapshot'}))
            args = ['describe.py', '--manifest', str(root/'m'), '--database', str(root/'db'),
                    '--quality', str(quality), '--aggregate', str(root/'agg'), '--output', str(root/'out')]
            with mock.patch.object(sys, 'argv', args), mock.patch.object(describe, 'sha', return_value='hash'), \
                 mock.patch.object(describe, 'load_module', return_value=fake):
                describe.main()
            import csv
            def rows(name):
                with (root/'out'/name).open(newline='') as fh:
                    return list(csv.DictReader(fh))
            self.assertEqual(len(rows('session-distributions-by-cohort.csv')), 600)
            self.assertEqual(len(rows('session-distributions-by-condition.csv')), 12)
            self.assertEqual(len(rows('sensitivity-by-domain.csv')), 500)
            self.assertEqual(len(rows('shared-utc-day-sensitivity.csv')), 500)
            self.assertEqual(float(rows('shared-utc-day-sensitivity.csv')[0]['mean_ratio_pct']), 100.0)
            shared_summary = rows('shared-utc-day-summary.csv')
            self.assertEqual(len(shared_summary), 10)
            self.assertEqual(int(shared_summary[0]['eligible_domains']), 50)
            self.assertEqual(float(shared_summary[0]['equal_domain_mean_overhead_pct']), 100.0)
            overall = rows('sensitivity-overall.csv')
            self.assertEqual(len(overall), 10)
            self.assertEqual(float(overall[0]['mean_ratio_pct_equal_domain_mean']), 100.0)
            self.assertEqual(len(rows('capture-epochs-by-cohort.csv')), 300)
            self.assertEqual(len(rows('capture-epoch-offsets-by-domain.csv')), 250)


if __name__ == '__main__':
    unittest.main()
