import contextlib
import hashlib
import io
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest import mock

import numpy as np
import day_bootstrap as day


class FixedRandom:
    def integers(self, low, high, size):
        assert (low, high, size) == (0, 2, (3, 2))
        return np.array([[0, 0], [0, 1], [1, 1]])


class DayBootstrapTests(unittest.TestCase):
    def test_utc_day_parsing_and_invalid_epochs(self):
        self.assertEqual(day.day_of('86400'), 1)
        self.assertEqual(day.day_of('-0.01'), -1)
        self.assertEqual(day.day_of('1795564799.999999999'), day.day_of('1795564800.000000000') - 1)
        self.assertEqual(day.day_of('-86400.000000001'), -2)
        self.assertEqual(day.day_of('-86400.000000000'), -1)
        for value in (None, '', 'NaN', 'Inf', 'bad', True, '1e200'):
            self.assertIsNone(day.day_of(value))

    def test_whole_day_resampling_preserves_unequal_cluster_sizes(self):
        # An unweighted mean of daily means would produce 5.0 for [0,1].
        means = day.cluster_means({1: [0., 0., 0.], 2: [10.]}, 3, FixedRandom())
        np.testing.assert_allclose(means, [0., 2.5, 10.])

    def test_fewer_than_two_days_blocks_ci(self):
        result, draws = day.cohort_comparison({1: [10.]}, {1: [2.], 2: [2.]}, 100, np.random.default_rng(1))
        self.assertEqual(result['status'], 'fewer_than_two_utc_days')
        self.assertAlmostEqual(result['overhead_pct'], 400.)
        self.assertIsNone(draws)

    def test_zero_baseline_and_empty_never_invent_ratio(self):
        result, draws = day.cohort_comparison({1: [1.], 2: [2.]}, {1: [0.], 2: [0.]}, 100, np.random.default_rng(1))
        self.assertEqual(result['status'], 'zero_baseline_mean')
        self.assertIsNone(result['overhead_pct'])
        self.assertIsNone(draws)
        result, draws = day.cohort_comparison({}, {1: [1.], 2: [1.]}, 100, np.random.default_rng(1))
        self.assertEqual(result['status'], 'no_epoch_eligible_observations')
        self.assertIsNone(draws)

    def test_reproducible_independent_day_bootstrap_and_few_day_warning(self):
        a = {1: [5., 6.], 2: [9.]}
        b = {1: [2.], 3: [3., 4.]}
        r1, d1 = day.cohort_comparison(a, b, 200, np.random.default_rng(91))
        r2, d2 = day.cohort_comparison(a, b, 200, np.random.default_rng(91))
        self.assertEqual(r1, r2)
        np.testing.assert_array_equal(d1, d2)
        self.assertTrue(r1['fewer_than_5_days_in_either_cohort'])
        self.assertTrue(r1['fewer_than_30_days_in_either_cohort'])
        self.assertEqual(r1['finite_draws'], 200)

    def test_metric_eligibility_matches_primary_rules(self):
        valid = {'ip_valid': True, 'ip_bytes': 10, 'span_seconds': 2.0, 'strict_order': 'True'}
        self.assertEqual(day.valid_value(valid, 'ip_bytes', 'ip_bytes'), 10.)
        self.assertEqual(day.valid_value(valid, 'observed_span', 'span_seconds'), 2.)
        self.assertIsNone(day.valid_value({**valid, 'ip_valid': False}, 'ip_bytes', 'ip_bytes'))
        self.assertIsNone(day.valid_value({**valid, 'strict_order': 'False'}, 'observed_span', 'span_seconds'))
        self.assertIsNone(day.valid_value({**valid, 'ip_bytes': True}, 'ip_bytes', 'ip_bytes'))

    def test_epoch_missingness_does_not_erase_valid_metric_count(self):
        r = {'ip_valid': True, 'ip_bytes': 5, 'first_epoch': None}
        groups, stats = day.groups_for({('front', 'x', 1): r}, 'front', 'x', 'ip_bytes', 'ip_bytes', sessions=1)
        self.assertEqual(groups, {})
        self.assertEqual(stats['valid_metric'], 1)
        self.assertEqual(stats['missing_epoch'], 1)

    def test_incomplete_quality_rejected_without_outputs(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); quality = root / 'quality.json'; quality.write_text('{"status":"provisional_incomplete"}')
            out = root / 'out'
            argv = ['day_bootstrap.py', '--manifest', str(root/'manifest'), '--database', str(root/'db'),
                    '--quality', str(quality), '--aggregate', str(root/'agg'), '--output', str(out), '--bootstrap', '100']
            with mock.patch.object(day.sys, 'argv', argv):
                with self.assertRaisesRegex(ValueError, 'complete, error-free'):
                    day.main()
            self.assertFalse(out.exists())

    def test_full_shape_synthetic_end_to_end_and_coverage(self):
        """Synthetic shared records test the real 120,000-key iteration only."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); manifest = root/'manifest.csv'; manifest.write_text('synthetic manifest\n')
            aggregate = root/'aggregate.py'; aggregate.write_text('# synthetic\n')
            file_sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
            quality = root/'quality.json'; quality.write_text(json.dumps({
                'status':'complete','manifest_sessions':120000,'accepted_metric_rows':120000,
                'extractor_errors':0,'identity_or_other_flags':{},'manifest_sha256':file_sha(manifest),
                'analysis_script_sha256':file_sha(aggregate),'metric_rows_content_sha256':'synthetic'}))
            domains = [f'fixture-{i:02d}.invalid' for i in range(50)]
            modes = ('undefended','front','tamaraw','buflo','cs-buflo','wtf-pad')
            record1 = {'status':'ok','ip_valid':True,'ip_bytes':10,'span_seconds':2.,'strict_order':'True','first_epoch':'86400'}
            record2 = {**record1,'first_epoch':'172800'}
            records = {(mode,domain,session): (record1 if session % 2 else record2)
                       for mode in modes for domain in domains for session in range(1,401)}
            fake = types.SimpleNamespace(CONDITIONS=modes,
                read_manifest=lambda *a: ({},domains),
                load_metrics=lambda *a: (records,{},'synthetic',[]))
            argv = ['day_bootstrap.py','--manifest',str(manifest),'--database',str(root/'db'),
                    '--quality',str(quality),'--aggregate',str(aggregate),'--output',str(root/'out'),'--bootstrap','100']
            with mock.patch.object(day.sys, 'argv', argv), mock.patch.object(day, 'load_aggregate', return_value=fake), contextlib.redirect_stdout(io.StringIO()):
                day.main()
            import csv
            with (root/'out'/'utc-day-cluster-by-domain.csv').open(newline='') as f: rows=list(csv.DictReader(f))
            self.assertEqual(len(rows), 500)
            self.assertTrue(all(row['status']=='eligible' for row in rows))
            with (root/'out'/'utc-day-cluster-eligible-subset-summary.csv').open(newline='') as f: summaries=list(csv.DictReader(f))
            self.assertEqual(len(summaries),10)
            self.assertTrue(all(s['eligible_domains']=='50' and s['all_domains_eligible']=='True' for s in summaries))
            self.assertTrue(all(float(s['equal_domain_mean_overhead_pct_eligible_subset'])==0 for s in summaries))

    def test_snapshot_mismatch_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); m=root/'m';m.write_text('m');a=root/'a';a.write_text('a')
            h=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
            q=root/'q';q.write_text(json.dumps({'status':'complete','manifest_sessions':120000,'accepted_metric_rows':120000,'extractor_errors':0,'identity_or_other_flags':{},'manifest_sha256':h(m),'analysis_script_sha256':h(a),'metric_rows_content_sha256':'EXPECTED'}))
            # A full-size sentinel makes this exercise the digest gate itself,
            # rather than passing merely because the record count was short.
            class FullSizeSentinel:
                def __len__(self): return 120000
            fake=types.SimpleNamespace(read_manifest=lambda *a:({},[]),load_metrics=lambda *a:(FullSizeSentinel(), {}, 'DIFFERENT', []))
            args=['day_bootstrap.py','--manifest',str(m),'--database',str(root/'db'),'--quality',str(q),'--aggregate',str(a),'--output',str(root/'out'),'--bootstrap','100']
            with mock.patch.object(day.sys,'argv',args),mock.patch.object(day,'load_aggregate',return_value=fake):
                with self.assertRaisesRegex(ValueError,'metrics snapshot'):
                    day.main()
            self.assertFalse((root/'out').exists())

    def test_full_size_snapshot_with_flags_or_errors_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);m=root/'m';m.write_text('m');a=root/'a';a.write_text('a')
            h=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
            q=root/'q';q.write_text(json.dumps({'status':'complete','manifest_sessions':120000,'accepted_metric_rows':120000,'extractor_errors':0,'identity_or_other_flags':{},'manifest_sha256':h(m),'analysis_script_sha256':h(a),'metric_rows_content_sha256':'EXPECTED'}))
            class FullSizeSentinel:
                def __len__(self): return 120000
            args=['day_bootstrap.py','--manifest',str(m),'--database',str(root/'db'),'--quality',str(q),'--aggregate',str(a),'--output',str(root/'out'),'--bootstrap','100']
            for flags,errors in (({'identity_or_status_mismatch':1},[]),({},[{'error':'fixture'}])):
                fake=types.SimpleNamespace(read_manifest=lambda *a:({},[]),load_metrics=lambda *a:(FullSizeSentinel(),flags,'EXPECTED',errors))
                with mock.patch.object(day.sys,'argv',args),mock.patch.object(day,'load_aggregate',return_value=fake):
                    with self.assertRaisesRegex(ValueError,'metrics snapshot'):
                        day.main()
                self.assertFalse((root/'out').exists())


if __name__ == '__main__':
    unittest.main()
