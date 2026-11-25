"""Synthetic fixtures only: no study values, captures, or runtime metadata."""
import copy
import contextlib
import importlib.util
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import build_day_report as report


def fixture():
    domains = ['a.example', 'b.example']
    rows, summaries = [], []
    for defense in report.DEFENSES:
        for metric in report.METRICS:
            unit = 'bytes' if metric == 'ip_bytes' else 'seconds'
            for domain in domains:
                eligible = domain == domains[0]
                r = {'defense': defense, 'metric': metric, 'domain': domain, 'unit': unit,
                     'status': 'eligible' if eligible else 'fewer_than_two_utc_days',
                     'defense_days': '3' if eligible else '1', 'baseline_days': '3',
                     'defense_valid_metric_n': '400', 'baseline_valid_metric_n': '400',
                     'defense_invalid_metric_n': '0', 'baseline_invalid_metric_n': '0',
                     'defense_missing_record_n': '0', 'baseline_missing_record_n': '0',
                     'defense_missing_epoch_n': '0', 'baseline_missing_epoch_n': '0',
                     'defense_n_with_epoch': '400', 'baseline_n_with_epoch': '400',
                     'defense_mean': '2', 'baseline_mean': '1', 'absolute_difference': '1',
                     'overhead_pct': '100',
                     'day_bootstrap_percentile95_low_pct': '90' if eligible else '',
                     'day_bootstrap_percentile95_high_pct': '110' if eligible else '',
                     'finite_draws': '2000' if eligible else '',
                     'fewer_than_5_days_in_either_cohort': 'True' if eligible else '',
                     'fewer_than_30_days_in_either_cohort': 'True' if eligible else ''}
                rows.append(r)
            summaries.append({'defense': defense, 'metric': metric, 'unit': unit,
                              'eligible_domains': '1', 'expected_domains': '2', 'all_domains_eligible': 'False',
                              'eligible_domains_with_fewer_than_5_days_in_either_cohort': '1',
                              'eligible_domains_with_fewer_than_30_days_in_either_cohort': '1',
                              'eligible_domains_with_missing_epochs': '0',
                              'status_counts_json': json.dumps({'eligible': 1, 'fewer_than_two_utc_days': 1}),
                              'equal_domain_mean_overhead_pct_eligible_subset': '100',
                              'day_bootstrap_percentile95_low_pct_eligible_subset': '90',
                              'day_bootstrap_percentile95_high_pct_eligible_subset': '110',
                              'finite_bootstrap_draws': '2000'})
    return domains, rows, summaries


class DomainSummaryTests(unittest.TestCase):
    def setUp(self):
        self.domains, self.rows, self.summaries = fixture()

    def valid(self):
        return report.validate_rows(self.rows, self.summaries, self.domains, 2000)

    def test_subset_result_and_explicit_scientific_caveats(self):
        result = self.valid()
        proof = {'bootstrap_replicates': 2000, 'manifest_sha256': 'a'*64,
                 'metric_rows_content_sha256': 'b'*64, 'bootstrap_code_sha256': 'c'*64,
                 'seed': 1, 'numpy_version': 'synthetic'}
        text = report.render(result, proof, {k: 'f'*64 for k in report.TABLES}, expected=2)
        self.assertIn('1/2', text)
        self.assertIn('fewer than all domains eligible', text)
        self.assertIn('not application-completion', text)
        self.assertIn('fewer than two utc days: 1', text)
        self.assertIn('does not itself prove independent execution', text)

    def test_no_eligible_subset_is_unavailable_not_zero(self):
        for row in self.rows:
            if row['status'] == 'eligible':
                row.update(status='fewer_than_two_utc_days', defense_days='1',
                           day_bootstrap_percentile95_low_pct='', day_bootstrap_percentile95_high_pct='',
                           finite_draws='', fewer_than_5_days_in_either_cohort='',
                           fewer_than_30_days_in_either_cohort='')
        for row in self.summaries:
            row.update(eligible_domains='0', eligible_domains_with_fewer_than_5_days_in_either_cohort='0',
                       eligible_domains_with_fewer_than_30_days_in_either_cohort='0',
                       status_counts_json=json.dumps({'fewer_than_two_utc_days': 2}),
                       equal_domain_mean_overhead_pct_eligible_subset='',
                       day_bootstrap_percentile95_low_pct_eligible_subset='',
                       day_bootstrap_percentile95_high_pct_eligible_subset='', finite_bootstrap_draws='0')
        result = self.valid()
        proof = {'bootstrap_replicates': 2000, 'manifest_sha256': 'a'*64,
                 'metric_rows_content_sha256': 'b'*64, 'bootstrap_code_sha256': 'c'*64,
                 'seed': 1, 'numpy_version': 'synthetic'}
        text = report.render(result, proof, {k: 'f'*64 for k in report.TABLES}, expected=2)
        self.assertIn('0/2', text)
        self.assertIn('Unavailable', text)

    def test_missing_or_duplicate_domain_rejected(self):
        self.rows.pop()
        with self.assertRaisesRegex(ValueError, 'coverage'):
            self.valid()
        self.rows.append(copy.deepcopy(self.rows[0]))
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            self.valid()

    def test_metric_unit_mismatch_rejected(self):
        self.rows[0]['unit'] = 'seconds'
        with self.assertRaisesRegex(ValueError, 'Unexpected'):
            self.valid()

    def test_invalid_or_inverted_range_rejected(self):
        self.rows[0]['day_bootstrap_percentile95_low_pct'] = '200'
        with self.assertRaisesRegex(ValueError, 'Invalid eligible'):
            self.valid()

    def test_summary_point_must_equal_equal_domain_mean(self):
        self.summaries[0]['equal_domain_mean_overhead_pct_eligible_subset'] = '900'
        with self.assertRaisesRegex(ValueError, 'point does not match'):
            self.valid()

    def test_few_day_warnings_are_checked(self):
        self.rows[0]['fewer_than_5_days_in_either_cohort'] = 'False'
        with self.assertRaisesRegex(ValueError, 'few-day'):
            self.valid()

    def test_missing_epoch_and_cohort_counts_are_checked(self):
        self.rows[0]['defense_missing_epoch_n'] = '1'
        with self.assertRaisesRegex(ValueError, 'cohort counts'):
            self.valid()
        self.rows[0]['defense_n_with_epoch'] = '399'
        with self.assertRaisesRegex(ValueError, 'missing-epoch'):
            self.valid()

    def test_wrong_ineligibility_reason_is_rejected(self):
        self.rows[1]['status'] = 'no_epoch_eligible_observations'
        with self.assertRaisesRegex(ValueError, 'No-epoch'):
            self.valid()

    def test_mismatching_status_counts_rejected(self):
        self.summaries[0]['status_counts_json'] = json.dumps({'eligible': 2})
        with self.assertRaisesRegex(ValueError, 'eligibility'):
            self.valid()

    def test_impossible_finite_draw_count_rejected(self):
        self.summaries[0]['finite_bootstrap_draws'] = '2001'
        with self.assertRaisesRegex(ValueError, 'Too many'):
            self.valid()

    def test_full_50_domain_shape_has_every_required_mode_and_metric(self):
        original_rows = copy.deepcopy(self.rows)
        domains = [f'fixture-{i:02d}.example' for i in range(50)]
        self.rows = []
        for template in original_rows:
            if template['domain'] != 'a.example':
                continue
            for d in domains:
                row = copy.deepcopy(template)
                row['domain'] = d
                self.rows.append(row)
        for row in self.summaries:
            row.update(eligible_domains='50', expected_domains='50', all_domains_eligible='True',
                       eligible_domains_with_fewer_than_5_days_in_either_cohort='50',
                       eligible_domains_with_fewer_than_30_days_in_either_cohort='50',
                       status_counts_json=json.dumps({'eligible': 50}))
        result = report.validate_rows(self.rows, self.summaries, domains, 2000)
        self.assertEqual(len(self.rows), 500)
        self.assertEqual(len(result), 10)


class BindingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.p = Path(self.tmp.name)
        self.manifest = self.p/'manifest'; self.manifest.write_bytes(b'synthetic manifest')
        self.aggregate = self.p/'aggregate'; self.aggregate.write_bytes(b'synthetic aggregator')
        self.day_code = self.p/'day'; self.day_code.write_bytes(b'synthetic day code')
        self.first = self.p/'first'; self.first.mkdir()
        self.second = self.p/'second'; self.second.mkdir()
        self.m = report.sha(self.manifest); self.a = report.sha(self.aggregate); self.d = report.sha(self.day_code)
        self.metric = 'b'*64
        self.quality = self.p/'quality.json'
        self.quality.write_text(json.dumps({'status': 'complete', 'manifest_sessions': 120000,
             'accepted_metric_rows': 120000, 'extractor_errors': 0, 'identity_or_other_flags': {},
             'manifest_sha256': self.m, 'analysis_script_sha256': self.a,
             'metric_rows_content_sha256': self.metric,
             'counts_by_condition': {m: 20000 for m in report.MODES}}))
        proof = {'status': 'complete', 'metric_rows': 120000, 'manifest_sha256': self.m,
                 'aggregate_code_sha256': self.a, 'bootstrap_code_sha256': self.d,
                 'metric_rows_content_sha256': self.metric, 'bootstrap_replicates': 2000,
                 'seed': 7, 'numpy_version': 'synthetic', 'python_version': 'synthetic'}
        for directory in (self.first, self.second):
            (directory/'utc-day-cluster-provenance.json').write_text(json.dumps(proof))
            for name in report.TABLES:
                (directory/name).write_text('synthetic\n')
        self.patchers = [mock.patch.object(report, 'MANIFEST_SHA', self.m),
                         mock.patch.object(report, 'AGGREGATE_SHA', self.a),
                         mock.patch.object(report, 'DAY_CODE_SHA', self.d),
                         mock.patch.object(report, 'manifest_domains', return_value=['a.example', 'b.example'])]
        for p in self.patchers:
            p.start(); self.addCleanup(p.stop)

    def bind(self):
        return report.provenance_inputs(self.manifest, self.quality, self.aggregate,
                                        self.day_code, self.first, self.second)

    def test_two_distinct_matching_runs_pass(self):
        domains, _, _, hashes = self.bind()
        self.assertEqual(len(domains), 2)
        self.assertEqual(len(hashes), 2)

    def test_same_directory_rejected(self):
        self.second = self.first
        with self.assertRaisesRegex(ValueError, 'distinct output'):
            self.bind()

    def test_same_files_hardlinked_rejected(self):
        import os
        name = report.TABLES[0]
        (self.second/name).unlink()
        os.link(self.first/name, self.second/name)
        with self.assertRaisesRegex(ValueError, 'distinct, ordinary'):
            self.bind()

    def test_mismatched_csv_rejected(self):
        (self.second/report.TABLES[0]).write_text('different')
        with self.assertRaisesRegex(ValueError, 'output mismatch'):
            self.bind()

    def test_incomplete_quality_rejected(self):
        q = json.loads(self.quality.read_text()); q['accepted_metric_rows'] = 119999
        self.quality.write_text(json.dumps(q))
        with self.assertRaisesRegex(ValueError, 'incomplete'):
            self.bind()

    def test_mismatching_snapshot_rejected(self):
        p = self.second/'utc-day-cluster-provenance.json'
        proof = json.loads(p.read_text()); proof['metric_rows_content_sha256'] = 'c'*64
        p.write_text(json.dumps(proof))
        with self.assertRaisesRegex(ValueError, 'provenance'):
            self.bind()

    def test_python_build_strings_can_differ_but_version_must_match(self):
        for path, version in ((self.first, '3.9.1 (build A)'), (self.second, '3.9.1 (build B)')):
            p = path/'utc-day-cluster-provenance.json'
            proof = json.loads(p.read_text()); proof['python_version'] = version
            p.write_text(json.dumps(proof))
        self.bind()
        p = self.second/'utc-day-cluster-provenance.json'
        proof = json.loads(p.read_text()); proof['python_version'] = '3.10.0 (build C)'
        p.write_text(json.dumps(proof))
        with self.assertRaisesRegex(ValueError, 'Python versions'):
            self.bind()

    def test_mismatching_source_code_rejected(self):
        self.day_code.write_text('not the verified code')
        with self.assertRaisesRegex(ValueError, 'UTC-day code'):
            self.bind()


@unittest.skipUnless(os.environ.get('NEQO_DAY_CODE'), 'set NEQO_DAY_CODE for optional end-to-end test')
class EndToEndSyntheticTests(unittest.TestCase):
    def test_independently_rerun_day_code_and_generate_validated_note(self):
        # 120,000 synthetic keys use two shared fabricated rows. TemporaryDirectory
        # removes every artifact on exit. This never contacts Drive or reads PCAPs.
        code = Path(os.environ['NEQO_DAY_CODE']).resolve()
        spec = importlib.util.spec_from_file_location('synthetic_day_processor', code)
        day = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(day)
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            manifest, aggregate, database = p/'manifest', p/'aggregate', p/'metrics'
            manifest.write_bytes(b'synthetic manifest'); aggregate.write_bytes(b'synthetic aggregator')
            database.write_bytes(b'no actual database is read')
            manifest_sha, aggregate_sha, day_sha = report.sha(manifest), report.sha(aggregate), report.sha(code)
            metric_hash = 'b'*64
            quality = p/'quality.json'
            quality.write_text(json.dumps({'status': 'complete', 'manifest_sessions': 120000,
                 'accepted_metric_rows': 120000, 'extractor_errors': 0, 'identity_or_other_flags': {},
                 'manifest_sha256': manifest_sha, 'analysis_script_sha256': aggregate_sha,
                 'metric_rows_content_sha256': metric_hash,
                 'counts_by_condition': {m: 20000 for m in report.MODES}}))
            domains = [f'fixture-{i:02d}.example' for i in range(50)]
            rec1 = {'ip_valid': True, 'ip_bytes': 10, 'strict_order': 'True',
                    'span_seconds': 1.0, 'first_epoch': '86400.000000001'}
            rec2 = {'ip_valid': True, 'ip_bytes': 20, 'strict_order': 'True',
                    'span_seconds': 2.0, 'first_epoch': '172800.000000001'}
            records = {(m, d, s): (rec1 if s % 2 else rec2)
                       for m in report.MODES for d in domains for s in range(1, 401)}
            class FakeAggregate:
                CONDITIONS = report.MODES
                @staticmethod
                def read_manifest(*args): return {}, domains
                @staticmethod
                def load_metrics(*args): return records, {}, metric_hash, []
            for label in ('run1', 'run2'):
                args = ['day_bootstrap.py', '--manifest', str(manifest), '--database', str(database),
                        '--quality', str(quality), '--aggregate', str(aggregate), '--output', str(p/label),
                        '--bootstrap', '100', '--seed', '7']
                with mock.patch.object(day, 'load_aggregate', return_value=FakeAggregate()), \
                     mock.patch.object(sys, 'argv', args), contextlib.redirect_stdout(io.StringIO()):
                    day.main()
            with mock.patch.object(report, 'MANIFEST_SHA', manifest_sha), \
                 mock.patch.object(report, 'AGGREGATE_SHA', aggregate_sha), \
                 mock.patch.object(report, 'DAY_CODE_SHA', day_sha), \
                 mock.patch.object(report, 'manifest_domains', return_value=domains):
                got_domains, _, proof, hashes = report.provenance_inputs(
                    manifest, quality, aggregate, code, p/'run1', p/'run2')
                rows = report.read_csv(p/'run1'/report.TABLES[0])
                summaries = report.read_csv(p/'run1'/report.TABLES[1])
                validated = report.validate_rows(rows, summaries, got_domains, 100)
                text = report.render(validated, proof, hashes)
                self.assertIn('50/50', text)
                self.assertIn('not application-completion', text)


if __name__ == '__main__':
    unittest.main()
