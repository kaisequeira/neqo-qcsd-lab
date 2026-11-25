"""Fabricated, non-study fixtures for the final bundle safeguards."""
import csv
import hashlib
import io
import json
from pathlib import Path
import sqlite3
import tempfile
from types import SimpleNamespace
import unittest
import zipfile

import build_bundle as b


def sha(data):
    return hashlib.sha256(data).hexdigest()


class BundleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.manifest_path = self.root / 'manifest.csv'
        self.rows = []
        for mode in b.MODES:
            for session in (1, 2):
                self.rows.append({'defense': mode, 'domain': 'fixture.invalid', 'session': str(session),
                                  'filename': 'session-%03d.pcap' % session,
                                  'drive_file_id': mode + str(session), 'sha256': sha((mode + str(session)).encode()),
                                  'size': str(100 + session)})
        with self.manifest_path.open('w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=self.rows[0], lineterminator='\n')
            writer.writeheader()
            writer.writerows(self.rows)
        self.manifest_sha = b.sha_file(self.manifest_path)
        self.manifest, self.domains = b.read_manifest(self.manifest_path, expected_domains=1, sessions=2,
                                                      expected_sha=self.manifest_sha)
        self.db = sqlite3.connect(self.root / 'metrics.sqlite3')
        self.db.execute('CREATE TABLE metadata (key TEXT PRIMARY KEY,value TEXT NOT NULL)')
        self.db.execute('CREATE TABLE errors (defense TEXT,domain TEXT,session INTEGER,error TEXT,updated REAL)')
        self.db.execute('CREATE TABLE metrics (defense TEXT,domain TEXT,session INTEGER,drive_file_id TEXT,sha256 TEXT,result_json TEXT, PRIMARY KEY(defense,domain,session))')
        self.db.executemany('INSERT INTO metadata VALUES (?,?)', [('manifest_sha256', self.manifest_sha), ('metrics_schema', b.SCHEMA)])
        for row in reversed(self.rows):
            vals = {k: 0 for k in b.METRIC_FIELDS}
            vals.update(defense=row['defense'], domain=row['domain'], session=int(row['session']),
                        filename=row['filename'], drive_file_id=row['drive_file_id'], sha256=row['sha256'],
                        capture_bytes=int(row['size']), capture_type='pcap', encapsulation='ether',
                        packet_count=2, packet_bytes=100, ip_bytes=72, ip_valid=True,
                        udp443_direction_valid=True, udp443_up_ip_bytes=40, udp443_down_ip_bytes=32,
                        udp443_candidate_overflow=False, span_seconds=0.5, first_epoch='1.0',
                        last_epoch='1.5', strict_order='True', source='local', status='ok', error='')
            self.db.execute('INSERT INTO metrics VALUES (?,?,?,?,?,?)',
                            (row['defense'], row['domain'], int(row['session']), row['drive_file_id'],
                             row['sha256'], json.dumps(vals, sort_keys=True)))
        self.db.commit()
        self.snapshot = self.calc_snapshot()

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def calc_snapshot(self):
        h = hashlib.sha256()
        for row in self.db.execute(b.QUERY):
            # Independent copy of the public aggregate canonical-row algorithm.
            h.update((json.dumps(list(row), ensure_ascii=False, separators=(',', ':')) + '\n').encode('utf-8'))
        return h.hexdigest()

    def clean_fixture(self):
        """Fabricated one-domain data with a single defense-side selection."""
        detail, primary, summaries = [], [], []
        for mode in b.MODES[1:]:
            for metric in ('ip_bytes', 'observed_span'):
                unit = 'bytes' if metric == 'ip_bytes' else 'seconds'
                row = {'defense': mode, 'metric': metric, 'domain': 'fixture.invalid', 'unit': unit,
                       'baseline_expected_n': 2, 'defense_expected_n': 2,
                       'baseline_full_n': 2, 'defense_full_n': 2, 'baseline_clean_n': 2, 'defense_clean_n': 1,
                       'baseline_removed_by_clean_filter': 0, 'defense_removed_by_clean_filter': 1,
                       'baseline_primary_exclusions': '{}', 'defense_primary_exclusions': '{}',
                       'baseline_clean_filter_reasons': '{}',
                       'defense_clean_filter_reasons': '{"direction_invalid_or_ambiguous": 1}',
                       'full_baseline_mean': 100, 'full_defense_mean': 150,
                       'full_absolute_difference': 50, 'full_overhead_pct': 50,
                       'clean_baseline_mean': 100, 'clean_defense_mean': 125,
                       'clean_absolute_difference': 25, 'clean_overhead_pct': 25,
                       'clean_minus_full_overhead_percentage_points': -25}
                detail.append({k: str(v) for k, v in row.items()})
                primary.append({'defense': mode, 'metric': metric, 'domain': 'fixture.invalid',
                                'baseline_n': '2', 'defense_n': '2', 'baseline_mean': '100',
                                'defense_mean': '150', 'absolute_difference': '50', 'overhead_pct': '50'})
                s = {'defense': mode, 'metric': metric, 'unit': unit, 'expected_domains': '1',
                     'common_domain_coverage_complete': 'True',
                     'clean_minus_full_common_macro_overhead_pct_percentage_points': '-25',
                     'clean_minus_full_common_pooled_cohort_mean_overhead_pct_percentage_points': '-25'}
                for name, pct, dm in (('full_available', 50, 150), ('full_common', 50, 150),
                                      ('clean_available', 25, 125), ('clean_common', 25, 125)):
                    s.update({name + '_domains': '1', name + '_macro_overhead_pct': str(pct),
                              name + '_pooled_cohort_mean_overhead_pct': str(pct),
                              name + '_baseline_equal_domain_mean': '100',
                              name + '_defense_equal_domain_mean': str(dm)})
                summaries.append(s)
        quality = {'status': 'complete', 'manifest_sha256': self.manifest_sha,
                   'metric_rows_content_sha256': self.snapshot, 'accepted_metric_rows': 12,
                   'analysis_script_sha256': b.AGGREGATE_SHA}
        clean_q = {'status': 'complete', 'manifest_sha256': self.manifest_sha,
                   'metric_rows_content_sha256': self.snapshot, 'accepted_records': 12,
                   'extractor_errors': 0, 'identity_or_other_flags': {},
                   'aggregate_library_sha256': b.AGGREGATE_SHA, 'analysis_script_sha256': 'b' * 64}
        return detail, summaries, primary, quality, clean_q

    def domain_fixture(self):
        """Small synthetic complete domain sensitivity, with one conditional row."""
        domain, summary, quality, output = [], [], {
            'status': 'complete', 'manifest_sha256': self.manifest_sha,
            'metric_rows_content_sha256': self.snapshot, 'accepted_metric_rows': 12,
            'analysis_script_sha256': b.AGGREGATE_SHA}, []
        for mode in b.MODES[1:]:
            for metric in ('ip_bytes', 'observed_span'):
                summary.append({'defense': mode, 'metric': metric, 'domains': 1,
                                'provisional': 'False', 'macro_overhead_pct': 50})
                domain.append({'defense': mode, 'metric': metric, 'domain': 'fixture.invalid'})
                output.append({'defense': mode, 'metric': metric,
                               'unit': 'bytes' if metric == 'ip_bytes' else 'seconds',
                               'expected_domains': 1, 'eligible_domains': 1, 'unavailable_domains': '[]',
                               'requested_replicates': 200, 'valid_replicates': 200,
                               'undefined_replicates': 0, 'undefined_domain_occurrences': 0,
                               'macro_overhead_pct': 50, 'domain_only_valid_replicates': 200,
                               'two_stage_percentile_95_low_pct': 10, 'two_stage_percentile_95_high_pct': 90,
                               'domain_only_percentile_95_low_pct': 20, 'domain_only_percentile_95_high_pct': 80,
                               'status': 'complete'})
        output[0].update(valid_replicates=199, undefined_replicates=1, undefined_domain_occurrences=2,
                         status='conditional_on_finite_draws')
        def table(rows):
            stream = io.StringIO(newline='')
            writer = csv.DictWriter(stream, fieldnames=list(rows[0]), lineterminator='\n')
            writer.writeheader(); writer.writerows(rows)
            return stream.getvalue().encode()
        qbytes, sbytes, dbytes, obytes = json.dumps(quality).encode(), table(summary), table(domain), table(output)
        script = b'# synthetic domain bootstrap source\n'
        provenance = {'status': 'review_required', 'manifest_sha256': self.manifest_sha,
                      'primary_aggregate_sha256': b.AGGREGATE_SHA, 'metric_rows_content_sha256': self.snapshot,
                      'analysis_script_sha256': sha(script), 'primary_summary_sha256': sha(sbytes),
                      'primary_quality_sha256': sha(qbytes), 'primary_domain_table_sha256': sha(dbytes),
                      'primary_domain_rows_checked': 10, 'primary_domain_rows_unavailable': 0,
                      'output_csv_sha256': sha(obytes), 'seed': 20261125, 'replicates': 200,
                      'captured_records': 12, 'numpy_version': 'synthetic', 'python_version': 'synthetic',
                      'random_generator': 'synthetic', 'method': 'synthetic', 'scope': 'synthetic'}
        return quality, provenance, script, qbytes, sbytes, dbytes, obytes, output

    def test_domain_bootstrap_binds_provenance_counts_and_primary_points(self):
        quality, provenance, script, qbytes, sbytes, dbytes, obytes, rows = self.domain_fixture()
        manifest = self.manifest_path.read_bytes()
        b.validate_domain_bootstrap(provenance, quality, sha(script), obytes, qbytes, sbytes, dbytes, manifest)
        for field, value in (('metric_rows_content_sha256', '0'*64), ('analysis_script_sha256', 'f'*64),
                             ('primary_summary_sha256', '0'*64), ('primary_domain_rows_checked', 9),
                             ('output_csv_sha256', '0'*64), ('status', 'complete')):
            with self.subTest(field=field), self.assertRaises(ValueError):
                b.validate_domain_bootstrap({**provenance, field: value}, quality, sha(script),
                                            obytes, qbytes, sbytes, dbytes, manifest)
        for field, value in (('macro_overhead_pct', 51), ('unit', 'bad'), ('valid_replicates', 201),
                             ('undefined_domain_occurrences', 0), ('status', 'complete'),
                             ('two_stage_percentile_95_high_pct', 0), ('eligible_domains', 0)):
            altered = [dict(r) for r in rows]; altered[0][field] = value
            stream = io.StringIO(newline=''); writer = csv.DictWriter(stream, fieldnames=list(rows[0]), lineterminator='\n')
            writer.writeheader(); writer.writerows(altered); data = stream.getvalue().encode()
            with self.subTest(field=field), self.assertRaises(ValueError):
                b.validate_domain_bootstrap({**provenance, 'output_csv_sha256': sha(data)}, quality,
                                            sha(script), data, qbytes, sbytes, dbytes, manifest)
        with self.assertRaisesRegex(ValueError, 'provenance'):
            b.validate_domain_bootstrap(provenance, quality, sha(script), obytes, qbytes, sbytes, dbytes,
                                        manifest + b'changed')
        # Even matching forged hashes must not hide a different identity grid.
        wrong_manifest = manifest.replace(b'fixture.invalid', b'other.invalid', 1)
        wrong_quality = {**quality, 'manifest_sha256': sha(wrong_manifest)}
        wrong_qbytes = json.dumps(wrong_quality).encode()
        wrong_provenance = {**provenance, 'manifest_sha256': sha(wrong_manifest),
                            'primary_quality_sha256': sha(wrong_qbytes)}
        with self.assertRaisesRegex(ValueError, 'manifest mismatch'):
            b.validate_domain_bootstrap(wrong_provenance, wrong_quality, sha(script), obytes,
                                        wrong_qbytes, sbytes, dbytes, wrong_manifest)
        wrong_domain = dbytes.replace(b'fixture.invalid', b'other.invalid', 1)
        with self.assertRaisesRegex(ValueError, 'primary domain coverage'):
            b.validate_domain_bootstrap({**provenance, 'primary_domain_table_sha256': sha(wrong_domain)},
                                        quality, sha(script), obytes, qbytes, sbytes, wrong_domain, manifest)

    def test_day_packet_eligibility_snapshot_counts_and_status(self):
        quality = {'accepted_metric_rows': 12, 'metric_rows_content_sha256': self.snapshot}
        result = {'status': 'passed', 'records': 12, 'metric_rows_content_sha256': self.snapshot,
                  'packet_count_categories': {'valid': 12}, 'scope': b.DAY_ELIGIBILITY_SCOPE}
        b.validate_day_packet_eligibility(result, quality)
        review = {**result, 'status': 'review_required', 'packet_count_categories': {'valid': 11, 'nonpositive': 1}}
        b.validate_day_packet_eligibility(review, quality)
        for changes in ({'status': 'passed', 'packet_count_categories': {'valid': 11, 'nonpositive': 1}},
                        {'metric_rows_content_sha256': '0'*64}, {'records': 11},
                        {'packet_count_categories': {'valid': 13}}, {'packet_count_categories': {'valid': True}},
                        {'packet_count_categories': {'valid': 11, 'unknown': 1}}, {'scope': ''}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                b.validate_day_packet_eligibility({**result, **changes}, quality)

    def test_arithmetic_audit_binds_coverage_scope_snapshot_and_tables(self):
        quality, _, _, _, sbytes, dbytes, _, _ = self.domain_fixture()
        result = {'status': 'passed', 'scope': b.ARITHMETIC_AUDIT_SCOPE,
                  'manifest_sha256': self.manifest_sha, 'aggregator_sha256': b.AGGREGATE_SHA,
                  'metric_rows_content_sha256': self.snapshot, 'captures': 12, 'domains': 1,
                  'domain_table_sha256': sha(dbytes), 'overall_table_sha256': sha(sbytes),
                  'domain_rows_checked': 10, 'overall_rows_checked': 10,
                  'unavailable_domain_rows': 0, 'unavailable_overall_rows': 0, 'differences': []}
        b.validate_arithmetic_audit(result, quality, dbytes, sbytes, expected_domains=1)
        unavailable = {**result, 'status': 'passed_with_unavailable', 'domain_rows_checked': 8,
                       'overall_rows_checked': 8, 'unavailable_domain_rows': 2, 'unavailable_overall_rows': 2}
        b.validate_arithmetic_audit(unavailable, quality, dbytes, sbytes, expected_domains=1)
        for changes in ({'status': 'passed_with_unavailable'}, {'scope': 'PCAPs independently checked'},
                        {'metric_rows_content_sha256': '0'*64}, {'captures': 11},
                        {'domain_rows_checked': 9}, {'domain_rows_checked': True},
                        {'overall_table_sha256': '0'*64}, {'differences': [{'field': 'overhead_pct'}]},
                        {'status': 'discrepancies'}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                b.validate_arithmetic_audit({**result, **changes}, quality, dbytes, sbytes, expected_domains=1)

    def test_clean_sensitivity_provenance_and_arithmetic(self):
        detail, summaries, primary, quality, clean_q = self.clean_fixture()
        b.validate_clean_provenance(clean_q, quality, 'b' * 64, expected_rows=12)
        b.validate_clean_tables(detail, summaries, primary, self.domains, sessions=2)
        for changes in ({'metric_rows_content_sha256': '0' * 64}, {'status': 'partial'},
                        {'aggregate_library_sha256': 'a' * 64}, {'extractor_errors': 1}):
            with self.assertRaisesRegex(ValueError, 'provenance'):
                b.validate_clean_provenance({**clean_q, **changes}, quality, 'b' * 64, expected_rows=12)
        cases = [('defense_clean_n', '3'), ('defense_clean_filter_reasons', '{}'), ('unit', 'mismatched'),
                 ('clean_overhead_pct', '999'), ('full_defense_mean', '999'),
                 ('clean_minus_full_overhead_percentage_points', '0')]
        for field, value in cases:
            altered = [dict(x) for x in detail]; altered[0][field] = value
            with self.assertRaises(ValueError, msg=field):
                b.validate_clean_tables(altered, summaries, primary, self.domains, sessions=2)
        altered = [dict(x) for x in summaries]; altered[0]['clean_available_domains'] = '0'
        with self.assertRaisesRegex(ValueError, 'domain count'):
            b.validate_clean_tables(detail, altered, primary, self.domains, sessions=2)
        altered = [dict(x) for x in summaries]; altered[0]['unit'] = 'mismatched'
        with self.assertRaisesRegex(ValueError, 'unit'):
            b.validate_clean_tables(detail, altered, primary, self.domains, sessions=2)
        with self.assertRaisesRegex(ValueError, 'incomplete or duplicated'):
            b.validate_clean_tables(detail[:-1], summaries, primary, self.domains, sessions=2)

    def test_clean_sensitivity_can_report_an_unavailable_domain(self):
        detail, summaries, primary, _, _ = self.clean_fixture()
        row, summary = detail[0], summaries[0]
        row.update(defense_clean_n='0', defense_removed_by_clean_filter='2',
                   defense_clean_filter_reasons='{"direction_invalid_or_ambiguous": 2}',
                   clean_minus_full_overhead_percentage_points='')
        for field in ('baseline_mean', 'defense_mean', 'absolute_difference', 'overhead_pct'):
            row['clean_' + field] = ''
        summary['common_domain_coverage_complete'] = 'False'
        for name in ('clean_available', 'full_common', 'clean_common'):
            summary[name + '_domains'] = '0'
            for field in ('macro_overhead_pct', 'pooled_cohort_mean_overhead_pct',
                          'baseline_equal_domain_mean', 'defense_equal_domain_mean'):
                summary[name + '_' + field] = ''
        for field in ('macro_overhead_pct', 'pooled_cohort_mean_overhead_pct'):
            summary['clean_minus_full_common_' + field + '_percentage_points'] = ''
        b.validate_clean_tables(detail, summaries, primary, self.domains, sessions=2)

    def test_complete_snapshot_binds_all_rows_and_conditions(self):
        result = b.verify_database(self.db, self.manifest, self.manifest_sha, self.snapshot)
        self.assertEqual(result['rows'], 12)
        self.assertEqual(result['metric_rows_content_sha256'], self.snapshot)
        self.assertEqual(result['counts_by_condition'], {mode: 2 for mode in b.MODES})

    def test_incomplete_or_error_snapshot_is_rejected(self):
        self.db.execute('DELETE FROM metrics WHERE defense=? AND session=?', ('front', 1))
        with self.assertRaisesRegex(ValueError, 'Incomplete'):
            b.verify_database(self.db, self.manifest, self.manifest_sha, self.snapshot)
        self.db.rollback()
        self.db.execute('INSERT INTO errors VALUES (?,?,?,?,?)', ('front', 'fixture.invalid', 1, 'synthetic', 0.))
        with self.assertRaisesRegex(ValueError, 'errors'):
            b.verify_database(self.db, self.manifest, self.manifest_sha, self.snapshot)

    def test_manifest_identity_and_snapshot_tampering_are_rejected(self):
        self.db.execute("UPDATE metrics SET drive_file_id='other' WHERE defense='front' AND session=1")
        with self.assertRaisesRegex(ValueError, 'identity'):
            b.verify_database(self.db, self.manifest, self.manifest_sha, self.snapshot)
        self.db.rollback()
        with self.assertRaisesRegex(ValueError, 'snapshot digest'):
            b.verify_database(self.db, self.manifest, self.manifest_sha, '0' * 64)

    def test_unknown_fields_paths_and_private_source_are_rejected(self):
        row = list(self.db.execute(b.QUERY).fetchone())
        x = json.loads(row[-1]); x['unreviewed_field'] = 'x'; row[-1] = json.dumps(x)
        with self.assertRaisesRegex(ValueError, 'Unexpected metric fields'):
            b.metric_object(row, self.manifest)
        x.pop('unreviewed_field'); x['encapsulation'] = '/Users/example/private'; row[-1] = json.dumps(x)
        with self.assertRaisesRegex(ValueError, 'Machine path'):
            b.metric_object(row, self.manifest)
        x['encapsulation'] = 'ether'; x['source'] = 'private-token'; row[-1] = json.dumps(x)
        with self.assertRaisesRegex(ValueError, 'contents'):
            b.metric_object(row, self.manifest)

    def test_csv_and_canonical_jsonl_recreate_exact_snapshot(self):
        path = self.root / 'synthetic-metrics.zip'
        hashes = {}
        with zipfile.ZipFile(path, 'x', compression=zipfile.ZIP_DEFLATED) as z:
            b.write_metrics(z, self.db, self.manifest, self.snapshot, hashes)
        with zipfile.ZipFile(path) as z:
            canonical = z.read('measurements/session-metrics-canonical.jsonl')
            csv_bytes = z.read('measurements/session-metrics.csv')
            self.assertEqual(sha(canonical), self.snapshot)
            self.assertEqual(sha(csv_bytes), hashes['measurements/session-metrics.csv'])
            decoded = [json.loads(line) for line in canonical.splitlines()]
            expected = [list(x) for x in self.db.execute(b.QUERY)]
            self.assertEqual(decoded, expected)
            table = list(csv.DictReader(csv_bytes.decode().splitlines()))
            self.assertEqual(len(table), 12)
            self.assertEqual({r['defense'] for r in table}, set(b.MODES))
            self.assertTrue(all('private' not in line for line in csv_bytes.decode().splitlines()))

    def test_synthetic_end_to_end_zip_contains_no_packet_data(self):
        ag, de, fi, day = [self.root / x for x in ('aggregate', 'descriptive', 'figures', 'day')]
        for p in (ag, de, fi, day): p.mkdir()
        for folder, names in ((ag, b.AGG_FILES), (de, b.DESC_FILES), (fi, b.FIG_FILES), (day, b.DAY_FILES)):
            for name in names:
                content = b'<svg>fixture</svg>' if name.endswith('.svg') else (b'%PDF fixture' if name.endswith('.pdf') else b'{}\n')
                (folder / name).write_bytes(content)
        resources = self.root / 'resources.csv'; resources.write_text('domain,url\nfixture.invalid,https://fixture.invalid/a\n')
        census = self.root / 'census.json'; census.write_text('{"status":"synthetic"}\n')
        report = b'# SYNTHETIC REPORT - NOT STUDY DATA\n'
        args = SimpleNamespace(output=self.root/'complete-synthetic.zip', manifest=self.manifest_path,
                               resources=resources, aggregate=ag, descriptive=de, figures=fi, day=day,
                               census_qa=census, reviewed_report_sha256=sha(report))
        result = b.verify_database(self.db, self.manifest, self.manifest_sha, self.snapshot)
        hashes = b.assemble_zip(args, self.db, self.manifest, {'metric_rows_content_sha256': self.snapshot},
                                result, report, '# SYNTHETIC DRAFT', synthetic=True)
        b.verify_zip(args.output, strict=True)
        with zipfile.ZipFile(args.output) as z:
            self.assertIn(b'SYNTHETIC FIXTURE', z.read('README.md'))
            provenance = json.loads(z.read('bundle-provenance.json'))
            self.assertEqual(provenance['status'], 'synthetic_fixture')
            self.assertEqual(sha(z.read('measurements/session-metrics-canonical.jsonl')), self.snapshot)
            self.assertIn('results/independent-census-qa.json', z.namelist())
            self.assertFalse(any(n.endswith(('.pcap','.pcapng','.tar','.zst')) for n in z.namelist()))
            self.assertEqual(set(hashes) | {'SHA256SUMS.txt'}, set(z.namelist()))
            self.assertEqual(z.read('results/aggregate/README.md'), b.AGGREGATE_WARNING.encode())
            draft = z.read('report/canonical-review-draft.md')
            banner = b.DRAFT_WARNING.encode()
            self.assertTrue(draft.startswith(banner))
            self.assertEqual(draft[len(banner):], b'# SYNTHETIC DRAFT')
            self.assertEqual(provenance['canonical_generated_draft_sha256'], sha(draft[len(banner):]))
            self.assertEqual(provenance['domain_cluster_caveat_version'], b.CAVEAT_VERSION)
            content = {n: z.read(n) for n in z.namelist() if n != 'SHA256SUMS.txt'}
            for name in z.namelist():
                if name.endswith(('.json','.jsonl','.csv','.md','.txt','.svg')):
                    self.assertNotRegex(z.read(name).decode('utf-8'), b.PERSONAL_PATH)

        def write_mutation(name, altered):
            path = self.root / (name + '.zip')
            with zipfile.ZipFile(path, 'x') as z:
                for member, data in altered.items(): z.writestr(member, data)
                z.writestr('SHA256SUMS.txt', ''.join(sha(altered[n]) + '  ' + n + '\n' for n in sorted(altered)))
            return path

        # Recomputed outer checksums must not hide removal of the mandatory
        # warning, a modified banner, or a changed generated-draft suffix.
        for mutation in ('missing_caveat', 'changed_caveat', 'changed_banner', 'changed_draft'):
            altered = dict(content)
            if mutation == 'missing_caveat':
                del altered['results/aggregate/README.md']
            elif mutation == 'changed_caveat':
                altered['results/aggregate/README.md'] = b'no warning\n'
            elif mutation == 'changed_banner':
                altered['report/canonical-review-draft.md'] = b'no warning\n' + draft[len(banner):]
            else:
                altered['report/canonical-review-draft.md'] = draft + b'changed\n'
            with self.assertRaisesRegex(ValueError, 'Domain-cluster caveat'):
                b.verify_zip(write_mutation(mutation, altered), strict=True)

        # Prior-version bundles had no caveat member or banner; strict restore
        # remains compatible while newly generated bundles include both.
        legacy = dict(content)
        del legacy['results/aggregate/README.md']
        legacy['report/canonical-review-draft.md'] = draft[len(banner):]
        legacy_provenance = dict(provenance)
        del legacy_provenance['canonical_generated_draft_sha256']
        del legacy_provenance['domain_cluster_caveat_version']
        legacy['bundle-provenance.json'] = json.dumps(legacy_provenance).encode()
        b.verify_zip(write_mutation('legacy', legacy), strict=True)

    def test_optional_clean_sensitivity_in_strict_archive_and_restore_verifier(self):
        detail, summary, primary, quality, clean_q = self.clean_fixture()
        ag, de, fi, day, clean = [self.root / x for x in ('aggregate', 'descriptive', 'figures', 'day', 'clean')]
        for p in (ag, de, fi, day, clean): p.mkdir()
        for folder, names in ((ag, b.AGG_FILES), (de, b.DESC_FILES), (fi, b.FIG_FILES), (day, b.DAY_FILES)):
            for name in names:
                content = b'<svg>fixture</svg>' if name.endswith('.svg') else (b'%PDF fixture' if name.endswith('.pdf') else b'{}\n')
                (folder / name).write_bytes(content)
        def write_table(path, rows):
            with path.open('w', newline='') as f:
                w = csv.DictWriter(f, fieldnames=rows[0]); w.writeheader(); w.writerows(rows)
        (ag / 'quality.json').write_text(json.dumps(quality))
        write_table(ag / 'domain-overheads.csv', primary)
        script = self.root / 'clean_tuple_sensitivity.py'; script.write_text('# synthetic fixture script\n')
        clean_q['analysis_script_sha256'] = b.sha_file(script)
        (clean / b.CLEAN_FILES[0]).write_text(json.dumps(clean_q))
        write_table(clean / b.CLEAN_FILES[1], detail)
        write_table(clean / b.CLEAN_FILES[2], summary)
        resources = self.root / 'resources.csv'; resources.write_text('domain\nfixture.invalid\n')
        census = self.root / 'census.json'; census.write_text('{"status":"synthetic"}\n')
        report = b'# SYNTHETIC REPORT\n'
        args = SimpleNamespace(output=self.root/'clean-synthetic.zip', manifest=self.manifest_path,
                               resources=resources, aggregate=ag, descriptive=de, figures=fi, day=day,
                               census_qa=census, reviewed_report_sha256=sha(report),
                               clean_tuple=clean, clean_tuple_script=script)
        result = b.verify_database(self.db, self.manifest, self.manifest_sha, self.snapshot)
        b.assemble_zip(args, self.db, self.manifest, quality, result, report, '# SYNTHETIC DRAFT', synthetic=True)
        # restore_metrics calls this same strict verifier before opening the DB.
        b.verify_zip(args.output, strict=True)
        with zipfile.ZipFile(args.output) as z:
            content = {n: z.read(n) for n in z.namelist() if n != 'SHA256SUMS.txt'}
        self.assertEqual(content['results/clean-tuple/clean_tuple_sensitivity.py'], script.read_bytes())
        # Even when an archive's outer checksums are recomputed, the optional
        # set must be complete and internally tied to its included source.
        for mutation in ('partial', 'all_removed', 'source'):
            altered = dict(content)
            if mutation == 'partial':
                del altered['results/clean-tuple/overall-clean-tuple-sensitivity.csv']
            elif mutation == 'all_removed':
                altered = {n: v for n, v in altered.items() if not n.startswith('results/clean-tuple/')}
            else:
                altered['results/clean-tuple/clean_tuple_sensitivity.py'] += b'# changed\n'
            out = self.root / (mutation + '.zip')
            with zipfile.ZipFile(out, 'x') as z:
                for name, data in altered.items(): z.writestr(name, data)
                z.writestr('SHA256SUMS.txt', ''.join(sha(altered[n]) + '  ' + n + '\n' for n in sorted(altered)))
            with self.assertRaisesRegex(ValueError, 'Clean tuple'):
                b.verify_zip(out, strict=True)

    def test_optional_domain_bootstrap_archive_checks_complete_bound_set(self):
        quality, provenance, script, qbytes, sbytes, dbytes, obytes, _ = self.domain_fixture()
        ag, de, fi, day, domain = [self.root / x for x in ('aggregate', 'descriptive', 'figures', 'day', 'domain')]
        for p in (ag, de, fi, day, domain): p.mkdir()
        for folder, names in ((ag, b.AGG_FILES), (de, b.DESC_FILES), (fi, b.FIG_FILES), (day, b.DAY_FILES)):
            for name in names:
                content = b'<svg>fixture</svg>' if name.endswith('.svg') else (b'%PDF fixture' if name.endswith('.pdf') else b'{}\n')
                (folder / name).write_bytes(content)
        (ag / 'quality.json').write_bytes(qbytes)
        (ag / 'overall-overheads.csv').write_bytes(sbytes)
        (ag / 'domain-overheads.csv').write_bytes(dbytes)
        (domain / b.DOMAIN_FILES[0]).write_text(json.dumps(provenance))
        (domain / b.DOMAIN_FILES[1]).write_bytes(obytes)
        source = self.root / 'domain_bootstrap.py'; source.write_bytes(script)
        day_result = self.root / 'day-packet-eligibility.json'
        day_result.write_text(json.dumps({'status': 'passed', 'records': 12,
                                         'metric_rows_content_sha256': self.snapshot,
                                         'packet_count_categories': {'valid': 12}, 'scope': b.DAY_ELIGIBILITY_SCOPE}))
        day_source = self.root / 'check_day_packet_count_eligibility.py'; day_source.write_text('# synthetic source\n')
        arithmetic_result = self.root / 'independent-arithmetic-audit.json'
        arithmetic_result.write_text(json.dumps({'status': 'passed', 'scope': b.ARITHMETIC_AUDIT_SCOPE,
            'manifest_sha256': self.manifest_sha, 'aggregator_sha256': b.AGGREGATE_SHA,
            'metric_rows_content_sha256': self.snapshot, 'captures': 12, 'domains': 1,
            'domain_table_sha256': sha(dbytes), 'overall_table_sha256': sha(sbytes),
            'domain_rows_checked': 10, 'overall_rows_checked': 10,
            'unavailable_domain_rows': 0, 'unavailable_overall_rows': 0, 'differences': []}))
        arithmetic_source = self.root / 'audit.py'; arithmetic_source.write_text('# synthetic arithmetic audit source\n')
        resources = self.root / 'resources.csv'; resources.write_text('domain\nfixture.invalid\n')
        census = self.root / 'census.json'; census.write_text('{"status":"synthetic"}\n')
        report = b'# SYNTHETIC REPORT\n'
        args = SimpleNamespace(output=self.root/'domain-synthetic.zip', manifest=self.manifest_path,
                               resources=resources, aggregate=ag, descriptive=de, figures=fi, day=day,
                               census_qa=census, reviewed_report_sha256=sha(report),
                               domain_bootstrap=domain, domain_bootstrap_script=source,
                               day_eligibility=day_result, day_eligibility_script=day_source,
                               arithmetic_audit=arithmetic_result, arithmetic_audit_script=arithmetic_source)
        result = b.verify_database(self.db, self.manifest, self.manifest_sha, self.snapshot)
        fake_day_sha = sha(day_source.read_bytes())
        fake_audit_sha = sha(arithmetic_source.read_bytes())
        b.assemble_zip(args, self.db, self.manifest, quality, result, report, '# SYNTHETIC DRAFT', synthetic=True,
                       expected_day_eligibility_sha=fake_day_sha, expected_arithmetic_audit_sha=fake_audit_sha,
                       expected_arithmetic_domains=1)
        b.verify_zip(args.output, strict=True, expected_day_eligibility_sha=fake_day_sha,
                     expected_arithmetic_audit_sha=fake_audit_sha, expected_arithmetic_domains=1)
        with self.assertRaisesRegex(ValueError, 'UTC-day packet-count eligibility source hash mismatch'):
            b.verify_zip(args.output, strict=True)
        with self.assertRaisesRegex(ValueError, 'Independent arithmetic audit source hash mismatch'):
            b.verify_zip(args.output, strict=True, expected_day_eligibility_sha=fake_day_sha,
                         expected_arithmetic_domains=1)
        with zipfile.ZipFile(args.output) as z:
            content = {n: z.read(n) for n in z.namelist() if n != 'SHA256SUMS.txt'}
        self.assertEqual(content['results/domain-bootstrap/domain_bootstrap.py'], script)
        for mutation in ('partial', 'all_removed', 'source', 'csv', 'primary',
                         'day_partial', 'day_all_removed', 'day_source', 'day_snapshot', 'day_status',
                         'audit_partial', 'audit_all_removed', 'audit_source', 'audit_snapshot', 'audit_difference'):
            altered = dict(content)
            if mutation == 'partial':
                del altered['results/domain-bootstrap/domain-session-bootstrap.csv']
            elif mutation == 'all_removed':
                altered = {n: v for n, v in altered.items() if not n.startswith('results/domain-bootstrap/')}
            elif mutation == 'source':
                altered['results/domain-bootstrap/domain_bootstrap.py'] += b'# changed\n'
            elif mutation == 'csv':
                altered['results/domain-bootstrap/domain-session-bootstrap.csv'] += b'changed\n'
            elif mutation == 'primary':
                altered['results/aggregate/overall-overheads.csv'] += b'changed\n'
            elif mutation == 'day_partial':
                del altered['results/day-eligibility/day-packet-eligibility.json']
            elif mutation == 'day_all_removed':
                altered = {n: v for n, v in altered.items() if not n.startswith('results/day-eligibility/')}
            elif mutation == 'day_source':
                altered['results/day-eligibility/check_day_packet_count_eligibility.py'] += b'# changed\n'
            elif mutation in ('day_snapshot', 'day_status'):
                row = json.loads(altered['results/day-eligibility/day-packet-eligibility.json'])
                row['metric_rows_content_sha256' if mutation == 'day_snapshot' else 'status'] = 'invalid'
                altered['results/day-eligibility/day-packet-eligibility.json'] = json.dumps(row).encode()
            elif mutation == 'audit_partial':
                del altered['results/independent-audit/independent-arithmetic-audit.json']
            elif mutation == 'audit_all_removed':
                altered = {n: v for n, v in altered.items() if not n.startswith('results/independent-audit/')}
            elif mutation == 'audit_source':
                altered['results/independent-audit/audit.py'] += b'# changed\n'
            else:
                row = json.loads(altered['results/independent-audit/independent-arithmetic-audit.json'])
                if mutation == 'audit_snapshot': row['metric_rows_content_sha256'] = '0' * 64
                else: row['differences'] = [{'field': 'overhead_pct'}]
                altered['results/independent-audit/independent-arithmetic-audit.json'] = json.dumps(row).encode()
            out = self.root / ('domain-' + mutation + '.zip')
            with zipfile.ZipFile(out, 'x') as z:
                for name, data in altered.items(): z.writestr(name, data)
                z.writestr('SHA256SUMS.txt', ''.join(sha(altered[n]) + '  ' + n + '\n' for n in sorted(altered)))
            with self.assertRaisesRegex(ValueError, 'Exploratory domain bootstrap|UTC-day packet-count eligibility|Independent arithmetic audit'):
                b.verify_zip(out, strict=True, expected_day_eligibility_sha=fake_day_sha,
                             expected_arithmetic_audit_sha=fake_audit_sha, expected_arithmetic_domains=1)

    def test_manifest_duplicate_and_nonportable_filename_rejected(self):
        path = self.root / 'invalid.csv'
        with path.open('w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=self.rows[0], lineterminator='\n')
            writer.writeheader(); writer.writerows(self.rows + [self.rows[0]])
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            b.read_manifest(path, expected_domains=1, sessions=2, expected_sha=b.sha_file(path))
        altered = list(self.rows); altered[0] = dict(altered[0], filename='../private.pcap')
        with path.open('w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=self.rows[0], lineterminator='\n')
            writer.writeheader(); writer.writerows(altered)
        with self.assertRaisesRegex(ValueError, 'Invalid'):
            b.read_manifest(path, expected_domains=1, sessions=2, expected_sha=b.sha_file(path))

    def test_independent_census_must_be_full_and_match_same_snapshot(self):
        path = self.root / 'census.json'
        result = {'status': 'verified_full', 'observed_rows': 12, 'expected_rows': 12,
                  'missing_rows': 0, 'database_error_rows': 0, 'structural_defects': {},
                  'schema': b.SCHEMA, 'manifest_sha256': self.manifest_sha,
                  'metric_rows_content_sha256': self.snapshot, 'verifier_sha256': b.VERIFIER_SHA,
                  'conditions': {m: {'rows': 2, 'defects': {}} for m in b.MODES}}
        path.write_text(json.dumps(result))
        self.assertEqual(b.validate_census(path, snapshot=self.snapshot, manifest_sha=self.manifest_sha,
                                           expected_rows=12)['status'], 'verified_full')
        for change in ({'status': 'verified_partial'}, {'missing_rows': 1}, {'structural_defects': {'bad': 1}},
                       {'metric_rows_content_sha256': '0' * 64}, {'verifier_sha256': '0' * 64}):
            path.write_text(json.dumps({**result, **change}))
            with self.assertRaisesRegex(ValueError, 'census'):
                b.validate_census(path, snapshot=self.snapshot, manifest_sha=self.manifest_sha, expected_rows=12)

    def test_day_subset_summary_preserves_explicit_eligibility(self):
        path = self.root / 'days'; path.mkdir()
        rows, summaries = [], []
        for mode in b.MODES[1:]:
            for metric in ('ip_bytes', 'observed_span'):
                rows += [{'defense': mode, 'metric': metric, 'domain': 'fixture.invalid',
                          'status': 'eligible', 'overhead_pct': '25'}]
                summaries += [{'defense': mode, 'metric': metric, 'eligible_domains': '1', 'expected_domains': '1',
                               'all_domains_eligible': 'True', 'equal_domain_mean_overhead_pct_eligible_subset': '25',
                               'day_bootstrap_percentile95_low_pct_eligible_subset': '10',
                               'day_bootstrap_percentile95_high_pct_eligible_subset': '40'}]
        for name, data in (('utc-day-cluster-by-domain.csv', rows),
                           ('utc-day-cluster-eligible-subset-summary.csv', summaries)):
            with (path / name).open('w', newline='') as f:
                w = csv.DictWriter(f, fieldnames=data[0], lineterminator='\n'); w.writeheader(); w.writerows(data)
        b.check_day_tables(path, self.domains)
        summaries[0]['equal_domain_mean_overhead_pct_eligible_subset'] = '999'
        with (path / 'utc-day-cluster-eligible-subset-summary.csv').open('w', newline='') as f:
            w = csv.DictWriter(f, fieldnames=summaries[0], lineterminator='\n'); w.writeheader(); w.writerows(summaries)
        with self.assertRaisesRegex(ValueError, 'summary mismatch'):
            b.check_day_tables(path, self.domains)

    def test_checksum_inventory_crc_and_paths_are_checked(self):
        path = self.root / 'synthetic.zip'; digests = {}
        with zipfile.ZipFile(path, 'x') as z:
            b.add_bytes(z, digests, 'README.md', b'SYNTHETIC FIXTURE')
            b.add_bytes(z, digests, 'results/table.csv', b'a,b\n1,2\n')
            z.writestr('SHA256SUMS.txt', ''.join(digests[n] + '  ' + n + '\n' for n in sorted(digests)))
        b.verify_zip(path)
        path2 = self.root / 'bad.zip'
        with zipfile.ZipFile(path2, 'x') as z:
            z.writestr('README.md', 'synthetic')
            z.writestr('SHA256SUMS.txt', '0' * 64 + '  README.md\n')
        with self.assertRaisesRegex(ValueError, 'hash mismatch'):
            b.verify_zip(path2)
        with zipfile.ZipFile(self.root / 'other.zip', 'x') as z:
            with self.assertRaisesRegex(ValueError, 'Invalid'):
                b.add_bytes(z, {}, '../private', b'synthetic')
        with self.assertRaisesRegex(ValueError, 'unexpected or missing'):
            b.verify_zip(path, strict=True)

    def test_provenance_rejects_incomplete_wrong_snapshot_and_figure_input(self):
        ag, de, fi, day = [self.root / x for x in ('aggregate', 'descriptive', 'figures', 'day')]
        for p in (ag, de, fi, day): p.mkdir()
        snap = self.snapshot
        q = {'status': 'complete', 'manifest_sessions': 12, 'accepted_metric_rows': 12,
             'extractor_errors': 0, 'identity_or_other_flags': {}, 'manifest_sha256': self.manifest_sha,
             'analysis_script_sha256': 'a' * 64, 'metric_rows_content_sha256': snap}
        (ag / 'quality.json').write_text(json.dumps(q))
        for name in ('overall-overheads.csv', 'domain-overheads.csv'):
            (ag / name).write_text('synthetic,value\n1,2\n')
        (ag / 'extraction-errors.json').write_text('[]\n')
        dp = {'status': 'complete', 'manifest_sha256': self.manifest_sha, 'metric_rows_content_sha256': snap,
              'aggregate_code_sha256': 'a' * 64, 'metric_rows': 12, 'descriptive_code_sha256': 'b' * 64}
        tp = {'status': 'complete', 'manifest_sha256': self.manifest_sha, 'metric_rows_content_sha256': snap,
              'aggregate_code_sha256': 'a' * 64, 'metric_rows': 12, 'bootstrap_code_sha256': 'd' * 64}
        fp = {'status': 'complete', 'manifest_sha256': self.manifest_sha, 'metric_rows_content_sha256': snap,
              'manifest_sessions': 12, 'accepted_metric_rows': 12, 'script_sha256': 'c' * 64,
              'inputs_sha256': {n: b.sha_file(ag / n) for n in ('quality.json','overall-overheads.csv','domain-overheads.csv')}}
        for name in b.DESC_FILES:
            (de / name).write_text(json.dumps(dp) if name == 'descriptive-provenance.json' else 'synthetic\n')
        for name in b.DAY_FILES:
            (day / name).write_text(json.dumps(tp) if name == 'utc-day-cluster-provenance.json' else 'synthetic\n')
        for name in b.FIG_FILES:
            (fi / name).write_text(json.dumps(fp) if name == 'figure-provenance.json' else 'synthetic\n')
        kwargs = dict(manifest_sha=self.manifest_sha, aggregate_sha='a'*64, describe_sha='b'*64,
                      figure_sha='c'*64, day_sha='d'*64, expected_rows=12)
        b.validate_provenance(ag, de, fi, day, **kwargs)
        (ag / 'overall-overheads.csv').write_text('tampered\n')
        with self.assertRaisesRegex(ValueError, 'Figure input mismatch'):
            b.validate_provenance(ag, de, fi, day, **kwargs)
        (ag / 'overall-overheads.csv').write_text('synthetic,value\n1,2\n')
        tp['metric_rows_content_sha256'] = '0' * 64
        (day / 'utc-day-cluster-provenance.json').write_text(json.dumps(tp))
        with self.assertRaisesRegex(ValueError, 'day cluster provenance'):
            b.validate_provenance(ag, de, fi, day, **kwargs)
        tp['metric_rows_content_sha256'] = snap
        (day / 'utc-day-cluster-provenance.json').write_text(json.dumps(tp))
        q['status'] = 'provisional_incomplete'
        (ag / 'quality.json').write_text(json.dumps(q))
        with self.assertRaisesRegex(ValueError, 'Primary quality'):
            b.validate_provenance(ag, de, fi, day, **kwargs)

    def test_text_personal_paths_and_wrong_code_are_rejected(self):
        p = self.root / 'report.md'; p.write_text('SYNTHETIC /Users/example/source')
        with self.assertRaisesRegex(ValueError, 'Machine|machine'):
            b.checked_text(p)
        with self.assertRaisesRegex(ValueError, 'hash mismatch'):
            b.load_builder(p)


if __name__ == '__main__':
    unittest.main()
