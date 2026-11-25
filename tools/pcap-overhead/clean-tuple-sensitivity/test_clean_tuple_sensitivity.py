import json
import csv
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import clean_tuple_sensitivity as m
aggregate = m.aggregate


def record(value, clean=True, ip_valid=True, ordered=True, reason='ambiguous'):
    r = {'packet_count': 1, 'ip_valid': ip_valid, 'ip_bytes': value,
         'span_seconds': value / 10, 'strict_order': 'true' if ordered else 'false',
         'udp443_direction_valid': clean, 'udp443_up_ip_bytes': value // 2,
         'udp443_down_ip_bytes': value - value // 2, 'other_ip_bytes': 0}
    if not clean and reason == 'other':
        r['udp443_direction_valid'] = True
        r['other_ip_bytes'] = 1
    return r


class SensitivityTest(unittest.TestCase):
    def test_counts_point_estimates_common_domain_and_primary_eligibility(self):
        records = {}
        for d in aggregate.CONDITIONS:
            for domain in ('a', 'b'):
                for s in (1, 2):
                    records[d, domain, s] = record(100 if d == 'undefended' else 200)
        records['front', 'a', 2] = record(400, clean=False, reason='other')
        records['front', 'b', 1] = record(200, clean=False)
        records['front', 'b', 2] = record(200, clean=False)
        # Primary IP eligibility differs from observed span eligibility.
        records['tamaraw', 'a', 2] = record(400, clean=False, ip_valid=False)
        details, summaries = m.compute(records, ['a', 'b'], 2)
        find = lambda metric, defense, domain: next(r for r in details if (r['metric'],r['defense'],r['domain']) == (metric,defense,domain))
        a = find('ip_bytes', 'front', 'a')
        self.assertEqual((a['defense_full_n'], a['defense_clean_n']), (2,1))
        self.assertEqual(a['full_overhead_pct'], 200)
        self.assertEqual(a['clean_overhead_pct'], 100)
        self.assertEqual(a['clean_minus_full_overhead_percentage_points'], -100)
        self.assertEqual(json.loads(a['defense_clean_filter_reasons']), {'other_ip_bytes_nonzero_or_unknown': 1})
        b = find('ip_bytes', 'front', 'b')
        self.assertIsNone(b['clean_overhead_pct'])
        s = next(r for r in summaries if (r['metric'],r['defense']) == ('ip_bytes','front'))
        self.assertEqual(s['full_available_domains'], 2)
        self.assertEqual(s['clean_available_domains'], 1)
        self.assertEqual(s['full_common_domains'], 1)
        self.assertEqual(s['full_available_macro_overhead_pct'], 150)
        self.assertEqual(s['full_common_macro_overhead_pct'], 200)
        self.assertFalse(s['common_domain_coverage_complete'])
        t = find('ip_bytes', 'tamaraw', 'a')
        self.assertEqual((t['defense_full_n'],t['defense_clean_n'], t['defense_removed_by_clean_filter']), (1,1,0))
        t_span = find('observed_span', 'tamaraw', 'a')
        self.assertEqual((t_span['defense_full_n'],t_span['defense_clean_n'], t_span['defense_removed_by_clean_filter']), (2,1,1))

    def test_pooled_is_ratio_of_domain_means(self):
        rows = [{'x_overhead_pct': 100, 'x_baseline_mean': 1, 'x_defense_mean': 2},
                {'x_overhead_pct': 0, 'x_baseline_mean': 9, 'x_defense_mean': 9}]
        got = m.overall(rows, 'x')
        self.assertAlmostEqual(got['macro_overhead_pct'], 50)
        self.assertAlmostEqual(got['pooled_cohort_mean_overhead_pct'], 10)

    def test_zero_baseline_unavailable(self):
        import numpy as np
        self.assertIsNone(m.estimate(np.array([1]), np.array([0])))
        self.assertIsNone(m.estimate(np.array([]), np.array([1])))

    def test_incomplete_database_is_refused_without_output(self):
        with tempfile.TemporaryDirectory() as td:
            manifest, database = Path(td) / 'manifest.csv', Path(td) / 'metrics.sqlite3'
            with manifest.open('w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=['defense', 'domain', 'session', 'drive_file_id', 'sha256', 'size'])
                writer.writeheader()
                for defense in aggregate.CONDITIONS:
                    for host in range(50):
                        for session in range(1, 401):
                            writer.writerow({'defense': defense, 'domain': str(host), 'session': session,
                                             'drive_file_id': f'{defense}-{host}-{session}',
                                             'sha256': '0' * 64, 'size': 1})
            with sqlite3.connect(database) as con:
                con.execute('CREATE TABLE metrics (defense, domain, session, drive_file_id, sha256, result_json)')
                con.execute('CREATE TABLE errors (defense, domain, session, error, updated)')
            output = Path(td) / 'out'
            p = subprocess.run([sys.executable, str(Path(m.__file__)), '--manifest', str(manifest), '--database', str(database), '--output', str(output)], capture_output=True, text=True)
            self.assertNotEqual(p.returncode, 0)
            self.assertIn('no output written', p.stderr)
            self.assertFalse(output.exists())


if __name__ == '__main__':
    unittest.main()
