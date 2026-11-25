import csv
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

import verify_metrics as qa


def row_value(mode, domain, session, obj, sha, size):
    return {'defense': mode, 'domain': domain, 'session': session, 'drive_file_id': obj,
            'sha256': sha, 'capture_bytes': size, 'status': 'ok', 'capture_type': 'pcapng',
            'encapsulation': 'ether', 'packet_count': 2, 'packet_bytes': 100, 'ip_bytes': 70,
            'ipv4_packets': 2, 'ipv6_packets': 0, 'ip_valid': True,
            **{name: 0 for name in qa.QUALITY_FIELDS}, 'strict_order': 'True',
            'udp443_direction_valid': True, 'udp443_tuple_candidates': 1,
            'udp443_candidate_overflow': False, 'udp443_up_ip_bytes': 20,
            'udp443_down_ip_bytes': 50, 'other_ip_bytes': 0,
            'first_epoch': '1791527418.256770703', 'last_epoch': '1791527418.297876170',
            'span_seconds': 0.041105467}


class VerifyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.manifest, self.db = root / 'manifest.csv', root / 'metrics.sqlite3'
        rows = []
        for mode in qa.MODES:
            for domain in ('a.invalid', 'b.invalid'):
                for session in (1, 2):
                    index = len(rows) + 1
                    rows.append({'defense': mode, 'domain': domain, 'session': session,
                                 'drive_file_id': 'object' + str(index),
                                 'sha256': ('%064x' % index), 'size': 1000 + index})
        self.rows = rows
        with self.manifest.open('w', newline='', encoding='utf-8') as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)
        self.c = sqlite3.connect(self.db)
        self.addCleanup(self.c.close)
        self.c.execute('CREATE TABLE metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL)')
        self.c.execute('CREATE TABLE metrics(defense TEXT,domain TEXT,session INTEGER,drive_file_id TEXT,sha256 TEXT,result_json TEXT,PRIMARY KEY(defense,domain,session))')
        self.c.execute('CREATE TABLE errors(defense TEXT,domain TEXT,session INTEGER,error TEXT,updated REAL,PRIMARY KEY(defense,domain,session))')
        self.c.executemany('INSERT INTO metadata VALUES(?,?)', [('manifest_sha256', qa.file_sha(self.manifest)), ('metrics_schema', qa.SCHEMA)])
        self.c.commit()

    def add(self, row, **changes):
        val = row_value(row['defense'], row['domain'], row['session'], row['drive_file_id'], row['sha256'], row['size'])
        val.update(changes)
        self.c.execute('INSERT INTO metrics VALUES(?,?,?,?,?,?)', (row['defense'], row['domain'], row['session'], row['drive_file_id'], row['sha256'], json.dumps(val)))
        self.c.commit()

    def inspect(self):
        return qa.inspect(self.db, self.manifest, domains=2, sessions=2, expected_hash=None)

    def test_partial_cannot_claim_complete(self):
        self.add(self.rows[0]); result = self.inspect()
        self.assertEqual((result['status'], result['observed_rows'], result['missing_rows']), ('verified_partial', 1, 23))

    def test_complete_and_snapshot_digest_matches_aggregation_convention(self):
        import hashlib
        for r in self.rows: self.add(r)
        result = self.inspect(); self.assertEqual(result['status'], 'verified_full')
        h = hashlib.sha256()
        for row in self.c.execute('SELECT defense,domain,session,drive_file_id,sha256,result_json FROM metrics ORDER BY defense,domain,session'):
            h.update((json.dumps(list(row), ensure_ascii=False, separators=(',', ':')) + '\n').encode())
        self.assertEqual(result['metric_rows_content_sha256'], h.hexdigest())

    def test_manifest_identity_and_embedded_identity_mismatch_fail(self):
        self.add(self.rows[0], sha256='f' * 64, session=88)
        x = self.inspect()
        self.assertEqual(x['status'], 'verification_failed')
        self.assertEqual(x['structural_defects']['identity_mismatch'], 1)
        self.assertEqual(x['structural_defects']['embedded_identity_mismatch'], 1)

    def test_decimal_span_uses_exact_epoch_arithmetic(self):
        self.add(self.rows[0], span_seconds=0.041105470)
        x = self.inspect()
        self.assertEqual(x['structural_defects']['epoch_span_mismatch'], 1)

    def test_valid_ip_claim_must_match_quality_flags(self):
        self.add(self.rows[0], truncated_packets=1)
        x = self.inspect()
        self.assertEqual(x['structural_defects']['ip_valid_inconsistent_with_flags'], 1)
        self.assertEqual(x['conditions'][self.rows[0]['defense']]['flags']['truncated_packets'], 1)

    def test_invalid_ip_is_explicit_quality_flag_not_record_corruption(self):
        self.add(self.rows[0], ip_valid=False, truncated_packets=1, udp443_direction_valid=False,
                 udp443_up_ip_bytes=None, udp443_down_ip_bytes=None, other_ip_bytes=None)
        x = self.inspect()
        self.assertEqual(x['status'], 'verified_partial')
        self.assertEqual(x['conditions'][self.rows[0]['defense']]['flags']['ip_invalid'], 1)

    def test_direction_totals_must_reconcile(self):
        self.add(self.rows[0], udp443_down_ip_bytes=49)
        self.assertEqual(self.inspect()['structural_defects']['direction_byte_accounting_mismatch'], 1)

    def test_db_error_prevents_full_status(self):
        for r in self.rows: self.add(r)
        self.c.execute('INSERT INTO errors VALUES(?,?,?,?,?)', ('front', 'a.invalid', 1, 'transient', 0)); self.c.commit()
        x = self.inspect(); self.assertEqual(x['status'], 'verified_partial'); self.assertEqual(x['database_error_rows'], 1)

    def test_manifest_hash_and_schema_are_checked(self):
        with self.assertRaises(ValueError): qa.read_manifest(self.manifest, domains=2, sessions=2)
        self.c.execute("UPDATE metadata SET value='wrong' WHERE key='metrics_schema'"); self.c.commit()
        with self.assertRaises(ValueError): self.inspect()

    def test_unbalanced_manifest_rejected(self):
        with self.assertRaises(ValueError): qa.read_manifest(self.manifest, domains=3, sessions=2, expected_hash=None)


if __name__ == '__main__':
    unittest.main()
