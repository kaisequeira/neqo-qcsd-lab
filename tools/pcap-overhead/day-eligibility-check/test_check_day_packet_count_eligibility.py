import sqlite3
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import check_day_packet_count_eligibility as audit


class PacketCountAuditTests(unittest.TestCase):
    @staticmethod
    def canonical_snapshot(connection):
        digest = hashlib.sha256()
        sql = ('SELECT defense,domain,session,drive_file_id,sha256,result_json '
               'FROM metrics ORDER BY defense,domain,session')
        for row in connection.execute(sql):
            digest.update((json.dumps(list(row), ensure_ascii=False, separators=(',', ':')) + '\n').encode())
        return digest.hexdigest()

    def test_categories_match_primary_numeric_criterion(self):
        cases = [('{', 'invalid_json'), ('[]', 'non_object'), ('{}', 'missing'),
                 ('{"packet_count":null}', 'null'), ('{"packet_count":true}', 'boolean'),
                 ('{"packet_count":"1"}', 'non_numeric'), ('{"packet_count":NaN}', 'nonfinite_or_overflow'),
                 ('{"packet_count":Infinity}', 'nonfinite_or_overflow'),
                 ('{"packet_count":' + ('9' * 400) + '}', 'nonfinite_or_overflow'),
                 ('{"packet_count":0}', 'nonpositive'), ('{"packet_count":-1}', 'nonpositive'),
                 ('{"packet_count":1}', 'valid'), ('{"packet_count":1.5}', 'valid')]
        for raw, expected in cases:
            with self.subTest(raw=raw[:40]):
                self.assertEqual(audit.category(raw), expected)

    def test_complete_snapshot_counts_and_error_gate(self):
        connection = sqlite3.connect(':memory:')
        self.addCleanup(connection.close)
        connection.execute('CREATE TABLE metrics(defense TEXT,domain TEXT,session INTEGER,drive_file_id TEXT,sha256 TEXT,result_json TEXT)')
        connection.execute('CREATE TABLE errors(error TEXT)')
        connection.executemany('INSERT INTO metrics VALUES (?,?,?,?,?,?)',
                               (('front', 'example', n, str(n), 'hash', '{"packet_count":1}') for n in range(audit.EXPECTED)))
        connection.commit()
        expected = self.canonical_snapshot(connection)
        counts, snapshot = audit.check(connection, expected)
        self.assertEqual(counts, {'valid': audit.EXPECTED})
        self.assertEqual(snapshot, expected)
        with self.assertRaisesRegex(ValueError, 'snapshot does not match'):
            audit.check(connection, '0' * 64)
        connection.execute('UPDATE metrics SET result_json=? WHERE rowid=1', ('{"packet_count":0}',))
        connection.commit()
        with self.assertRaisesRegex(ValueError, 'snapshot does not match'):
            audit.check(connection, expected)
        changed = self.canonical_snapshot(connection)
        counts, snapshot = audit.check(connection, changed)
        self.assertEqual(counts, {'valid': audit.EXPECTED - 1, 'nonpositive': 1})
        self.assertEqual(snapshot, changed)
        connection.execute('INSERT INTO errors VALUES (?)', ('synthetic',))
        connection.commit()
        with self.assertRaisesRegex(ValueError, 'Complete error-free census required'):
            audit.check(connection, changed)

    def test_incomplete_cli_refuses_without_partial_output(self):
        with tempfile.TemporaryDirectory(prefix='synthetic audit? ') as temp:
            database = Path(temp) / 'synthetic ?.sqlite'
            connection = sqlite3.connect(database)
            connection.execute('CREATE TABLE metrics(result_json TEXT)')
            connection.execute('CREATE TABLE errors(error TEXT)')
            connection.commit()
            connection.close()
            result = subprocess.run([sys.executable, str(Path(audit.__file__)), '--database', str(database),
                                     '--expected-snapshot', 'a' * 64],
                                    capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(result.stdout, '')
            self.assertIn('Complete error-free census required', result.stderr)


if __name__ == '__main__':
    unittest.main()
