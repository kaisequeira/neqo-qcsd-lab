"""Synthetic-only tests for restoring the PCAP-derived measurement table."""
import io
import json
import sqlite3
import unittest
import zipfile

import build_bundle as b
import restore_metrics as r
import test_build_bundle as fixture


class RestoreTests(unittest.TestCase):
    # Reuse the synthetic 12-row balanced fixture; none of its values or files
    # are actual study results.
    setUp = fixture.BundleTests.setUp
    tearDown = fixture.BundleTests.tearDown
    calc_snapshot = fixture.BundleTests.calc_snapshot
    def target(self):
        c = sqlite3.connect(':memory:')
        r.create_tables(c, self.manifest_sha)
        return c

    def canonical(self):
        return b''.join(b.canonical_row(row) for row in self.db.execute(b.QUERY))

    def test_restore_roundtrip_preserves_raw_rows_and_public_digest(self):
        c = self.target()
        try:
            result = r.restore_stream(io.BytesIO(self.canonical()), c, self.manifest, self.snapshot)
            self.assertEqual(result['rows'], 12)
            self.assertEqual(result['metric_rows_content_sha256'], self.snapshot)
            self.assertEqual(list(c.execute(b.QUERY)), list(self.db.execute(b.QUERY)))
            self.assertEqual(b.verify_database(c, self.manifest, self.manifest_sha, self.snapshot)['rows'], 12)
        finally:
            c.close()

    def test_readable_csv_must_match_every_canonical_row(self):
        out = self.root / 'synthetic-measurements.zip'
        with zipfile.ZipFile(out, 'x') as z:
            b.write_metrics(z, self.db, self.manifest, self.snapshot, {})
        with zipfile.ZipFile(out) as z:
            canonical = z.read('measurements/session-metrics-canonical.jsonl')
            table = z.read('measurements/session-metrics.csv').decode('utf-8')
        c = self.target()
        try:
            result = r.restore_stream(io.BytesIO(canonical), c, self.manifest, self.snapshot,
                                      flat_text=io.StringIO(table, newline=''))
            self.assertEqual(result['rows'], 12)
        finally:
            c.close()
        c = self.target()
        try:
            altered = table.replace('fixture.invalid', 'other.invalid', 1)
            with self.assertRaisesRegex(ValueError, 'differs'):
                r.restore_stream(io.BytesIO(canonical), c, self.manifest, self.snapshot,
                                 flat_text=io.StringIO(altered, newline=''))
        finally:
            c.close()
        c = self.target()
        try:
            with self.assertRaisesRegex(ValueError, 'unexpected header'):
                r.restore_stream(io.BytesIO(canonical), c, self.manifest, self.snapshot,
                                 flat_text=io.StringIO('wrong,headers\n1,2\n'))
        finally:
            c.close()

    def test_missing_duplicate_and_reordered_rows_fail(self):
        lines = self.canonical().splitlines(keepends=True)
        for data in (b''.join(lines[:-1]), b''.join(lines + lines[:1]), b''.join(reversed(lines))):
            c = self.target()
            try:
                with self.assertRaises(ValueError):
                    r.restore_stream(io.BytesIO(data), c, self.manifest, self.snapshot)
            finally:
                c.close()

    def test_noncanonical_json_bytes_and_wrong_digest_fail(self):
        lines = self.canonical().splitlines(keepends=True)
        # Whitespace may be valid JSON, but the public aggregate hashes exact
        # canonical bytes and the format must therefore remain byte-stable.
        lines[0] = b' ' + lines[0]
        c = self.target()
        try:
            with self.assertRaisesRegex(ValueError, 'Canonical'):
                r.restore_stream(io.BytesIO(b''.join(lines)), c, self.manifest, self.snapshot)
        finally:
            c.close()
        c = self.target()
        try:
            with self.assertRaisesRegex(ValueError, 'digest'):
                r.restore_stream(io.BytesIO(self.canonical()), c, self.manifest, '0' * 64)
        finally:
            c.close()

    def test_tampered_identity_or_extra_secret_field_fails(self):
        for mutate in ('identity', 'extra'):
            lines = self.canonical().splitlines(keepends=True)
            row = json.loads(lines[0])
            if mutate == 'identity':
                row[3] = 'wrong-file-id'
            else:
                data = json.loads(row[5]); data['api_key'] = 'synthetic-secret'; row[5] = json.dumps(data)
            lines[0] = b.canonical_row(row)
            c = self.target()
            try:
                with self.assertRaises(ValueError):
                    r.restore_stream(io.BytesIO(b''.join(lines)), c, self.manifest, self.snapshot)
            finally:
                c.close()

    def test_require_complete_rejects_incomplete_or_mismatched_provenance(self):
        q = {'status': 'complete', 'manifest_sessions': 120000, 'accepted_metric_rows': 120000,
             'extractor_errors': 0, 'identity_or_other_flags': {}, 'manifest_sha256': b.MANIFEST_SHA,
             'analysis_script_sha256': b.AGGREGATE_SHA, 'metric_rows_content_sha256': self.snapshot}
        prov = {'status': 'complete_hash_bound_inputs', 'manifest_sha256': b.MANIFEST_SHA,
                'resources_sha256': b.RESOURCES_SHA, 'metric_rows': 120000,
                'metric_rows_content_sha256': self.snapshot, 'aggregate_code_sha256': b.AGGREGATE_SHA,
                'independent_census_verifier_sha256': b.VERIFIER_SHA}
        self.assertEqual(r.require_complete(q, prov), self.snapshot)
        for changed in ({'status': 'provisional_incomplete'}, {'accepted_metric_rows': 119999},
                        {'metric_rows_content_sha256': '0' * 64}):
            with self.assertRaises(ValueError):
                r.require_complete({**q, **changed}, prov)
        with self.assertRaises(ValueError):
            r.require_complete(q, {**prov, 'independent_census_verifier_sha256': '0' * 64})


if __name__ == '__main__':
    unittest.main()
