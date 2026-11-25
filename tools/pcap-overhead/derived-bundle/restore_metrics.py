#!/usr/bin/env python3
"""Restore aggregate-compatible *derived* metrics from a verified bundle.

This never extracts packet captures.  The output is a new SQLite database of
the exact PCAP-derived metrics rows. Checksums detect accidental changes; they
do not authenticate a bundle. Recompute from the final PCAPs for independent
scientific verification.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import zipfile

import build_bundle as b


def require_complete(q, provenance):
    snapshot = q.get('metric_rows_content_sha256')
    if (q.get('status') != 'complete' or q.get('manifest_sessions') != 120000 or
            q.get('accepted_metric_rows') != 120000 or q.get('extractor_errors') != 0 or
            q.get('identity_or_other_flags') != {} or q.get('manifest_sha256') != b.MANIFEST_SHA or
            q.get('analysis_script_sha256') != b.AGGREGATE_SHA or not b.valid_sha(snapshot)):
        raise ValueError('Bundle quality is incomplete or mismatched')
    if (provenance.get('status') != 'complete_hash_bound_inputs' or
            provenance.get('manifest_sha256') != b.MANIFEST_SHA or
            provenance.get('resources_sha256') != b.RESOURCES_SHA or
            provenance.get('metric_rows') != 120000 or
            provenance.get('metric_rows_content_sha256') != snapshot or
            provenance.get('aggregate_code_sha256') != b.AGGREGATE_SHA or
            provenance.get('independent_census_verifier_sha256') != b.VERIFIER_SHA):
        raise ValueError('Bundle provenance is incomplete or mismatched')
    return snapshot


def create_tables(con, manifest_sha):
    con.execute('CREATE TABLE metadata (key TEXT PRIMARY KEY,value TEXT NOT NULL)')
    con.execute('CREATE TABLE metrics (defense TEXT NOT NULL,domain TEXT NOT NULL,session INTEGER NOT NULL,drive_file_id TEXT NOT NULL,sha256 TEXT NOT NULL,result_json TEXT NOT NULL,PRIMARY KEY(defense,domain,session))')
    con.execute('CREATE TABLE errors (defense TEXT NOT NULL,domain TEXT NOT NULL,session INTEGER NOT NULL,error TEXT NOT NULL,updated REAL NOT NULL,PRIMARY KEY(defense,domain,session))')
    con.executemany('INSERT INTO metadata VALUES (?,?)', [('manifest_sha256', manifest_sha), ('metrics_schema', b.SCHEMA)])


def restore_stream(stream, con, manifest, expected_snapshot, *, flat_text=None):
    """Validate exact rows and, if supplied, the readable CSV against JSONL."""
    h = hashlib.sha256()
    count = 0
    modes = {}
    prior = None
    flat = csv.DictReader(flat_text) if flat_text is not None else None
    if flat is not None and tuple(flat.fieldnames or ()) != b.METRIC_FIELDS:
        raise ValueError('Readable metric CSV has an unexpected header')
    for line in stream:
        try:
            row = json.loads(line)
        except (ValueError, TypeError) as exc:
            raise ValueError('Invalid canonical JSONL row') from exc
        if (not isinstance(row, list) or len(row) != 6 or type(row[2]) is not int or
                not all(isinstance(row[i], str) for i in (0, 1, 3, 4, 5))):
            raise ValueError('Unexpected canonical JSONL schema')
        if b.canonical_row(row) != line:
            raise ValueError('Canonical JSONL bytes differ from the public aggregation format')
        key = (row[0], row[1], row[2])
        if prior is not None and key <= prior:
            raise ValueError('Canonical rows are not strictly ordered by cohort identity')
        obj = b.metric_object(row, manifest)
        if flat is not None:
            csv_row = next(flat, None)
            if csv_row is None or any(csv_row.get(name) != ('' if obj[name] is None else str(obj[name]))
                                      for name in b.METRIC_FIELDS):
                raise ValueError('Readable metric CSV differs from canonical JSONL')
        try:
            con.execute('INSERT INTO metrics VALUES (?,?,?,?,?,?)', row)
        except sqlite3.IntegrityError as exc:
            raise ValueError('Duplicate canonical metric identity') from exc
        h.update(line)
        modes[row[0]] = modes.get(row[0], 0) + 1
        count += 1
        prior = key
    if count != len(manifest) or h.hexdigest() != expected_snapshot:
        raise ValueError('Canonical metric row count or digest mismatch')
    if flat is not None and next(flat, None) is not None:
        raise ValueError('Readable metric CSV has extra rows')
    return {'rows': count, 'counts_by_condition': modes, 'metric_rows_content_sha256': h.hexdigest()}


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--bundle', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args(argv)
    if args.output.exists():
        raise ValueError('Refusing to overwrite output')
    b.regular(args.bundle)
    b.verify_zip(args.bundle, strict=True)
    with zipfile.ZipFile(args.bundle) as z, tempfile.TemporaryDirectory(prefix='pcap-metrics-verify-') as tmp:
        q = json.loads(z.read('results/aggregate/quality.json'))
        prov = json.loads(z.read('bundle-provenance.json'))
        snapshot = require_complete(q, prov)
        manifest_path = Path(tmp) / 'manifest.csv'
        manifest_path.write_bytes(z.read('inputs/session-manifest.csv'))
        if hashlib.sha256(z.read('inputs/resources.csv')).hexdigest() != b.RESOURCES_SHA:
            raise ValueError('Final resource roster hash mismatch')
        manifest, _ = b.read_manifest(manifest_path)
        census_path = Path(tmp) / 'census.json'
        census_path.write_bytes(z.read('results/independent-census-qa.json'))
        b.validate_census(census_path, snapshot=snapshot)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        created = False
        con = None
        try:
            fd = os.open(str(args.output), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.close(fd)
            created = True
            con = sqlite3.connect(args.output)
            create_tables(con, b.MANIFEST_SHA)
            with z.open('measurements/session-metrics-canonical.jsonl') as stream, \
                    z.open('measurements/session-metrics.csv') as flat_raw, \
                    io.TextIOWrapper(flat_raw, encoding='utf-8', newline='') as flat_text:
                result = restore_stream(stream, con, manifest, snapshot, flat_text=flat_text)
            if result['counts_by_condition'] != {m: 20000 for m in b.MODES}:
                raise ValueError('Restored cohort counts do not match final design')
            con.commit()
            if con.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
                raise ValueError('Restored SQLite integrity check failed')
            print(json.dumps({'status': 'restored_verified_metrics', **result}, sort_keys=True))
        except Exception:
            if con is not None:
                con.close()
                con = None
            if created:
                args.output.unlink(missing_ok=True)
            raise
        finally:
            if con is not None:
                con.close()


if __name__ == '__main__':
    main()
