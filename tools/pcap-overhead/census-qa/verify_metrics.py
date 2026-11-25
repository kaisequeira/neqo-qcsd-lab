#!/usr/bin/env python3
"""Read-only verification of a final-PCAP metrics census and its manifest.

This validates recorded extraction results; it does not independently re-read
packet captures, establish scientific eligibility, or calculate overheads.
"""
from __future__ import annotations

import argparse
import collections
import csv
from decimal import Decimal, InvalidOperation
import hashlib
import json
from pathlib import Path
import sqlite3

MODES = ('undefended', 'front', 'tamaraw', 'buflo', 'cs-buflo', 'wtf-pad')
EXPECTED_MANIFEST_SHA = 'ef0e87f1138db2675e655813b0667b3860235df5c635f045e18f48fac1d72abf'
SCHEMA = '2026-11-25-ip-frame-direction-v2'
QUALITY_FIELDS = ('truncated_packets', 'non_ip_packets', 'multiple_ip_packets',
                  'ipv6_zero_payload_packets', 'malformed_ip_packets', 'unverified_link_packets')


def file_sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def nonneg_int(x):
    return isinstance(x, int) and not isinstance(x, bool) and x >= 0


def valid_sha(value):
    return isinstance(value, str) and len(value) == 64 and all(c in '0123456789abcdef' for c in value)


def read_manifest(path, *, domains=50, sessions=400, expected_hash=EXPECTED_MANIFEST_SHA):
    digest = file_sha(path)
    if expected_hash is not None and digest != expected_hash:
        raise ValueError('Unexpected final manifest SHA-256')
    rows, ids = {}, set()
    with Path(path).open(newline='', encoding='utf-8-sig') as f:
        for row in csv.DictReader(f):
            key = (row['defense'], row['domain'], int(row['session']))
            obj, digest_value, size = row['drive_file_id'], row['sha256'].lower(), int(row['size'])
            if (key[0] not in MODES or not key[1] or key in rows or not obj or obj in ids
                    or not valid_sha(digest_value) or size <= 0):
                raise ValueError('Duplicate or invalid manifest identity')
            rows[key] = (obj, digest_value, size)
            ids.add(obj)
    hosts = {k[1] for k in rows}
    expected = {(mode, host, n) for mode in MODES for host in hosts for n in range(1, sessions + 1)}
    if len(hosts) != domains or set(rows) != expected:
        raise ValueError('Manifest does not match the configured complete balanced design')
    return rows, digest


def inspect_metric(key, obj, digest, value, expected):
    """Return structural defects and quality flags; never interpret overhead."""
    defects, flags = [], []
    if expected is None:
        return ['outside_manifest'], flags
    if not isinstance(value, dict):
        return ['invalid_json_object'], flags
    if (obj, digest) != expected[:2] or value.get('drive_file_id') != obj or value.get('sha256') != digest:
        defects.append('identity_mismatch')
    if (value.get('defense'), value.get('domain'), value.get('session')) != key:
        defects.append('embedded_identity_mismatch')
    if value.get('status') != 'ok' or value.get('capture_bytes') != expected[2]:
        defects.append('status_or_size_mismatch')
    for name in ('packet_count', 'packet_bytes', 'ip_bytes', 'ipv4_packets', 'ipv6_packets', *QUALITY_FIELDS):
        if not nonneg_int(value.get(name)):
            defects.append('invalid_' + name)
    packets = value.get('packet_count')
    if nonneg_int(packets) and packets == 0:
        defects.append('empty_capture')
    if type(value.get('ip_valid')) is not bool or type(value.get('udp443_direction_valid')) is not bool:
        defects.append('invalid_quality_boolean')
    for name in QUALITY_FIELDS:
        if nonneg_int(value.get(name)) and value[name]:
            flags.append(name)
    if value.get('ip_valid') is False:
        flags.append('ip_invalid')
    if value.get('udp443_direction_valid') is False:
        flags.append('direction_ambiguous')
    if str(value.get('strict_order')).lower() != 'true':
        flags.append('timestamp_order_not_verified')
    if value.get('capture_type') not in ('pcap', 'pcapng'):
        flags.append('other_capture_format')
    if value.get('encapsulation') != 'ether':
        flags.append('other_encapsulation')

    if value.get('ip_valid') is True:
        if any(value.get(k) != 0 for k in QUALITY_FIELDS):
            defects.append('ip_valid_inconsistent_with_flags')
        a, b, n = value.get('ipv4_packets'), value.get('ipv6_packets'), value.get('packet_count')
        if all(nonneg_int(x) for x in (a, b, n)) and a + b != n:
            defects.append('ip_valid_packet_count_mismatch')
        ip, frame = value.get('ip_bytes'), value.get('packet_bytes')
        if nonneg_int(ip) and nonneg_int(frame) and ip > frame:
            defects.append('ip_bytes_exceed_original_frame_bytes')
    if value.get('udp443_direction_valid') is True:
        a, b, other, total = (value.get(k) for k in
                              ('udp443_up_ip_bytes', 'udp443_down_ip_bytes', 'other_ip_bytes', 'ip_bytes'))
        if (value.get('ip_valid') is not True or value.get('udp443_tuple_candidates') != 1
                or value.get('udp443_candidate_overflow') is not False
                or not all(nonneg_int(x) for x in (a, b, other, total))
                or a + b + other != total):
            defects.append('direction_byte_accounting_mismatch')
        if nonneg_int(other) and other:
            flags.append('direction_other_ip_bytes_present')
    try:
        start, end, span = (Decimal(str(value[k])) for k in ('first_epoch', 'last_epoch', 'span_seconds'))
        if (not all(x.is_finite() for x in (start, end, span)) or end < start or span < 0
                or abs((end - start) - span) > Decimal('0.000000001')):
            defects.append('epoch_span_mismatch')
    except (KeyError, InvalidOperation, ValueError, TypeError):
        defects.append('invalid_epoch_or_span')
    return defects, flags


def inspect(database, manifest_path, *, domains=50, sessions=400, expected_hash=EXPECTED_MANIFEST_SHA):
    expected, manifest_sha = read_manifest(manifest_path, domains=domains, sessions=sessions,
                                           expected_hash=expected_hash)
    c = sqlite3.connect(Path(database).resolve().as_uri() + '?mode=ro', uri=True, timeout=30)
    c.execute('PRAGMA query_only = ON')
    c.execute('BEGIN')
    by_condition = {k: {'rows': 0, 'defects': collections.Counter(), 'flags': collections.Counter(),
                        'capture_types': collections.Counter(), 'encapsulations': collections.Counter(),
                        'timestamp_decimal_places': collections.Counter()} for k in MODES}
    defects, snapshot = collections.Counter(), hashlib.sha256()
    observed, seen = 0, set()
    try:
        meta = dict(c.execute('SELECT key,value FROM metadata'))
        if meta.get('manifest_sha256') != manifest_sha or meta.get('metrics_schema') != SCHEMA:
            raise ValueError('Database manifest or metric-schema provenance mismatch')
        db_errors = c.execute('SELECT COUNT(*) FROM errors').fetchone()[0]
        sql = ('SELECT defense,domain,session,drive_file_id,sha256,result_json '
               'FROM metrics ORDER BY defense,domain,session')
        for mode, domain, session, obj, digest, raw in c.execute(sql):
            observed += 1
            snapshot.update((json.dumps([mode, domain, session, obj, digest, raw],
                                        ensure_ascii=False, separators=(',', ':')) + '\n').encode())
            key = (mode, domain, session)
            if mode not in by_condition or key in seen:
                defects['unexpected_or_duplicate_key'] += 1
                continue
            seen.add(key)
            item = by_condition[mode]
            item['rows'] += 1
            try:
                value = json.loads(raw)
            except (TypeError, ValueError):
                defects['invalid_json'] += 1
                item['defects']['invalid_json'] += 1
                continue
            ds, fs = inspect_metric(key, obj, digest, value, expected.get(key))
            defects.update(ds)
            item['defects'].update(ds)
            item['flags'].update(fs)
            if isinstance(value, dict):
                item['capture_types'][str(value.get('capture_type', 'missing'))] += 1
                item['encapsulations'][str(value.get('encapsulation', 'missing'))] += 1
                for field in ('first_epoch', 'last_epoch'):
                    text = str(value.get(field, ''))
                    item['timestamp_decimal_places'][field + ':' + str(len(text.partition('.')[2]))] += 1
    finally:
        c.rollback()
        c.close()
    complete = observed == len(expected) and len(seen) == len(expected) and not defects and db_errors == 0
    return {'status': 'verified_full' if complete else ('verification_failed' if defects else 'verified_partial'),
            'scope': 'Manifest/record consistency only; captures are not re-read and scientific eligibility is not established.',
            'manifest_sha256': manifest_sha, 'schema': SCHEMA, 'expected_rows': len(expected),
            'observed_rows': observed, 'missing_rows': len(set(expected) - seen), 'database_error_rows': db_errors,
            'structural_defects': dict(defects), 'metric_rows_content_sha256': snapshot.hexdigest(),
            'verifier_sha256': file_sha(__file__), 'conditions': by_condition}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--manifest', type=Path, required=True)
    p.add_argument('--database', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True, help='new JSON report path')
    args = p.parse_args()
    report = inspect(args.database, args.manifest)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('x', encoding='utf-8') as f:
        json.dump(report, f, indent=2, sort_keys=True)
        f.write('\n')
    print(json.dumps({'status': report['status'], 'rows': report['observed_rows'],
                      'expected': report['expected_rows'], 'errors': report['database_error_rows']}))
    return 1 if report['status'] == 'verification_failed' else 0


if __name__ == '__main__':
    raise SystemExit(main())
