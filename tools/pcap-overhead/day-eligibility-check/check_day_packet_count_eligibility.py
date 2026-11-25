#!/usr/bin/env python3
"""Check the day/primary packet-count criterion on a complete metrics census.

Run only after independent final-manifest, identity and snapshot verification.
This check does not establish those properties or repair the general mismatch:
the primary aggregator requires a positive finite numeric packet_count, while
the UTC-day implementation does not itself enforce that criterion. The check
reads one SQLite snapshot, refuses an incomplete/error census without reporting
partial counts, and never writes to the database.
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import json
import math
from pathlib import Path
import sqlite3
import sys
import re
from urllib.parse import quote

EXPECTED = 120_000


def category(raw):
    try:
        record = json.loads(raw)
    except (TypeError, ValueError):
        return 'invalid_json'
    if not isinstance(record, dict):
        return 'non_object'
    if 'packet_count' not in record:
        return 'missing'
    value = record['packet_count']
    if value is None:
        return 'null'
    if isinstance(value, bool):
        return 'boolean'
    if not isinstance(value, (int, float)):
        return 'non_numeric'
    try:
        finite = math.isfinite(value)
    except OverflowError:
        finite = False
    if not finite:
        return 'nonfinite_or_overflow'
    return 'nonpositive' if value <= 0 else 'valid'


def check(connection, expected_snapshot):
    connection.execute('BEGIN')
    try:
        total = connection.execute('SELECT count(*) FROM metrics').fetchone()[0]
        errors = connection.execute('SELECT count(*) FROM errors').fetchone()[0]
        if total != EXPECTED or errors:
            raise ValueError('Complete error-free census required; no partial counts reported')
        counts, digest = collections.Counter(), hashlib.sha256()
        sql = ('SELECT defense,domain,session,drive_file_id,sha256,result_json '
               'FROM metrics ORDER BY defense,domain,session')
        for row in connection.execute(sql):
            digest.update((json.dumps(list(row), ensure_ascii=False, separators=(',', ':')) + '\n').encode())
            counts[category(row[-1])] += 1
        if sum(counts.values()) != EXPECTED:
            raise ValueError('Metrics count changed within the read snapshot')
        snapshot = digest.hexdigest()
        if snapshot != expected_snapshot:
            raise ValueError('Metrics snapshot does not match the independently verified snapshot')
        return counts, snapshot
    finally:
        connection.rollback()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--database', type=Path, required=True)
    parser.add_argument('--expected-snapshot', required=True,
                        help='Canonical metric-row SHA-256 from the completed primary and independent census')
    args = parser.parse_args()
    if not re.fullmatch('[0-9a-f]{64}', args.expected_snapshot):
        parser.error('Expected snapshot must be a lowercase SHA-256')
    uri = 'file:' + quote(str(args.database.resolve()), safe='/') + '?mode=ro'
    try:
        with sqlite3.connect(uri, uri=True, timeout=30) as connection:
            counts, snapshot = check(connection, args.expected_snapshot)
    except (OSError, sqlite3.Error, ValueError) as exc:
        print('Check did not run: ' + str(exc), file=sys.stderr)
        return 2
    status = 'passed' if counts['valid'] == EXPECTED else 'review_required'
    print(json.dumps({'status': status, 'records': EXPECTED,
                      'metric_rows_content_sha256': snapshot,
                      'packet_count_categories': dict(sorted(counts.items())),
                      'scope': 'Packet-count eligibility only; requires independent manifest/identity QA and does not fix the day tool.'},
                     sort_keys=True))
    return 0 if status == 'passed' else 1


if __name__ == '__main__':
    sys.exit(main())
