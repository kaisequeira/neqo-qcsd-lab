#!/usr/bin/env python3
"""Export a complete, reviewed, PCAP-only results bundle; never read PCAPs.

The bundle contains compact *derived* metrics, not the packet dataset.  Its
canonical JSONL is byte-for-byte the row stream hashed by the public aggregate.
It does not contact Drive, publish, or modify the source database.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import importlib.util
import io
import json
import math
import os
from pathlib import Path
import re
import shutil
import sqlite3
import sys
import tempfile
import zipfile

MODES = ('undefended', 'front', 'tamaraw', 'buflo', 'cs-buflo', 'wtf-pad')
MANIFEST_SHA = 'ef0e87f1138db2675e655813b0667b3860235df5c635f045e18f48fac1d72abf'
RESOURCES_SHA = 'baf7b64dad9397843b3fa83e6fbac9db9f6b34e33005136074e146b191fc64f8'
AGGREGATE_SHA = '6e6427360998bd4da1f4bfdfea3c619931003448f2dfd0c573f6ad8bafdc32e6'
DESCRIBE_SHA = 'f10aacf06857a7040366ba043f1294771ee72ddbb5b10fd047bcee408eac470d'
FIGURE_SHA = 'e7354d9285fe4ee9a5b8228e601254a6cb39a36cf20fd86ad4cc26e3fa499244'
DAY_SHA = '9ae4b14c64ad24b684c2507c127dd20a074c145539e4d51a65ea7aed54b25ca9'
REPORT_SHA = 'fd7e47dbfdbe04ed68436a5800c88a28e5e6669f26d3fe9aaae6bd716a11a6d4'
VERIFIER_SHA = '865964780a80b87be79f96a37216995dfb1cc99f0f6e9baa7e52c9739b840696'
DAY_ELIGIBILITY_SHA = 'a7b4aecabd8c6e3cfe08884a9c12a4b9bcca639ae95c03439f04342755d16a35'
DAY_ELIGIBILITY_SCOPE = 'Packet-count eligibility only; requires independent manifest/identity QA and does not fix the day tool.'
SCHEMA = '2026-11-25-ip-frame-direction-v2'
AGG_FILES = ('quality.json', 'overall-overheads.csv', 'domain-overheads.csv', 'extraction-errors.json')
DESC_FILES = ('descriptive-provenance.json', 'session-distributions-by-cohort.csv',
              'session-distributions-by-condition.csv', 'sensitivity-by-domain.csv',
              'sensitivity-overall.csv', 'shared-utc-day-sensitivity.csv', 'shared-utc-day-summary.csv',
              'capture-epochs-by-cohort.csv', 'capture-epoch-offsets-by-domain.csv')
DAY_FILES = ('utc-day-cluster-provenance.json', 'utc-day-cluster-by-domain.csv',
             'utc-day-cluster-eligible-subset-summary.csv')
FIG_FILES = ('figure-provenance.json', '01-overall-overheads.svg', '01-overall-overheads.pdf',
             '02-domain-spread.svg', '02-domain-spread.pdf')
CLEAN_FILES = ('clean-tuple-quality.json', 'domain-clean-tuple-sensitivity.csv',
               'overall-clean-tuple-sensitivity.csv')
DOMAIN_FILES = ('domain-session-provenance.json', 'domain-session-bootstrap.csv')
CAVEAT_VERSION = 'domain-cluster-reused-draw-v1'
DRAFT_WARNING = '''> **PROVISIONAL GENERATOR DRAFT — NOT REVIEWED.** Its domain-cluster interval
> columns use the original aggregator's reused within-domain session draw for
> repeated domain selections. This is not an independent-occurrence two-stage
> bootstrap and can inflate the within-domain contribution. Remove or replace
> the affected intervals, related prose and replicate-count labels during review.
> Point estimates and fixed-domain session
> intervals are unaffected by this specific issue; their assumptions still apply.
> The separate UTC-day sensitivity is a different analysis. The exact unmodified
> generator output starts after this warning and is hashed in bundle provenance.

'''
AGGREGATE_WARNING = '''# Caveat for the original aggregate tables

The pinned original aggregator reuses the same within-domain session draw when
a domain is selected more than once in a resampling replicate. The
`macro_ci95_domain_cluster_low` and `macro_ci95_domain_cluster_high` fields in
`overall-overheads.csv` are therefore not conventional independent-occurrence
two-stage bootstrap intervals and can inflate the within-domain contribution.
Do not use these fields as the reviewed domain uncertainty results. Consult the
supplied report and any supplementary sensitivity after independent review.
The point estimates and fixed-domain session-bootstrap intervals are unaffected
by this specific implementation issue, though their statistical assumptions and
temporal limitations remain. UTC-day cluster sensitivity is a separate method.
The unmodified raw tables are retained for transparency and reproducibility.
'''
METRIC_FIELDS = ('defense', 'domain', 'session', 'filename', 'drive_file_id', 'sha256', 'capture_bytes',
                 'capture_type', 'encapsulation', 'packet_count', 'packet_bytes', 'ip_bytes', 'ip_valid',
                 'udp443_direction_valid', 'udp443_up_ip_bytes', 'udp443_down_ip_bytes', 'other_ip_bytes',
                 'no_udp_ports_ip_bytes', 'udp443_tuple_candidates', 'udp443_candidate_overflow',
                 'span_seconds', 'first_epoch', 'last_epoch', 'strict_order', 'ipv4_packets', 'ipv6_packets',
                 'truncated_packets', 'non_ip_packets', 'multiple_ip_packets', 'ipv6_zero_payload_packets',
                 'malformed_ip_packets', 'unverified_link_packets')
ALLOWED_KEYS = set(METRIC_FIELDS) | {'source', 'status', 'error'}
PERSONAL_PATH = re.compile(r'(?i)(?:/Users/|/Volumes/|/home/|/tmp/|file://|~/\.)')


def sha_file(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def regular(path):
    p = Path(path)
    if p.is_symlink() or not p.is_file():
        raise ValueError('Expected a regular non-symlink file: ' + p.name)
    return p


def fixed_file(path, expected):
    p = regular(path)
    if sha_file(p) != expected:
        raise ValueError('Input hash mismatch: ' + p.name)
    return p


def json_file(path):
    obj = json.loads(regular(path).read_text(encoding='utf-8'))
    if not isinstance(obj, dict):
        raise ValueError('Expected JSON object: ' + Path(path).name)
    return obj


def valid_sha(s):
    return isinstance(s, str) and len(s) == 64 and all(c in '0123456789abcdef' for c in s)


def read_manifest(path, *, expected_domains=50, sessions=400, expected_sha=MANIFEST_SHA):
    fixed_file(path, expected_sha)
    result, objects = {}, set()
    with Path(path).open(newline='', encoding='utf-8-sig') as f:
        for row in csv.DictReader(f):
            try:
                key = (row['defense'], row['domain'], int(row['session']))
                obj, digest, size, name = row['drive_file_id'], row['sha256'], int(row['size']), row['filename']
            except (KeyError, ValueError) as exc:
                raise ValueError('Malformed manifest row') from exc
            if (key in result or key[0] not in MODES or obj in objects or not obj or
                    not valid_sha(digest) or size <= 0 or not name or '/' in name or '\\' in name):
                raise ValueError('Invalid or duplicate manifest identity')
            result[key] = {'id': obj, 'sha': digest, 'size': size, 'filename': name}
            objects.add(obj)
    domains = {k[1] for k in result}
    expected = {(d, h, i) for d in MODES for h in domains for i in range(1, sessions + 1)}
    if len(domains) != expected_domains or set(result) != expected:
        raise ValueError('Manifest is not the complete balanced design')
    return result, sorted(domains)


def metric_object(row, manifest):
    mode, domain, session, file_id, digest, raw = row
    key = (mode, domain, session)
    target = manifest.get(key)
    if not target or file_id != target['id'] or digest != target['sha'] or not isinstance(raw, str):
        raise ValueError('Metric identity differs from final manifest')
    try:
        obj = json.loads(raw)
    except (ValueError, TypeError) as exc:
        raise ValueError('Invalid metric JSON') from exc
    if not isinstance(obj, dict) or set(obj) != ALLOWED_KEYS:
        raise ValueError('Unexpected metric fields require review')
    if (obj['defense'] != mode or obj['domain'] != domain or type(obj['session']) is not int or obj['session'] != session or
            obj['drive_file_id'] != file_id or obj['sha256'] != digest or
            obj['filename'] != target['filename'] or obj['capture_bytes'] != target['size'] or
            obj['source'] not in ('local', 'drive-http') or obj['status'] != 'ok' or obj['error'] != ''):
        raise ValueError('Metric contents differ from manifest or contain error')
    for key, value in obj.items():
        if isinstance(value, (dict, list)):
            raise ValueError('Nested metric value requires review')
        if isinstance(value, str) and PERSONAL_PATH.search(value):
            raise ValueError('Machine path in metric requires review')
    for field in ('ip_bytes', 'packet_bytes', 'packet_count', 'capture_bytes'):
        if type(obj[field]) is not int or obj[field] < 0:
            raise ValueError('Invalid metric integer: ' + field)
    if obj['packet_count'] < 1 or type(obj['ip_valid']) is not bool:
        raise ValueError('Invalid packet count or IP quality flag')
    span = obj['span_seconds']
    if isinstance(span, bool) or not isinstance(span, (int, float)) or not math.isfinite(span) or span < 0:
        raise ValueError('Invalid observed span')
    return obj


def canonical_row(row):
    # Must match aggregate.load_metrics exactly, including original JSON text.
    return (json.dumps(list(row), ensure_ascii=False, separators=(',', ':')) + '\n').encode('utf-8')


QUERY = 'SELECT defense,domain,session,drive_file_id,sha256,result_json FROM metrics ORDER BY defense,domain,session'


def verify_database(con, manifest, expected_manifest_sha, expected_snapshot, *, expected_schema=SCHEMA):
    meta = dict(con.execute('SELECT key,value FROM metadata'))
    if meta.get('manifest_sha256') != expected_manifest_sha or meta.get('metrics_schema') != expected_schema:
        raise ValueError('Database manifest or metric schema mismatch')
    if con.execute('SELECT COUNT(*) FROM errors').fetchone()[0] != 0:
        raise ValueError('Extractor errors remain')
    if con.execute('SELECT COUNT(*) FROM metrics').fetchone()[0] != len(manifest):
        raise ValueError('Incomplete metric census')
    count, h, modes = 0, hashlib.sha256(), {}
    for row in con.execute(QUERY):
        metric_object(row, manifest)
        h.update(canonical_row(row))
        count += 1
        modes[row[0]] = modes.get(row[0], 0) + 1
    if count != len(manifest) or h.hexdigest() != expected_snapshot:
        raise ValueError('Metric snapshot digest does not match completed analysis')
    return {'rows': count, 'counts_by_condition': modes, 'metric_rows_content_sha256': h.hexdigest()}


def validate_provenance(aggregate, descriptive, figures, day, *, manifest_sha=MANIFEST_SHA,
                        aggregate_sha=AGGREGATE_SHA, describe_sha=DESCRIBE_SHA,
                        figure_sha=FIGURE_SHA, day_sha=DAY_SHA, expected_rows=120000):
    a, d, f, t = map(Path, (aggregate, descriptive, figures, day))
    q = json_file(a / 'quality.json')
    dp = json_file(d / 'descriptive-provenance.json')
    fp = json_file(f / 'figure-provenance.json')
    tp = json_file(t / 'utc-day-cluster-provenance.json')
    snapshot = q.get('metric_rows_content_sha256')
    if (q.get('status') != 'complete' or q.get('manifest_sessions') != expected_rows or
            q.get('accepted_metric_rows') != expected_rows or q.get('extractor_errors') != 0 or
            q.get('identity_or_other_flags') != {} or q.get('manifest_sha256') != manifest_sha or
            q.get('analysis_script_sha256') != aggregate_sha or not valid_sha(snapshot)):
        raise ValueError('Primary quality/provenance is incomplete or mismatched')
    for obj, label, codekey, code in ((dp, 'descriptive', 'descriptive_code_sha256', describe_sha),
                                      (tp, 'day cluster', 'bootstrap_code_sha256', day_sha)):
        if (obj.get('status') != 'complete' or obj.get('manifest_sha256') != manifest_sha or
                obj.get('metric_rows_content_sha256') != snapshot or obj.get('aggregate_code_sha256') != aggregate_sha or
                obj.get('metric_rows') != expected_rows or obj.get(codekey) != code):
            raise ValueError(label + ' provenance mismatch')
    if (fp.get('status') != 'complete' or fp.get('manifest_sha256') != manifest_sha or
            fp.get('metric_rows_content_sha256') != snapshot or fp.get('manifest_sessions') != expected_rows or
            fp.get('accepted_metric_rows') != expected_rows or fp.get('script_sha256') != figure_sha):
        raise ValueError('Figure provenance mismatch')
    for name in ('quality.json', 'overall-overheads.csv', 'domain-overheads.csv'):
        if fp.get('inputs_sha256', {}).get(name) != sha_file(regular(a / name)):
            raise ValueError('Figure input mismatch: ' + name)
    for directory, names in ((a, AGG_FILES), (d, DESC_FILES), (f, FIG_FILES), (t, DAY_FILES)):
        for name in names:
            regular(directory / name)
    if json.loads((a / 'extraction-errors.json').read_text(encoding='utf-8')) != []:
        raise ValueError('Published extractor error report is not empty')
    return q, dp, fp, tp


def check_day_tables(day, domains):
    """Check day-cluster table identities and summary coverage independently."""
    def read(path):
        with Path(path).open(newline='', encoding='utf-8-sig') as f:
            return list(csv.DictReader(f))
    rows = read(Path(day) / 'utc-day-cluster-by-domain.csv')
    sums = read(Path(day) / 'utc-day-cluster-eligible-subset-summary.csv')
    expected = {(mode, metric, domain) for mode in MODES[1:] for metric in ('ip_bytes', 'observed_span') for domain in domains}
    keys = [(r['defense'], r['metric'], r['domain']) for r in rows]
    if len(keys) != len(expected) or set(keys) != expected:
        raise ValueError('Day-cluster domain table is incomplete or duplicated')
    expected_summary = {(m, metric) for m in MODES[1:] for metric in ('ip_bytes', 'observed_span')}
    summary_keys = [(r['defense'], r['metric']) for r in sums]
    if len(summary_keys) != len(expected_summary) or set(summary_keys) != expected_summary:
        raise ValueError('Day-cluster summaries are incomplete or duplicated')
    for s in sums:
        subset = [r for r in rows if r['defense'] == s['defense'] and r['metric'] == s['metric']]
        eligible = [r for r in subset if r['status'] == 'eligible']
        if (int(s['eligible_domains']) != len(eligible) or int(s['expected_domains']) != len(domains) or
                s['all_domains_eligible'].lower() != str(len(eligible) == len(domains)).lower()):
            raise ValueError('Day-cluster eligible domain count mismatch')
        if eligible:
            value = sum(float(r['overhead_pct']) for r in eligible) / len(eligible)
            recorded = float(s['equal_domain_mean_overhead_pct_eligible_subset'])
            if not math.isfinite(value) or not math.isclose(value, recorded, rel_tol=1e-10, abs_tol=1e-8):
                raise ValueError('Day-cluster subset point summary mismatch')
            lo = float(s['day_bootstrap_percentile95_low_pct_eligible_subset'])
            hi = float(s['day_bootstrap_percentile95_high_pct_eligible_subset'])
            if not math.isfinite(lo) or not math.isfinite(hi) or lo > hi:
                raise ValueError('Day-cluster subset percentile interval invalid')
        elif s['equal_domain_mean_overhead_pct_eligible_subset'].strip():
            raise ValueError('Day-cluster summary invents an empty-subset value')


def validate_census(path, *, snapshot, manifest_sha=MANIFEST_SHA,
                    verifier_sha=VERIFIER_SHA, expected_rows=120000):
    """Require a separate verifier's complete report on the same DB snapshot."""
    result = json_file(path)
    if (result.get('status') != 'verified_full' or result.get('observed_rows') != expected_rows or
            result.get('expected_rows') != expected_rows or result.get('missing_rows') != 0 or
            result.get('database_error_rows') != 0 or result.get('structural_defects') != {} or
            result.get('schema') != SCHEMA or result.get('manifest_sha256') != manifest_sha or
            result.get('metric_rows_content_sha256') != snapshot or result.get('verifier_sha256') != verifier_sha):
        raise ValueError('Independent census is incomplete or mismatched')
    conditions = result.get('conditions')
    if not isinstance(conditions, dict) or set(conditions) != set(MODES):
        raise ValueError('Independent census condition coverage is incomplete')
    expected_per_condition = expected_rows // len(MODES)
    for condition in conditions.values():
        if (not isinstance(condition, dict) or condition.get('rows') != expected_per_condition or
                condition.get('defects') != {}):
            raise ValueError('Independent census condition identity defects')
    return result


def validate_clean_provenance(clean_quality, primary_quality, script_sha, *, expected_rows=120000):
    """Bind optional whole-capture sensitivity to this exact primary snapshot.

    The script hash binds the supplied source bytes, not the scientific
    correctness of the analysis; inspect and independently review the code.
    """
    if (not valid_sha(script_sha) or clean_quality.get('status') != 'complete' or
            clean_quality.get('manifest_sha256') != primary_quality.get('manifest_sha256') or
            clean_quality.get('metric_rows_content_sha256') != primary_quality.get('metric_rows_content_sha256') or
            clean_quality.get('aggregate_library_sha256') != primary_quality.get('analysis_script_sha256') or
            clean_quality.get('analysis_script_sha256') != script_sha or
            clean_quality.get('accepted_records') != expected_rows or
            clean_quality.get('extractor_errors') != 0 or clean_quality.get('identity_or_other_flags') != {}):
        raise ValueError('Clean tuple sensitivity provenance mismatch')


def validate_clean_tables(detail, summaries, primary, domains, *, sessions=400):
    """Check identities, eligibility, primary joins and sensitivity arithmetic."""
    metrics = ('ip_bytes', 'observed_span')
    def key(row):
        return (row['defense'], row['metric'], row['domain'])
    expected = {(d, m, h) for d in MODES[1:] for m in metrics for h in domains}
    detail_keys = [key(r) for r in detail]
    if len(detail_keys) != len(expected) or set(detail_keys) != expected:
        raise ValueError('Clean tuple domain table is incomplete or duplicated')
    primary_rows = [r for r in primary if r['metric'] in metrics]
    primary_keys = [key(r) for r in primary_rows]
    if len(primary_keys) != len(expected) or set(primary_keys) != expected:
        raise ValueError('Primary domain table is incomplete or duplicated')
    primary_map = {key(r): r for r in primary_rows}
    summary_keys = [(r['defense'], r['metric']) for r in summaries]
    expected_summary = {(d, m) for d in MODES[1:] for m in metrics}
    if len(summary_keys) != len(expected_summary) or set(summary_keys) != expected_summary:
        raise ValueError('Clean tuple summaries are incomplete or duplicated')

    def nint(value):
        try:
            n = int(value)
        except (ValueError, TypeError) as exc:
            raise ValueError('Invalid clean tuple count') from exc
        if n < 0:
            raise ValueError('Negative clean tuple count')
        return n

    def number(value):
        try:
            x = float(value)
        except (ValueError, TypeError) as exc:
            raise ValueError('Invalid clean tuple numeric value') from exc
        if not math.isfinite(x):
            raise ValueError('Non-finite clean tuple numeric value')
        return x

    def close(actual, expected_value):
        if not math.isclose(number(actual), expected_value, rel_tol=1e-9, abs_tol=1e-8):
            raise ValueError('Clean tuple table arithmetic mismatch')

    for row in detail:
        ref = primary_map[key(row)]
        if row.get('unit') != ('bytes' if row['metric'] == 'ip_bytes' else 'seconds'):
            raise ValueError('Clean tuple metric unit mismatch')
        for side in ('baseline', 'defense'):
            total = nint(row[side + '_expected_n'])
            full = nint(row[side + '_full_n'])
            clean = nint(row[side + '_clean_n'])
            removed = nint(row[side + '_removed_by_clean_filter'])
            if total != sessions or full > total or clean > full or removed != full - clean:
                raise ValueError('Inconsistent clean tuple cohort counts')
            if full != nint(ref[side + '_n']):
                raise ValueError('Clean tuple primary cohort count mismatch')
            for field, count in ((side + '_primary_exclusions', total - full),
                                 (side + '_clean_filter_reasons', removed)):
                try:
                    reasons = json.loads(row[field])
                except (ValueError, TypeError) as exc:
                    raise ValueError('Invalid clean tuple exclusion reasons') from exc
                if (not isinstance(reasons, dict) or any(type(v) is not int or v < 0 for v in reasons.values())
                        or sum(reasons.values()) != count):
                    raise ValueError('Clean tuple exclusion reasons do not match counts')
        for field in ('baseline_mean', 'defense_mean', 'absolute_difference', 'overhead_pct'):
            close(row['full_' + field], number(ref[field]))
        for label in ('full', 'clean'):
            fields = [row[label + '_' + f] for f in ('baseline_mean', 'defense_mean', 'absolute_difference', 'overhead_pct')]
            if not any(fields):
                if label == 'full':
                    raise ValueError('Clean tuple full comparison missing')
                continue
            if not all(fields):
                raise ValueError('Partially missing clean tuple comparison')
            baseline, defended = map(number, fields[:2])
            if baseline <= 0 or defended < 0 or not nint(row['baseline_' + label + '_n']) or not nint(row['defense_' + label + '_n']):
                raise ValueError('Invalid clean tuple cohort mean')
            close(fields[2], defended - baseline)
            close(fields[3], 100 * (defended / baseline - 1))
        if row['clean_overhead_pct']:
            close(row['clean_minus_full_overhead_percentage_points'],
                  number(row['clean_overhead_pct']) - number(row['full_overhead_pct']))
        elif row['clean_minus_full_overhead_percentage_points']:
            raise ValueError('Clean tuple difference exists without a clean comparison')

    for row in summaries:
        if row.get('unit') != ('bytes' if row['metric'] == 'ip_bytes' else 'seconds'):
            raise ValueError('Clean tuple summary unit mismatch')
        subset = [r for r in detail if (r['defense'], r['metric']) == (row['defense'], row['metric'])]
        selections = {'full_available': [r for r in subset if r['full_overhead_pct']],
                      'clean_available': [r for r in subset if r['clean_overhead_pct']]}
        common = [r for r in subset if r['full_overhead_pct'] and r['clean_overhead_pct']]
        selections.update(full_common=common, clean_common=common)
        if nint(row['expected_domains']) != len(domains) or row['common_domain_coverage_complete'].lower() != str(len(common) == len(domains)).lower():
            raise ValueError('Clean tuple summary coverage mismatch')
        for name, selected in selections.items():
            label = name.split('_')[0]
            if nint(row[name + '_domains']) != len(selected):
                raise ValueError('Clean tuple summary domain count mismatch')
            fields = ('macro_overhead_pct', 'pooled_cohort_mean_overhead_pct',
                      'baseline_equal_domain_mean', 'defense_equal_domain_mean')
            if not selected:
                if any(row[name + '_' + f] for f in fields):
                    raise ValueError('Clean tuple empty summary has values')
                continue
            base = sum(number(r[label + '_baseline_mean']) for r in selected)
            defended = sum(number(r[label + '_defense_mean']) for r in selected)
            values = (sum(number(r[label + '_overhead_pct']) for r in selected) / len(selected),
                      100 * (defended / base - 1), base / len(selected), defended / len(selected))
            for field, val in zip(fields, values):
                close(row[name + '_' + field], val)
        for field in ('macro_overhead_pct', 'pooled_cohort_mean_overhead_pct'):
            diff = row['clean_minus_full_common_' + field + '_percentage_points']
            if common:
                close(diff, number(row['clean_common_' + field]) - number(row['full_common_' + field]))
            elif diff:
                raise ValueError('Clean tuple empty comparison has a difference')


def validate_domain_bootstrap(prov, quality, script_sha, data, primary_quality, primary_summary, primary_domain, manifest_data):
    """Bind optional exploratory domain bootstrap to the exact primary inputs.

    This checks provenance, coverage, interval shape and point-estimate joins;
    it does not rerun bootstrap draws or establish interval coverage.
    """
    digest = lambda x: hashlib.sha256(x).hexdigest()
    if (prov.get('status') not in ('complete', 'review_required')
            or prov.get('manifest_sha256') != quality.get('manifest_sha256')
            or prov.get('metric_rows_content_sha256') != quality.get('metric_rows_content_sha256')
            or prov.get('primary_aggregate_sha256') != quality.get('analysis_script_sha256')
            or prov.get('captured_records') != quality.get('accepted_metric_rows')
            or prov.get('analysis_script_sha256') != script_sha
            or prov.get('primary_quality_sha256') != digest(primary_quality)
            or prov.get('primary_summary_sha256') != digest(primary_summary)
            or prov.get('primary_domain_table_sha256') != digest(primary_domain)
            or prov.get('output_csv_sha256') != digest(data)
            or quality.get('manifest_sha256') != digest(manifest_data)
            or (quality.get('accepted_metric_rows') == 120000 and quality.get('manifest_sha256') != MANIFEST_SHA)
            or type(prov.get('seed')) is not int or type(prov.get('replicates')) is not int
            or prov['replicates'] < 100
            or any(not isinstance(prov.get(k), str) or not prov[k].strip()
                   for k in ('numpy_version', 'python_version', 'random_generator', 'method', 'scope'))):
        raise ValueError('Exploratory domain bootstrap provenance mismatch')
    def read(raw):
        return list(csv.DictReader(io.StringIO(raw.decode('utf-8-sig'), newline='')))
    primary_rows = [r for r in read(primary_summary) if r.get('metric') in ('ip_bytes', 'observed_span')]
    bootstrap_rows = read(data)
    expected = {(mode, metric) for mode in MODES[1:] for metric in ('ip_bytes', 'observed_span')}
    def keyed(rows):
        result = {}
        for row in rows:
            key = (row.get('defense'), row.get('metric'))
            if key in result:
                raise ValueError('Duplicate exploratory domain bootstrap row')
            result[key] = row
        return result
    actual, primary = keyed(bootstrap_rows), keyed(primary_rows)
    if set(actual) != expected or set(primary) != expected:
        raise ValueError('Incomplete exploratory domain bootstrap or primary summary')
    detail = [r for r in read(primary_domain) if r.get('metric') in ('ip_bytes', 'observed_span')]
    detail_keys = [(r.get('defense'), r.get('metric'), r.get('domain')) for r in detail]
    domain_names = {key[2] for key in detail_keys}
    if (None in domain_names or '' in domain_names or not domain_names
            or len(detail_keys) != len(set(detail_keys))
            or set(detail_keys) != {(mode, metric, domain) for mode, metric in expected for domain in domain_names}
            or (quality.get('accepted_metric_rows') == 120000 and len(domain_names) != 50)):
        raise ValueError('Exploratory domain bootstrap primary domain coverage mismatch')
    try:
        identities = [(r['defense'], r['domain'], int(r['session'])) for r in read(manifest_data)]
        sessions = {key[2] for key in identities}
        if (not sessions or sessions != set(range(1, len(sessions) + 1))
                or len(identities) != len(set(identities))
                or len(identities) != quality.get('accepted_metric_rows')
                or set(identities) != {(mode, domain, session) for mode in MODES for domain in domain_names for session in sessions}):
            raise ValueError('Manifest identities differ from primary domain coverage')
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError('Exploratory domain bootstrap manifest mismatch: ' + str(exc)) from exc
    domains = None
    statuses = set()
    for key, row in actual.items():
        try:
            p = primary[key]
            n = int(row['expected_domains'])
            if (n <= 0 or int(row['eligible_domains']) != n or json.loads(row['unavailable_domains']) != []
                    or int(p['domains']) != n or p['provisional'].lower() != 'false'
                    or row['unit'] != ('bytes' if key[1] == 'ip_bytes' else 'seconds')):
                raise ValueError('Incomplete exploratory domain cohort')
            if domains is None:
                domains = n
            if n != domains or n != len(domain_names):
                raise ValueError('Inconsistent domain coverage')
            point, ref = float(row['macro_overhead_pct']), float(p['macro_overhead_pct'])
            if not math.isfinite(point) or not math.isfinite(ref) or not math.isclose(point, ref, rel_tol=1e-10, abs_tol=1e-8):
                raise ValueError('Exploratory domain macro does not match primary summary')
            req, valid = int(row['requested_replicates']), int(row['valid_replicates'])
            undefined, occurrences = int(row['undefined_replicates']), int(row['undefined_domain_occurrences'])
            domain_valid = int(row['domain_only_valid_replicates'])
            if (req != prov['replicates'] or not 0 <= valid <= req or undefined != req - valid
                    or not undefined <= occurrences <= req * n or domain_valid != req):
                raise ValueError('Invalid exploratory domain bootstrap replicate counts')
            expected_status = 'complete' if valid == req else 'conditional_on_finite_draws' if valid else 'no_valid_replicates'
            if row['status'] != expected_status:
                raise ValueError('Exploratory domain bootstrap row status mismatch')
            statuses.add(expected_status)
            for prefix, count in (('two_stage', valid), ('domain_only', domain_valid)):
                lo, hi = row[prefix + '_percentile_95_low_pct'], row[prefix + '_percentile_95_high_pct']
                if count == 0:
                    if lo or hi:
                        raise ValueError('Unavailable exploratory interval has bounds')
                elif not (math.isfinite(float(lo)) and math.isfinite(float(hi)) and float(lo) <= float(hi)):
                    raise ValueError('Invalid exploratory interval bounds')
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ValueError('Invalid exploratory domain bootstrap table: ' + str(exc)) from exc
    if (prov.get('primary_domain_rows_checked') != len(expected) * domains
            or prov.get('primary_domain_rows_unavailable') != 0
            or prov['status'] != ('complete' if statuses == {'complete'} else 'review_required')):
        raise ValueError('Exploratory domain bootstrap coverage/status mismatch')


def validate_day_packet_eligibility(result, quality):
    """Check packet-count QA schema/snapshot, not the check's computation."""
    categories = result.get('packet_count_categories')
    allowed = {'valid', 'invalid_json', 'non_object', 'missing', 'null', 'boolean',
               'non_numeric', 'nonfinite_or_overflow', 'nonpositive'}
    total = quality.get('accepted_metric_rows')
    if (not isinstance(categories, dict) or not set(categories) <= allowed
            or any(type(v) is not int or v < 0 for v in categories.values())
            or type(total) is not int or total <= 0 or sum(categories.values()) != total
            or result.get('records') != total
            or result.get('metric_rows_content_sha256') != quality.get('metric_rows_content_sha256')
            or result.get('scope') != DAY_ELIGIBILITY_SCOPE):
        raise ValueError('UTC-day packet-count eligibility result is invalid or mismatched')
    expected_status = 'passed' if categories.get('valid', 0) == total else 'review_required'
    if result.get('status') != expected_status:
        raise ValueError('UTC-day packet-count eligibility status mismatch')


def load_builder(path, expected_sha=REPORT_SHA):
    fixed_file(path, expected_sha)
    spec = importlib.util.spec_from_file_location('verified_study_report_builder', path)
    if not spec or not spec.loader:
        raise ValueError('Cannot load verified report builder')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def checked_text(path):
    data = regular(path).read_bytes()
    text = data.decode('utf-8-sig')
    if PERSONAL_PATH.search(text):
        raise ValueError('Historical machine path in publishable text: ' + Path(path).name)
    return data


def add_bytes(z, digests, name, data):
    if name.startswith('/') or '..' in Path(name).parts or name in digests:
        raise ValueError('Invalid or duplicate bundle member')
    z.writestr(name, data)
    digests[name] = hashlib.sha256(data).hexdigest()


def add_file(z, digests, name, path, *, text=False):
    p = regular(path)
    # Tables are small; check text for machine paths and preserve original bytes.
    data = checked_text(p) if text else p.read_bytes()
    add_bytes(z, digests, name, data)


def write_metrics(z, con, manifest, expected_snapshot, digests):
    """Write exact canonical rows and a useful flat CSV from one DB snapshot."""
    h = hashlib.sha256()
    with z.open('measurements/session-metrics-canonical.jsonl', 'w', force_zip64=True) as out:
        for row in con.execute(QUERY):
            metric_object(row, manifest)
            data = canonical_row(row)
            h.update(data)
            out.write(data)
    if h.hexdigest() != expected_snapshot:
        raise ValueError('Metric snapshot changed while exporting')
    digests['measurements/session-metrics-canonical.jsonl'] = h.hexdigest()
    hcsv = hashlib.sha256()
    # Reuse a one-line text buffer: ZIP members cannot have two writers open,
    # and this avoids retaining the 120,000-row CSV in memory.
    with z.open('measurements/session-metrics.csv', 'w', force_zip64=True) as raw:
        buffer = io.StringIO(newline='')
        csv_writer = csv.DictWriter(buffer, fieldnames=METRIC_FIELDS, lineterminator='\n', extrasaction='ignore')
        def flush_line():
            data = buffer.getvalue().encode('utf-8')
            hcsv.update(data)
            raw.write(data)
            buffer.seek(0)
            buffer.truncate(0)
        csv_writer.writeheader()
        flush_line()
        for row in con.execute(QUERY):
            csv_writer.writerow(metric_object(row, manifest))
            flush_line()
    digests['measurements/session-metrics.csv'] = hcsv.hexdigest()


README = '''# Final PCAP-only study: derived results bundle

This archive contains derived data and results, **not packet captures**. Input
captures are in the final [six-defense handoff](https://drive.google.com/drive/folders/1mE0wM6ZJ7AoJli-9d0ckRnShO2bWVdNQ).
All traffic and time values here came from that handoff's standalone PCAPs.
No historical runtime or application-completion values were used.

**Domain-cluster interval caveat:** The original aggregate's domain-cluster
interval reuses a domain's same within-domain session draw when that domain is
selected repeatedly in a replicate. It is not an independent-occurrence
two-stage bootstrap and can inflate the within-domain component. The raw
`results/aggregate/overall-overheads.csv` fields and the provisional generator
draft retain those original intervals; see `results/aggregate/README.md` and
the draft's warning. Review the supplied report and any exploratory sensitivity
before using them. Point estimates and fixed-domain session-bootstrap
intervals are unaffected by this particular issue. UTC-day analysis is separate.

`measurements/session-metrics.csv` is a readable table by defense, domain and
session. `measurements/session-metrics-canonical.jsonl` contains the exact
ordered JSON array rows hashed by the public aggregator, including the original
metric JSON as a JSON *string*. Its SHA-256 must equal the
`metric_rows_content_sha256` in `results/aggregate/quality.json` and bundle provenance.
The JSONL contains no packet contents or credential data. To reconstruct a
SQLite `metrics` table, JSON-decode each line's six fields and insert them in
the column order documented by the public aggregation code. The original
`source` value says only whether that capture was read locally or by Drive HTTP.
The public toolkit's derived-bundle `restore_metrics.py` performs this restore
into a new SQLite database and cross-checks the CSV against the canonical rows.

`inputs/session-manifest.csv` and `resources.csv` identify the exact handoff.
`results/` provides cohort and aggregate tables, bootstrap uncertainty,
exclusions, distribution/timing sensitivities and exploratory day-cluster
results. Optional `results/clean-tuple/` contains whole-capture selection
sensitivity tables, provenance and the exact sensitivity script. It is not a
correction for unrelated traffic or confounding. The archived script is a
source record and is not runnable from its archive location: use the published
toolkit copy, or place this exact script in its toolkit subdirectory with the
matching `aggregate.py` one directory above. Optional `results/domain-bootstrap/`
contains exploratory domain-only and independent-occurrence two-stage
sensitivities and their exact source. These require independent review, do not establish confidence
coverage or representativeness, and two-stage resampling can overstate variance.
Optional `results/day-eligibility/` preserves the snapshot-bound packet-count
eligibility check and its source. Its status covers this one criterion only;
it does not establish other UTC-day eligibility or interval validity. The check
JSON does not identify its source hash; the archived source is checked against
the watcher's pinned version, but matching bytes do not prove that code ran it.
`figures/` provides SVG/PDF
figures and input provenance. The report
folder contains the supplied report and the provisional generator draft, with a
warning prepended and the original draft's hash recorded in bundle provenance.
Supplying a matching report hash binds the report bytes; it does
**not** establish that anyone reviewed the report or that its claims are true.
An independent reviewer should check the report and figures against the source
tables before publication. `SHA256SUMS.txt` hashes every other archive member.

The primary volume metric sums observed IP datagram bytes, including captured
retransmissions; PCAP container size is not network volume. The time metric is
first-to-last observed packet span, which can include padding or teardown and
is **not application completion or page-load time**. Defended and baseline
sessions are separately recorded, unpaired cohorts. Results do not establish
causality, defense fidelity or classifier resistance. Refer to the [methods](https://drive.google.com/file/d/1J_WjNax8tIs57md4HN8bFKD32C8V2sg4/view),
[practicality notes](https://drive.google.com/file/d/1fVF7y0gwBWwWIvrk4vtPFpqTLI4XTeOU/view),
and [public analysis toolkit](https://github.com/kaisequeira/neqo-qcsd-lab/tree/main/tools/pcap-overhead).
All methods/metrics remain reproducible from the final captures and manifest.
Checksums detect changes, not authorship or correctness: independently re-run
the measurement code on the PCAPs when scientific verification is needed.
UTC-day sensitivity is exploratory, may cover only a subset of domains, and
cannot remove temporal confounding or establish independent days.
'''


def verify_zip(path, *, strict=False, expected_day_eligibility_sha=DAY_ELIGIBILITY_SHA):
    with zipfile.ZipFile(path) as z:
        if z.testzip() is not None:
            raise ValueError('ZIP CRC validation failed')
        lines = z.read('SHA256SUMS.txt').decode('utf-8').splitlines()
        listed = {}
        for line in lines:
            digest, name = line.split('  ', 1)
            if not valid_sha(digest) or name in listed:
                raise ValueError('Invalid bundle checksum list')
            listed[name] = digest
        names = set(z.namelist())
        if len(names) != len(z.namelist()) or names != set(listed) | {'SHA256SUMS.txt'}:
            raise ValueError('Bundle member/checksum inventory mismatch')
        if any(name.startswith('/') or '\\' in name or '..' in Path(name).parts for name in names):
            raise ValueError('Unsafe bundle member name')
        if strict:
            expected = {'README.md', 'inputs/session-manifest.csv', 'inputs/resources.csv',
                        'measurements/session-metrics-canonical.jsonl', 'measurements/session-metrics.csv',
                        'report/supplied-report.md', 'report/canonical-review-draft.md',
                        'results/independent-census-qa.json', 'bundle-provenance.json', 'SHA256SUMS.txt'}
            for prefix, files in (('results/aggregate', AGG_FILES), ('results/descriptive', DESC_FILES),
                                  ('results/day-cluster', DAY_FILES), ('figures', FIG_FILES)):
                expected.update(prefix + '/' + n for n in files)
            allowed_exclusions = {'results/aggregate/cohort-exclusions.csv',
                                  'results/aggregate/no-cohort-exclusions.txt'}
            clean_members = {'results/clean-tuple/' + n for n in CLEAN_FILES} | {'results/clean-tuple/clean_tuple_sensitivity.py'}
            domain_members = {'results/domain-bootstrap/' + n for n in DOMAIN_FILES} | {'results/domain-bootstrap/domain_bootstrap.py'}
            day_eligibility_members = {'results/day-eligibility/day-packet-eligibility.json',
                                       'results/day-eligibility/check_day_packet_count_eligibility.py'}
            caveat_member = {'results/aggregate/README.md'}
            present_clean = names & clean_members
            present_domain = names & domain_members
            present_day_eligibility = names & day_eligibility_members
            if present_clean and present_clean != clean_members:
                raise ValueError('Clean tuple sensitivity is incomplete')
            if present_domain and present_domain != domain_members:
                raise ValueError('Exploratory domain bootstrap is incomplete')
            if present_day_eligibility and present_day_eligibility != day_eligibility_members:
                raise ValueError('UTC-day packet-count eligibility evidence is incomplete')
            if len(names & allowed_exclusions) != 1 or names != expected | (names & allowed_exclusions) | present_clean | present_domain | present_day_eligibility | (names & caveat_member):
                raise ValueError('Bundle contains an unexpected or missing member')
            provenance = json.loads(z.read('bundle-provenance.json'))
            if ('clean_tuple_analysis_sha256' in provenance) != bool(present_clean):
                raise ValueError('Clean tuple provenance and archive members disagree')
            if ('domain_bootstrap_analysis_sha256' in provenance) != bool(present_domain):
                raise ValueError('Exploratory domain bootstrap provenance and archive members disagree')
            if ('day_packet_eligibility_script_sha256' in provenance) != bool(present_day_eligibility):
                raise ValueError('UTC-day packet-count eligibility provenance and archive members disagree')
            caveat_version = provenance.get('domain_cluster_caveat_version')
            original_draft_sha = provenance.get('canonical_generated_draft_sha256')
            if caveat_version is None and original_draft_sha is None:
                if names & caveat_member:
                    raise ValueError('Domain-cluster caveat member lacks provenance')
            elif (caveat_version != CAVEAT_VERSION or not valid_sha(original_draft_sha)
                  or not caveat_member <= names):
                raise ValueError('Domain-cluster caveat provenance or member is invalid')
        for name, expected in listed.items():
            h = hashlib.sha256()
            with z.open(name) as f:
                for block in iter(lambda: f.read(1024 * 1024), b''):
                    h.update(block)
            if h.hexdigest() != expected:
                raise ValueError('Bundle member hash mismatch: ' + name)
        if strict and caveat_version is not None:
            archived_draft = z.read('report/canonical-review-draft.md')
            banner = DRAFT_WARNING.encode('utf-8')
            if (z.read('results/aggregate/README.md') != AGGREGATE_WARNING.encode('utf-8')
                    or not archived_draft.startswith(banner)
                    or hashlib.sha256(archived_draft[len(banner):]).hexdigest() != original_draft_sha):
                raise ValueError('Domain-cluster caveat or original draft hash mismatch')
        if strict and present_domain:
            script_sha = hashlib.sha256(z.read('results/domain-bootstrap/domain_bootstrap.py')).hexdigest()
            if provenance.get('domain_bootstrap_analysis_sha256') != script_sha:
                raise ValueError('Exploratory domain bootstrap source hash mismatch')
            validate_domain_bootstrap(
                json.loads(z.read('results/domain-bootstrap/domain-session-provenance.json')),
                json.loads(z.read('results/aggregate/quality.json')), script_sha,
                z.read('results/domain-bootstrap/domain-session-bootstrap.csv'),
                z.read('results/aggregate/quality.json'), z.read('results/aggregate/overall-overheads.csv'),
                z.read('results/aggregate/domain-overheads.csv'), z.read('inputs/session-manifest.csv'))
        if strict and present_day_eligibility:
            code_sha = hashlib.sha256(z.read('results/day-eligibility/check_day_packet_count_eligibility.py')).hexdigest()
            if (provenance.get('day_packet_eligibility_script_sha256') != code_sha
                    or code_sha != expected_day_eligibility_sha):
                raise ValueError('UTC-day packet-count eligibility source hash mismatch')
            validate_day_packet_eligibility(
                json.loads(z.read('results/day-eligibility/day-packet-eligibility.json')),
                json.loads(z.read('results/aggregate/quality.json')))
        if strict and present_clean:
            quality = json.loads(z.read('results/aggregate/quality.json'))
            clean_quality = json.loads(z.read('results/clean-tuple/clean-tuple-quality.json'))
            source_sha = hashlib.sha256(z.read('results/clean-tuple/clean_tuple_sensitivity.py')).hexdigest()
            if provenance.get('clean_tuple_analysis_sha256') != source_sha:
                raise ValueError('Clean tuple source hash mismatch')
            validate_clean_provenance(clean_quality, quality, source_sha,
                                      expected_rows=quality.get('accepted_metric_rows'))
            def csv_rows(name):
                return list(csv.DictReader(io.StringIO(z.read(name).decode('utf-8-sig'), newline='')))
            primary = csv_rows('results/aggregate/domain-overheads.csv')
            detail = csv_rows('results/clean-tuple/domain-clean-tuple-sensitivity.csv')
            summary = csv_rows('results/clean-tuple/overall-clean-tuple-sensitivity.csv')
            domains = {r['domain'] for r in primary if r['metric'] in ('ip_bytes', 'observed_span')}
            if not domains or not detail:
                raise ValueError('Empty clean tuple domain table')
            sessions = int(detail[0]['baseline_expected_n'])
            if quality.get('accepted_metric_rows') != len(MODES) * len(domains) * sessions:
                raise ValueError('Clean tuple design does not match the complete primary census')
            validate_clean_tables(detail, summary, primary, domains, sessions=sessions)


def assemble_zip(args, con, manifest, quality, result, reviewed, draft, *, synthetic=False,
                 expected_day_eligibility_sha=DAY_ELIGIBILITY_SHA):
    """Write a previously validated snapshot. The synthetic flag is test-only."""
    args.output.parent.mkdir(parents=True, exist_ok=True)
    digests = {}
    with zipfile.ZipFile(args.output, mode='x', compression=zipfile.ZIP_DEFLATED, compresslevel=6,
                         allowZip64=True) as z:
        readme = ('SYNTHETIC FIXTURE — NOT STUDY RESULTS\n\n' if synthetic else '') + README
        add_bytes(z, digests, 'README.md', readme.encode('utf-8'))
        add_file(z, digests, 'inputs/session-manifest.csv', args.manifest, text=True)
        add_file(z, digests, 'inputs/resources.csv', args.resources, text=True)
        write_metrics(z, con, manifest, quality['metric_rows_content_sha256'], digests)
        for prefix, directory, names in (('results/aggregate', args.aggregate, AGG_FILES),
                                          ('results/descriptive', args.descriptive, DESC_FILES),
                                          ('results/day-cluster', args.day, DAY_FILES),
                                          ('figures', args.figures, FIG_FILES)):
            for name in names:
                source = Path(directory) / name
                if name.endswith('.svg') and 'SYNTHETIC FIXTURE' in checked_text(source).decode('utf-8-sig'):
                    raise ValueError('Synthetic figure cannot be exported')
                add_file(z, digests, prefix + '/' + name, source, text=not name.endswith('.pdf'))
        add_bytes(z, digests, 'results/aggregate/README.md', AGGREGATE_WARNING.encode('utf-8'))
        clean_dir = getattr(args, 'clean_tuple', None)
        clean_script = getattr(args, 'clean_tuple_script', None)
        if bool(clean_dir) != bool(clean_script):
            raise ValueError('Supply both clean tuple directory and script')
        if clean_dir:
            for name in CLEAN_FILES:
                add_file(z, digests, 'results/clean-tuple/' + name, Path(clean_dir) / name, text=True)
            add_file(z, digests, 'results/clean-tuple/clean_tuple_sensitivity.py', clean_script, text=True)
        domain_dir = getattr(args, 'domain_bootstrap', None)
        domain_script = getattr(args, 'domain_bootstrap_script', None)
        if bool(domain_dir) != bool(domain_script):
            raise ValueError('Supply both domain bootstrap directory and script')
        if domain_dir:
            for name in DOMAIN_FILES:
                add_file(z, digests, 'results/domain-bootstrap/' + name, Path(domain_dir) / name, text=True)
            add_file(z, digests, 'results/domain-bootstrap/domain_bootstrap.py', domain_script, text=True)
        day_eligibility = getattr(args, 'day_eligibility', None)
        day_eligibility_script = getattr(args, 'day_eligibility_script', None)
        if bool(day_eligibility) != bool(day_eligibility_script):
            raise ValueError('Supply both UTC-day packet-count eligibility result and script')
        if day_eligibility:
            add_file(z, digests, 'results/day-eligibility/day-packet-eligibility.json', day_eligibility, text=True)
            add_file(z, digests, 'results/day-eligibility/check_day_packet_count_eligibility.py', day_eligibility_script, text=True)
        optional = Path(args.aggregate) / 'cohort-exclusions.csv'
        if optional.exists():
            add_file(z, digests, 'results/aggregate/cohort-exclusions.csv', optional, text=True)
        else:
            add_bytes(z, digests, 'results/aggregate/no-cohort-exclusions.txt',
                      b'The aggregator did not emit a cohort-exclusions.csv file; consult quality.json.\n')
        add_bytes(z, digests, 'report/supplied-report.md', reviewed)
        draft_bytes = draft.encode('utf-8')
        add_bytes(z, digests, 'report/canonical-review-draft.md', DRAFT_WARNING.encode('utf-8') + draft_bytes)
        add_file(z, digests, 'results/independent-census-qa.json', args.census_qa, text=True)
        provenance = {'status': 'synthetic_fixture' if synthetic else 'complete_hash_bound_inputs',
                      'manifest_sha256': MANIFEST_SHA, 'resources_sha256': RESOURCES_SHA,
                      'metric_rows_content_sha256': result['metric_rows_content_sha256'],
                      'metric_rows': result['rows'], 'counts_by_condition': result['counts_by_condition'],
                      'aggregate_code_sha256': AGGREGATE_SHA, 'descriptive_code_sha256': DESCRIBE_SHA,
                      'figure_code_sha256': FIGURE_SHA, 'day_cluster_code_sha256': DAY_SHA,
                      'report_builder_sha256': REPORT_SHA, 'independent_census_verifier_sha256': VERIFIER_SHA,
                      'domain_cluster_caveat_version': CAVEAT_VERSION,
                      'canonical_generated_draft_sha256': hashlib.sha256(draft_bytes).hexdigest(),
                      'exporter_code_sha256': sha_file(__file__), 'supplied_report_sha256': args.reviewed_report_sha256,
                      'review_note': 'A matching supplied report hash binds its bytes only; it does not prove any human or agent review or the correctness of its claims.',
                      'scope': 'Final-PCAP-derived measurements; no PCAP payloads, historical runtime values or classification.'}
        if clean_script:
            provenance['clean_tuple_analysis_sha256'] = sha_file(clean_script)
        if domain_script:
            provenance['domain_bootstrap_analysis_sha256'] = sha_file(domain_script)
        if day_eligibility_script:
            provenance['day_packet_eligibility_script_sha256'] = sha_file(day_eligibility_script)
        add_bytes(z, digests, 'bundle-provenance.json', (json.dumps(provenance, sort_keys=True, indent=2) + '\n').encode())
        sums = ''.join(digests[name] + '  ' + name + '\n' for name in sorted(digests)).encode()
        z.writestr('SHA256SUMS.txt', sums)
    verify_zip(args.output, strict=True, expected_day_eligibility_sha=expected_day_eligibility_sha)
    return digests


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('manifest', 'resources', 'database', 'aggregate', 'descriptive', 'figures', 'day',
                 'census-qa', 'report-builder', 'reviewed-report', 'output'):
        p.add_argument('--' + name, type=Path, required=True)
    p.add_argument('--reviewed-report-sha256', required=True,
                   help='SHA-256 binds the supplied report bytes only; it does not prove review or correctness')
    p.add_argument('--clean-tuple', type=Path, help='Optional completed whole-capture clean tuple sensitivity directory')
    p.add_argument('--clean-tuple-script', type=Path, help='Exact source script used to create the optional sensitivity')
    p.add_argument('--domain-bootstrap', type=Path, help='Optional completed exploratory domain bootstrap output directory')
    p.add_argument('--domain-bootstrap-script', type=Path, help='Exact source script used for the optional domain bootstrap')
    p.add_argument('--day-eligibility', type=Path, help='Optional completed UTC-day packet-count check JSON')
    p.add_argument('--day-eligibility-script', type=Path, help='Pinned source archived for inspection; the check JSON does not bind its source bytes')
    args = p.parse_args(argv)
    if args.output.exists():
        raise ValueError('Refusing to overwrite output')
    if not valid_sha(args.reviewed_report_sha256):
        raise ValueError('Reviewed report SHA-256 must be lowercase hexadecimal')
    if bool(args.clean_tuple) != bool(args.clean_tuple_script):
        raise ValueError('Supply both --clean-tuple and --clean-tuple-script, or neither')
    if bool(args.domain_bootstrap) != bool(args.domain_bootstrap_script):
        raise ValueError('Supply both --domain-bootstrap and --domain-bootstrap-script, or neither')
    if bool(args.day_eligibility) != bool(args.day_eligibility_script):
        raise ValueError('Supply both --day-eligibility and --day-eligibility-script, or neither')
    fixed_file(args.resources, RESOURCES_SHA)
    fixed_file(args.reviewed_report, args.reviewed_report_sha256)
    reviewed = checked_text(args.reviewed_report)
    if b'SYNTHETIC FIXTURE' in reviewed or b'SYNTHETIC DATA' in reviewed:
        raise ValueError('Synthetic report cannot be exported')
    manifest, domains = read_manifest(args.manifest)
    quality, desc, fig, day = validate_provenance(args.aggregate, args.descriptive, args.figures, args.day)
    if quality.get('counts_by_condition') != {m: 20000 for m in MODES}:
        raise ValueError('Primary condition counts differ from final design')
    check_day_tables(args.day, domains)
    if args.clean_tuple:
        source = regular(args.clean_tuple_script)
        clean_quality = json_file(Path(args.clean_tuple) / CLEAN_FILES[0])
        validate_clean_provenance(clean_quality, quality, sha_file(source))
        def rows(path):
            with regular(path).open(newline='', encoding='utf-8-sig') as f:
                return list(csv.DictReader(f))
        validate_clean_tables(rows(Path(args.clean_tuple) / CLEAN_FILES[1]),
                              rows(Path(args.clean_tuple) / CLEAN_FILES[2]),
                              rows(Path(args.aggregate) / 'domain-overheads.csv'), domains)
    if args.domain_bootstrap:
        source = regular(args.domain_bootstrap_script)
        folder = Path(args.domain_bootstrap)
        validate_domain_bootstrap(
            json_file(folder / DOMAIN_FILES[0]), quality, sha_file(source),
            checked_text(folder / DOMAIN_FILES[1]), checked_text(Path(args.aggregate) / 'quality.json'),
            checked_text(Path(args.aggregate) / 'overall-overheads.csv'),
            checked_text(Path(args.aggregate) / 'domain-overheads.csv'), checked_text(args.manifest))
    if args.day_eligibility:
        fixed_file(args.day_eligibility_script, DAY_ELIGIBILITY_SHA)
        validate_day_packet_eligibility(json_file(args.day_eligibility), quality)
    validate_census(args.census_qa, snapshot=quality['metric_rows_content_sha256'])
    builder = load_builder(args.report_builder)
    draft = builder.make_report(args.aggregate, args.descriptive, args.figures, manifest=args.manifest)
    if not isinstance(draft, str) or 'SYNTHETIC FIXTURE' in draft or PERSONAL_PATH.search(draft):
        raise ValueError('Unexpected generated draft')
    if quality.get('mal_timing_sha256') is not None:
        raise ValueError('Core aggregation consumed auxiliary timing labels')
    uri = Path(args.database).resolve().as_uri() + '?mode=ro'
    con = sqlite3.connect(uri, uri=True, timeout=30)
    try:
        con.execute('BEGIN')
        result = verify_database(con, manifest, MANIFEST_SHA, quality['metric_rows_content_sha256'])
        if result['counts_by_condition'] != quality['counts_by_condition']:
            raise ValueError('SQLite/quality condition counts differ')
        # Build and verify our own temporary archive first. Only after it passes
        # CRC/member-hash checks do we create the requested output exclusively.
        # A normal failure removes only the newly created output, never inputs.
        output = args.output
        output.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='.pcap-bundle-', dir=output.parent) as tmp:
            args.output = Path(tmp) / 'verified.partial.zip'
            digests = assemble_zip(args, con, manifest, quality, result, reviewed, draft)
            expected_zip_hash = sha_file(args.output)
            created = False
            try:
                with output.open('xb') as dst:
                    created = True
                    with args.output.open('rb') as src:
                        shutil.copyfileobj(src, dst, length=1024 * 1024)
                    dst.flush()
                    os.fsync(dst.fileno())
                if sha_file(output) != expected_zip_hash:
                    raise ValueError('Final output copy differs from verified temporary ZIP')
            except Exception:
                if created:
                    output.unlink(missing_ok=True)
                raise
        args.output = output
        print(json.dumps({'status': 'verified_bundle', 'sha256': sha_file(args.output),
                          'bytes': args.output.stat().st_size, 'rows': result['rows'],
                          'members': len(digests) + 1}, sort_keys=True))
    finally:
        con.rollback()
        con.close()


if __name__ == '__main__':
    main()
