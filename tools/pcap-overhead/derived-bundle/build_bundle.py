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

`measurements/session-metrics.csv` is a readable table by defense, domain and
session. `measurements/session-metrics-canonical.jsonl` contains the exact
ordered JSON array rows hashed by the public aggregator, including the original
metric JSON as a JSON *string*. Its SHA-256 must equal the
`metric_rows_content_sha256` in `results/quality.json` and bundle provenance.
The JSONL contains no packet contents or credential data. To reconstruct a
SQLite `metrics` table, JSON-decode each line's six fields and insert them in
the column order documented by the public aggregation code. The original
`source` value says only whether that capture was read locally or by Drive HTTP.
The public toolkit's derived-bundle `restore_metrics.py` performs this restore
into a new SQLite database and cross-checks the CSV against the canonical rows.

`inputs/session-manifest.csv` and `resources.csv` identify the exact handoff.
`results/` provides cohort and aggregate tables, bootstrap uncertainty,
exclusions, distribution/timing sensitivities and exploratory day-cluster
results. `figures/` provides SVG/PDF figures and input provenance. The report
folder contains the supplied report and the canonical generated draft for
comparison. Supplying a matching report hash binds the report bytes; it does
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


def verify_zip(path, *, strict=False):
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
            if len(names & allowed_exclusions) != 1 or names != expected | (names & allowed_exclusions):
                raise ValueError('Bundle contains an unexpected or missing member')
        for name, expected in listed.items():
            h = hashlib.sha256()
            with z.open(name) as f:
                for block in iter(lambda: f.read(1024 * 1024), b''):
                    h.update(block)
            if h.hexdigest() != expected:
                raise ValueError('Bundle member hash mismatch: ' + name)


def assemble_zip(args, con, manifest, quality, result, reviewed, draft, *, synthetic=False):
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
        optional = Path(args.aggregate) / 'cohort-exclusions.csv'
        if optional.exists():
            add_file(z, digests, 'results/aggregate/cohort-exclusions.csv', optional, text=True)
        else:
            add_bytes(z, digests, 'results/aggregate/no-cohort-exclusions.txt',
                      b'The aggregator did not emit a cohort-exclusions.csv file; consult quality.json.\n')
        add_bytes(z, digests, 'report/supplied-report.md', reviewed)
        add_bytes(z, digests, 'report/canonical-review-draft.md', draft.encode('utf-8'))
        add_file(z, digests, 'results/independent-census-qa.json', args.census_qa, text=True)
        provenance = {'status': 'synthetic_fixture' if synthetic else 'complete_hash_bound_inputs',
                      'manifest_sha256': MANIFEST_SHA, 'resources_sha256': RESOURCES_SHA,
                      'metric_rows_content_sha256': result['metric_rows_content_sha256'],
                      'metric_rows': result['rows'], 'counts_by_condition': result['counts_by_condition'],
                      'aggregate_code_sha256': AGGREGATE_SHA, 'descriptive_code_sha256': DESCRIBE_SHA,
                      'figure_code_sha256': FIGURE_SHA, 'day_cluster_code_sha256': DAY_SHA,
                      'report_builder_sha256': REPORT_SHA, 'independent_census_verifier_sha256': VERIFIER_SHA,
                      'exporter_code_sha256': sha_file(__file__), 'supplied_report_sha256': args.reviewed_report_sha256,
                      'review_note': 'A matching supplied report hash binds its bytes only; it does not prove any human or agent review or the correctness of its claims.',
                      'scope': 'Final-PCAP-derived measurements; no PCAP payloads, historical runtime values or classification.'}
        add_bytes(z, digests, 'bundle-provenance.json', (json.dumps(provenance, sort_keys=True, indent=2) + '\n').encode())
        sums = ''.join(digests[name] + '  ' + name + '\n' for name in sorted(digests)).encode()
        z.writestr('SHA256SUMS.txt', sums)
    verify_zip(args.output, strict=True)
    return digests


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('manifest', 'resources', 'database', 'aggregate', 'descriptive', 'figures', 'day',
                 'census-qa', 'report-builder', 'reviewed-report', 'output'):
        p.add_argument('--' + name, type=Path, required=True)
    p.add_argument('--reviewed-report-sha256', required=True,
                   help='SHA-256 binds the supplied report bytes only; it does not prove review or correctness')
    args = p.parse_args(argv)
    if args.output.exists():
        raise ValueError('Refusing to overwrite output')
    if not valid_sha(args.reviewed_report_sha256):
        raise ValueError('Reviewed report SHA-256 must be lowercase hexadecimal')
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
