#!/usr/bin/env python3
"""Build a review-only PCAP UTC-day sensitivity note from two matching runs.

No captures, runtime records, receipts, or classifier outputs are read. The
public day-bootstrap processor must first be run twice, independently, with
the same verified aggregate inputs and recorded software versions. This tool
never publishes; it refuses incomplete, inconsistent, or mismatching inputs.
"""
from __future__ import annotations

import argparse
import collections
import csv
import hashlib
import json
import math
import os
from pathlib import Path

MANIFEST_SHA = 'ef0e87f1138db2675e655813b0667b3860235df5c635f045e18f48fac1d72abf'
AGGREGATE_SHA = '6e6427360998bd4da1f4bfdfea3c619931003448f2dfd0c573f6ad8bafdc32e6'
DAY_CODE_SHA = '9ae4b14c64ad24b684c2507c127dd20a074c145539e4d51a65ea7aed54b25ca9'
MODES = ('undefended', 'front', 'tamaraw', 'buflo', 'cs-buflo', 'wtf-pad')
DEFENSES = MODES[1:]
METRICS = ('ip_bytes', 'observed_span')
LABELS = {'front': 'FRONT', 'tamaraw': 'Tamaraw', 'buflo': 'BuFLO',
          'cs-buflo': 'CS-BuFLO', 'wtf-pad': 'WTF-PAD'}
TABLES = ('utc-day-cluster-by-domain.csv', 'utc-day-cluster-eligible-subset-summary.csv')
STATUSES = {'eligible', 'no_epoch_eligible_observations', 'zero_baseline_mean',
            'fewer_than_two_utc_days', 'no_finite_bootstrap_draws'}


def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def read_csv(path):
    with Path(path).open(newline='', encoding='utf-8-sig') as f:
        return list(csv.DictReader(f))


def integer(value, field):
    try:
        if isinstance(value, bool) or str(value).strip() != str(int(value)):
            raise ValueError()
        result = int(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError('Invalid integer: ' + field) from exc
    if result < 0:
        raise ValueError('Negative integer: ' + field)
    return result


def number(value, field):
    try:
        n = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError('Invalid number: ' + field) from exc
    if not math.isfinite(n):
        raise ValueError('Non-finite number: ' + field)
    return n


def boolean(value, field):
    if value == 'True':
        return True
    if value == 'False':
        return False
    raise ValueError('Invalid boolean: ' + field)


def is_blank(value):
    return value is None or value == ''


def manifest_domains(path, *, expected=50, sessions=400, expected_sha=MANIFEST_SHA):
    if sha(path) != expected_sha:
        raise ValueError('Final manifest hash does not match')
    keys, objects = set(), set()
    for r in read_csv(path):
        k = (r['defense'], r['domain'], integer(r['session'], 'session'))
        obj = r['drive_file_id']
        if k in keys or not k[1] or not obj or obj in objects:
            raise ValueError('Duplicate or invalid manifest identity')
        keys.add(k)
        objects.add(obj)
    domains = sorted({k[1] for k in keys})
    design = {(m, d, n) for m in MODES for d in domains for n in range(1, sessions + 1)}
    if len(domains) != expected or keys != design:
        raise ValueError('Manifest does not have the complete balanced design')
    return domains


def provenance_inputs(manifest, quality_path, aggregate, day_code, first, second):
    """Require separate executions and exact matching CSVs before interpreting."""
    first, second = Path(first).resolve(), Path(second).resolve()
    if first == second or not first.is_dir() or not second.is_dir():
        raise ValueError('Two distinct output directories are required')
    domains = manifest_domains(manifest)
    q = json.loads(Path(quality_path).read_text(encoding='utf-8'))
    if (q.get('status') != 'complete' or q.get('manifest_sessions') != 120000
            or q.get('accepted_metric_rows') != 120000 or q.get('extractor_errors') != 0
            or q.get('identity_or_other_flags') != {} or q.get('manifest_sha256') != MANIFEST_SHA
            or q.get('analysis_script_sha256') != AGGREGATE_SHA or sha(aggregate) != AGGREGATE_SHA):
        raise ValueError('Aggregate quality is incomplete or has mismatching source')
    counts = q.get('counts_by_condition')
    if counts != {mode: 20000 for mode in MODES}:
        raise ValueError('Aggregate condition counts are not complete')
    metric_hash = q.get('metric_rows_content_sha256')
    if not isinstance(metric_hash, str) or len(metric_hash) != 64 or any(c not in '0123456789abcdef' for c in metric_hash):
        raise ValueError('Aggregate metrics snapshot hash is invalid')
    if sha(day_code) != DAY_CODE_SHA:
        raise ValueError('UTC-day code does not match the verified study version')
    proofs = []
    for directory in (first, second):
        p = json.loads((directory / 'utc-day-cluster-provenance.json').read_text(encoding='utf-8'))
        if (p.get('status') != 'complete' or p.get('metric_rows') != 120000
                or p.get('manifest_sha256') != MANIFEST_SHA or p.get('aggregate_code_sha256') != AGGREGATE_SHA
                or p.get('bootstrap_code_sha256') != DAY_CODE_SHA or p.get('metric_rows_content_sha256') != metric_hash
                or type(p.get('bootstrap_replicates')) is not int or p['bootstrap_replicates'] < 100
                or type(p.get('seed')) is not int or not p.get('numpy_version') or not p.get('python_version')):
            raise ValueError('UTC-day provenance does not match the completed aggregate')
        proofs.append(p)
    for k in ('manifest_sha256', 'aggregate_code_sha256', 'bootstrap_code_sha256',
              'metric_rows_content_sha256', 'bootstrap_replicates', 'seed', 'numpy_version'):
        if proofs[0][k] != proofs[1][k]:
            raise ValueError('Independent runs have different provenance: ' + k)
    # Python's full sys.version includes host-specific build/compiler strings.
    # Match the version number; the subsequent CSV byte comparison is decisive.
    if proofs[0]['python_version'].split()[0] != proofs[1]['python_version'].split()[0]:
        raise ValueError('Independent runs have different Python versions')
    hashes = {}
    for name in TABLES:
        if (first / name).is_symlink() or (second / name).is_symlink() or os.path.samefile(first / name, second / name):
            raise ValueError('Output tables must be distinct, ordinary files')
        if sha(first / name) != sha(second / name):
            raise ValueError('Independent UTC-day output mismatch: ' + name)
        hashes[name] = sha(first / name)
    return domains, q, proofs[0], hashes


def validate_rows(domain_rows, summary_rows, domains, reps, *, sessions=400):
    expected_keys = {(d, m, h) for d in DEFENSES for m in METRICS for h in domains}
    by_key = {}
    for r in domain_rows:
        key = (r.get('defense'), r.get('metric'), r.get('domain'))
        expected_unit = 'bytes' if key[1] == 'ip_bytes' else 'seconds'
        if key not in expected_keys or key in by_key or r.get('status') not in STATUSES or r.get('unit') != expected_unit:
            raise ValueError('Unexpected or duplicate domain/status row')
        for prefix in ('defense', 'baseline'):
            valid = integer(r[prefix + '_valid_metric_n'], prefix + ' valid')
            invalid = integer(r[prefix + '_invalid_metric_n'], prefix + ' invalid')
            missing_record = integer(r[prefix + '_missing_record_n'], prefix + ' missing record')
            missing_epoch = integer(r[prefix + '_missing_epoch_n'], prefix + ' missing epoch')
            used = integer(r[prefix + '_n_with_epoch'], prefix + ' with epoch')
            days = integer(r[prefix + '_days'], prefix + ' days')
            if valid + invalid + missing_record != sessions or used + missing_epoch != valid or days > used:
                raise ValueError('Inconsistent cohort counts')
        days_min = min(int(r['defense_days']), int(r['baseline_days']))
        if r['status'] == 'eligible':
            if days_min < 2:
                raise ValueError('Eligible comparison has too few days')
            a = number(r['defense_mean'], 'defense mean')
            b = number(r['baseline_mean'], 'baseline mean')
            pct = number(r['overhead_pct'], 'overhead')
            lo = number(r['day_bootstrap_percentile95_low_pct'], 'lower range')
            hi = number(r['day_bootstrap_percentile95_high_pct'], 'upper range')
            draws = integer(r['finite_draws'], 'finite draws')
            if a < 0 or b <= 0 or not math.isclose(pct, 100 * (a / b - 1), rel_tol=1e-9, abs_tol=1e-8) or lo > hi or not 1 <= draws <= reps:
                raise ValueError('Invalid eligible comparison')
            if boolean(r['fewer_than_5_days_in_either_cohort'], 'under 5') != (days_min < 5) or boolean(r['fewer_than_30_days_in_either_cohort'], 'under 30') != (days_min < 30):
                raise ValueError('Inconsistent few-day warning')
        else:
            if not is_blank(r.get('day_bootstrap_percentile95_low_pct')) or not is_blank(r.get('day_bootstrap_percentile95_high_pct')):
                raise ValueError('Ineligible comparison contains a percentile range')
            an, bn = int(r['defense_n_with_epoch']), int(r['baseline_n_with_epoch'])
            if r['status'] == 'no_epoch_eligible_observations':
                if an and bn:
                    raise ValueError('No-epoch status contradicts cohort counts')
            else:
                if not an or not bn:
                    raise ValueError('A missing cohort has the wrong status')
                baseline_mean = number(r['baseline_mean'], 'baseline mean')
                if r['status'] == 'zero_baseline_mean' and baseline_mean > 0:
                    raise ValueError('Zero-baseline status contradicts cohort mean')
                if r['status'] == 'fewer_than_two_utc_days' and (days_min >= 2 or baseline_mean <= 0):
                    raise ValueError('Few-day status contradicts cohort data')
                if r['status'] == 'no_finite_bootstrap_draws' and (days_min < 2 or baseline_mean <= 0):
                    raise ValueError('No-draw status contradicts cohort data')
        by_key[key] = r
    if set(by_key) != expected_keys:
        raise ValueError('UTC-day domain coverage is incomplete')
    summaries = {}
    for r in summary_rows:
        key = (r.get('defense'), r.get('metric'))
        expected_unit = 'bytes' if key[1] == 'ip_bytes' else 'seconds'
        if key not in {(d, m) for d in DEFENSES for m in METRICS} or key in summaries or r.get('unit') != expected_unit:
            raise ValueError('Unexpected or duplicate summary')
        subset = [by_key[(key[0], key[1], h)] for h in domains]
        eligible = [x for x in subset if x['status'] == 'eligible']
        count = integer(r['eligible_domains'], 'eligible domains')
        if (count != len(eligible) or integer(r['expected_domains'], 'expected domains') != len(domains)
                or boolean(r['all_domains_eligible'], 'all eligible') != (count == len(domains))
                or json.loads(r['status_counts_json']) != dict(collections.Counter(x['status'] for x in subset))):
            raise ValueError('Summary eligibility does not match domain rows')
        for threshold in (5, 30):
            expected = sum(boolean(x[f'fewer_than_{threshold}_days_in_either_cohort'], 'few-day') for x in eligible)
            if integer(r[f'eligible_domains_with_fewer_than_{threshold}_days_in_either_cohort'], 'few-day count') != expected:
                raise ValueError('Summary few-day count does not match')
        missing = sum(int(x['defense_missing_epoch_n']) > 0 or int(x['baseline_missing_epoch_n']) > 0 for x in eligible)
        if integer(r['eligible_domains_with_missing_epochs'], 'missing-epoch domains') != missing:
            raise ValueError('Summary missing-epoch count does not match')
        draws = integer(r['finite_bootstrap_draws'], 'summary finite draws')
        if draws > reps:
            raise ValueError('Too many finite bootstrap draws')
        point = r.get('equal_domain_mean_overhead_pct_eligible_subset')
        lo, hi = r.get('day_bootstrap_percentile95_low_pct_eligible_subset'), r.get('day_bootstrap_percentile95_high_pct_eligible_subset')
        if not count:
            if not is_blank(point) or not is_blank(lo) or not is_blank(hi) or draws:
                raise ValueError('Empty eligible subset contains a result')
        else:
            actual = sum(number(x['overhead_pct'], 'domain point') for x in eligible) / count
            if not math.isclose(number(point, 'summary point'), actual, rel_tol=1e-9, abs_tol=1e-8):
                raise ValueError('Eligible-subset point does not match domain mean')
            if draws:
                if number(lo, 'summary low') > number(hi, 'summary high'):
                    raise ValueError('Invalid summary percentile range')
            elif not is_blank(lo) or not is_blank(hi):
                raise ValueError('Summary range exists without finite draws')
        summaries[key] = r
    if set(summaries) != {(d, m) for d in DEFENSES for m in METRICS}:
        raise ValueError('UTC-day summaries are incomplete')
    return summaries


def render(summaries, proof, hashes, *, expected=50):
    lines = ['# Exploratory UTC-day cluster sensitivity — review draft', '',
             '**PCAP-only supplement; interpret alongside, not as a replacement for, the primary results.**', '',
             'Within each domain and condition, the procedure independently resamples whole UTC-day groups based on the first packet timestamp and retains session weights. This does not pair sessions, model shared shocks across domains, establish independence of days, or remove changing-content, temporal, network or capture-clock confounding. Two days is only a computational minimum. Under-five and under-30-day counts below are descriptive warnings, not a guarantee of reliability.', '',
             'The point estimates and percentile ranges below describe **only the eligible subset of domains**, and may use only the epoch-available subset of sessions. Percentile ranges are exploratory bootstrap percentiles, not established 95% confidence coverage. A result with fewer than all domains eligible is not an estimate for all 50 domains.', '',
             '| Defense | PCAP metric | Eligible domains | Eligible with <5 / <30 days | Eligible with missing epochs | Equal-domain subset overhead | Exploratory 2.5th–97.5th percentile range | Finite / requested draws |',
             '| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |']
    for defense in DEFENSES:
        for metric in METRICS:
            r = summaries[(defense, metric)]
            n = int(r['eligible_domains'])
            low, high = r['day_bootstrap_percentile95_low_pct_eligible_subset'], r['day_bootstrap_percentile95_high_pct_eligible_subset']
            point = 'Unavailable' if not n else f"{float(r['equal_domain_mean_overhead_pct_eligible_subset']):+,.2f}%"
            interval = 'Unavailable' if is_blank(low) or is_blank(high) else f'[{float(low):+,.2f}%, {float(high):+,.2f}%]'
            label = 'IP datagram bytes' if metric == 'ip_bytes' else 'Observed packet-trace span'
            lines.append(f"| {LABELS[defense]} | {label} | {n}/{expected} | {r['eligible_domains_with_fewer_than_5_days_in_either_cohort']} / {r['eligible_domains_with_fewer_than_30_days_in_either_cohort']} | {r['eligible_domains_with_missing_epochs']} | {point} | {interval} | {r['finite_bootstrap_draws']} / {proof['bootstrap_replicates']} |")
    lines += ['', '### Eligibility and reasons', '', '| Defense | PCAP metric | Domain status counts |', '| --- | --- | --- |']
    for defense in DEFENSES:
        for metric in METRICS:
            r = summaries[(defense, metric)]
            counts = json.loads(r['status_counts_json'])
            readable = '; '.join(f'{name.replace("_", " ")}: {n}' for name, n in sorted(counts.items()))
            label = 'IP datagram bytes' if metric == 'ip_bytes' else 'Observed packet-trace span'
            lines.append(f'| {LABELS[defense]} | {label} | {readable} |')
    lines += ['', 'A blank range is unavailable, not a zero-cost result. Inspect `utc-day-cluster-by-domain.csv` for domain-level statuses, counts, missing timestamps and warnings. The associated trace span runs from the first to the last observed packet, potentially including setup, acknowledgments, padding and teardown; it is **not application-completion or browser page-load time**. IP bytes include traffic observed at the capture point, not PCAP file headers and not necessarily application payload.', '',
              'The CSVs in two separately provided output directories matched byte-for-byte. They should be produced by separately rerunning the same code and seed; the match checks reproducibility but does not itself prove independent execution, validate the method, or establish the bootstrap assumptions.', '',
              f"Final manifest SHA-256: `{proof['manifest_sha256']}`; canonical metric-row snapshot SHA-256: `{proof['metric_rows_content_sha256']}`; UTC-day code SHA-256: `{proof['bootstrap_code_sha256']}`. Seed: `{proof['seed']}`; NumPy: `{proof['numpy_version']}`.", '',
              f"Domain-table SHA-256: `{hashes[TABLES[0]]}`; summary-table SHA-256: `{hashes[TABLES[1]]}`.", '',
              'See the [PCAP-only methods](https://drive.google.com/file/d/1J_WjNax8tIs57md4HN8bFKD32C8V2sg4/view) and the [UTC-day sensitivity method and source](https://github.com/kaisequeira/neqo-qcsd-lab/tree/main/tools/pcap-overhead/day-bootstrap). Future classifier performance remains unmeasured; no privacy ranking follows from this sensitivity.', '']
    return '\n'.join(lines)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('manifest', 'quality', 'aggregate', 'day-code', 'day-output', 'independent-day-output', 'output'):
        p.add_argument('--' + name, type=Path, required=True)
    a = p.parse_args()
    if a.output.exists():
        raise ValueError('Output already exists')
    roots = (a.day_output.resolve(), a.independent_day_output.resolve())
    if any(a.output.resolve().is_relative_to(root) for root in roots):
        raise ValueError('Output must not modify an input directory')
    quality_hash = sha(a.quality)
    proof_hashes = [sha(root / 'utc-day-cluster-provenance.json') for root in roots]
    domains, _, proof, hashes = provenance_inputs(a.manifest, a.quality, a.aggregate, a.day_code, a.day_output, a.independent_day_output)
    rows = read_csv(a.day_output / TABLES[0])
    summaries = read_csv(a.day_output / TABLES[1])
    result = render(validate_rows(rows, summaries, domains, proof['bootstrap_replicates']), proof, hashes)
    if (sha(a.quality) != quality_hash or sha(a.manifest) != MANIFEST_SHA or sha(a.aggregate) != AGGREGATE_SHA
            or sha(a.day_code) != DAY_CODE_SHA or any(sha(root / name) != hashes[name] for root in roots for name in TABLES)
            or any(sha(root / 'utc-day-cluster-provenance.json') != h for root, h in zip(roots, proof_hashes))):
        raise ValueError('Input changed during validation')
    # Avoid publishing or overwriting existing work. The result is a review draft.
    a.output.parent.mkdir(parents=True, exist_ok=True)
    with a.output.open('x', encoding='utf-8', newline='\n') as f:
        f.write(result)
    print(json.dumps({'status': 'review_draft', 'sha256': sha(a.output), 'csv_sha256': hashes}))


if __name__ == '__main__':
    main()
