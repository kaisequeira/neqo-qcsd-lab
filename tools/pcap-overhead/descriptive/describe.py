#!/usr/bin/env python3
"""PCAP-only distribution, capture-epoch, and sensitivity analysis.

This consumes the completed aggregate's quality record and its exact SQLite
snapshot. It does not read source archives or any application/runtime logs.
"""
from __future__ import annotations

import argparse
import collections
import csv
import datetime as dt
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import sys

import numpy as np


def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for b in iter(lambda: f.read(1024 * 1024), b''):
            h.update(b)
    return h.hexdigest()


def load_module(path):
    spec = importlib.util.spec_from_file_location('verified_aggregate', path)
    if spec is None or spec.loader is None:
        raise ValueError('Cannot load aggregate module')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def q(values, pct):
    return float(np.percentile(np.asarray(values, dtype=float), pct, method='linear'))


def describe(values):
    values = np.asarray(values, dtype=float)
    if len(values) == 0:
        return None
    out = {'n': len(values), 'sum': float(values.sum()), 'mean': float(values.mean())}
    for label, pct in [('p05', 5), ('p25', 25), ('p50', 50), ('p75', 75),
                       ('p90', 90), ('p95', 95), ('p99', 99), ('max', 100)]:
        out[label] = q(values, pct)
    return out


def compare(defended, baseline):
    """Unpaired, independently trimmed cohort summaries; no slot pairing."""
    a, b = np.sort(np.asarray(defended, dtype=float)), np.sort(np.asarray(baseline, dtype=float))
    if not len(a) or not len(b):
        return None
    trim_a, trim_b = int(math.floor(len(a) * .01)), int(math.floor(len(b) * .01))
    ta = a[:-trim_a] if trim_a else a
    tb = b[:-trim_b] if trim_b else b
    def ratio(x, y):
        return None if y <= 0 else float(100 * (x / y - 1))
    return {
        'defense_n': len(a), 'baseline_n': len(b),
        'defense_mean': float(a.mean()), 'baseline_mean': float(b.mean()),
        'mean_difference': float(a.mean() - b.mean()),
        'mean_ratio_pct': ratio(float(a.mean()), float(b.mean())),
        'defense_median': q(a, 50), 'baseline_median': q(b, 50),
        'median_ratio_pct': ratio(q(a, 50), q(b, 50)),
        'defense_trimmed_n': len(ta), 'baseline_trimmed_n': len(tb),
        'defense_trimmed_mean': float(ta.mean()), 'baseline_trimmed_mean': float(tb.mean()),
        'upper_1pct_trimmed_mean_ratio_pct': ratio(float(ta.mean()), float(tb.mean())),
    }


def parse_epoch(value):
    try:
        n = float(value)
        if not math.isfinite(n):
            return None
        # Avoid implausible ranges only for conversions; no arbitrary epoch
        # cutoff is imposed on scientific data.
        dt.datetime.fromtimestamp(n, tz=dt.timezone.utc)
        return n
    except (TypeError, ValueError, OverflowError, OSError):
        return None


def iso(epoch):
    return dt.datetime.fromtimestamp(epoch, tz=dt.timezone.utc).isoformat()


def epoch_summary(starts):
    starts = np.asarray(starts, dtype=float)
    if not len(starts):
        return None
    return {'n': len(starts), 'first_start_utc': iso(float(starts.min())),
            'start_p05_utc': iso(q(starts, 5)), 'start_p25_utc': iso(q(starts, 25)),
            'start_median_utc': iso(q(starts, 50)), 'start_p75_utc': iso(q(starts, 75)),
            'start_p95_utc': iso(q(starts, 95)), 'last_start_utc': iso(float(starts.max()))}


def compare_epochs(a, b):
    """Compare first-packet timestamp ranges; overlapping spans are not matching."""
    a, b = np.asarray(a, dtype=float), np.asarray(b, dtype=float)
    if not len(a) or not len(b):
        return None
    amin, amax, bmin, bmax = float(a.min()), float(a.max()), float(b.min()), float(b.max())
    overlap = max(0.0, min(amax, bmax) - max(amin, bmin))
    gap = max(0.0, max(amin, bmin) - min(amax, bmax))
    # UTC calendar-day overlap is a coverage diagnostic, not a pairing rule.
    adays = collections.Counter(int(math.floor(x / 86400)) for x in a)
    bdays = collections.Counter(int(math.floor(x / 86400)) for x in b)
    shared = set(adays).intersection(bdays)
    return {'defense_n': len(a), 'baseline_n': len(b),
            'defense_first_start_utc': iso(amin), 'defense_last_start_utc': iso(amax),
            'baseline_first_start_utc': iso(bmin), 'baseline_last_start_utc': iso(bmax),
            'defense_median_start_utc': iso(q(a, 50)), 'baseline_median_start_utc': iso(q(b, 50)),
            'median_offset_days': float((q(a, 50) - q(b, 50)) / 86400),
            'start_ranges_intersect': bool(max(amin, bmin) <= min(amax, bmax)),
            'start_range_overlap_days': overlap / 86400,
            'start_range_gap_days': gap / 86400,
            'defense_utc_days': len(adays), 'baseline_utc_days': len(bdays),
            'shared_utc_days': len(shared),
            'defense_sessions_on_shared_utc_days': sum(adays[x] for x in shared),
            'baseline_sessions_on_shared_utc_days': sum(bdays[x] for x in shared)}


def metric_value(record, metric, field):
    """Mirror the public aggregator's eligibility gates for these two metrics."""
    if metric == 'ip_bytes' and record.get('ip_valid') is not True:
        return None
    if metric == 'observed_span' and str(record.get('strict_order')).lower() != 'true':
        return None
    value = record.get(field)
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
        return None
    return float(value)


def shared_day_compare(defense_values, baseline_values):
    """Restrict to UTC days observed in both cohorts, without pairing sessions."""
    adays = {day for day, _ in defense_values}
    bdays = {day for day, _ in baseline_values}
    shared = adays.intersection(bdays)
    a = [value for day, value in defense_values if day in shared]
    b = [value for day, value in baseline_values if day in shared]
    if not shared or not a or not b:
        return {'status': 'no_shared_utc_day', 'shared_utc_days': 0,
                'defense_n': len(a), 'baseline_n': len(b),
                'defense_mean': None, 'baseline_mean': None,
                'mean_difference': None, 'mean_ratio_pct': None}
    da, db = float(np.mean(a)), float(np.mean(b))
    return {'status': 'ok' if db > 0 else 'zero_baseline_mean', 'shared_utc_days': len(shared),
            'defense_n': len(a), 'baseline_n': len(b), 'defense_mean': da,
            'baseline_mean': db, 'mean_difference': da - db,
            'mean_ratio_pct': float(100 * (da / db - 1)) if db > 0 else None}


def write_csv(path, rows):
    if not rows:
        return
    with path.open('w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]), lineterminator='\n')
        w.writeheader()
        w.writerows(rows)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--manifest', type=Path, required=True)
    p.add_argument('--database', type=Path, required=True)
    p.add_argument('--quality', type=Path, required=True, help='quality.json from completed aggregate')
    p.add_argument('--aggregate', type=Path, required=True, help='exact aggregate.py that wrote quality.json')
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    quality = json.loads(args.quality.read_text(encoding='utf-8'))
    if (quality.get('status') != 'complete' or quality.get('manifest_sessions') != 120000
            or quality.get('accepted_metric_rows') != 120000 or quality.get('extractor_errors') != 0
            or quality.get('identity_or_other_flags')):
        raise ValueError('A complete, error-free 120,000-capture aggregate is required')
    if sha(args.manifest) != quality.get('manifest_sha256') or sha(args.aggregate) != quality.get('analysis_script_sha256'):
        raise ValueError('Manifest or aggregate code does not match quality.json')
    agg = load_module(args.aggregate)
    manifest, domains = agg.read_manifest(args.manifest, 50, 400)
    records, flags, snapshot_sha, errors = agg.load_metrics(args.database, manifest)
    if (len(records) != 120000 or flags or errors
            or snapshot_sha != quality.get('metric_rows_content_sha256')):
        raise ValueError('Metrics snapshot differs from the verified aggregate inputs')
    args.output.mkdir(parents=True, exist_ok=True)
    if any(args.output.iterdir()):
        raise ValueError('Output directory must be empty')
    modes = agg.CONDITIONS
    cohorts, distribution_rows, epoch_rows = {}, [], []
    metrics = {'ip_bytes': ('ip_bytes', 'bytes'), 'observed_span': ('span_seconds', 'seconds')}
    pooled = collections.defaultdict(list)
    for mode in modes:
        for domain in domains:
            starts, missing_epochs = [], 0
            for session in range(1, 401):
                record = records[(mode, domain, session)]
                value = parse_epoch(record.get('first_epoch'))
                if value is None:
                    missing_epochs += 1
                else:
                    starts.append(value)
            cohorts[(mode, domain, 'starts')] = starts
            e = epoch_summary(starts)
            if not e:
                e = dict.fromkeys(('first_start_utc', 'start_p05_utc', 'start_p25_utc',
                                   'start_median_utc', 'start_p75_utc', 'start_p95_utc',
                                   'last_start_utc'), None)
                e['n'] = 0
                # Preserve a stable field order even for entirely missing cohorts.
                e = {'n': e.pop('n'), **e}
            epoch_rows.append({'defense': mode, 'domain': domain, 'expected_n': 400,
                               'missing_epoch_n': missing_epochs, **e})
            for metric, (field, unit) in metrics.items():
                vals, reasons, _ = agg.cohort_data(records, mode, domain, field, 400,
                                                   strict_order=(metric == 'observed_span'))
                eligible, by_day = [], []
                for session in range(1, 401):
                    record = records[(mode, domain, session)]
                    value = metric_value(record, metric, field)
                    if value is None:
                        continue
                    eligible.append(value)
                    epoch = parse_epoch(record.get('first_epoch'))
                    if epoch is not None:
                        by_day.append((int(math.floor(epoch / 86400)), value))
                if not np.array_equal(np.asarray(eligible, dtype=float), vals):
                    raise ValueError('Public aggregator metric eligibility changed or does not match')
                cohorts[(mode, domain, metric)] = vals
                cohorts[(mode, domain, metric + '_by_day')] = by_day
                pooled[(mode, metric)].extend(vals)
                d = describe(vals)
                if d:
                    distribution_rows.append({'defense': mode, 'domain': domain, 'metric': metric,
                                              'unit': unit, 'expected_n': 400,
                                              'excluded_n': 400 - len(vals),
                                              'exclusion_reasons_json': json.dumps(reasons, sort_keys=True), **d})
    overall_rows = []
    for mode in modes:
        for metric, (_, unit) in metrics.items():
            values = pooled[(mode, metric)]
            d = describe(values)
            if d:
                overall_rows.append({'defense': mode, 'metric': metric, 'unit': unit,
                                     'expected_n': len(domains) * 400,
                                     'excluded_n': len(domains) * 400 - len(values), **d})
    sensitivity_rows, offset_rows, same_day_rows = [], [], []
    for mode in modes[1:]:
        for domain in domains:
            for metric, (_, unit) in metrics.items():
                x = compare(cohorts[(mode, domain, metric)], cohorts[('undefended', domain, metric)])
                if x:
                    sensitivity_rows.append({'defense': mode, 'domain': domain, 'metric': metric, 'unit': unit, **x})
                s = shared_day_compare(cohorts[(mode, domain, metric + '_by_day')],
                                       cohorts[('undefended', domain, metric + '_by_day')])
                same_day_rows.append({'defense': mode, 'domain': domain, 'metric': metric,
                                      'unit': unit,
                                      'defense_all_valid_n': len(cohorts[(mode, domain, metric)]),
                                      'baseline_all_valid_n': len(cohorts[('undefended', domain, metric)]),
                                      'defense_valid_with_epoch_n': len(cohorts[(mode, domain, metric + '_by_day')]),
                                      'baseline_valid_with_epoch_n': len(cohorts[('undefended', domain, metric + '_by_day')]),
                                      **s})
            e = compare_epochs(cohorts[(mode, domain, 'starts')], cohorts[('undefended', domain, 'starts')])
            if not e:
                e = dict.fromkeys(('defense_n', 'baseline_n', 'defense_first_start_utc',
                                   'defense_last_start_utc', 'baseline_first_start_utc',
                                   'baseline_last_start_utc', 'defense_median_start_utc',
                                   'baseline_median_start_utc', 'median_offset_days',
                                   'start_ranges_intersect', 'start_range_overlap_days',
                                   'start_range_gap_days', 'defense_utc_days',
                                   'baseline_utc_days', 'shared_utc_days',
                                   'defense_sessions_on_shared_utc_days',
                                   'baseline_sessions_on_shared_utc_days'), None)
                e['defense_n'] = len(cohorts[(mode, domain, 'starts')])
                e['baseline_n'] = len(cohorts[('undefended', domain, 'starts')])
            offset_rows.append({'defense': mode, 'domain': domain, **e})
    sensitivity_summary = []
    for mode in modes[1:]:
        for metric, (_, unit) in metrics.items():
            rows = [r for r in sensitivity_rows if r['defense'] == mode and r['metric'] == metric]
            result = {'defense': mode, 'metric': metric, 'unit': unit,
                      'observed_domains': len(rows), 'expected_domains': len(domains)}
            for field in ('mean_ratio_pct', 'median_ratio_pct', 'upper_1pct_trimmed_mean_ratio_pct'):
                eligible = [r[field] for r in rows if r[field] is not None]
                result[field + '_domains'] = len(eligible)
                result[field + '_equal_domain_mean'] = float(np.mean(eligible)) if eligible else None
            sensitivity_summary.append(result)
    same_day_summary = []
    for mode in modes[1:]:
        for metric, (_, unit) in metrics.items():
            rows = [r for r in same_day_rows if r['defense'] == mode and r['metric'] == metric]
            eligible = [r for r in rows if r['status'] == 'ok']
            same_day_summary.append({
                'defense': mode, 'metric': metric, 'unit': unit,
                'eligible_domains': len(eligible), 'expected_domains': len(domains),
                'domains_without_shared_utc_day': sum(r['status'] == 'no_shared_utc_day' for r in rows),
                'domains_with_zero_baseline_mean': sum(r['status'] == 'zero_baseline_mean' for r in rows),
                'defense_sessions_in_eligible_domains': sum(r['defense_n'] for r in eligible),
                'baseline_sessions_in_eligible_domains': sum(r['baseline_n'] for r in eligible),
                'equal_domain_mean_overhead_pct': float(np.mean([r['mean_ratio_pct'] for r in eligible])) if eligible else None,
            })
    write_csv(args.output / 'session-distributions-by-cohort.csv', distribution_rows)
    write_csv(args.output / 'session-distributions-by-condition.csv', overall_rows)
    write_csv(args.output / 'sensitivity-by-domain.csv', sensitivity_rows)
    write_csv(args.output / 'sensitivity-overall.csv', sensitivity_summary)
    write_csv(args.output / 'shared-utc-day-sensitivity.csv', same_day_rows)
    write_csv(args.output / 'shared-utc-day-summary.csv', same_day_summary)
    write_csv(args.output / 'capture-epochs-by-cohort.csv', epoch_rows)
    write_csv(args.output / 'capture-epoch-offsets-by-domain.csv', offset_rows)
    provenance = {
        'status': 'complete', 'manifest_sha256': quality['manifest_sha256'],
        'metric_rows_content_sha256': snapshot_sha, 'aggregate_code_sha256': quality['analysis_script_sha256'],
        'descriptive_code_sha256': sha(Path(__file__)), 'metric_rows': len(records),
        'python_version': sys.version, 'numpy_version': np.__version__,
        'scope': 'Final PCAP-derived records only; no external runtime or completion values.',
        'epoch_limitations': 'First-packet timestamps are recorded clocks and may be inaccurate; overlapping ranges or UTC days do not establish contemporaneous or equivalent workloads. The shared-day restriction is exploratory, independently captured, may compare different hours and weights days by their available sessions.',
        'sensitivity': 'Each condition/domain is trimmed independently, removing floor(n * 0.01) largest observations. Median and trimmed ratios are descriptive and exploratory, not paired or causal.',
        'percentiles': 'NumPy linear/R7 interpolation; each session has equal weight within its reported cohort or condition.',
    }
    (args.output / 'descriptive-provenance.json').write_text(json.dumps(provenance, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'status': 'complete', 'rows': len(records), 'cohort_distributions': len(distribution_rows),
                      'domain_sensitivities': len(sensitivity_rows), 'epoch_comparisons': len(offset_rows)}))


if __name__ == '__main__':
    main()
