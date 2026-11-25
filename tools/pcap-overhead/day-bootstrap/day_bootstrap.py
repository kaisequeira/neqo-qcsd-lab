#!/usr/bin/env python3
"""Exploratory PCAP-only UTC-day cluster bootstrap for complete study metrics.

This does not infer independent days or contemporaneous workloads. It preserves
whole first-packet UTC-day clusters and independently resamples the observed
defended and undefended cohorts within the same domain.
"""
from __future__ import annotations

import argparse
import collections
import csv
from datetime import date
from decimal import Decimal, InvalidOperation, localcontext
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import sys

import numpy as np

METRICS = {'ip_bytes': ('ip_bytes', 'bytes'), 'observed_span': ('span_seconds', 'seconds')}


def sha256(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def day_of(value):
    try:
        if isinstance(value, bool):
            return None
        value = Decimal(str(value))
        if not value.is_finite() or len(value.as_tuple().digits) > 64:
            return None
        origin = date(1970, 1, 1)
        min_day = (date.min - origin).days
        max_day = (date.max - origin).days
        if not (Decimal(min_day * 86400) <= value < Decimal((max_day + 1) * 86400)):
            return None
        # Decimal division/remainder preserves sub-microsecond timestamps near
        # midnight. Decimal's integer division truncates toward zero, so adjust
        # negative nonmultiples to mathematical floor.
        with localcontext() as context:
            context.prec = max(28, len(value.as_tuple().digits) + 6)
            quotient, remainder = divmod(value, Decimal(86400))
            if value < 0 and remainder:
                quotient -= 1
        return int(quotient)
    except (TypeError, ValueError, OverflowError, InvalidOperation):
        return None


def valid_value(record, metric, field):
    if metric == 'ip_bytes' and record.get('ip_valid') is not True:
        return None
    if metric == 'observed_span' and str(record.get('strict_order')).lower() != 'true':
        return None
    value = record.get(field)
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
        return None
    return float(value)


def groups_for(records, condition, domain, metric, field, sessions=400):
    """Return day buckets and count outcomes; epochs are first packet UTC."""
    groups = collections.defaultdict(list)
    stats = collections.Counter()
    for session in range(1, sessions + 1):
        record = records.get((condition, domain, session))
        if record is None:
            stats['missing_record'] += 1
            continue
        value = valid_value(record, metric, field)
        if value is None:
            stats['invalid_metric'] += 1
            continue
        stats['valid_metric'] += 1
        day = day_of(record.get('first_epoch'))
        if day is None:
            stats['missing_epoch'] += 1
            continue
        groups[day].append(value)
    return dict(groups), stats


def cluster_means(groups, reps, rng):
    """Sample each cohort's observed UTC days with replacement, retaining sizes.

    A day with 200 sessions contributes 200 observations when drawn, whereas a
    day with 20 contributes 20. The bootstrap ratio therefore targets the
    session-weighted mean, not the unweighted mean of daily means.
    """
    days = sorted(groups)
    sums = np.asarray([sum(groups[d]) for d in days], dtype=float)
    counts = np.asarray([len(groups[d]) for d in days], dtype=float)
    choices = rng.integers(0, len(days), size=(reps, len(days)))
    return sums[choices].sum(axis=1) / counts[choices].sum(axis=1)


def cohort_comparison(defended, baseline, reps, rng):
    """Return status, statistics and optional day-cluster bootstrap draws."""
    adays, bdays = len(defended), len(baseline)
    an, bn = sum(map(len, defended.values())), sum(map(len, baseline.values()))
    result = {'defense_days': adays, 'baseline_days': bdays,
              'defense_n_with_epoch': an, 'baseline_n_with_epoch': bn}
    if not an or not bn:
        return {**result, 'status': 'no_epoch_eligible_observations'}, None
    am = sum(map(sum, defended.values())) / an
    bm = sum(map(sum, baseline.values())) / bn
    result.update(defense_mean=am, baseline_mean=bm,
                  absolute_difference=am - bm,
                  overhead_pct=(100 * (am / bm - 1)) if bm > 0 else None)
    if bm <= 0:
        return {**result, 'status': 'zero_baseline_mean'}, None
    if adays < 2 or bdays < 2:
        return {**result, 'status': 'fewer_than_two_utc_days'}, None
    a = cluster_means(defended, reps, rng)
    b = cluster_means(baseline, reps, rng)
    ratios = np.full(reps, np.nan)
    np.divide(a, b, out=ratios, where=b > 0)
    ratios = (ratios - 1) * 100
    finite = ratios[np.isfinite(ratios)]
    if not len(finite):
        return {**result, 'status': 'no_finite_bootstrap_draws'}, None
    low, high = np.percentile(finite, [2.5, 97.5])
    return {**result, 'status': 'eligible', 'day_bootstrap_percentile95_low_pct': float(low),
            'day_bootstrap_percentile95_high_pct': float(high), 'finite_draws': int(len(finite)),
            'fewer_than_5_days_in_either_cohort': adays < 5 or bdays < 5,
            'fewer_than_30_days_in_either_cohort': adays < 30 or bdays < 30}, ratios


def write_csv(path, rows, columns):
    with path.open('w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=columns, extrasaction='raise', lineterminator='\n')
        writer.writeheader()
        writer.writerows(rows)


def load_aggregate(path):
    spec = importlib.util.spec_from_file_location('verified_pcap_aggregate', path)
    if spec is None or spec.loader is None:
        raise ValueError('cannot import public aggregate')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--database', type=Path, required=True)
    parser.add_argument('--quality', type=Path, required=True)
    parser.add_argument('--aggregate', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--bootstrap', type=int, default=2000)
    parser.add_argument('--seed', type=int, default=20261125)
    args = parser.parse_args()
    if args.bootstrap < 100:
        parser.error('at least 100 bootstrap replicates are required')
    quality = json.loads(args.quality.read_text(encoding='utf-8'))
    if (quality.get('status') != 'complete' or quality.get('manifest_sessions') != 120000
            or quality.get('accepted_metric_rows') != 120000 or quality.get('extractor_errors') != 0
            or quality.get('identity_or_other_flags')):
        raise ValueError('a complete, error-free 120,000-capture quality record is required')
    if sha256(args.manifest) != quality.get('manifest_sha256') or sha256(args.aggregate) != quality.get('analysis_script_sha256'):
        raise ValueError('manifest or aggregation code does not match verified quality record')
    agg = load_aggregate(args.aggregate)
    manifest, domains = agg.read_manifest(args.manifest, 50, 400)
    records, flags, snapshot_sha, errors = agg.load_metrics(args.database, manifest)
    if len(records) != 120000 or flags or errors or snapshot_sha != quality.get('metric_rows_content_sha256'):
        raise ValueError('metrics snapshot differs from verified aggregation input')
    args.output.mkdir(parents=True, exist_ok=True)
    if any(args.output.iterdir()):
        raise ValueError('output directory must be empty')

    # Cache cohort groups once; each optional domain-level comparison uses the
    # same eligibility rules as the fixed-domain primary aggregate.
    grouped = {}
    for mode in agg.CONDITIONS:
        for domain in domains:
            for metric, (field, _) in METRICS.items():
                grouped[(mode, domain, metric)] = groups_for(records, mode, domain, metric, field)
    rng = np.random.default_rng(args.seed)
    domain_rows, summaries = [], []
    for metric, (_, unit) in METRICS.items():
        for defense in agg.CONDITIONS[1:]:
            eligible, draws, statuses = [], [], collections.Counter()
            under_5_domains, under_30_domains, missing_epoch_domains = 0, 0, 0
            for domain in domains:
                a, ast = grouped[(defense, domain, metric)]
                b, bst = grouped[('undefended', domain, metric)]
                result, sample = cohort_comparison(a, b, args.bootstrap, rng)
                statuses[result['status']] += 1
                row = {'defense': defense, 'domain': domain, 'metric': metric, 'unit': unit,
                       'defense_valid_metric_n': ast['valid_metric'], 'baseline_valid_metric_n': bst['valid_metric'],
                       'defense_invalid_metric_n': ast['invalid_metric'], 'baseline_invalid_metric_n': bst['invalid_metric'],
                       'defense_missing_record_n': ast['missing_record'], 'baseline_missing_record_n': bst['missing_record'],
                       'defense_missing_epoch_n': ast['missing_epoch'], 'baseline_missing_epoch_n': bst['missing_epoch'],
                       **result}
                domain_rows.append(row)
                if sample is not None:
                    eligible.append(result['overhead_pct'])
                    draws.append(sample)
                    under_5_domains += int(result['fewer_than_5_days_in_either_cohort'])
                    under_30_domains += int(result['fewer_than_30_days_in_either_cohort'])
                    missing_epoch_domains += int(ast['missing_epoch'] > 0 or bst['missing_epoch'] > 0)
            summary = {'defense': defense, 'metric': metric, 'unit': unit,
                       'eligible_domains': len(eligible), 'expected_domains': len(domains),
                       'all_domains_eligible': len(eligible) == len(domains),
                       'eligible_domains_with_fewer_than_5_days_in_either_cohort': under_5_domains,
                       'eligible_domains_with_fewer_than_30_days_in_either_cohort': under_30_domains,
                       'eligible_domains_with_missing_epochs': missing_epoch_domains,
                       'status_counts_json': json.dumps(statuses, sort_keys=True),
                       'equal_domain_mean_overhead_pct_eligible_subset': None,
                       'day_bootstrap_percentile95_low_pct_eligible_subset': None,
                       'day_bootstrap_percentile95_high_pct_eligible_subset': None,
                       'finite_bootstrap_draws': 0}
            if eligible:
                macro = np.mean(np.stack(draws), axis=0)
                finite = macro[np.isfinite(macro)]
                summary['equal_domain_mean_overhead_pct_eligible_subset'] = float(np.mean(eligible))
                summary['finite_bootstrap_draws'] = int(len(finite))
                if len(finite):
                    low, high = np.percentile(finite, [2.5, 97.5])
                    summary['day_bootstrap_percentile95_low_pct_eligible_subset'] = float(low)
                    summary['day_bootstrap_percentile95_high_pct_eligible_subset'] = float(high)
            summaries.append(summary)

    domain_columns = ['defense', 'domain', 'metric', 'unit', 'status', 'defense_days', 'baseline_days',
                      'defense_valid_metric_n', 'baseline_valid_metric_n', 'defense_invalid_metric_n',
                      'baseline_invalid_metric_n', 'defense_missing_record_n', 'baseline_missing_record_n', 'defense_missing_epoch_n',
                      'baseline_missing_epoch_n', 'defense_n_with_epoch', 'baseline_n_with_epoch',
                      'defense_mean', 'baseline_mean', 'absolute_difference', 'overhead_pct',
                      'day_bootstrap_percentile95_low_pct', 'day_bootstrap_percentile95_high_pct', 'finite_draws',
                      'fewer_than_5_days_in_either_cohort', 'fewer_than_30_days_in_either_cohort']
    summary_columns = ['defense', 'metric', 'unit', 'eligible_domains', 'expected_domains', 'all_domains_eligible',
                       'eligible_domains_with_fewer_than_5_days_in_either_cohort',
                       'eligible_domains_with_fewer_than_30_days_in_either_cohort', 'eligible_domains_with_missing_epochs',
                       'status_counts_json', 'equal_domain_mean_overhead_pct_eligible_subset',
                       'day_bootstrap_percentile95_low_pct_eligible_subset', 'day_bootstrap_percentile95_high_pct_eligible_subset',
                       'finite_bootstrap_draws']
    write_csv(args.output / 'utc-day-cluster-by-domain.csv', domain_rows, domain_columns)
    write_csv(args.output / 'utc-day-cluster-eligible-subset-summary.csv', summaries, summary_columns)
    provenance = {'status': 'complete', 'manifest_sha256': quality['manifest_sha256'],
                  'metric_rows_content_sha256': snapshot_sha, 'aggregate_code_sha256': quality['analysis_script_sha256'],
                  'bootstrap_code_sha256': sha256(Path(__file__)), 'metric_rows': len(records),
                  'bootstrap_replicates': args.bootstrap, 'seed': args.seed,
                  'python_version': sys.version, 'numpy_version': np.__version__,
                  'scope': 'Final-PCAP-derived IP bytes and observed trace span only; no runtime/receipt values.',
                  'method': 'Independently resample first-packet UTC-day clusters within each condition/domain, retaining all sessions within each sampled day and its session weight.',
                  'limitations': 'Distinct UTC days are not proof of independent clusters, comparable workloads or valid clocks. Two days per cohort is merely a computational minimum, and intervals with few days may be unstable. Result summaries cover only eligible domains and cannot be generalized to excluded domains.',
                  'uncertainty': 'These are exploratory percentile intervals conditional on the observed cluster structure. Independently resampling the cohorts and domains does not model shared shocks on the same day or cross-domain correlation. Intervals do not remove day-to-day confounding, temporal drift, selection or clustering within days.'}
    (args.output / 'utc-day-cluster-provenance.json').write_text(json.dumps(provenance, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'status': 'complete', 'records': len(records), 'domain_results': len(domain_rows), 'summaries': len(summaries)}))


if __name__ == '__main__':
    main()
