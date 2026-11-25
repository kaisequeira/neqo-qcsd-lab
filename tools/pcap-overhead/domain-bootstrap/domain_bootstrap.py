#!/usr/bin/env python3
"""Exploratory independent-within-occurrence domain/session bootstrap.

Reads only a complete final PCAP-derived metrics database and manifest, plus the
primary aggregate's quality record. This is not a reparse, causal analysis, or
an assertion that the convenience-selected domains are representative.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import importlib.util
import json
import math
import sys
from pathlib import Path

import numpy as np

MANIFEST_SHA = 'ef0e87f1138db2675e655813b0667b3860235df5c635f045e18f48fac1d72abf'
AGGREGATE_SHA = '6e6427360998bd4da1f4bfdfea3c619931003448f2dfd0c573f6ad8bafdc32e6'
METRICS = {'ip_bytes': ('ip_bytes', 'bytes'), 'observed_span': ('span_seconds', 'seconds')}


def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def load_aggregate(path):
    if sha(path) != AGGREGATE_SHA:
        raise ValueError('Primary aggregate source does not match the pinned study version')
    spec = importlib.util.spec_from_file_location('pinned_aggregate', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def validate_quality(q):
    if not (q.get('status') == 'complete' and q.get('manifest_sessions') == 120000
            and q.get('accepted_metric_rows') == 120000 and q.get('extractor_errors') == 0
            and not q.get('identity_or_other_flags') and q.get('manifest_sha256') == MANIFEST_SHA
            and q.get('analysis_script_sha256') == AGGREGATE_SHA):
        raise ValueError('Primary aggregate quality/provenance is incomplete or mismatched')


def independent_occurrence_draws(cohorts, reps, rng, chunk=64):
    """Draw a fresh unpaired session bootstrap for each selected domain occurrence.

    ``cohorts`` is [(defended_values, baseline_values), ...]. Returns equal-domain
    mean percentage draws and the count of undefined domain occurrences. A zero
    resampled baseline makes its entire replicate undefined. Memory is bounded
    by ``chunk``; no denominator is replaced by a synthetic small number.
    """
    n = len(cohorts)
    if not n or reps <= 0 or chunk <= 0:
        raise ValueError('At least one domain, replicate and positive chunk required')
    draws = np.full(reps, np.nan)
    invalid_occurrences = 0
    for start in range(0, reps, chunk):
        size = min(chunk, reps - start)
        choices = rng.integers(0, n, size=(size, n))
        total, valid = np.zeros(size), np.zeros(size, dtype=int)
        for domain, (defended, baseline) in enumerate(cohorts):
            rr, _ = np.where(choices == domain)
            if not len(rr):
                continue
            defended, baseline = np.asarray(defended, dtype=float), np.asarray(baseline, dtype=float)
            a = defended[rng.integers(0, len(defended), size=(len(rr), len(defended)))].mean(axis=1)
            b = baseline[rng.integers(0, len(baseline), size=(len(rr), len(baseline)))].mean(axis=1)
            ratio = np.full(len(rr), np.nan)
            np.divide(a, b, out=ratio, where=b > 0)
            ratio = (ratio - 1) * 100
            good = np.isfinite(ratio)
            invalid_occurrences += int((~good).sum())
            total += np.bincount(rr[good], weights=ratio[good], minlength=size)
            valid += np.bincount(rr[good], minlength=size)
        good_replicates = valid == n
        draws[start:start + size][good_replicates] = total[good_replicates] / n
    return draws, invalid_occurrences


def domain_only_draws(cohorts, reps, rng):
    """Resample whole domain point estimates; retain defended/baseline pairing."""
    if not cohorts or reps <= 0:
        raise ValueError('At least one domain and replicate required')
    ratios = np.asarray([100 * (np.mean(a) / np.mean(b) - 1) for a, b in cohorts], dtype=float)
    if not np.isfinite(ratios).all():
        raise ValueError('Non-finite domain point estimate')
    return ratios[rng.integers(0, len(ratios), size=(reps, len(ratios)))].mean(axis=1)


def calculate(agg, records, domains, reps, rng, sessions=400):
    result = []
    for metric, (field, unit) in METRICS.items():
        for defense in agg.CONDITIONS[1:]:
            cohorts, unavailable = [], []
            for domain in domains:
                kwargs = {'strict_order': metric == 'observed_span'}
                a, _, _ = agg.cohort_data(records, defense, domain, field, sessions, **kwargs)
                b, _, _ = agg.cohort_data(records, 'undefended', domain, field, sessions, **kwargs)
                if not len(a) or not len(b) or not math.isfinite(float(b.mean())) or b.mean() <= 0:
                    unavailable.append(domain)
                else:
                    cohorts.append((a, b))
            row = {'defense': defense, 'metric': metric, 'unit': unit,
                   'expected_domains': len(domains), 'eligible_domains': len(cohorts),
                   'unavailable_domains': json.dumps(unavailable), 'requested_replicates': reps,
                   'valid_replicates': 0, 'undefined_replicates': 0,
                   'undefined_domain_occurrences': 0, 'macro_overhead_pct': '',
                   'domain_only_valid_replicates': 0,
                   'two_stage_percentile_95_low_pct': '', 'two_stage_percentile_95_high_pct': '',
                   'domain_only_percentile_95_low_pct': '', 'domain_only_percentile_95_high_pct': '',
                   'status': 'unavailable'}
            if not unavailable:
                point = float(np.mean([100 * (a.mean() / b.mean() - 1) for a, b in cohorts]))
                draws, invalid_occurrences = independent_occurrence_draws(cohorts, reps, rng)
                finite = draws[np.isfinite(draws)]
                domain_only = domain_only_draws(cohorts, reps, rng)
                row.update(macro_overhead_pct=point, valid_replicates=len(finite),
                           domain_only_valid_replicates=len(domain_only),
                           undefined_replicates=reps - len(finite),
                           undefined_domain_occurrences=invalid_occurrences,
                           status='complete' if len(finite) == reps else 'conditional_on_finite_draws' if len(finite) else 'no_valid_replicates')
                if len(finite):
                    row['two_stage_percentile_95_low_pct'], row['two_stage_percentile_95_high_pct'] = map(float, np.percentile(finite, [2.5, 97.5]))
                row['domain_only_percentile_95_low_pct'], row['domain_only_percentile_95_high_pct'] = map(float, np.percentile(domain_only, [2.5, 97.5]))
            result.append(row)
    return result


def validate_primary_domains(agg, records, domains, sessions, primary_csv):
    """Bind every eligible comparison's means, counts and ratio to the main table."""
    table = {}
    with Path(primary_csv).open(newline='', encoding='utf-8-sig') as f:
        for row in csv.DictReader(f):
            if row.get('metric') not in METRICS:
                continue
            key = (row['defense'], row['metric'], row['domain'])
            if key in table:
                raise ValueError('Duplicate primary domain row')
            table[key] = row
    checked, unavailable = 0, 0
    for metric, (field, unit) in METRICS.items():
        for defense in agg.CONDITIONS[1:]:
            for domain in domains:
                kwargs = {'strict_order': metric == 'observed_span'}
                a, _, _ = agg.cohort_data(records, defense, domain, field, sessions, **kwargs)
                b, _, _ = agg.cohort_data(records, 'undefended', domain, field, sessions, **kwargs)
                row = table.pop((defense, metric, domain), None)
                if not len(a) or not len(b) or not math.isfinite(float(b.mean())) or b.mean() <= 0:
                    if row is not None:
                        raise ValueError('Primary domain row exists for an unavailable cohort')
                    unavailable += 1
                    continue
                if row is None:
                    raise ValueError('Primary domain row missing')
                if row.get('unit') != unit:
                    raise ValueError('Primary domain metric unit differs')
                for name, expected in (('baseline_n', len(b)), ('defense_n', len(a)),
                                       ('baseline_expected_n', sessions), ('defense_expected_n', sessions)):
                    if int(row[name]) != expected:
                        raise ValueError('Primary domain cohort count differs')
                a_mean, b_mean = float(a.mean()), float(b.mean())
                for name, expected in (('baseline_mean', b_mean), ('defense_mean', a_mean),
                                       ('absolute_difference', a_mean - b_mean),
                                       ('overhead_pct', 100 * (a_mean / b_mean - 1))):
                    actual = float(row[name])
                    if not math.isfinite(actual) or not math.isclose(actual, expected, rel_tol=1e-10, abs_tol=1e-8):
                        raise ValueError('Primary domain value differs: ' + name)
                checked += 1
    if table:
        raise ValueError('Unexpected primary domain rows')
    return checked, unavailable


def validate_primary_points(results, primary_csv):
    """Bind the new sensitivity's fixed-50 point estimands to the main tables."""
    with Path(primary_csv).open(newline='', encoding='utf-8-sig') as f:
        table = {}
        for row in csv.DictReader(f):
            if row.get('metric') not in METRICS:
                continue
            key = (row['defense'], row['metric'])
            if key in table:
                raise ValueError('Duplicate primary summary row')
            table[key] = row
    for row in results:
        key = (row['defense'], row['metric'])
        primary = table.pop(key, None)
        if row['status'] == 'unavailable':
            if primary is not None:
                raise ValueError('Primary summary exists for an unavailable domain cohort')
            continue
        if (primary is None or primary.get('provisional', '').lower() != 'false'
                or int(primary['domains']) != row['expected_domains']
                or not math.isclose(float(primary['macro_overhead_pct']), row['macro_overhead_pct'],
                                    rel_tol=1e-10, abs_tol=1e-8)):
            raise ValueError('Exploratory point estimate does not match complete primary summary')
    if table:
        raise ValueError('Unexpected primary summary rows')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--manifest', type=Path, required=True)
    p.add_argument('--database', type=Path, required=True)
    p.add_argument('--quality', type=Path, required=True)
    p.add_argument('--aggregate', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--seed', type=int, default=20261125)
    p.add_argument('--replicates', type=int, default=2000)
    args = p.parse_args()
    if args.output.exists() or args.replicates < 100:
        p.error('Output must not exist and at least 100 replicates are required')
    if sha(args.manifest) != MANIFEST_SHA:
        p.error('Manifest checksum mismatch')
    agg = load_aggregate(args.aggregate)
    quality = json.loads(args.quality.read_text(encoding='utf-8'))
    validate_quality(quality)
    manifest, domains = agg.read_manifest(args.manifest, 50, 400)
    records, flags, snapshot, errors = agg.load_metrics(args.database, manifest)
    if len(records) != 120000 or flags or errors or snapshot != quality.get('metric_rows_content_sha256'):
        p.error('Metrics are incomplete, contain errors, or differ from the primary snapshot')
    domain_table = args.quality.parent / 'domain-overheads.csv'
    checked, unavailable = validate_primary_domains(agg, records, domains, 400, domain_table)
    results = calculate(agg, records, domains, args.replicates, np.random.default_rng(args.seed))
    primary = args.quality.parent / 'overall-overheads.csv'
    validate_primary_points(results, primary)
    args.output.mkdir(parents=True, exist_ok=False)
    with (args.output / 'domain-session-bootstrap.csv').open('w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=list(results[0])); writer.writeheader(); writer.writerows(results)
    provenance = {'status': 'complete' if all(row['status'] == 'complete' for row in results) else 'review_required',
                  'manifest_sha256': MANIFEST_SHA, 'primary_aggregate_sha256': AGGREGATE_SHA,
                  'metric_rows_content_sha256': snapshot, 'analysis_script_sha256': sha(__file__),
                  'primary_summary_sha256': sha(primary), 'primary_quality_sha256': sha(args.quality),
                  'primary_domain_table_sha256': sha(domain_table), 'primary_domain_rows_checked': checked,
                  'primary_domain_rows_unavailable': unavailable,
                  'output_csv_sha256': sha(args.output / 'domain-session-bootstrap.csv'),
                  'seed': args.seed, 'replicates': args.replicates, 'numpy_version': np.__version__,
                  'python_version': sys.version, 'random_generator': 'numpy.random.default_rng',
                  'captured_records': len(records),
                  'method': 'Two-stage: domains sampled with replacement; for each selected occurrence independently resample defended and baseline sessions within that domain and recompute their ratio. Replicates with any zero baseline are undefined and excluded from percentile calculation. Domain-only: resample whole per-domain ratio estimates, preserving each domain\'s defended/baseline pairing; no within-domain session resampling.',
                  'scope': 'Both are exploratory hypothetical domain-population sensitivities, not replacements for fixed-50 session intervals. Domains are convenience-selected and captures may be dependent. Two-stage resampling may double-count within-domain variation and neither method guarantees interval coverage. No causal, representativeness, application-completion or fidelity claim.'}
    (args.output / 'domain-session-provenance.json').write_text(json.dumps(provenance, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    print(json.dumps({'status': provenance['status'], 'results': len(results)}))


if __name__ == '__main__':
    main()
