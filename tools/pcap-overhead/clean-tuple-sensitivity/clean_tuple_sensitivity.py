#!/usr/bin/env python3
"""Compare capture-wide primary and clean UDP/443-subset cohort estimates.

Requires aggregate.py from the parent toolkit directory. This consumes only the finalized
manifest and the PCAP-derived metrics database, never the captures or historical
metadata. A complete 6 x 50 x 400 manifest-matched census with no extraction
errors is required before the command creates an output directory.
"""
from __future__ import annotations

import argparse
import csv
import importlib.util
import json
import math
from pathlib import Path

_aggregate_path = Path(__file__).resolve().parent.parent / 'aggregate.py'
_spec = importlib.util.spec_from_file_location('pcap_overhead_aggregate', _aggregate_path)
if _spec is None or _spec.loader is None:
    raise ImportError(f'Unable to load toolkit aggregator: {_aggregate_path}')
aggregate = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(aggregate)

METRICS = {"ip_bytes": ("ip_bytes", "bytes"),
           "observed_span": ("span_seconds", "seconds")}


def clean_selection(rec):
    # Mirror primary directional-IP eligibility even for the span sensitivity.
    return rec.get('ip_valid') is True and aggregate.direction_complete(rec)


def cohort_values_cached(records, clean_records, defense, domain, field, sessions):
    kwargs = {"strict_order": field == "span_seconds"}
    full, reasons, _ = aggregate.cohort_data(records, defense, domain, field, sessions, **kwargs)
    clean, _, _ = aggregate.cohort_data(clean_records, defense, domain, field, sessions, **kwargs)
    # Count filter failures only among primary-eligible rows. Categories are
    # mutually exclusive and prioritized; they do not imply a traffic source.
    rejected = {}
    for session in range(1, sessions + 1):
        key = (defense, domain, session)
        rec = records.get(key)
        if rec is None or clean_selection(rec):
            continue
        if rec.get('ip_valid') is not True:
            reason = 'ip_parse_or_capture_not_valid'
        elif rec.get('udp443_direction_valid') is not True:
            reason = 'direction_invalid_or_ambiguous'
        elif rec.get('other_ip_bytes') != 0:
            reason = 'other_ip_bytes_nonzero_or_unknown'
        else:
            reason = 'direction_bytes_invalid_or_inconsistent'
        rejected.setdefault(reason, {})[key] = rec
    filter_reasons = {}
    for reason, subset in rejected.items():
        valid, _, _ = aggregate.cohort_data(subset, defense, domain, field, sessions, **kwargs)
        if len(valid):
            filter_reasons[reason] = len(valid)
    assert sum(filter_reasons.values()) == len(full) - len(clean)
    return full, clean, reasons, filter_reasons


def estimate(defended, baseline):
    if not len(defended) or not len(baseline):
        return None
    dm, bm = float(defended.mean()), float(baseline.mean())
    if not math.isfinite(dm) or not math.isfinite(bm) or bm <= 0:
        return None
    return {"baseline_mean": bm, "defense_mean": dm,
            "absolute_difference": dm - bm, "overhead_pct": 100 * (dm / bm - 1)}


def overall(rows, prefix):
    values = [r for r in rows if r[prefix + "_overhead_pct"] is not None]
    if not values:
        return {"domains": 0, "macro_overhead_pct": None,
                "pooled_cohort_mean_overhead_pct": None,
                "baseline_equal_domain_mean": None, "defense_equal_domain_mean": None}
    bsum = sum(r[prefix + "_baseline_mean"] for r in values)
    dsum = sum(r[prefix + "_defense_mean"] for r in values)
    n = len(values)
    return {"domains": n,
            "macro_overhead_pct": sum(r[prefix + "_overhead_pct"] for r in values) / n,
            "pooled_cohort_mean_overhead_pct": 100 * (dsum / bsum - 1),
            "baseline_equal_domain_mean": bsum / n,
            "defense_equal_domain_mean": dsum / n}


def compute(records, domains, sessions):
    """Pure computation, also callable with synthetic fixtures for tests."""
    clean_records = {k: v for k, v in records.items() if clean_selection(v)}
    details, summaries = [], []
    for metric, (field, unit) in METRICS.items():
        cohorts = {}
        for defense in aggregate.CONDITIONS:
            for domain in domains:
                cohorts[defense, domain] = cohort_values_cached(records, clean_records, defense, domain, field, sessions)
        for defense in aggregate.CONDITIONS[1:]:
            rows = []
            for domain in domains:
                df, dc, dr, dfilter = cohorts[defense, domain]
                bf, bc, br, bfilter = cohorts['undefended', domain]
                full, clean = estimate(df, bf), estimate(dc, bc)
                r = {"metric": metric, "unit": unit, "defense": defense, "domain": domain,
                     "baseline_expected_n": sessions, "defense_expected_n": sessions,
                     "baseline_full_n": len(bf), "defense_full_n": len(df),
                     "baseline_clean_n": len(bc), "defense_clean_n": len(dc),
                     "baseline_removed_by_clean_filter": len(bf) - len(bc),
                     "defense_removed_by_clean_filter": len(df) - len(dc),
                     "baseline_primary_exclusions": json.dumps(dict(br), sort_keys=True),
                     "defense_primary_exclusions": json.dumps(dict(dr), sort_keys=True),
                     "baseline_clean_filter_reasons": json.dumps(bfilter, sort_keys=True),
                     "defense_clean_filter_reasons": json.dumps(dfilter, sort_keys=True)}
                for label, val in (("full", full), ("clean", clean)):
                    for key in ("baseline_mean", "defense_mean", "absolute_difference", "overhead_pct"):
                        r[label + "_" + key] = None if val is None else val[key]
                r["clean_minus_full_overhead_percentage_points"] = (
                    None if full is None or clean is None else clean["overhead_pct"] - full["overhead_pct"])
                rows.append(r)
            full_all, clean_all = overall(rows, "full"), overall(rows, "clean")
            common = [r for r in rows if r["full_overhead_pct"] is not None and r["clean_overhead_pct"] is not None]
            full_common, clean_common = overall(common, "full"), overall(common, "clean")
            summary = {"metric": metric, "unit": unit, "defense": defense,
                       "expected_domains": len(domains),
                       "common_domain_coverage_complete": len(common) == len(domains)}
            for label, item in (("full_available", full_all), ("clean_available", clean_all),
                                ("full_common", full_common), ("clean_common", clean_common)):
                summary.update({label + "_" + k: v for k, v in item.items()})
            for key in ("macro_overhead_pct", "pooled_cohort_mean_overhead_pct"):
                a, b = full_common[key], clean_common[key]
                summary["clean_minus_full_common_" + key + "_percentage_points"] = (
                    None if a is None or b is None else b - a)
            details.extend(rows)
            summaries.append(summary)
    return details, summaries


def write_csv(path, rows):
    with path.open('w', newline='', encoding='utf-8') as out:
        writer = csv.DictWriter(out, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--manifest', type=Path, required=True)
    p.add_argument('--database', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    if args.output.exists():
        p.error('Output directory must not already exist')
    manifest, domains = aggregate.read_manifest(args.manifest, 50, 400)
    records, flags, snapshot, errors = aggregate.load_metrics(args.database, manifest)
    if len(records) != 120000 or len(records) != len(manifest) or flags or errors:
        p.error('Final complete manifest-matched census without extractor errors required; no output written')
    detail, summary = compute(records, domains, 400)
    args.output.mkdir(parents=True, exist_ok=False)
    write_csv(args.output / 'domain-clean-tuple-sensitivity.csv', detail)
    write_csv(args.output / 'overall-clean-tuple-sensitivity.csv', summary)
    quality = {'status': 'complete', 'manifest_sha256': aggregate.digest(args.manifest),
               'metric_rows_content_sha256': snapshot, 'accepted_records': len(records),
               'extractor_errors': len(errors), 'identity_or_other_flags': dict(flags),
               'analysis_script_sha256': aggregate.digest(Path(__file__)),
               'aggregate_library_sha256': aggregate.digest(Path(aggregate.__file__)),
               'clean_selection': 'Valid IP capture and unique bidirectional UDP/443 candidate accounting for all observed IP bytes, as defined by aggregate.direction_complete; still not proof of intended flow.',
               'comparison': 'Within each condition and domain, means are independent cohorts. Full and clean estimates use their respective valid rows; changes in percentage points are descriptive, potentially selection-biased, not causal or paired.',
               'coverage': 'Available summaries use their own eligible domains. Differences use only domains eligible in BOTH full and clean estimates. The completeness flag identifies whether this is all 50 domains.',
               'metric_limits': 'IP bytes include all observed capture traffic; span is first-to-last packet, not application completion. No confidence intervals are estimated by this sensitivity analysis.'}
    (args.output / 'clean-tuple-quality.json').write_text(json.dumps(quality, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    print(json.dumps({'status': 'complete', 'accepted': len(records), 'output': str(args.output)}))


if __name__ == '__main__':
    main()
