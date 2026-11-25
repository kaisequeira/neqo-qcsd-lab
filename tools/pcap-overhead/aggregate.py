#!/usr/bin/env python3
"""Aggregate verified NEQO capture metrics without assuming session pairing.

See README.md for estimands and limitations. This consumes the capture
extractor's SQLite snapshot; it never reads packet captures.
"""

from __future__ import annotations

import argparse
import collections
import csv
import datetime as dt
import hashlib
import json
import math
import sqlite3
import sys
from pathlib import Path

import numpy as np


CONDITIONS = ("undefended", "front", "tamaraw", "buflo", "cs-buflo", "wtf-pad")
METRICS = {
    "frame_bytes": ("packet_bytes", "capture-reported original frame bytes, untruncated captures", "bytes"),
    "packet_count": ("packet_count", "observed packets", "packets"),
    "observed_span": ("span_seconds", "first-to-last observed packet span", "seconds"),
    # Optional fields are included only if produced for the whole compared cohort.
    "ip_bytes": ("ip_bytes", "observed IP datagram bytes", "bytes"),
    "udp443_up_ip_bytes": ("udp443_up_ip_bytes", "candidate UDP/443 upstream IP datagram bytes", "bytes"),
    "udp443_down_ip_bytes": ("udp443_down_ip_bytes", "candidate UDP/443 downstream IP datagram bytes", "bytes"),
}
DIRECTION_FIELDS = {"udp443_up_ip_bytes", "udp443_down_ip_bytes"}
IP_FIELDS = {"ip_bytes", *DIRECTION_FIELDS}


def direction_complete(rec):
    """Allow comparisons only if a unique bidirectional candidate accounts for all IP bytes.

    UDP port 443 is a candidate, not proof of a specific resource or QUIC flow.
    """
    up, down, total = rec.get("udp443_up_ip_bytes"), rec.get("udp443_down_ip_bytes"), rec.get("ip_bytes")
    return (rec.get("udp443_direction_valid") is True and rec.get("other_ip_bytes") == 0
            and all(isinstance(x, int) and not isinstance(x, bool) and x >= 0 for x in (up, down, total))
            and up + down == total)


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def read_manifest(path: Path, expected_domains: int, expected_sessions: int):
    rows, object_ids = {}, set()
    with path.open(newline="", encoding="utf-8-sig") as f:
        for row in csv.DictReader(f):
            k = (row["defense"], row["domain"], int(row["session"]))
            if k[0] not in CONDITIONS or k in rows or row["drive_file_id"] in object_ids:
                raise ValueError(f"Invalid/duplicate manifest identity: {k}")
            rows[k] = row
            object_ids.add(row["drive_file_id"])
    domains = sorted({k[1] for k in rows})
    expected = {(d, h, n) for d in CONDITIONS for h in domains
                for n in range(1, expected_sessions + 1)}
    if len(domains) != expected_domains or set(rows) != expected:
        raise ValueError("Manifest does not contain the configured balanced design")
    return rows, domains


def load_metrics(path: Path, manifest):
    """Read a transaction-consistent snapshot and independently join identities."""
    con = sqlite3.connect(f"file:{path.resolve()}?mode=ro", uri=True, timeout=30)
    con.execute("BEGIN")
    records, flags = {}, collections.Counter()
    h = hashlib.sha256()
    try:
        q = "SELECT defense,domain,session,drive_file_id,sha256,result_json FROM metrics ORDER BY defense,domain,session"
        for d, host, session, file_id, sha, raw in con.execute(q):
            fields = [d, host, session, file_id, sha, raw]
            h.update((json.dumps(fields, ensure_ascii=False, separators=(",", ":")) + "\n").encode())
            key = (d, host, int(session))
            target = manifest.get(key)
            if target is None:
                flags["outside_manifest"] += 1
                continue
            try:
                value = json.loads(raw)
            except (ValueError, TypeError):
                flags["invalid_json"] += 1
                continue
            if not isinstance(value, dict):
                flags["invalid_json"] += 1
                continue
            if (file_id != target["drive_file_id"] or sha.lower() != target["sha256"].lower()
                    or value.get("status") != "ok" or value.get("sha256", "").lower() != sha.lower()
                    or value.get("drive_file_id") != file_id):
                flags["identity_or_status_mismatch"] += 1
                continue
            try:
                size_matches = int(value.get("capture_bytes", -1)) == int(target["size"])
            except (TypeError, ValueError):
                size_matches = False
            if not size_matches:
                flags["capture_size_mismatch"] += 1
                continue
            records[key] = value
        errors = [dict(zip(("defense", "domain", "session", "error", "updated"), row))
                  for row in con.execute("SELECT defense,domain,session,error,updated FROM errors ORDER BY defense,domain,session")]
    finally:
        con.rollback()
        con.close()
    return records, flags, h.hexdigest(), errors


def quantiles(x):
    p = np.percentile(np.asarray(x, dtype=float), [2.5, 50, 97.5])
    return float(p[0]), float(p[1]), float(p[2])


def draw_means(values, rng, reps):
    """Nonparametric resampling independently within each cohort."""
    values = np.asarray(values, dtype=float)
    return values[rng.integers(0, len(values), size=(reps, len(values)))].mean(axis=1)


def cohort_data(records, defense, domain, field, sessions, *, strict_order=False):
    vals, reasons, encaps = [], collections.Counter(), collections.Counter()
    for session in range(1, sessions + 1):
        rec = records.get((defense, domain, session))
        if rec is None:
            reasons["missing_or_rejected"] += 1
            continue
        packet_count = rec.get("packet_count")
        if isinstance(packet_count, bool) or not isinstance(packet_count, (int, float)) or not math.isfinite(packet_count) or packet_count <= 0:
            reasons["no_valid_observed_packets"] += 1
            continue
        if field == "packet_bytes" and rec.get("truncated_packets") != 0:
            reasons["frame_capture_truncated_or_unknown"] += 1
            continue
        if field in IP_FIELDS and rec.get("ip_valid") is not True:
            reasons["ip_parse_or_capture_not_valid"] += 1
            continue
        if field in DIRECTION_FIELDS and not direction_complete(rec):
            reasons["ambiguous_or_unaccounted_direction"] += 1
            continue
        v = rec.get(field)
        if isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v) or v < 0:
            reasons["missing_or_invalid_metric"] += 1
            continue
        if field == "span_seconds" and strict_order and str(rec.get("strict_order")).lower() != "true":
            reasons["timestamp_order_not_verified"] += 1
            continue
        vals.append(float(v))
        encaps[str(rec.get("encapsulation", "unknown"))] += 1
    return np.asarray(vals, dtype=float), reasons, encaps


def estimate_domain(def_vals, base_vals, reps, rng):
    def_mean, base_mean = float(np.mean(def_vals)), float(np.mean(base_vals))
    if base_mean <= 0:
        return None
    db, bb = draw_means(def_vals, rng, reps), draw_means(base_vals, rng, reps)
    # Zero bootstrap baselines make the associated ratio undefined. Never replace
    # zero with a tiny constant; report valid replicate counts separately.
    ratio_draws = np.full(reps, np.nan)
    np.divide(db, bb, out=ratio_draws, where=bb > 0)
    ratio_draws = (ratio_draws - 1) * 100
    finite = ratio_draws[np.isfinite(ratio_draws)]
    lo, _, hi = quantiles(finite) if len(finite) else (None, None, None)
    return {"baseline_n": len(base_vals), "defense_n": len(def_vals),
            "baseline_mean": base_mean, "defense_mean": def_mean,
            "absolute_difference": def_mean - base_mean,
            "overhead_pct": 100 * (def_mean / base_mean - 1),
            "ci95_lower_pct": lo, "ci95_upper_pct": hi,
            "bootstrap_valid": len(finite)}, db, bb


def summarize(defense, metric, domain_rows, draws_d, draws_b, rng):
    ratios = np.array([r["overhead_pct"] for r in domain_rows])
    dm = np.array([r["defense_mean"] for r in domain_rows])
    bm = np.array([r["baseline_mean"] for r in domain_rows])
    dd, bd = np.array(draws_d), np.array(draws_b)
    per = np.full_like(dd, np.nan)
    np.divide(dd, bd, out=per, where=bd > 0)
    per = (per - 1) * 100
    macro_draw = np.mean(per, axis=0)
    pooled_draw = (np.sum(dd, axis=0) / np.sum(bd, axis=0) - 1) * 100
    # Separate domain-cluster uncertainty: resample domains in addition to each
    # within-domain session bootstrap. This targets a superpopulation inference
    # and is not the same estimand as uncertainty for the 50 fixed domains.
    n, reps = dd.shape
    choices = rng.integers(0, n, size=(n, reps))
    clustered = np.take_along_axis(per, choices, axis=0).mean(axis=0)
    def ci(x):
        x = x[np.isfinite(x)]
        return (None, None) if not len(x) else (float(np.percentile(x, 2.5)), float(np.percentile(x, 97.5)))
    mlo, mhi = ci(macro_draw)
    plo, phi = ci(pooled_draw)
    clo, chi = ci(clustered)
    return {"defense": defense, "metric": metric, "domains": len(domain_rows),
            "macro_overhead_pct": float(ratios.mean()),
            "macro_ci95_sessions_low": mlo, "macro_ci95_sessions_high": mhi,
            "macro_ci95_domain_cluster_low": clo, "macro_ci95_domain_cluster_high": chi,
            "macro_bootstrap_valid": int(np.isfinite(macro_draw).sum()),
            "domain_cluster_bootstrap_valid": int(np.isfinite(clustered).sum()),
            "domain_median_pct": float(np.median(ratios)),
            "domain_p05_pct": float(np.percentile(ratios, 5)),
            "domain_p95_pct": float(np.percentile(ratios, 95)),
            "pooled_cohort_mean_overhead_pct": float(100 * (dm.sum() / bm.sum() - 1)),
            "pooled_ci95_sessions_low": plo, "pooled_ci95_sessions_high": phi,
            "pooled_bootstrap_valid": int(np.isfinite(pooled_draw).sum()),
            "mean_absolute_difference": float((dm - bm).mean()),
            "baseline_equal_domain_mean": float(bm.mean()),
            "defense_equal_domain_mean": float(dm.mean()),
            "bootstrap_draws": dd.shape[1]}


def read_timing(path, manifest):
    labels = {}
    with path.open(newline="", encoding="utf-8-sig") as f:
        for r in csv.DictReader(f):
            n = int(r["session"])
            key = ("buflo", "cdn.myanimelist.net", n)
            if key not in manifest or r["drive_file_id"] != manifest[key]["drive_file_id"] or n in labels:
                raise ValueError("MAL timing map does not match final manifest")
            labels[n] = r["timing_variant"]
    expected = {k[2] for k in manifest if k[:2] == ("buflo", "cdn.myanimelist.net")}
    if set(labels) != expected:
        raise ValueError("MAL timing map is missing or has unexpected sessions")
    return labels


def write_csv(path, rows):
    if not rows:
        return
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--manifest", type=Path, required=True)
    p.add_argument("--database", type=Path, required=True)
    p.add_argument("--mal-timing", type=Path,
                   help="Optional supplemental labels for MAL BuFLO strata; never required for core PCAP results")
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--seed", type=int, default=20261125)
    p.add_argument("--bootstrap", type=int, default=2000)
    p.add_argument("--expected-domains", type=int, default=50)
    p.add_argument("--sessions", type=int, default=400)
    p.add_argument("--allow-incomplete", action="store_true", help="Mark estimates provisional; use complete cohorts only")
    args = p.parse_args()
    if args.bootstrap < 100 or args.sessions < 1:
        p.error("At least 100 bootstrap replicates and one session are required")
    args.output.mkdir(parents=True, exist_ok=True)
    if any(args.output.iterdir()):
        p.error("Output directory must be empty to avoid stale results")
    manifest, domains = read_manifest(args.manifest, args.expected_domains, args.sessions)
    labels = read_timing(args.mal_timing, manifest) if args.mal_timing else {}
    records, flags, snapshot_hash, errors = load_metrics(args.database, manifest)
    counts = collections.Counter(k[0] for k in records)
    complete = len(records) == len(manifest) and not flags and not errors
    rng = np.random.default_rng(args.seed)
    # Supplemental strata must not perturb the main analysis RNG stream.
    variant_rng = np.random.default_rng(np.random.SeedSequence([args.seed, 0x4D414C]))
    detail, overall, missing, variants = [], [], [], []
    for metric, (field, label, unit) in METRICS.items():
        # Optional network-layer fields must be present in at least one record to be considered.
        if metric in {"ip_bytes", *DIRECTION_FIELDS} and not any(field in r for r in records.values()):
            continue
        for defense in CONDITIONS[1:]:
            drows, ddraws, bdraws = [], [], []
            for domain in domains:
                a, ar, ac = cohort_data(records, defense, domain, field, args.sessions, strict_order=(metric == "observed_span"))
                b, br, bc = cohort_data(records, "undefended", domain, field, args.sessions, strict_order=(metric == "observed_span"))
                present_a = sum((defense, domain, s) in records for s in range(1, args.sessions + 1))
                present_b = sum(("undefended", domain, s) in records for s in range(1, args.sessions + 1))
                reasons, fatal = [], []
                if present_a != args.sessions or present_b != args.sessions:
                    reasons.append("incomplete_extraction")
                    fatal.append("incomplete_extraction")
                if len(a) != present_a or len(b) != present_b:
                    reasons.append("metric_rows_excluded")
                if not len(a) or not len(b):
                    reasons.append("no_valid_observations")
                    fatal.append("no_valid_observations")
                ambiguous_encap = any(str(k).strip().lower() in {"", "unknown", "none", "per packet", "mixed"} for k in set(ac) | set(bc))
                if metric == "frame_bytes" and (len(ac) != 1 or set(ac) != set(bc) or ambiguous_encap):
                    reasons.append("incompatible_or_ambiguous_encapsulation")
                    fatal.append("incompatible_or_ambiguous_encapsulation")
                if len(b) and float(b.mean()) <= 0:
                    reasons.append("zero_baseline_mean")
                    fatal.append("zero_baseline_mean")
                if reasons:
                    missing.append({"metric": metric, "defense": defense, "domain": domain,
                                    "defense_valid": len(a), "baseline_valid": len(b),
                                    "reasons": ";".join(reasons), "defense_invalid": json.dumps(ar, sort_keys=True),
                                    "baseline_invalid": json.dumps(br, sort_keys=True),
                                    "defense_encapsulation": json.dumps(ac, sort_keys=True),
                                    "baseline_encapsulation": json.dumps(bc, sort_keys=True)})
                if fatal:
                    continue
                row, da, ba = estimate_domain(a, b, args.bootstrap, rng)
                row = {"metric": metric, "unit": unit, "defense": defense, "domain": domain,
                       "baseline_expected_n": args.sessions, "defense_expected_n": args.sessions, **row}
                detail.append(row); drows.append(row); ddraws.append(da); bdraws.append(ba)
            if drows and (args.allow_incomplete or len(drows) == len(domains)):
                summary = summarize(defense, metric, drows, ddraws, bdraws, rng)
                summary["provisional"] = len(drows) != len(domains) or not complete
                overall.append(summary)
        if labels and "cdn.myanimelist.net" in domains:
            # Variant subset analysis is intentionally confined to the one domain.
            base, _, base_encaps = cohort_data(records, "undefended", "cdn.myanimelist.net", field, args.sessions, strict_order=(metric == "observed_span"))
            for variant in sorted(set(labels.values())):
                ids = [s for s, v in labels.items() if v == variant]
                data, var_encaps = [], collections.Counter()
                for s in ids:
                    rec = records.get(("buflo", "cdn.myanimelist.net", s))
                    v = None if rec is None else rec.get(field)
                    packet_count = None if rec is None else rec.get("packet_count")
                    if (isinstance(packet_count, (int, float)) and not isinstance(packet_count, bool) and math.isfinite(packet_count) and packet_count > 0
                            and isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v) and v >= 0
                            and (metric != "frame_bytes" or rec.get("truncated_packets") == 0)
                            and (metric != "observed_span" or str(rec.get("strict_order")).lower() == "true")
                            and (metric not in IP_FIELDS or rec.get("ip_valid") is True)
                            and (metric not in DIRECTION_FIELDS or direction_complete(rec))):
                        data.append(v)
                        var_encaps[str(rec.get("encapsulation", "unknown"))] += 1
                # Full denominators and a nonzero baseline are required for a published comparison.
                ambiguous_encap = any(str(k).strip().lower() in {"", "unknown", "none", "per packet", "mixed"} for k in set(var_encaps) | set(base_encaps))
                comparable_frame = (metric != "frame_bytes" or (len(var_encaps) == 1 and set(var_encaps) == set(base_encaps) and not ambiguous_encap))
                if len(base) == args.sessions and len(data) == len(ids) and len(data) and float(base.mean()) > 0 and comparable_frame:
                    row, _, _ = estimate_domain(data, base, args.bootstrap, variant_rng)
                    variants.append({"metric": metric, "unit": unit, "domain": "cdn.myanimelist.net", "defense": "buflo", "timing_variant": variant, **row})
    quality_by_condition = {}
    for condition in CONDITIONS:
        cohort = [r for k,r in records.items() if k[0] == condition]
        quality_by_condition[condition] = {
            "rows": len(cohort), "ip_valid_true": sum(r.get("ip_valid") is True for r in cohort),
            "ip_valid_false": sum(r.get("ip_valid") is False for r in cohort),
            "ip_valid_missing": sum("ip_valid" not in r for r in cohort),
            "udp443_direction_valid_true": sum(r.get("udp443_direction_valid") is True for r in cohort),
            "udp443_direction_valid_false": sum(r.get("udp443_direction_valid") is False for r in cohort),
            "udp443_direction_valid_missing": sum("udp443_direction_valid" not in r for r in cohort),
            "direction_complete": sum(direction_complete(r) for r in cohort),
            "other_ip_bytes_in_direction_valid_sessions": sum(int(r.get("other_ip_bytes", 0) or 0) for r in cohort if r.get("udp443_direction_valid") is True),
            "strict_timestamp_order_not_true": sum(str(r.get("strict_order")).lower() != "true" for r in cohort),
            "zero_packet_records": sum(r.get("packet_count") == 0 for r in cohort),
            "zero_span_records": sum(r.get("span_seconds") == 0 for r in cohort),
            "encapsulation": dict(collections.Counter(str(r.get("encapsulation", "unknown")) for r in cohort)),
            **{flag: sum(int(r.get(flag, 0) or 0) for r in cohort) for flag in (
                "truncated_packets", "non_ip_packets", "multiple_ip_packets", "ipv6_zero_payload_packets",
                "malformed_ip_packets", "unverified_link_packets")},
        }
    report = {"generated_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
              "status": "complete" if complete else "provisional_incomplete",
              "manifest_sha256": digest(args.manifest), "mal_timing_sha256": digest(args.mal_timing) if args.mal_timing else None,
              "mal_variant_scope": "secondary analysis requiring supplemental labels" if args.mal_timing else "not requested; no supplemental labels consumed",
              "analysis_script_sha256": digest(Path(__file__)),
              "python_version": sys.version, "numpy_version": np.__version__,
              "metric_rows_content_sha256": snapshot_hash, "manifest_sessions": len(manifest),
              "accepted_metric_rows": len(records), "counts_by_condition": dict(counts),
              "quality_by_condition": quality_by_condition,
              "identity_or_other_flags": dict(flags), "extractor_errors": len(errors),
              "bootstrap_replicates": args.bootstrap, "seed": args.seed,
              "source_note": "Manifest-matched extractor rows, not independent assessment of defense fidelity or application completion.",
              "metrics": {k: {"json_field": v[0], "label": v[1], "unit": v[2]} for k,v in METRICS.items()},
              "publication_gate": "Use only full 50-domain comparisons with explicitly reported metric exclusions; incomplete analysis is provisional."}
    (args.output / "quality.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    (args.output / "extraction-errors.json").write_text(json.dumps(errors, indent=2) + "\n")
    write_csv(args.output / "cohort-exclusions.csv", missing)
    write_csv(args.output / "domain-overheads.csv", detail)
    write_csv(args.output / "overall-overheads.csv", overall)
    write_csv(args.output / "mal-buflo-variants.csv", variants)
    print(json.dumps({"status": report["status"], "accepted": len(records), "expected": len(manifest),
                      "overall_rows": len(overall), "output": str(args.output)}, sort_keys=True))


if __name__ == "__main__":
    main()
