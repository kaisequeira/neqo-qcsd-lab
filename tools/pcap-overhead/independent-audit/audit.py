#!/usr/bin/env python3
"""Independently recompute primary point estimates; only accept the final census.

No raw PCAPs are read. This audits numerical aggregation of verified extractor
rows, not extraction correctness, uncertainty intervals, fidelity or causality.
"""
import argparse
import collections
import csv
import hashlib
import json
import math
import sqlite3
import sys
from pathlib import Path

CONDITIONS = ("undefended", "front", "tamaraw", "buflo", "cs-buflo", "wtf-pad")
MANIFEST_SHA = "ef0e87f1138db2675e655813b0667b3860235df5c635f045e18f48fac1d72abf"
AGGREGATOR_SHA = "6e6427360998bd4da1f4bfdfea3c619931003448f2dfd0c573f6ad8bafdc32e6"
FIELDS = {"ip_bytes": "ip_bytes", "observed_span": "span_seconds"}


def file_sha(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def read_final_manifest(path):
    if file_sha(path) != MANIFEST_SHA:
        raise ValueError("final manifest SHA-256 mismatch")
    entries, object_ids = {}, set()
    with path.open(encoding="utf-8-sig", newline="") as stream:
        for row in csv.DictReader(stream):
            key = row["defense"], row["domain"], int(row["session"])
            if key in entries or row["drive_file_id"] in object_ids:
                raise ValueError("duplicate manifest identity or file ID")
            entries[key] = (row["drive_file_id"], row["sha256"].lower(), int(row["size"]))
            object_ids.add(row["drive_file_id"])
    domains = sorted({k[1] for k in entries})
    expected = {(condition, domain, session) for condition in CONDITIONS
                for domain in domains for session in range(1, 401)}
    if len(domains) != 50 or set(entries) != expected:
        raise ValueError("manifest is not the complete balanced 120,000-capture design")
    return entries, domains


def valid_number(value, minimum=0):
    return (not isinstance(value, bool) and isinstance(value, (int, float))
            and math.isfinite(value) and value >= minimum)


def eligible(rec, metric):
    packets = rec.get("packet_count")
    value = rec.get(FIELDS[metric])
    return (valid_number(packets) and packets > 0 and valid_number(value)
            and (metric != "ip_bytes" or rec.get("ip_valid") is True)
            and (metric != "observed_span" or str(rec.get("strict_order")).lower() == "true"))


def read_database(path, manifest):
    groups, seen = collections.defaultdict(list), set()
    digest = hashlib.sha256()
    con = sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True, timeout=30)
    con.execute("BEGIN")
    try:
        if con.execute("SELECT count(*) FROM errors").fetchone()[0] != 0:
            raise ValueError("extractor error table is nonempty")
        query = ("SELECT defense,domain,session,drive_file_id,sha256,result_json "
                 "FROM metrics ORDER BY defense,domain,session")
        for condition, domain, session, file_id, sha, raw in con.execute(query):
            digest.update((json.dumps([condition, domain, session, file_id, sha, raw],
                                     ensure_ascii=False, separators=(",", ":")) + "\n").encode())
            key = condition, domain, int(session)
            if key in seen or key not in manifest:
                raise ValueError("duplicate or non-manifest database identity")
            seen.add(key)
            rec = json.loads(raw)
            manifest_id, manifest_sha, manifest_size = manifest[key]
            if (file_id != manifest_id or sha.lower() != manifest_sha
                    or rec.get("status") != "ok" or rec.get("drive_file_id") != file_id
                    or rec.get("sha256", "").lower() != manifest_sha
                    or int(rec.get("capture_bytes", -1)) != manifest_size):
                raise ValueError("database/manifest identity, size or status mismatch")
            for metric, field in FIELDS.items():
                if eligible(rec, metric):
                    groups[condition, domain, metric].append(float(rec[field]))
        if seen != set(manifest):
            raise ValueError("database census incomplete")
    finally:
        con.rollback()
        con.close()
    return groups, digest.hexdigest()


def expected_values(groups, domains):
    detail, summaries = {}, {}
    for metric in FIELDS:
        for defense in CONDITIONS[1:]:
            for domain in domains:
                a = groups[defense, domain, metric]
                b = groups["undefended", domain, metric]
                if not a or not b:
                    continue
                amean, bmean = math.fsum(a) / len(a), math.fsum(b) / len(b)
                if bmean <= 0:
                    continue
                detail[metric, defense, domain] = {
                    "baseline_n": len(b), "defense_n": len(a),
                    "baseline_expected_n": 400, "defense_expected_n": 400,
                    "baseline_mean": bmean, "defense_mean": amean,
                    "absolute_difference": amean - bmean,
                    "overhead_pct": 100 * (amean / bmean - 1),
                }
            rows = [detail[metric, defense, d] for d in domains if (metric, defense, d) in detail]
            if len(rows) == len(domains):
                n = len(rows)
                btotal = math.fsum(row["baseline_mean"] for row in rows)
                atotal = math.fsum(row["defense_mean"] for row in rows)
                summaries[metric, defense] = {
                    "domains": n,
                    "macro_overhead_pct": math.fsum(row["overhead_pct"] for row in rows) / n,
                    "pooled_cohort_mean_overhead_pct": 100 * (atotal / btotal - 1),
                    "mean_absolute_difference": math.fsum(row["absolute_difference"] for row in rows) / n,
                    "baseline_equal_domain_mean": btotal / n,
                    "defense_equal_domain_mean": atotal / n,
                }
    return detail, summaries


def read_actual(path, keyfields):
    result = {}
    with path.open(encoding="utf-8-sig", newline="") as stream:
        for row in csv.DictReader(stream):
            if row["metric"] not in FIELDS:
                continue
            key = tuple(row[f] for f in keyfields)
            if key in result:
                raise ValueError(f"duplicate aggregate row {key}")
            result[key] = row
    return result


def compare(expected, actual, label):
    differences = []
    for key in sorted(set(expected) - set(actual)):
        differences.append({"table": label, "key": key, "issue": "missing_row"})
    for key in sorted(set(actual) - set(expected)):
        differences.append({"table": label, "key": key, "issue": "unexpected_row"})
    for key in sorted(set(expected) & set(actual)):
        for field, value in expected[key].items():
            try:
                got = float(actual[key][field])
            except (ValueError, KeyError, TypeError):
                got = float("nan")
            if not math.isfinite(got) or not math.isclose(got, value, rel_tol=1e-10, abs_tol=1e-8):
                differences.append({"table": label, "key": key, "field": field,
                                    "expected": value, "actual": str(actual[key].get(field))})
    return differences


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--manifest", type=Path, required=True)
    p.add_argument("--database", type=Path, required=True)
    p.add_argument("--aggregate-dir", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True, help="New JSON report path; never overwrites")
    args = p.parse_args()
    if args.output.exists():
        p.error("output already exists")
    manifest, domains = read_final_manifest(args.manifest)
    quality = json.loads((args.aggregate_dir / "quality.json").read_text())
    if (quality.get("status") != "complete" or quality.get("manifest_sha256") != MANIFEST_SHA
            or quality.get("analysis_script_sha256") != AGGREGATOR_SHA
            or quality.get("manifest_sessions") != 120000 or quality.get("accepted_metric_rows") != 120000
            or quality.get("identity_or_other_flags") or quality.get("extractor_errors") != 0):
        raise ValueError("aggregate quality/provenance is not complete and pinned")
    groups, snapshot_sha = read_database(args.database, manifest)
    if snapshot_sha != quality.get("metric_rows_content_sha256"):
        raise ValueError("aggregate and database metric snapshots differ")
    detail, summaries = expected_values(groups, domains)
    domain_file = args.aggregate_dir / "domain-overheads.csv"
    overall_file = args.aggregate_dir / "overall-overheads.csv"
    actual_detail = read_actual(domain_file, ("metric", "defense", "domain"))
    actual_overall = read_actual(overall_file, ("metric", "defense"))
    differences = compare(detail, actual_detail, "domain") + compare(summaries, actual_overall, "overall")
    for key, row in actual_overall.items():
        if row.get("provisional", "").lower() != "false":
            differences.append({"table": "overall", "key": key, "issue": "provisional_or_unknown"})
    unavailable = 2 * 5 * len(domains) - len(detail)
    status = "discrepancies" if differences else "passed_with_unavailable" if unavailable else "passed"
    report = {"status": status,
              "scope": "point estimates and counts only; no independent PCAP reparse or uncertainty verification",
              "manifest_sha256": MANIFEST_SHA, "aggregator_sha256": AGGREGATOR_SHA,
              "metric_rows_content_sha256": snapshot_sha, "captures": len(manifest), "domains": len(domains),
              "domain_table_sha256": file_sha(domain_file), "overall_table_sha256": file_sha(overall_file),
              "domain_rows_checked": len(detail), "overall_rows_checked": len(summaries),
              "unavailable_domain_rows": unavailable,
              "unavailable_overall_rows": 10 - len(summaries), "differences": differences}
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2, sort_keys=True, allow_nan=False)
        stream.write("\n")
    print(json.dumps({"status": report["status"], "domain_rows": len(detail),
                      "overall_rows": len(summaries), "difference_count": len(differences)}))
    return 1 if differences else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, TypeError, sqlite3.Error) as exc:
        print(f"audit did not run: {exc}", file=sys.stderr)
        sys.exit(2)
