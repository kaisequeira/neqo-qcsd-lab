"""Synthetic integration test against the pinned aggregator's actual CSV writer.

Requires its NumPy environment. Never reads the real dataset or writes results.
"""
import collections
import importlib.util
import json
import sqlite3
import tempfile
from pathlib import Path

import numpy as np
import audit

SOURCE = Path(__file__).resolve().parent.parent / "aggregate.py"
if audit.file_sha(SOURCE) != audit.AGGREGATOR_SHA:
    raise SystemExit("aggregator source no longer matches pinned SHA")
spec = importlib.util.spec_from_file_location("pinned_aggregator", SOURCE)
agg = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agg)

with tempfile.TemporaryDirectory() as tmp:
    tmp = Path(tmp)
    database = tmp / "synthetic.sqlite3"
    con = sqlite3.connect(database)
    con.executescript("CREATE TABLE metrics(defense,domain,session,drive_file_id,sha256,result_json);"
                      "CREATE TABLE errors(defense,domain,session,error,updated);")
    entries, agg_manifest = {}, {}
    domains = ["alpha.example", "beta.example"]
    count = 3
    for di, defense in enumerate(agg.CONDITIONS):
        for hi, domain in enumerate(domains):
            for session in range(1, count + 1):
                key = (defense, domain, session)
                file_id = "-".join(map(str, key))
                sha = f"{di * 100 + hi * 10 + session:064x}"
                size = 1234 + session
                rec = {"status": "ok", "drive_file_id": file_id, "sha256": sha, "capture_bytes": size,
                       "packet_count": session, "ip_bytes": (di + 1) * 100 + hi * 13 + session * 7,
                       "ip_valid": not (defense == "front" and hi == 0 and session == 1),
                       "span_seconds": (di + 1) * 1.23 + hi * .37 + session * .11,
                       "strict_order": not (defense == "tamaraw" and hi == 1 and session == 1)}
                con.execute("INSERT INTO metrics VALUES(?,?,?,?,?,?)", (*key, file_id, sha, json.dumps(rec)))
                entries[key] = (file_id, sha, size)
                agg_manifest[key] = {"drive_file_id": file_id, "sha256": sha, "size": str(size)}
    con.commit()
    con.close()

    groups, digest = audit.read_database(database, entries)
    records, flags, agg_digest, errors = agg.load_metrics(database, agg_manifest)
    assert not flags and not errors and len(records) == len(entries)
    assert digest == agg_digest, "canonical snapshot differs from the pinned aggregator"
    expected, overall = audit.expected_values(groups, domains)
    details, summaries = [], []
    rng = np.random.default_rng(42)
    for metric, field in audit.FIELDS.items():
        for defense in agg.CONDITIONS[1:]:
            rows, draws_a, draws_b = [], [], []
            for domain in domains:
                a, _, _ = agg.cohort_data(records, defense, domain, field, count,
                                           strict_order=(metric == "observed_span"))
                b, _, _ = agg.cohort_data(records, "undefended", domain, field, count,
                                           strict_order=(metric == "observed_span"))
                row, da, db = agg.estimate_domain(a, b, 100, rng)
                # Audit hardcodes the production expected cohort size. This field
                # is adjusted solely for this tiny synthetic table.
                row = {"metric": metric, "unit": "synthetic", "defense": defense, "domain": domain,
                       "baseline_expected_n": 400, "defense_expected_n": 400, **row}
                details.append(row)
                rows.append(row)
                draws_a.append(da)
                draws_b.append(db)
            summary = agg.summarize(defense, metric, rows, draws_a, draws_b, rng)
            summary["provisional"] = False
            summaries.append(summary)
    agg.write_csv(tmp / "domain-overheads.csv", details)
    agg.write_csv(tmp / "overall-overheads.csv", summaries)
    actual = audit.read_actual(tmp / "domain-overheads.csv", ("metric", "defense", "domain"))
    actual_overall = audit.read_actual(tmp / "overall-overheads.csv", ("metric", "defense"))
    differences = (audit.compare(expected, actual, "domain")
                   + audit.compare(overall, actual_overall, "overall"))
    assert not differences, differences
    assert all(row["provisional"].lower() == "false" for row in actual_overall.values())
    # The comparison must detect one altered numeric field.
    actual[("ip_bytes", "front", domains[0])]["overhead_pct"] = "999999"
    assert audit.compare(expected, actual, "domain")
    print(f"Synthetic aggregator CSV and snapshot integration: {len(details)} domain rows, "
          f"{len(summaries)} overall rows, no differences; tampering detected")
