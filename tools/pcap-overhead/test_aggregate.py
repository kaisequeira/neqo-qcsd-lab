#!/usr/bin/env python3
"""Meaningful checks for estimands, joins, exclusions and provisional output."""
import csv
import json
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import numpy as np
import aggregate as a


class AggregationTests(unittest.TestCase):
    def test_ratio_of_means_not_arbitrary_session_pairing(self):
        row, _, _ = a.estimate_domain([4, 4], [1, 3], 300, np.random.default_rng(7))
        self.assertEqual(row["overhead_pct"], 100)
        self.assertNotEqual(row["overhead_pct"], ((4 / 1 - 1) + (4 / 3 - 1)) * 50)

    def test_invalid_ip_metrics_are_excluded_but_frame_metrics_remain(self):
        records = {("front", "x", 1): {"ip_valid": False, "ip_bytes": 40, "packet_bytes": 54, "packet_count": 1, "truncated_packets": 0, "encapsulation": "ether"}}
        ip, why, _ = a.cohort_data(records, "front", "x", "ip_bytes", 1)
        fr, _, _ = a.cohort_data(records, "front", "x", "packet_bytes", 1)
        self.assertEqual(len(ip), 0)
        self.assertEqual(why["ip_parse_or_capture_not_valid"], 1)
        self.assertEqual(list(fr), [54])

    def test_unknown_direction_excluded_from_directional_comparisons(self):
        records = {("front", "x", 1): {"ip_valid": True, "udp443_direction_valid": True,
                   "other_ip_bytes": 10, "udp443_up_ip_bytes": 40, "udp443_down_ip_bytes": 50,
                   "ip_bytes": 100, "packet_count": 1, "encapsulation": "ether"}}
        upstream, why, _ = a.cohort_data(records, "front", "x", "udp443_up_ip_bytes", 1)
        self.assertEqual(len(upstream), 0)
        self.assertEqual(why["ambiguous_or_unaccounted_direction"], 1)
        records[("front", "x", 1)].update(other_ip_bytes=0, ip_bytes=90)
        upstream, _, _ = a.cohort_data(records, "front", "x", "udp443_up_ip_bytes", 1)
        self.assertEqual(list(upstream), [40])

    def test_truncated_or_unknown_frame_bytes_excluded(self):
        records = {("front", "x", 1): {"packet_bytes": 54, "packet_count": 1, "truncated_packets": 1, "encapsulation": "ether"}}
        values, why, _ = a.cohort_data(records, "front", "x", "packet_bytes", 1)
        self.assertEqual(len(values), 0)
        self.assertEqual(why["frame_capture_truncated_or_unknown"], 1)
        del records[("front", "x", 1)]["truncated_packets"]
        values, _, _ = a.cohort_data(records, "front", "x", "packet_bytes", 1)
        self.assertEqual(len(values), 0)

    def make_fixture(self, root, *, missing=False, invalid_ip=False, wrong_id=False):
        root = Path(root)
        manifest, timing, db, out = root / "manifest.csv", root / "timing.csv", root / "metrics.sqlite3", root / "out"
        domains = ("cdn.myanimelist.net", "example.org")
        rows = []
        conn = sqlite3.connect(db)
        conn.executescript("CREATE TABLE metrics(defense TEXT,domain TEXT,session INTEGER,drive_file_id TEXT,sha256 TEXT,result_json TEXT,PRIMARY KEY(defense,domain,session)); CREATE TABLE errors(defense TEXT,domain TEXT,session INTEGER,error TEXT,updated REAL);")
        for d in a.CONDITIONS:
            for host in domains:
                for s in range(1, 5):
                    fid = f"{d}-{host}-{s}"; sha = (f"{s:x}" * 64)
                    rows.append({"defense": d, "domain": host, "session": s, "drive_file_id": fid, "sha256": sha, "size": 100})
                    if missing and (d, host, s) == ("front", "example.org", 4):
                        continue
                    if host == domains[0]:
                        base, other = 10, 20
                    else:
                        base, other = 100, 150
                    ip = base if d == "undefended" else other
                    value = {"status": "ok", "sha256": sha, "drive_file_id": fid, "capture_bytes": 100,
                             "packet_bytes": ip + 5, "packet_count": 3, "span_seconds": ip / 100,
                             "truncated_packets": 0,
                             "strict_order": True, "encapsulation": "ether", "ip_bytes": ip,
                             "ip_valid": not (invalid_ip and (d, host, s) == ("front", "example.org", 3))}
                    conn.execute("INSERT INTO metrics VALUES(?,?,?,?,?,?)", (d, host, s, "bad" if wrong_id and d == "front" and s == 1 else fid, sha, json.dumps(value)))
        conn.commit(); conn.close()
        with manifest.open("w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)
        with timing.open("w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=["session", "drive_file_id", "timing_variant"]); w.writeheader()
            for s in range(1, 5): w.writerow({"session": s, "drive_file_id": f"buflo-{domains[0]}-{s}", "timing_variant": "original_5ms" if s <= 2 else "relaxed_20ms"})
        return manifest, timing, db, out

    def execute(self, paths, *extra, with_timing=True):
        m, t, db, out = paths
        command = [sys.executable, str(Path(a.__file__)), "--manifest", str(m),
                   "--database", str(db), "--output", str(out), "--sessions", "4",
                   "--expected-domains", "2", "--bootstrap", "100", *extra]
        if with_timing:
            command.extend(("--mal-timing", str(t)))
        subprocess.run(command, check=True, capture_output=True)
        return json.loads((out / "quality.json").read_text())

    def test_full_design_macro_and_pooled_estimands(self):
        with tempfile.TemporaryDirectory() as root:
            paths = self.make_fixture(root); quality = self.execute(paths)
            self.assertEqual(quality["status"], "complete")
            with (paths[3] / "overall-overheads.csv").open() as f:
                rows = list(csv.DictReader(f))
            row = next(r for r in rows if r["metric"] == "ip_bytes" and r["defense"] == "front")
            self.assertAlmostEqual(float(row["macro_overhead_pct"]), 75.0)
            self.assertAlmostEqual(float(row["pooled_cohort_mean_overhead_pct"]), (170 / 110 - 1) * 100)
            with (paths[3] / "mal-buflo-variants.csv").open() as f:
                variants = [r for r in csv.DictReader(f) if r["metric"] == "ip_bytes"]
            self.assertEqual({r["timing_variant"] for r in variants}, {"original_5ms", "relaxed_20ms"})
            self.assertEqual({r["defense_n"] for r in variants}, {"2"})

    def test_incomplete_census_does_not_claim_full_result(self):
        with tempfile.TemporaryDirectory() as root:
            paths = self.make_fixture(root, missing=True); quality = self.execute(paths, "--allow-incomplete")
            self.assertEqual(quality["status"], "provisional_incomplete")
            with (paths[3] / "overall-overheads.csv").open() as f: rows = list(csv.DictReader(f))
            row = next(r for r in rows if r["metric"] == "ip_bytes" and r["defense"] == "front")
            self.assertEqual((row["domains"], row["provisional"]), ("1", "True"))

    def test_core_results_identical_without_optional_mal_labels(self):
        with tempfile.TemporaryDirectory() as root:
            paths = self.make_fixture(root)
            with_labels = self.execute(paths)
            primary = (paths[3] / "overall-overheads.csv").read_bytes()
            domain = (paths[3] / "domain-overheads.csv").read_bytes()
            other_out = Path(root) / "without-labels"
            without_labels = self.execute((*paths[:3], other_out), with_timing=False)
            self.assertEqual(primary, (other_out / "overall-overheads.csv").read_bytes())
            self.assertEqual(domain, (other_out / "domain-overheads.csv").read_bytes())
            self.assertFalse((other_out / "mal-buflo-variants.csv").exists())
            self.assertIsNone(without_labels["mal_timing_sha256"])
            self.assertIsNotNone(with_labels["mal_timing_sha256"])

    def test_invalid_ip_row_reported_without_dropping_valid_cohort(self):
        with tempfile.TemporaryDirectory() as root:
            paths = self.make_fixture(root, invalid_ip=True); self.execute(paths)
            with (paths[3] / "domain-overheads.csv").open() as f: rows = list(csv.DictReader(f))
            row = next(r for r in rows if r["metric"] == "ip_bytes" and r["defense"] == "front" and r["domain"] == "example.org")
            self.assertEqual((row["defense_n"], row["baseline_n"]), ("3", "4"))
            self.assertIn("ip_parse_or_capture_not_valid", (paths[3] / "cohort-exclusions.csv").read_text())

    def test_identity_mismatch_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            paths = self.make_fixture(root, wrong_id=True); quality = self.execute(paths, "--allow-incomplete")
            self.assertEqual(quality["identity_or_other_flags"]["identity_or_status_mismatch"], 2)
            self.assertEqual(quality["status"], "provisional_incomplete")


if __name__ == "__main__":
    unittest.main()
