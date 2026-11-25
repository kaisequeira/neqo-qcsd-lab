import collections
import csv
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import audit


class AuditTests(unittest.TestCase):
    def test_estimates_check_domain_weighting_and_pooled_mean(self):
        g = collections.defaultdict(list)
        for metric in audit.FIELDS:
            g["undefended", "a", metric] = [10, 20]
            g["undefended", "b", metric] = [5, 15]
            for defense in audit.CONDITIONS[1:]:
                g[defense, "a", metric] = [30, 30]
                g[defense, "b", metric] = [5, 5]
        detail, overall = audit.expected_values(g, ["a", "b"])
        self.assertEqual(len(detail), 20)
        self.assertEqual(len(overall), 10)
        self.assertAlmostEqual(detail["ip_bytes", "front", "a"]["overhead_pct"], 100)
        self.assertAlmostEqual(detail["ip_bytes", "front", "b"]["overhead_pct"], -50)
        self.assertAlmostEqual(overall["ip_bytes", "front"]["macro_overhead_pct"], 25)
        self.assertAlmostEqual(overall["ip_bytes", "front"]["pooled_cohort_mean_overhead_pct"], 40)
        g["front", "b", "ip_bytes"] = []
        detail, overall = audit.expected_values(g, ["a", "b"])
        self.assertNotIn(("ip_bytes", "front", "b"), detail)
        self.assertNotIn(("ip_bytes", "front"), overall)

    def test_eligibility_separates_byte_and_time_quality(self):
        rec = {"packet_count": 1, "ip_bytes": 7, "span_seconds": 2,
               "ip_valid": False, "strict_order": True}
        self.assertFalse(audit.eligible(rec, "ip_bytes"))
        self.assertTrue(audit.eligible(rec, "observed_span"))
        rec["strict_order"] = False
        self.assertFalse(audit.eligible(rec, "observed_span"))
        rec.update(ip_valid=True, packet_count=True)
        self.assertFalse(audit.eligible(rec, "ip_bytes"))

    def test_comparison_detects_modified_and_missing_fields(self):
        expected = {("ip_bytes", "front", "a"): {"baseline_n": 2, "overhead_pct": 100.0}}
        good = {("ip_bytes", "front", "a"): {"baseline_n": "2", "overhead_pct": "100.0"}}
        self.assertEqual(audit.compare(expected, good, "domain"), [])
        self.assertEqual(len(audit.compare(expected, {}, "domain")), 1)
        good[("ip_bytes", "front", "a")]["overhead_pct"] = "101"
        self.assertEqual(len(audit.compare(expected, good, "domain")), 1)

    def test_incomplete_manifest_and_database_fail_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            manifest_path = root / "manifest.csv"
            manifest_path.write_text("defense,domain,session,drive_file_id,sha256,size\n"
                                     "undefended,a,1,id,aaaa,12\n")
            with patch.object(audit, "MANIFEST_SHA", audit.file_sha(manifest_path)):
                with self.assertRaisesRegex(ValueError, "balanced"):
                    audit.read_final_manifest(manifest_path)
            db = root / "metrics.sqlite3"
            con = sqlite3.connect(db)
            con.executescript("CREATE TABLE metrics(defense,domain,session,drive_file_id,sha256,result_json);"
                              "CREATE TABLE errors(error);")
            row = {"status": "ok", "drive_file_id": "id", "sha256": "aaaa", "capture_bytes": 12,
                   "packet_count": 1, "ip_bytes": 7, "ip_valid": True, "span_seconds": 2, "strict_order": True}
            con.execute("INSERT INTO metrics VALUES(?,?,?,?,?,?)", ("undefended", "a", 1, "id", "aaaa", json.dumps(row)))
            con.commit()
            con.close()
            manifest = {("undefended", "a", 1): ("id", "aaaa", 12),
                        ("undefended", "a", 2): ("id2", "bbbb", 13)}
            with self.assertRaisesRegex(ValueError, "incomplete"):
                audit.read_database(db, manifest)

    def test_duplicate_aggregate_rows_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "rows.csv"
            path.write_text("metric,defense,domain\nip_bytes,front,a\nip_bytes,front,a\n")
            with self.assertRaisesRegex(ValueError, "duplicate"):
                audit.read_actual(path, ("metric", "defense", "domain"))


if __name__ == "__main__":
    unittest.main()
