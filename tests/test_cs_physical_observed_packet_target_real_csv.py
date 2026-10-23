"""Real immutable Native131 CSV counterexample and mutations; no qualification claim."""
import copy
import csv
import hashlib
import io
import json
from pathlib import Path
import pytest
from qcsd_lab import buflo_handoff as h

FIXTURES = {'negative74': {'run.json': {'path': '/Users/joshkai/Documents/neqo-obfuscation/mac-migration-20261009/evidence/CS131-R4-slot74-outgoing-binding-negative-Raw-HOST-001/run.json', 'sha256': '856288e058d86606b3a07d9b9a8f87352429b947201270687c92622a4d8baec1'}, 'schedule.csv': {'path': '/Users/joshkai/Documents/neqo-obfuscation/mac-migration-20261009/evidence/CS131-R4-slot74-outgoing-binding-negative-Raw-HOST-001/schedule.csv', 'sha256': '69bae44a9ce46b1224334ac50988715dab7f951ce9ff0be9a02b54940056a9ff'}, 'packets.csv': {'path': '/Users/joshkai/Documents/neqo-obfuscation/mac-migration-20261009/evidence/CS131-R4-slot74-outgoing-binding-negative-Raw-HOST-001/packets.csv', 'sha256': '3ab66d842b3c359a5a080e6164da28f298c9925ad90900ba655d7682e0c3db6e'}}, 'positive70': {'run.json': {'path': '/Users/joshkai/Documents/neqo-obfuscation/mac-migration-20261009/evidence/CS131-R4-slot70-outgoing-binding-negative-Raw-HOST-001/run.json', 'sha256': 'b2619774a70b1e1b8a344b0e95b0ef58a9ffbba7a7b09d7eed515cb34b083af3'}, 'schedule.csv': {'path': '/Users/joshkai/Documents/neqo-obfuscation/mac-migration-20261009/evidence/CS131-R4-slot70-outgoing-binding-negative-Raw-HOST-001/schedule.csv', 'sha256': 'c06fd3c3f2bef71b82e18f3d6100c25062ca25be3f6f6fa62da5a317acf7e70d'}, 'packets.csv': {'path': '/Users/joshkai/Documents/neqo-obfuscation/mac-migration-20261009/evidence/CS131-R4-slot70-outgoing-binding-negative-Raw-HOST-001/packets.csv', 'sha256': '810d2408fc8e01b8d2feeff2d24c9a920ccc0c2a96e550a75f9ed57eb5c7cf13'}}}
EXPECTED_HANDOFF_SHA256 = '27d9ff696ab87584b5d9ba86c0ec0cbc1b2704ab71ebcacf9c6ab8179dc7e3b4'


def test_real_native131_partial_packet_binding_preserves_requested_and_observed_sizes():
    assert hashlib.sha256(Path(h.__file__).read_bytes()).hexdigest() == EXPECTED_HANDOFF_SHA256
    cases = {}
    for name, refs in FIXTURES.items():
        content = {}
        for role, ref in refs.items():
            raw = Path(ref["path"]).read_bytes()
            assert hashlib.sha256(raw).hexdigest() == ref["sha256"]
            content[role] = raw
        run = json.loads(content["run.json"])
        assert run["migration_commit"] == "4919a0976b30933f81f5fa39bf557fd63e9895aa"
        assert run["completion_status"] == "complete" and run["error"] is None
        assert len(run["responses"]) == 20
        assert all(r["complete"] is True and r["status"] == 200 and r["outcome"] == "succeeded"
                   for r in run["responses"])
        schedule = list(csv.DictReader(io.StringIO(content["schedule.csv"].decode())))
        packets = list(csv.DictReader(io.StringIO(content["packets.csv"].decode())))
        h._validate_cs_buflo_outgoing_packet_evidence(
            schedule, packets, defense_start_monotonic_ns=run["defense_start_monotonic_ns"])
        cases[name] = (schedule, packets, run)
    # Exact recorded counterexample has600 requested and481 actually built.
    schedule, packets, run = cases["negative74"]
    original_s = next(r for r in schedule if r["direction"] == "outgoing" and r["slot_id"] == "9217")
    original_p = next(r for r in packets if r["direction"] == "outgoing" and r["slot_id"] == "9217")
    assert original_s["size"] == original_p["desired_udp_bytes"] == "600"
    assert original_s["observed_udp_bytes"] == original_p["scheduled_target"] == "481"
    # These independent mutations must all refuse before any later admission.
    for side, key, value in (
        ("packet", "scheduled_target", "600"),
        ("packet", "desired_udp_bytes", "481"),
        ("packet", "observed_udp_length", "480"),
        ("packet", "quic_padding_bytes", "439"),
        ("packet", "connection", "1"),
        ("packet", "qcsd_outcome_schema_version", "3"),
        ("schedule", "size", "480"),
        ("schedule", "desired_udp_bytes", "481"),
        ("schedule", "miss_reason", "PacingLimited"),
    ):
        s, p = copy.deepcopy(schedule), copy.deepcopy(packets)
        row = next(r for r in (p if side == "packet" else s)
                   if r["direction"] == "outgoing" and r["slot_id"] == "9217")
        row[key] = value
        with pytest.raises(ValueError):
            h._validate_cs_buflo_outgoing_packet_evidence(
                s, p, defense_start_monotonic_ns=run["defense_start_monotonic_ns"])
    # Matching forged composition values in both logs cannot create funding.
    s, p = copy.deepcopy(schedule), copy.deepcopy(packets)
    for rows in (s, p):
        row = next(r for r in rows if r["direction"] == "outgoing" and r["slot_id"] == "9217")
        row["quic_padding_bytes"] = "439"
    with pytest.raises(ValueError):
        h._validate_cs_buflo_outgoing_packet_evidence(
            s, p, defense_start_monotonic_ns=run["defense_start_monotonic_ns"])
