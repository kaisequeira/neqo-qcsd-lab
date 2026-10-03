"""Optional retained-raw oracle for the FRONT production/reduction clock repair.

Set QCSD_TEST_FRONT_RETAINED_RUNNER to the preserved FRONT004 attempt's neqo
directory. This reads the failed recording without granting it capture credit.
The ordinary portable fixtures exercise the same boundary without private data.
"""
import csv
import json
import os
from pathlib import Path
import shutil
from types import SimpleNamespace

import pytest

from qcsd_lab import capture_acceptance_policy as policy, capture_session, fidelity
from qcsd_lab.util import sha256_file


RAW_SHA256 = {
    "run.json": "a7c5ef3a8e44238a031d79d5a53d669b45ab317038fe118fe2d5b76e922de163",
    "schedule.csv": "f453a6db5ab4e04421e9d24f1960fea642e7055283ef1ff63b83dc14c1033736",
    "events.csv": "ef319fb336ff4e32337e6f2021ea3bb883c20a8a8c42802cc5eaf16e2690128c",
    "packets.csv": "e1ee71b9c42e3b80dba781d498ba2c5accc4ccc76e9b203fc567cf1eb6f18a59",
}


@pytest.fixture
def retained_runner():
    value = os.environ.get("QCSD_TEST_FRONT_RETAINED_RUNNER")
    if value is None:
        pytest.skip("optional retained FRONT004 evidence is not supplied")
    root = Path(value)
    for name, digest in RAW_SHA256.items():
        assert (root / name).is_file() and not (root / name).is_symlink()
        assert sha256_file(root / name) == digest
    return root


def read_csv(path):
    with path.open(newline="", encoding="utf-8") as source:
        reader = csv.DictReader(source)
        return reader.fieldnames, list(reader)


def write_csv(path, fields, rows):
    with path.open("w", newline="", encoding="utf-8") as output:
        writer = csv.DictWriter(output, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def run_binding(native, retained_runner):
    result_root = retained_runner.parents[3]
    workload_id = "rapid-v5-curated-e5114f8d4f027cce4481-attempt-000004"
    inputs = result_root / "inputs"
    return {
        "manifest": inputs / "runtime-workloads" / f"{workload_id}.json",
        "chaff_manifest": inputs / "chaff-manifests" / f"{workload_id}.json",
        "application_workload_source": inputs / "workloads" / f"{workload_id}.json",
        "workload_id": workload_id,
        "defense": capture_session.Defense("front", "front", False),
        "seed": native["seed"],
        "context": SimpleNamespace(request_policy="as-defined", udp_payload_ceiling=1200,
            limits=capture_session.Limits(max_response_bytes=1048576)),
    }


def test_retained_front004_oracle_preserves_the_real_full_graph_and_raw_omission(retained_runner):
    native = json.loads((retained_runner / "run.json").read_text())
    _, rows = read_csv(retained_runner / "schedule.csv")
    _, events = read_csv(retained_runner / "events.csv")
    misses = [row for row in rows if row["satisfaction"] == "missed"]
    assert len(misses) == 1
    row = misses[0]
    observations = [json.loads(event["details"]) for event in events
        if event["event"] == "observation" and event["outcome"] == "recorded"]
    missed = [event for event in observations if event.get("type") == "slot_missed"]
    assert len(missed) == 1
    assert row["slot_id"] == "727" and missed[0]["slot"] == 727
    assert missed[0]["production_monotonic_ns"] == 1531261876
    assert native["defense_start_monotonic_ns"] == 289973097
    assert (missed[0]["production_monotonic_ns"] - native["defense_start_monotonic_ns"]) // 1000 == 1241288
    assert row["terminal_defense_elapsed_us"] == "1241385"
    assert native["completion_status"] == "complete" and native["error"] is None
    assert len(native["responses"]) == 260
    assert {response["resource_id"] for response in native["responses"]} == set(range(260))
    assert all(response["complete"] and response["outcome"] == "succeeded" for response in native["responses"])
    binding = run_binding(native, retained_runner)
    prepared = json.loads(binding["application_workload_source"].read_text())
    assert len(prepared["resources"]) == 260
    source = json.loads((retained_runner.parents[3] / "inputs/source.json").read_text())
    assert source["lab_commit"] == "a8a42de19a58212b4ec4a5acf8e1295b3aa710df"
    assert source["neqo_commit"] == "3d994f0d557e2d27873bace0f4efd0f401660bc7"
    assert source["lab_dirty"] is False and source["neqo_dirty"] is False
    policy.validate_front_source_binding(prepared, native)
    capture_session._validate_run_binding(native, **binding)
    metrics = fidelity._schedule_realization_metrics_from_path(retained_runner / "schedule.csv")
    assert metrics["scheduled_outgoing_events"] == 828
    assert metrics["scheduled_incoming_events"] == 848
    assert metrics["missed_events"] == metrics["front_outgoing_congestion_omissions"] == 1
    assert metrics["front_outgoing_shaped_handoff_events"] == 827
    assert metrics["front_outgoing_omissions_within_bound"] is True
    assert fidelity.fidelity_eligible("front", native["defense_diagnostics"], sample_eligible=True,
        missed_events=metrics["missed_events"], outgoing_size_mismatches=metrics["outgoing_size_mismatch_events"],
        schedule_metrics=metrics, resolved_configuration=native["resolved_configuration"],
        require_defense_activation=True)
    for name, digest in RAW_SHA256.items():
        assert sha256_file(retained_runner / name) == digest


@pytest.mark.parametrize("mutation", ["packet-target", "packet-direction", "packet-length", "event-clock",
    "production-clock", "reduction-before-production", "endpoint", "duplicate-observation", "marker-source"])
def test_retained_front004_packet_and_clock_mutations_remain_rejected(tmp_path, retained_runner, mutation):
    for name in RAW_SHA256:
        shutil.copyfile(retained_runner / name, tmp_path / name)
    fields, events = read_csv(tmp_path / "events.csv")
    selected = next(event for event in events if event["event"] == "observation"
        and json.loads(event["details"]).get("type") == "slot_missed")
    detail = json.loads(selected["details"])
    if mutation == "packet-target": detail["packet"]["timestamp_us"] -= 1
    elif mutation == "packet-direction": detail["packet"]["direction"] = "incoming"
    elif mutation == "packet-length": detail["packet"]["length"] = 1199
    elif mutation == "event-clock": selected["monotonic_us"] = str(int(selected["monotonic_us"]) - 1)
    elif mutation == "production-clock": detail["production_monotonic_ns"] += 1000
    elif mutation == "reduction-before-production":
        detail["production_monotonic_ns"] = 289973097 + 1241386 * 1000
        selected["monotonic_us"] = str(detail["production_monotonic_ns"] // 1000)
    elif mutation == "endpoint": detail["endpoint"] = 2
    elif mutation == "duplicate-observation": events.append(dict(selected))
    else:
        native = json.loads((tmp_path / "run.json").read_text())
        native[policy.FRONT_FIELD]["source"] = "unbound-source"
        (tmp_path / "run.json").write_text(json.dumps(native))
    selected["details"] = json.dumps(detail)
    write_csv(tmp_path / "events.csv", fields, events)
    with pytest.raises(ValueError, match="FRONT"):
        fidelity._schedule_realization_metrics_from_path(tmp_path / "schedule.csv")


def test_retained_front004_stale_source_identity_is_not_reused(retained_runner):
    native = json.loads((retained_runner / "run.json").read_text())
    binding = run_binding(native, retained_runner)
    native["application_workload_source_hash_sha256"] = "f" * 64
    with pytest.raises(ValueError, match="application-source"):
        capture_session._validate_run_binding(native, **binding)
