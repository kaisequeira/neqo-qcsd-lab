"""Physical kernel TAI bounds retain strict slots, owners and deadlines."""
from copy import deepcopy
import csv
import json

import pytest

from qcsd_lab import fidelity, kernel_tx, orchestrator
from tests import test_kernel_tx_incoming_window as incoming
from tests import test_kernel_tx_late_selection as selection
from tests import test_kernel_tx_preparation_reserve as reserve
from tests.test_capture_terminal_primary_partial import partial_fixture


def case(tmp_path, schema=10, carrier="post-main"):
    raw = {10: incoming._raw, 11: selection._modern, 12: reserve.raw_receipt}[schema]()
    run = incoming._run(raw)
    if schema == 12:
        run[reserve.policy.BUFLO_KERNEL_PREPARATION_FIELD] = reserve.marker()
    # Retain a truthful nonfatal CLOCK_MONOTONIC drift envelope. The final
    # TAI/REALTIME physical intervals and all their original validators remain.
    mapping = raw["clock_mapping"]
    drift = 7_000_000
    mapping["end"]["monotonic"]["clock_ns"] -= drift
    raw["clock_end"]["monotonic"]["clock_ns"] -= drift
    mapping["effective_monotonic_offset_upper_ns"] += drift
    mapping["max_observed_offset_drift_ns"] = drift
    job = raw["jobs"][0]
    if carrier == "coalesced":
        job["items"] = job["items"][:1]
        mapping["per_item_monotonic_evidence_count"] = 1
        mapping["per_item_realtime_evidence_count"] = 1
        identity = job["credit_identities"][0]
        identity.update(endpoint_index=1, endpoint=1,
                        resolution="coalesced-in-main-finalized", carrier_item_id=None)
        job["helper_job_close"]["unused_post_main_datagrams"] = 2
        raw["runtime_contract"]["helper_lifecycle"]["completed_immediate_datagrams"] = 0
        raw["runtime_contract"]["helper_shutdown"]["lifecycle"]["completed_immediate_datagrams"] = 0
        raw["aggregate"].update(item_count=1, ordered_item_count=0,
            main_coalesced_credit_identity_count=1, carrier_credit_identity_count=0,
            transmitted_item_count=1, tx_sched_timestamp_count=1,
            tx_software_timestamp_count=1,
            max_tx_software_lateness_ns=job["items"][0]["tx_software_tai_upper_ns"] - job["release_tai_ns"])
    elif carrier == "aggregate":
        identity = deepcopy(job["credit_identities"][0])
        identity.update(endpoint_index=1, endpoint=1,
                        resolution="coalesced-in-main-finalized", carrier_item_id=None)
        job["credit_identities"].append(identity)
        raw["aggregate"].update(captured_credit_identity_count=2,
                                main_coalesced_credit_identity_count=1)
    run["defense_start_monotonic_ns"] = 1_000_000
    rows = [{"direction": "incoming", "slot_id": "1", "target_time_us": "0",
        "connection": "" if carrier == "aggregate" else "1" if carrier == "coalesced" else "0",
        "satisfaction": "satisfied", "action_time_us": "50",
        "credit_advertised_at_us": "100", "credit_advertisement_delay_us": "50"}]
    assert kernel_tx.kernel_tx_runner_receipt_success_valid(raw)
    assert kernel_tx.kernel_tx_incoming_window_bound_to_run_valid(run)
    save(tmp_path, run, rows)
    return run, raw, rows


def save(root, run, rows):
    (root / "run.json").write_text(json.dumps(run), encoding="utf-8")
    with (root / "schedule.csv").open("w", newline="", encoding="utf-8") as output:
        writer = csv.DictWriter(output, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


@pytest.mark.parametrize("schema", [10, 11, 12])
def test_validated_modern_carrier_uses_tai_despite_false_monotonic_early_stamp(tmp_path, schema):
    run, raw, rows = case(tmp_path, schema)
    assert int(rows[0]["credit_advertised_at_us"]) * 1000 < run["defense_start_monotonic_ns"]
    result = fidelity._incoming_credit_release_metrics(tmp_path / "schedule.csv", rows)
    assert result["incoming_credit_release_time_basis"] == "validated-kernel-physical-CLOCK_TAI-v1"
    assert result["incoming_credit_release_window_us"] == 10_000
    assert result["incoming_credit_release_timing_events"] == 1
    assert result["incoming_credit_release_window_violations"] == 0
    assert result["incoming_credit_release_lateness_upper_bound_us_max"] == 6100
    assert result["incoming_credit_release_original_5000us_violations"] == 1
    # This helper gives engineering timing metrics, never a complete acceptance
    # proof: the unchanged fidelity gate still rejects an incomplete schedule.
    assert not fidelity.fidelity_eligible("buflo", run["defense_diagnostics"],
        sample_eligible=True, missed_events=0, outgoing_size_mismatches=0,
        schedule_metrics=result, resolved_configuration=run["resolved_configuration"])


@pytest.mark.parametrize("carrier", ["coalesced", "aggregate"])
def test_coalesced_main_and_multiple_exact_owners_join_all_physical_carriers(tmp_path, carrier):
    _, _, rows = case(tmp_path, carrier=carrier)
    result = fidelity._incoming_credit_release_metrics(tmp_path / "schedule.csv", rows)
    assert result["incoming_credit_release_window_violations"] == 0
    assert result["incoming_credit_release_lateness_upper_bound_us_max"] == (3100 if carrier == "coalesced" else 6100)


@pytest.mark.parametrize("role,offset", [("incoming", -1), ("incoming", 10_000_000), ("outgoing", 5_000_000)])
def test_genuinely_early_or_exclusive_deadline_physical_handoff_is_refused(tmp_path, role, offset):
    run, raw, rows = case(tmp_path)
    item = raw["jobs"][0]["items"][1 if role == "incoming" else 0]
    incoming._set_item_times(item, enqueue_offset_ns=offset - 10_000, tx_offset_ns=offset)
    raw["aggregate"]["max_tx_software_lateness_ns"] = max(6100000, offset)
    assert not kernel_tx.kernel_tx_runner_receipt_success_valid(raw)
    save(tmp_path, run, rows)
    with pytest.raises(ValueError, match="valid bound modern kernel"):
        fidelity._incoming_credit_release_metrics(tmp_path / "schedule.csv", rows)


@pytest.mark.parametrize("mutation", ["target", "slot", "duplicate", "wrong-owner", "blank-single-owner",
    "missing-row", "carrier", "identity", "policy", "future-schema", "csv-delay"])
def test_modern_evidence_cannot_fall_back_or_drop_slot_owner_policy_binding(tmp_path, mutation):
    run, raw, rows = case(tmp_path)
    job = raw["jobs"][0]
    if mutation == "target": rows[0]["target_time_us"] = "20000"
    elif mutation == "slot": rows[0]["slot_id"] = "3"
    elif mutation == "duplicate": rows.append(deepcopy(rows[0]))
    elif mutation == "wrong-owner": rows[0]["connection"] = "1"
    elif mutation == "blank-single-owner": rows[0]["connection"] = ""
    elif mutation == "missing-row": rows[0]["direction"] = "outgoing"
    elif mutation == "carrier": job["credit_identities"][0]["carrier_item_id"] = 0
    elif mutation == "identity": job["credit_identities"][0]["slot"] = 3
    elif mutation == "policy": run.pop(incoming.FIELD)
    elif mutation == "future-schema": raw["schema_version"] = 13
    elif mutation == "csv-delay": rows[0]["credit_advertisement_delay_us"] = "51"
    save(tmp_path, run, rows)
    with pytest.raises(ValueError):
        fidelity._incoming_credit_release_metrics(tmp_path / "schedule.csv", rows)


def test_raw_partial_advertisement_keeps_slot_coverage_but_not_timing_count(tmp_path):
    _, _, rows = case(tmp_path)
    rows[0].update(satisfaction="missed", miss_reason="ReceiveCreditRetired")
    result = fidelity._incoming_credit_release_metrics(tmp_path / "schedule.csv", rows)
    assert result["incoming_credit_release_timing_events"] == 0
    assert result["incoming_credit_release_window_violations"] == 0
    # Timing exclusion alone cannot authenticate a missed terminal cell.
    assert fidelity._terminal_primary_partial_allowance("buflo", result) == (0, 0)


def test_report_uses_bound_ten_ms_window_and_authenticated_terminal_partial_count(tmp_path):
    neqo = tmp_path / "neqo"
    neqo.mkdir()
    native, _, _, _ = partial_fixture(neqo, "buflo")
    metrics = fidelity._schedule_realization_metrics_from_path(neqo / "schedule.csv")
    assert fidelity._terminal_primary_partial_allowance("buflo", metrics) == (1, 600)
    assert orchestrator._buflo_incoming_credit_delay_failure(tmp_path, metrics) is None
    incomplete = {**metrics, "incoming_credit_release_timing_events": metrics["incoming_credit_release_timing_events"] - 1}
    report = orchestrator._buflo_incoming_credit_delay_failure(tmp_path, incomplete)
    assert report["limit_us"] == 10000
    assert report["expected_events"] == metrics["scheduled_incoming_events"] - 1
    assert report["violating_slots"] == []
    unproved = deepcopy(metrics)
    unproved.pop("terminal_primary_partial_events_sha256")
    assert orchestrator._buflo_incoming_credit_delay_failure(tmp_path, unproved)["expected_events"] is None
    assert not fidelity.fidelity_eligible("buflo", native["defense_diagnostics"], sample_eligible=True,
        missed_events=1, outgoing_size_mismatches=0, schedule_metrics=unproved,
        resolved_configuration=native["resolved_configuration"])


def test_report_uses_joined_tai_even_when_other_timing_coverage_is_incomplete(tmp_path):
    neqo = tmp_path / "neqo"
    neqo.mkdir()
    _, _, rows = case(neqo, carrier="aggregate")
    metrics = fidelity._incoming_credit_release_metrics(neqo / "schedule.csv", rows)
    metrics.update(scheduled_incoming_events=2)
    report = orchestrator._buflo_incoming_credit_delay_failure(tmp_path, metrics)
    assert report["time_basis"] == "validated-kernel-physical-CLOCK_TAI-v1"
    assert report["expected_events"] == 2 and report["timing_events"] == 1
    assert report["limit_us"] == 10000 and report["violating_slots"] == []
