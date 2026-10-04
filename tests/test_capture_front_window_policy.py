"""FRONT V3 changes only explicit padding timing and the omission budget."""
from copy import deepcopy
import json

import pytest

from qcsd_lab import capture_acceptance_policy as policy, fidelity
from tests.test_capture_front_policy import eligible, persist
from tests.test_capture_front_padding_policy import fixture as v2_fixture, marker as v2_marker


def marker():
    value = v2_marker()
    value.update(schema_version=3, policy=policy.FRONT_WINDOW_POLICY,
        outgoing_omission_ratio_denominator=10, outgoing_release_window_us=10000,
        historical_outgoing_release_window_us=5000)
    return value


def fixture(root, reasons=("DeadlineExpired",), outgoing=100):
    native, rows, packets, events = v2_fixture(root, reasons, outgoing)
    native[policy.FRONT_FIELD] = marker()
    for event in events:
        details = json.loads(event["details"])
        if details["type"] == "send_packet":
            details["deadline_after_us"] = 10000
        else:
            target = details["packet"]["timestamp_us"]
            details["production_monotonic_ns"] = native["defense_start_monotonic_ns"] + (target + 11000) * 1000 + 603
            event["monotonic_us"] = str(details["production_monotonic_ns"] // 1000)
        event["details"] = json.dumps(details)
    for row in rows:
        if row["direction"] == "outgoing" and row["satisfaction"] == "missed":
            row["terminal_defense_elapsed_us"] = str(int(row["target_time_us"]) + 11000)
    persist(root, native, rows, packets, events)
    return native, rows, packets, events


@pytest.mark.parametrize("congestion,expired,accepted", [(0, 0, True), (5, 5, True), (5, 6, False), (10, 0, True), (0, 10, True)])
def test_combined_exact_ten_percent_retains_all_raw_misses(tmp_path, congestion, expired, accepted):
    reasons = ("CongestionLimited",) * congestion + ("DeadlineExpired",) * expired
    native, _, _, _ = fixture(tmp_path, reasons)
    metrics = fidelity._schedule_realization_metrics_from_path(tmp_path / "schedule.csv")
    assert metrics["missed_events"] == metrics["front_outgoing_padding_omissions"] == len(reasons)
    assert metrics["front_outgoing_congestion_omissions"] == congestion
    assert metrics["front_outgoing_deadline_omissions"] == expired
    assert metrics["satisfied_events"] == 200 - len(reasons)
    assert metrics["front_outgoing_shaped_handoff_events"] == 100 - len(reasons)
    assert eligible(native, metrics) is accepted


def test_small_schedule_does_not_round_one_omission_up(tmp_path):
    native, rows, packets, events = fixture(tmp_path)
    rows = rows[:9] + rows[100:]
    packets = packets[:8]
    persist(tmp_path, native, rows, packets, events)
    metrics = fidelity._schedule_realization_metrics_from_path(tmp_path / "schedule.csv")
    assert metrics["scheduled_outgoing_events"] == 9
    assert not metrics["front_outgoing_omissions_within_bound"] and not eligible(native, metrics)


@pytest.mark.parametrize("window,accepted", [(5000, False), (9998, False), (9999, True), (10000, True), (10001, False)])
def test_only_actual_declared_ten_ms_padding_opportunity_is_supported(tmp_path, window, accepted):
    native, rows, packets, events = fixture(tmp_path)
    action = json.loads(events[0]["details"])
    action["deadline_after_us"] = window
    events[0]["details"] = json.dumps(action)
    persist(tmp_path, native, rows, packets, events)
    if accepted:
        assert eligible(native, fidelity._schedule_realization_metrics_from_path(tmp_path / "schedule.csv"))
    else:
        with pytest.raises(ValueError, match="pure-padding opportunity"):
            fidelity._schedule_realization_metrics_from_path(tmp_path / "schedule.csv")


@pytest.mark.parametrize("stamp,accepted", [(10_000_999, False), (10_001_000, True)])
def test_expiry_proof_retains_conservative_nanosecond_boundary(tmp_path, stamp, accepted):
    native, rows, packets, events = fixture(tmp_path)
    miss = json.loads(events[1]["details"])
    miss["production_monotonic_ns"] = native["defense_start_monotonic_ns"] + stamp
    events[1].update(monotonic_us=str(miss["production_monotonic_ns"] // 1000), details=json.dumps(miss))
    persist(tmp_path, native, rows, packets, events)
    if accepted:
        assert eligible(native, fidelity._schedule_realization_metrics_from_path(tmp_path / "schedule.csv"))
    else:
        with pytest.raises(ValueError, match="expiry deadline"):
            fidelity._schedule_realization_metrics_from_path(tmp_path / "schedule.csv")


@pytest.mark.parametrize("mutation", ["data", "fake-handoff", "missing-miss", "incoming-miss", "missing-credit", "invalid-reason"])
def test_v3_preserves_data_physical_credit_reason_and_packet_guards(tmp_path, mutation):
    native, rows, packets, events = fixture(tmp_path)
    if mutation == "data":
        action = json.loads(events[0]["details"]); action["allow_stream_data"] = True
        events[0]["details"] = json.dumps(action)
    elif mutation == "fake-handoff":
        fake = deepcopy(packets[0]); fake["slot_id"] = rows[0]["slot_id"]; packets.append(fake)
    elif mutation == "missing-miss": events.pop(1)
    elif mutation == "incoming-miss": rows[100].update(satisfaction="missed", miss_reason="DeadlineExpired")
    elif mutation == "missing-credit": rows[100]["credit_advertised_at_us"] = rows[100]["credit_advertisement_delay_us"] = ""
    else: rows[0]["miss_reason"] = "RunAborted"
    persist(tmp_path, native, rows, packets, events)
    try:
        metrics = fidelity._schedule_realization_metrics_from_path(tmp_path / "schedule.csv")
    except ValueError:
        return
    assert not eligible(native, metrics)


@pytest.mark.parametrize("field,value", [("schema_version", 2), ("schema_version", True),
    ("outgoing_omission_ratio_numerator", 2), ("outgoing_omission_ratio_denominator", 100),
    ("outgoing_release_window_us", 10001), ("outgoing_release_window_us", 10000.0),
    ("historical_outgoing_release_window_us", 10000), ("require_pure_padding", False),
    ("policy", []), ("scientific_credit", True)])
def test_v3_closed_marker_cannot_widen_or_disguise_its_contract(field, value):
    current = marker(); current[field] = value
    with pytest.raises(ValueError): policy.validate_front_capture_marker(current)


def test_legacy_marker_and_prepared_source_cannot_acquire_v3_authority(tmp_path):
    native, rows, packets, events = fixture(tmp_path)
    prepared = {"preparation": {policy.FRONT_FIELD: policy.FRONT_WINDOW_POLICY,
        "primary_document_identity_policy": "variable-primary-document-body-v1",
        "application_response_policy": "completed-terminal-http-errors-v1",
        "qualified_chaff_origin_policy": "prepared-approved-origins-v1"}}
    policy.validate_front_source_binding(prepared, native)
    for literal in (policy.FRONT_POLICY, policy.FRONT_PADDING_POLICY):
        changed = deepcopy(prepared); changed["preparation"][policy.FRONT_FIELD] = literal
        with pytest.raises(ValueError, match="differs"): policy.validate_front_source_binding(changed, native)
    native[policy.FRONT_FIELD] = v2_marker()
    persist(tmp_path, native, rows, packets, events)
    with pytest.raises(ValueError, match="pure-padding opportunity"):
        fidelity._schedule_realization_metrics_from_path(tmp_path / "schedule.csv")


@pytest.mark.parametrize("mutation", ["control", "cell", "client-count", "server-count", "peaks", "drop", "mode"])
def test_v3_changes_no_traffic_or_controller_configuration(tmp_path, mutation):
    native, _, _, _ = fixture(tmp_path)
    resolved = native["resolved_configuration"]; defense = resolved["defense"]
    if mutation == "control": resolved["control_interval_us"] = 10000
    elif mutation == "cell": defense["packet_size"] = 1199
    elif mutation == "client-count": defense["n_client_packets"] = 901
    elif mutation == "server-count": defense["n_server_packets"] = 1201
    elif mutation == "peaks": defense["peak_minimum_seconds"] = 0.2
    elif mutation == "drop": resolved["drop_unsatisfied_events"] = True
    else: defense["kind"] = "buflo"
    with pytest.raises(ValueError): policy.validate_front_capture_run(native)


def test_incoming_release_diagnostic_is_still_not_a_front_gate(tmp_path):
    native, rows, packets, events = fixture(tmp_path)
    for row in rows[100:]:
        row["credit_advertised_at_us"] = str(int(row["credit_advertised_at_us"]) + 15000)
        row["credit_advertisement_delay_us"] = str(int(row["credit_advertisement_delay_us"]) + 15000)
        row["credit_consumed_at_us"] = str(int(row["credit_consumed_at_us"]) + 15000)
        row["credit_consumption_delay_us"] = str(int(row["credit_consumption_delay_us"]) + 15000)
    persist(tmp_path, native, rows, packets, events)
    metrics = fidelity._schedule_realization_metrics_from_path(tmp_path / "schedule.csv")
    assert metrics["incoming_credit_release_window_violations"] == 100
    assert eligible(native, metrics)
