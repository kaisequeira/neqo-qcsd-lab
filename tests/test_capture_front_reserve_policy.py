"""V4 distinguishes unbuilt padding expiry from actual ten-millisecond sends."""
from copy import deepcopy
import json

import pytest

from qcsd_lab import capture_acceptance_policy as policy, fidelity
from tests.test_capture_front_policy import eligible, persist
from tests.test_capture_front_window_policy import fixture as v3_fixture, marker as v3_marker


def marker():
    value = v3_marker()
    value.update(schema_version=4, policy=policy.FRONT_RESERVE_POLICY,
        outgoing_construction_window_us=9000, outgoing_preparation_reserve_us=1000,
        expired_construction_target="not-built-not-sent")
    return value


def fixture(root, reasons=("DeadlineExpired",), *, preexpired=False):
    native, rows, packets, old_events = v3_fixture(root, reasons)
    native[policy.FRONT_FIELD] = marker()
    start = native["defense_start_monotonic_ns"]
    events = []
    for row in rows[:100]:
        target, slot = int(row["target_time_us"]), int(row["slot_id"])
        early = preexpired and slot == 0
        action_ns = start + (target + (9500 if early else 0)) * 1000
        action = {"type": "send_packet", "endpoint": 1, "slot": slot,
            "packet": {"timestamp_us": target, "direction": "outgoing", "length": 1200},
            "not_before_after_us": 0, "deadline_after_us": 500 if early else 10000,
            "allow_stream_data": False}
        events.append({"monotonic_us": str(action_ns // 1000), "connection": "1", "event": "action",
            "outcome": "expired_construction_window" if early else "applied", "details": json.dumps(action)})
        window = {"schema_version": 1, "policy": policy.FRONT_RESERVE_POLICY,
            "construction_deadline_monotonic_ns": start + (target + 9000) * 1000,
            "socket_deadline_monotonic_ns": start + (target + 10000) * 1000,
            "preparation_reserve_us": 1000}
        if early:
            window.update(original_action=action, transport_output_mutated=False, socket_handoff_succeeded=False)
            row["terminal_defense_elapsed_us"] = str(target + 9500)
        else:
            shortened = deepcopy(action); shortened["deadline_after_us"] -= 1000
            window["transport_action"] = shortened
        events.append({"monotonic_us": str(action_ns // 1000), "connection": "1",
            "event": "front_padding_preparation_window",
            "outcome": "expired_before_registration" if early else "registered", "details": json.dumps(window)})
    for event in old_events:
        detail = json.loads(event["details"])
        if detail.get("type") != "slot_missed" or preexpired and detail["slot"] == 0:
            continue
        target = detail["packet"]["timestamp_us"]
        detail["production_monotonic_ns"] = start + (target + 9000) * 1000 + 603
        events.append({**event, "monotonic_us": str(detail["production_monotonic_ns"] // 1000),
                       "details": json.dumps(detail)})
        rows[detail["slot"]]["terminal_defense_elapsed_us"] = str(target + 9000)
    for packet in packets:
        ns = int(packet["monotonic_us"]) * 1000 + 603
        detail = {"type": "datagram", "endpoint": 1, "direction": "outgoing", "length": 1200,
            "timestamp_us": (ns - start) // 1000, "production_monotonic_ns": ns,
            "production_sequence": 1000 + int(packet["slot_id"])}
        events.append({"monotonic_us": str(ns // 1000), "connection": "1", "event": "observation",
            "outcome": "recorded", "details": json.dumps(detail)})
    persist(root, native, rows, packets, events)
    return native, rows, packets, events


@pytest.mark.parametrize("reasons,accepted", [((), True), (("DeadlineExpired",), True),
    (("CongestionLimited",) * 5 + ("DeadlineExpired",) * 5, True), (("DeadlineExpired",) * 11, False)])
def test_v4_keeps_exact_combined_ten_percent_budget_and_raw_misses(tmp_path, reasons, accepted):
    native, _, _, _ = fixture(tmp_path, reasons)
    metrics = fidelity._schedule_realization_metrics_from_path(tmp_path / "schedule.csv")
    assert metrics["missed_events"] == metrics["front_outgoing_padding_omissions"] == len(reasons)
    assert metrics["front_outgoing_preparation_window_events"] == 100
    assert metrics["front_outgoing_shaped_handoff_events"] == 100 - len(reasons)
    assert metrics["front_outgoing_pre_registration_omissions"] == 0
    assert eligible(native, metrics) is accepted


@pytest.mark.parametrize("offset,accepted", [(-1, False), (0, True), (1, True)])
def test_actual_nanosecond_expiry_uses_recorded_construction_cutoff(tmp_path, offset, accepted):
    native, rows, packets, events = fixture(tmp_path)
    event = next(row for row in events if json.loads(row["details"]).get("type") == "slot_missed")
    detail = json.loads(event["details"])
    detail["production_monotonic_ns"] = native["defense_start_monotonic_ns"] + 9_000_000 + offset
    event.update(monotonic_us=str(detail["production_monotonic_ns"] // 1000), details=json.dumps(detail))
    persist(tmp_path, native, rows, packets, events)
    if accepted:
        assert eligible(native, fidelity._schedule_realization_metrics_from_path(tmp_path / "schedule.csv"))
    else:
        with pytest.raises(ValueError, match="construction deadline"):
            fidelity._schedule_realization_metrics_from_path(tmp_path / "schedule.csv")


def test_registration_in_reserved_tail_is_unbuilt_and_never_gains_handoff_credit(tmp_path):
    native, _, _, _ = fixture(tmp_path, preexpired=True)
    metrics = fidelity._schedule_realization_metrics_from_path(tmp_path / "schedule.csv")
    assert metrics["front_outgoing_pre_registration_omissions"] == 1
    assert metrics["front_outgoing_padding_omissions"] == 1
    assert metrics["front_outgoing_shaped_handoff_events"] == 99
    assert eligible(native, metrics)


@pytest.mark.parametrize("offset,accepted", [(-1, True), (0, False), (1, False)])
def test_actual_socket_send_stays_strict_at_original_ten_ms_boundary(tmp_path, offset, accepted):
    native, rows, packets, events = fixture(tmp_path)
    packet = packets[0]
    slot, target = int(packet["slot_id"]), int(rows[int(packet["slot_id"])]["target_time_us"])
    ns = native["defense_start_monotonic_ns"] + (target + 10000) * 1000 + offset
    packet["monotonic_us"] = str(ns // 1000)
    rows[slot]["terminal_defense_elapsed_us"] = str((ns - native["defense_start_monotonic_ns"]) // 1000)
    event = next(row for row in events if json.loads(row["details"]).get("production_sequence") == 1000 + slot)
    detail = json.loads(event["details"])
    detail.update(production_monotonic_ns=ns, timestamp_us=(ns - native["defense_start_monotonic_ns"]) // 1000)
    event.update(monotonic_us=str(ns // 1000), details=json.dumps(detail))
    persist(tmp_path, native, rows, packets, events)
    if accepted:
        assert eligible(native, fidelity._schedule_realization_metrics_from_path(tmp_path / "schedule.csv"))
    else:
        with pytest.raises(ValueError, match="socket window"):
            fidelity._schedule_realization_metrics_from_path(tmp_path / "schedule.csv")


@pytest.mark.parametrize("mutation", ["missing-window", "duplicate-window", "reserve", "socket", "clock",
    "transport-data", "transport-deadline", "bool-deadline", "physical-proof", "physical-clock", "prepared-failure",
    "fake-handoff", "incoming-miss", "missing-credit"])
def test_v4_cannot_forge_omissions_clocks_physical_packets_or_incoming_credit(tmp_path, mutation):
    native, rows, packets, events = fixture(tmp_path)
    window_event = next(row for row in events if row["event"] == "front_padding_preparation_window")
    window = json.loads(window_event["details"])
    if mutation == "missing-window": events.remove(window_event)
    elif mutation == "duplicate-window": events.append(deepcopy(window_event))
    elif mutation == "reserve": window["preparation_reserve_us"] = 1
    elif mutation == "socket": window["socket_deadline_monotonic_ns"] += 1_000_000
    elif mutation == "clock": window_event["monotonic_us"] = "0"
    elif mutation == "transport-data": window["transport_action"]["allow_stream_data"] = True
    elif mutation == "transport-deadline": window["transport_action"]["deadline_after_us"] += 1
    elif mutation == "bool-deadline": window["construction_deadline_monotonic_ns"] = True
    elif mutation in {"physical-proof", "physical-clock"}:
        event = next(row for row in events if json.loads(row["details"]).get("type") == "datagram")
        if mutation == "physical-proof": events.remove(event)
        else:
            detail = json.loads(event["details"]); detail["production_monotonic_ns"] += 1000
            event["details"] = json.dumps(detail)
    elif mutation == "prepared-failure": events.append({"event": "front_prepared_output_failure", "outcome": "not_sent", "details": "{}"})
    elif mutation == "fake-handoff":
        packet = deepcopy(packets[0]); packet["slot_id"] = "0"; packets.append(packet)
    elif mutation == "incoming-miss": rows[100].update(satisfaction="missed", miss_reason="DeadlineExpired")
    else: rows[100]["credit_advertised_at_us"] = rows[100]["credit_advertisement_delay_us"] = ""
    window_event["details"] = json.dumps(window)
    persist(tmp_path, native, rows, packets, events)
    try:
        metrics = fidelity._schedule_realization_metrics_from_path(tmp_path / "schedule.csv")
    except ValueError:
        return
    assert not eligible(native, metrics)


@pytest.mark.parametrize("mutation", ["mutated", "success", "future", "terminal", "native-miss"])
def test_pre_registration_omission_cannot_hide_transport_or_control_mutation(tmp_path, mutation):
    native, rows, packets, events = fixture(tmp_path, preexpired=True)
    window_event = next(row for row in events if row["outcome"] == "expired_before_registration")
    window = json.loads(window_event["details"])
    if mutation == "mutated": window["transport_output_mutated"] = True
    elif mutation == "success": window["socket_handoff_succeeded"] = True
    elif mutation == "future": window["original_action"]["not_before_after_us"] = 1
    elif mutation == "terminal": rows[0]["terminal_defense_elapsed_us"] = "9501"
    else:
        stamp = native["defense_start_monotonic_ns"] + 9_500_000
        detail = {"type": "slot_missed", "endpoint": 1, "slot": 0,
            "packet": window["original_action"]["packet"], "reason": "deadline_expired",
            "production_monotonic_ns": stamp, "production_sequence": 9000}
        events.append({"monotonic_us": str(stamp // 1000), "connection": "1", "event": "observation",
            "outcome": "recorded", "details": json.dumps(detail)})
    window_event["details"] = json.dumps(window)
    persist(tmp_path, native, rows, packets, events)
    with pytest.raises(ValueError, match="FRONT"):
        fidelity._schedule_realization_metrics_from_path(tmp_path / "schedule.csv")


@pytest.mark.parametrize("field,value", [("schema_version", 3), ("schema_version", True),
    ("outgoing_construction_window_us", 9001), ("outgoing_preparation_reserve_us", 1000.0),
    ("outgoing_release_window_us", 11000), ("outgoing_omission_ratio_denominator", 9),
    ("expired_construction_target", "built-but-not-sent"), ("require_pure_padding", False)])
def test_v4_marker_is_closed_and_cannot_relax_physical_or_data_contract(field, value):
    changed = marker(); changed[field] = value
    with pytest.raises(ValueError): policy.validate_front_capture_marker(changed)


def test_prepared_v3_cannot_authorize_v4_and_v3_evidence_retains_old_rules(tmp_path):
    native, _, _, _ = fixture(tmp_path)
    prepared = {"preparation": {policy.FRONT_FIELD: policy.FRONT_RESERVE_POLICY,
        "primary_document_identity_policy": "variable-primary-document-body-v1",
        "application_response_policy": "completed-terminal-http-errors-v1",
        "qualified_chaff_origin_policy": "prepared-approved-origins-v1"}}
    policy.validate_front_source_binding(prepared, native)
    prepared["preparation"][policy.FRONT_FIELD] = policy.FRONT_WINDOW_POLICY
    with pytest.raises(ValueError, match="differs"): policy.validate_front_source_binding(prepared, native)
    original, _, _, _ = v3_fixture(tmp_path)
    metrics = fidelity._schedule_realization_metrics_from_path(tmp_path / "schedule.csv")
    assert eligible(original, metrics)
    assert "front_outgoing_preparation_window_events" not in metrics
