"""Prospective Tamaraw source binding preserves physical cells and old measurements."""
from copy import deepcopy
import json

import pytest

from qcsd_lab import capture_acceptance_policy as policy, fidelity
from tests.test_capture_buflo_ack_start import write_csv


def marker():
    return {"schema_version": 1, "source": "bound-preparation-v1", "policy": policy.TAMARAW_POLICY,
        "incoming_credit_semantics": policy.TAMARAW_CREDIT_SEMANTICS,
        "incoming_period_us": 5000, "outgoing_period_us": 20000,
        "cell_bytes": 1200, "padding_modulus": 100, "outgoing_release_window_us": 10000,
        "historical_outgoing_release_window_us": 5000, "paper_equivalent": False, "scientific_credit": False}


def preparation():
    return {policy.TAMARAW_FIELD: policy.TAMARAW_POLICY,
        "primary_document_identity_policy": "variable-primary-document-body-v1",
        "application_response_policy": "completed-terminal-http-errors-v1",
        "qualified_chaff_origin_policy": "prepared-approved-origins-v1"}


def native_run():
    params = {"kind": "tamaraw", "incoming_interval_us": 5000,
        "outgoing_interval_us": 20000, "packet_size": 1200, "modulo": 100}
    return {policy.TAMARAW_FIELD: marker(), "defense_parameters": None,
        "defense_start_monotonic_ns": 1_000_000,
        "primary_document_identity_policy": "variable-primary-document-body-v1",
        "application_response_policy": "completed-terminal-http-errors-v1",
        "resolved_configuration": {"schema_version": 2, "defense": params, "max_udp_payload_size": 1200,
            "control_interval_us": 5000, "drop_unsatisfied_events": False}}


def fixture(root, delay_us=6000):
    native = native_run()
    schedule, packets = [], []
    fields = fidelity.SCHEDULE_PREFIX_FIELDS + fidelity.SCHEDULE_QCSD_FIELDS
    for direction, period in (("outgoing", 20000), ("incoming", 5000)):
        for index in range(100):
            target, action = index * period, 1000 + index * period
            row = {key: "" for key in fields}
            row.update(target_time_us=str(target), direction=direction, size="1200", connection="1",
                action_time_us=str(action), satisfaction="satisfied", slot_id=str(len(schedule)),
                qcsd_outcome_schema_version="3", send_policy="exact", desired_udp_bytes="1200",
                terminal_defense_elapsed_us=str(target + (delay_us if direction == "outgoing" else 500)))
            if direction == "outgoing":
                row.update(observed_size="1200", observed_udp_bytes="1200")
                packet = {key: "" for key in fidelity.RUNNER_PACKET_FIELDS + fidelity.SCHEDULE_QCSD_FIELDS}
                packet.update(direction="outgoing", monotonic_us=str(action + delay_us), connection="1",
                    observed_udp_length="1200", scheduled_target="1200", satisfaction="satisfied",
                    slot_id=row["slot_id"], qcsd_outcome_schema_version="3", send_policy="exact",
                    desired_udp_bytes="1200", observed_udp_bytes="1200", terminal_defense_elapsed_us=row["terminal_defense_elapsed_us"])
                packets.append(packet)
            else:
                row.update(credit_advertised_at_us=str(action + 100), credit_advertisement_delay_us="100",
                    credit_consumed_at_us=str(action + 500), credit_consumption_delay_us="500")
            schedule.append(row)
    save(root, native, schedule, packets)
    return native, schedule, packets


def save(root, native, schedule, packets):
    (root / "run.json").write_text(json.dumps(native))
    write_csv(root / "schedule.csv", fidelity.SCHEDULE_PREFIX_FIELDS + fidelity.SCHEDULE_QCSD_FIELDS, schedule)
    write_csv(root / "packets.csv", fidelity.RUNNER_PACKET_FIELDS + fidelity.SCHEDULE_QCSD_FIELDS, packets)


def eligible(native, metrics):
    diagnostics = {"scheduled_incoming_requested_bytes": 120000, "scheduled_incoming_advertised_bytes": 120000,
        "scheduled_incoming_consumed_bytes": 120000, "scheduled_incoming_retired_bytes": 0,
        "scheduled_incoming_unresolved_bytes": 0}
    return fidelity.fidelity_eligible("tamaraw", diagnostics, sample_eligible=True,
        missed_events=metrics["missed_events"], outgoing_size_mismatches=metrics["outgoing_size_mismatch_events"],
        schedule_metrics=metrics, resolved_configuration=native["resolved_configuration"], require_defense_activation=True)


@pytest.mark.parametrize("delay,old,new", [(4999, 0, 0), (5000, 100, 0), (6000, 100, 0),
    (9999, 100, 0), (10000, 100, 100), (-1, 100, 100)])
def test_tamaraw_actual_physical_window_keeps_historical_lateness_and_half_open_boundaries(tmp_path, delay, old, new):
    native, _, _ = fixture(tmp_path, delay)
    policy.validate_tamaraw_source_binding({"preparation": preparation()}, native)
    metrics = fidelity._schedule_realization_metrics_from_path(tmp_path / "schedule.csv")
    assert metrics["tamaraw_outgoing_release_original_5000us_violations"] == old
    assert metrics["tamaraw_outgoing_release_window_violations"] == new
    assert eligible(native, metrics) is (new == 0)


@pytest.mark.parametrize("mutation", ["missing-advertisement", "missing-consumption", "partial-cell", "missed"])
def test_tamaraw_owned_retry_cannot_promote_missing_physical_credit_or_partial_cells(tmp_path, mutation):
    native, rows, packets = fixture(tmp_path)
    row = rows[100]
    if mutation == "missing-advertisement": row["credit_advertised_at_us"] = row["credit_advertisement_delay_us"] = ""
    elif mutation == "missing-consumption": row["credit_consumed_at_us"] = row["credit_consumption_delay_us"] = ""
    elif mutation == "partial-cell": row["size"] = row["desired_udp_bytes"] = "1199"
    else: row.update(satisfaction="missed", miss_reason="RunAborted")
    save(tmp_path, native, rows, packets)
    assert not eligible(native, fidelity._schedule_realization_metrics_from_path(tmp_path / "schedule.csv"))


@pytest.mark.parametrize("mutation", ["missing", "duplicate", "wrong-endpoint", "short", "unshaped"])
def test_tamaraw_outgoing_requires_unique_actual_packet_handoff(tmp_path, mutation):
    native, rows, packets = fixture(tmp_path)
    if mutation == "missing": packets.pop()
    elif mutation == "duplicate": packets.append(deepcopy(packets[0]))
    elif mutation == "wrong-endpoint": packets[0]["connection"] = "2"
    elif mutation == "short": packets[0]["observed_udp_length"] = "1199"
    else: packets[0]["send_policy"] = "unscheduled"
    save(tmp_path, native, rows, packets)
    with pytest.raises(ValueError, match="Tamaraw physical"):
        fidelity._schedule_realization_metrics_from_path(tmp_path / "schedule.csv")


@pytest.mark.parametrize("key,bad", [("schema_version", True), ("cell_bytes", 1200.0),
    ("incoming_credit_semantics", "slotless-reclassified"), ("outgoing_release_window_us", 20000),
    ("historical_outgoing_release_window_us", 10000), ("paper_equivalent", 0), ("scientific_credit", True)])
def test_tamaraw_marker_exact_types_and_closed_contract(key, bad):
    value = marker(); value[key] = bad
    with pytest.raises(ValueError, match="invalid Tamaraw"):
        policy.tamaraw_outgoing_window_from_policy(value)


@pytest.mark.parametrize("bad", [None, True, 10000, {}, "unknown"])
def test_tamaraw_present_malformed_preparation_is_not_legacy(bad):
    value = preparation(); value[policy.TAMARAW_FIELD] = bad
    with pytest.raises(ValueError, match="Tamaraw capture policy"):
        policy.validate_tamaraw_preparation_policy(value)


def test_tamaraw_policy_requires_prepared_source_fixed_runtime_and_actual_mode(tmp_path):
    native, rows, packets = fixture(tmp_path)
    for mutation in ("source", "missing", "mode", "control", "drop", "period", "primary", "udp-ceiling", "udp-bool"):
        current, prepared = deepcopy(native), {"preparation": preparation()}
        if mutation == "source": prepared = {}
        elif mutation == "missing": del current[policy.TAMARAW_FIELD]
        elif mutation == "mode": current["resolved_configuration"]["defense"]["kind"] = "buflo"
        elif mutation == "control": current["resolved_configuration"]["control_interval_us"] = 10000
        elif mutation == "drop": current["resolved_configuration"]["drop_unsatisfied_events"] = True
        elif mutation == "period": current["resolved_configuration"]["defense"]["outgoing_interval_us"] = 10000
        elif mutation == "udp-ceiling": current["resolved_configuration"]["max_udp_payload_size"] = 1500
        elif mutation == "udp-bool": current["resolved_configuration"]["max_udp_payload_size"] = True
        else: current["primary_document_identity_policy"] = None
        with pytest.raises(ValueError): policy.validate_tamaraw_source_binding(prepared, current)
    for kind in ("none", "front", "buflo", "cs_buflo"):
        current = deepcopy(native); del current[policy.TAMARAW_FIELD]
        current["resolved_configuration"]["defense"]["kind"] = kind
        policy.validate_tamaraw_source_binding({"preparation": preparation()}, current)
    del native[policy.TAMARAW_FIELD]
    save(tmp_path, native, rows, packets)
    metrics = fidelity._schedule_realization_metrics_from_path(tmp_path / "schedule.csv")
    assert policy.tamaraw_outgoing_release_window(native) == 5000
    assert policy.TAMARAW_FIELD not in metrics
