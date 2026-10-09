"""Resource zero is a qualified chaff ID, not an absent startup identity.

The DTO below is the retained Flashscore pilot003 startup. Synthetic events
exercise its joins without replaying or promoting that failed live attempt.
Native01e accepts Some(0), requires an actual Chaff role and terminal request
ACK, and validates the selected schema-three resource against its frozen
qualification. See neqo-csdef/src/defense/buflo.rs and controller/mod.rs.
"""
from copy import deepcopy
import json

import pytest

from qcsd_lab import capture_acceptance_policy as policy, kernel_tx
from tests import test_buflo_cadence64_budget640 as cadence
from tests import test_capture_buflo_ack_start as ack


FLASH_STARTUP = {
    "schema_version": 1,
    "policy": "qualified-chaff-terminal-ack-cadence-start-v1",
    "time_basis": "native-controller-defense-elapsed-us-v1",
    "period_us": 64_000,
    "packet_size_bytes": 1_200,
    "armed": True,
    "armed_at_us": 128_000,
    "ready_at_us": 68_011,
    "startup_suppressed_opportunities": 2,
    "ready_endpoint": 0,
    "ready_stream": 80,
    "ready_resource_id": 0,
    "ready_request_id": 0,
    "request_stream_final_size": 75,
    "ack_observed_at_us": 67_936,
    "eligible_exact_capacity_bytes": 9_392,
}


def zero_evidence(tmp_path):
    """Bind the retained DTO to synthetic raw ACK and64ms schedule fixtures."""
    run, events, _ = ack.fixture(tmp_path, ready_at_us=68_011,
        ack_observed_at_us=67_936, acknowledgments=[(0, 75, True, 67_936)])
    current = cadence.native_run()
    run.update({key: current[key] for key in ("method", "defense_parameters",
        "runner_wakeup_metrics", policy.FIELD, policy.BUFLO_KERNEL_PREPARATION_FIELD)})
    run["resolved_configuration"]["defense"].update(current["resolved_configuration"]["defense"])
    run["buflo_summary"]["incoming_startup"] = deepcopy(FLASH_STARTUP)
    run["defense_diagnostics"]["buflo_incoming_startup"] = deepcopy(FLASH_STARTUP)
    run["chaff_responses"][0].update(resource_id=0, request_stream_bytes=75,
        expected_request_stream_bytes=75)
    for row in events:
        row["connection"] = "0"
        details = json.loads(row["details"])
        if row["event"] == "buflo_incoming_startup_ready":
            details = deepcopy(FLASH_STARTUP)
        else:
            observation = details.get("observation", details)
            observation.update(endpoint=0, stream=80,
                role={"chaff": {"resource_id": 0, "request_id": 0}})
        row["details"] = json.dumps(details)
    rows = [{"direction": direction, "target_time_us": str(target), "size": "1200"}
        for target in range(0, 10_048_001, 64_000) for direction in ("outgoing", "incoming")
        if direction != "incoming" or target >= FLASH_STARTUP["armed_at_us"]]
    ack.write_csv(tmp_path / "events.csv",
        ("monotonic_us", "connection", "event", "outcome", "details"), events)
    return run, events, rows


def test_retained_resource_zero_startup_and_synthetic_raw_join(tmp_path):
    assert policy.validate_buflo_startup_receipt(FLASH_STARTUP, period_us=64_000) == FLASH_STARTUP
    run, _, rows = zero_evidence(tmp_path)
    assert policy.validate_buflo_startup_evidence(run, runner_directory=tmp_path,
        schedule_rows=rows) == FLASH_STARTUP
    assert policy.buflo_incoming_release_window(run) == 32_000
    assert kernel_tx.kernel_tx_incoming_window_bound_to_run_valid(run)


def test_resource_zero_keeps_legacy20ms_cadence():
    dto = ack.startup()
    dto["ready_resource_id"] = 0
    assert policy.validate_buflo_startup_receipt(dto) == dto
    with pytest.raises(ValueError):
        policy.validate_buflo_startup_receipt(dto, period_us=64_000)
    with pytest.raises(ValueError):
        policy.validate_buflo_startup_receipt(FLASH_STARTUP)


@pytest.mark.parametrize("value", [False, True, -1, 0.0, 0.5, None, "0", 2**64])
def test_resource_zero_does_not_accept_wrong_identity_types(value):
    dto = {**FLASH_STARTUP, "ready_resource_id": value}
    with pytest.raises(ValueError, match="startup"):
        policy.validate_buflo_startup_receipt(dto, period_us=64_000)


def test_resource_identity_is_required():
    dto = deepcopy(FLASH_STARTUP)
    del dto["ready_resource_id"]
    with pytest.raises(ValueError, match="startup"):
        policy.validate_buflo_startup_receipt(dto, period_us=64_000)


@pytest.mark.parametrize("key,value", [
    ("request_stream_final_size", 0), ("eligible_exact_capacity_bytes", 1_199),
    ("ready_at_us", 67_935), ("armed_at_us", 68_011), ("armed_at_us", 64_000),
    ("startup_suppressed_opportunities", 1), ("ready_request_id", False),
    ("ready_stream", -1), ("ack_observed_at_us", 67_936.0), ("packet_size_bytes", 1_199),
])
def test_zero_resource_preserves_ack_capacity_cadence_and_fixed_cell_checks(key, value):
    dto = {**FLASH_STARTUP, key: value}
    with pytest.raises(ValueError, match="startup"):
        policy.validate_buflo_startup_receipt(dto, period_us=64_000)


@pytest.mark.parametrize("mutation", ["application-role", "missing-original", "no-fin",
    "wrong-resource", "wrong-request", "wrong-response-size", "incoming-before-arm"])
def test_zero_resource_requires_actual_chaff_ack_response_and_schedule_joins(tmp_path, mutation):
    run, events, rows = zero_evidence(tmp_path)
    if mutation == "missing-original":
        del events[1]
    elif mutation in {"application-role", "no-fin"}:
        for row in events:
            if row["event"] == "buflo_incoming_startup_ready":
                continue
            details = json.loads(row["details"])
            observation = details.get("observation", details)
            if mutation == "application-role":
                observation["role"] = {"application": {"resource_id": 0}}
            elif observation.get("type") == "stream_data_acknowledged":
                observation["fin"] = False
            row["details"] = json.dumps(details)
    elif mutation == "wrong-resource":
        run["chaff_responses"][0]["resource_id"] = 1
    elif mutation == "wrong-request":
        run["chaff_responses"][0]["request_id"] = 1
    elif mutation == "wrong-response-size":
        run["chaff_responses"][0]["expected_request_stream_bytes"] = 74
    else:
        next(row for row in rows if row["direction"] == "incoming")["target_time_us"] = "64000"
    ack.write_csv(tmp_path / "events.csv",
        ("monotonic_us", "connection", "event", "outcome", "details"), events)
    with pytest.raises(ValueError):
        policy.validate_buflo_startup_evidence(run, runner_directory=tmp_path, schedule_rows=rows)


def test_zero_resource_cannot_bypass_a_prepared_candidate_policy(tmp_path):
    run, _, rows = zero_evidence(tmp_path)
    # Historical approved-origin selection excludes navigation resource zero.
    # Resource-study schema-three selection has separate Native qualification;
    # this DTO correction must not silently change the historical selector.
    with pytest.raises(ValueError, match="unqualified"):
        policy.validate_buflo_startup_evidence(run, runner_directory=tmp_path,
            prepared=ack.prepared_source(), schedule_rows=rows)


@pytest.mark.parametrize("window", [32_000_001, 32_000_000.0, True, 10_000_000])
def test_zero_resource_keeps_exact_source_bound_incoming_deadline(window):
    run = cadence.native_run()
    run["buflo_summary"]["incoming_startup"] = deepcopy(FLASH_STARTUP)
    run["defense_diagnostics"]["buflo_incoming_startup"] = deepcopy(FLASH_STARTUP)
    run["runner_wakeup_metrics"]["buflo_kernel_tx"]["incoming_credit_release_window_ns"] = window
    assert not kernel_tx.kernel_tx_incoming_window_bound_to_run_valid(run)
