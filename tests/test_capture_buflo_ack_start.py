"""V2 reopens production ACKs, actual reduction clocks and strict active targets."""
from copy import deepcopy
import csv
import json

import pytest

from qcsd_lab import capture_acceptance_policy as policy
from qcsd_lab import fidelity
from tests.test_buflo_handoff import _complete_buflo_run
from tests.test_buflo_study import _incoming_credit


def startup():
    return {"schema_version": 1, "policy": policy.STARTUP_POLICY,
        "time_basis": policy.STARTUP_TIME_BASIS, "period_us": 20_000,
        "packet_size_bytes": 1_200, "armed": True, "armed_at_us": 40_000,
        "ready_at_us": 22_000, "startup_suppressed_opportunities": 2,
        "ready_endpoint": 1, "ready_stream": 0, "ready_resource_id": 14,
        "ready_request_id": 0, "request_stream_final_size": 185,
        "ack_observed_at_us": 21_000, "eligible_exact_capacity_bytes": 24_048}


def write_csv(path, fields, rows):
    with path.open("w", newline="", encoding="utf-8") as output:
        writer = csv.DictWriter(output, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def fixture(tmp_path, *, acknowledgments=None, ready_at_us=22_000,
            ack_observed_at_us=21_000, final_target_us=10_000_000):
    acknowledgments = acknowledgments or [(100, 85, True, 20_000), (0, 100, False, 21_000)]
    dto = startup()
    dto.update(ready_at_us=ready_at_us, ack_observed_at_us=ack_observed_at_us,
        armed_at_us=(ready_at_us // 20_000 + 1) * 20_000)
    dto["startup_suppressed_opportunities"] = dto["armed_at_us"] // 20_000
    outgoing = final_target_us // 20_000 + 1
    incoming = outgoing - dto["startup_suppressed_opportunities"]
    native = _complete_buflo_run(scheduled_outgoing=outgoing, scheduled_incoming=incoming, current_runner=False)
    native.update(primary_document_identity_policy="variable-primary-document-body-v1",
        application_response_policy="completed-terminal-http-errors-v1", defense_start_monotonic_ns=1_000_000,
        defense_parameters={"kind": "buflo"})
    native[policy.FIELD] = {"schema_version": 1, "source": "bound-preparation-v1",
        "policy": policy.ACK_START_POLICY, "incoming_release_window_us": 10_000,
        "period_us": 20_000, "cell_bytes": 1_200, "scientific_credit": False}
    native["resolved_configuration"]["control_interval_us"] = 5_000
    native["defense_diagnostics"].update(_incoming_credit(incoming * 1_200), buflo_incoming_startup=dto,
        buflo_schedule_stop_latched_at_us=final_target_us,
        buflo_terminal_subcell_latched_at_us=final_target_us + 501)
    native["buflo_summary"]["incoming_startup"] = dto
    native["chaff_responses"] = [{"resource_id": 14, "request_id": 0,
        "url": "https://cdn.test/chaff", "request_stream_bytes": 185,
        "expected_request_stream_bytes": 185, "outcome": "succeeded"}]
    role = {"chaff": {"resource_id": 14, "request_id": 0}}
    events = [{"monotonic_us": "2000", "connection": "1", "event": "observation", "outcome": "recorded",
        "details": json.dumps({"type": "stream_opened", "endpoint": 1, "stream": 0, "role": role,
            "production_sequence": 0, "production_monotonic_ns": 2_000_000})}]
    for sequence, (offset, count, fin, at) in enumerate(acknowledgments, 1):
        observation = {"type": "stream_data_acknowledged", "endpoint": 1,
            "stream": 0, "role": role, "offset": offset, "bytes": count, "fin": fin}
        production = 1_000_000 + at * 1_000
        common = {"monotonic_us": str(production // 1_000), "connection": "1"}
        events.append({**common, "event": "observation", "outcome": "recorded", "details": json.dumps({
            **observation, "production_sequence": sequence, "production_monotonic_ns": production})})
        events.append({**common, "event": "buflo_incoming_startup_ack", "outcome": "controller_reduced",
            "details": json.dumps({"schema_version": 1, "source": policy.STARTUP_TIME_BASIS,
                "production_sequence": sequence, "production_monotonic_ns": production,
                "controller_defense_elapsed_us": at, "observation": observation})})
    events.append({"monotonic_us": str(1_000 + ready_at_us), "connection": "1", "event": "buflo_incoming_startup_ready",
        "outcome": "armed", "details": json.dumps(dto)})
    rows = []
    fields = fidelity.SCHEDULE_PREFIX_FIELDS + fidelity.SCHEDULE_QCSD_FIELDS
    for target in range(0, final_target_us + 1, 20_000):
        for direction in ("outgoing", "incoming"):
            if direction == "incoming" and target < dto["armed_at_us"]:
                continue
            action = 1_000 + target
            row = {key: "" for key in fields}
            row.update(target_time_us=str(target), direction=direction, size="1200", connection="1",
                action_time_us=str(action), satisfaction="satisfied", slot_id=str(len(rows) + 1),
                qcsd_outcome_schema_version="3", send_policy="exact", desired_udp_bytes="1200",
                terminal_defense_elapsed_us=str(target + 500))
            if direction == "outgoing":
                row.update(observed_size="1200", observed_udp_bytes="1200")
            else:
                row.update(credit_advertised_at_us=str(action + 100), credit_advertisement_delay_us="100",
                    credit_consumed_at_us=str(action + 500), credit_consumption_delay_us="500")
            rows.append(row)
    save(tmp_path, native, events, rows)
    return native, events, rows


def save(root, native, events, rows):
    (root / "run.json").write_text(json.dumps(native), encoding="utf-8")
    write_csv(root / "events.csv", ("monotonic_us", "connection", "event", "outcome", "details"), events)
    write_csv(root / "schedule.csv", fidelity.SCHEDULE_PREFIX_FIELDS + fidelity.SCHEDULE_QCSD_FIELDS, rows)


@pytest.mark.parametrize("acknowledgments", [
    [(100, 85, True, 20_000), (0, 100, False, 21_000)],
    [(0, 185, False, 20_000), (185, 0, True, 21_000)],
    [(0, 185, True, 21_000)],
    [(100, 85, True, 20_000), (0, 100, False, 21_000), (0, 185, True, 40_000)],
])
def test_v2_full_ack_ranges_and_fin_reopen_actual_schedule_and_fidelity_output(tmp_path, acknowledgments):
    native, _, _ = fixture(tmp_path, acknowledgments=acknowledgments)
    assert policy.validate_buflo_startup_evidence(native, runner_directory=tmp_path) == startup()
    metrics = fidelity._schedule_realization_metrics_from_path(tmp_path / "schedule.csv")
    assert metrics["scheduled_incoming_events"] == 499
    assert metrics["scheduled_outgoing_events"] == 501
    assert metrics["incoming_credit_release_timing_events"] == 499
    assert metrics["buflo_incoming_startup"] == startup()
    assert metrics["incoming_credit_release_window_violations"] == 0
    assert fidelity.fidelity_eligible("buflo", native["defense_diagnostics"], sample_eligible=True,
        missed_events=0, outgoing_size_mismatches=0, schedule_metrics=metrics)
    assert fidelity.new_defense_terminal_receipts_valid(native, "buflo", runner_directory=tmp_path)
    assert not fidelity.new_defense_terminal_receipts_valid(native, "buflo")
    marker_only = deepcopy(metrics)
    del marker_only["buflo_incoming_startup_events_sha256"]
    assert not fidelity.fidelity_eligible("buflo", native["defense_diagnostics"], sample_eligible=True,
        missed_events=0, outgoing_size_mismatches=0, schedule_metrics=marker_only)


def test_v2_startup_after_global_minimum_reopens_full_ack_and_preserves_active_fidelity(tmp_path):
    native, _, _ = fixture(tmp_path, acknowledgments=[
        (100, 85, True, 10_004_000), (0, 100, False, 10_005_000)],
        ack_observed_at_us=10_005_000, ready_at_us=10_010_000, final_target_us=10_040_000)
    policy.validate_buflo_source_binding(prepared_source(), native, runner_directory=tmp_path)
    metrics = fidelity._schedule_realization_metrics_from_path(tmp_path / "schedule.csv")
    assert metrics["buflo_incoming_startup"]["armed_at_us"] == 10_020_000
    assert metrics["buflo_incoming_startup"]["startup_suppressed_opportunities"] == 501
    assert metrics["scheduled_outgoing_events"] == 503
    assert metrics["scheduled_incoming_events"] == 2
    assert 10_000_000 in metrics["target_times_us_by_direction"]["outgoing"]
    assert metrics["target_times_us_by_direction"]["incoming"] == [10_020_000, 10_040_000]
    assert native["defense_diagnostics"]["scheduled_incoming_requested_bytes"] == 2_400
    assert fidelity.fidelity_eligible("buflo", native["defense_diagnostics"], sample_eligible=True,
        missed_events=0, outgoing_size_mismatches=0, schedule_metrics=metrics)
    assert fidelity.new_defense_terminal_receipts_valid(native, "buflo", runner_directory=tmp_path)
    # The V2 exception applies only after its actual first incoming tick.
    # Default and V1 still require the global minimum in each zero-based direction.
    before_minimum = list(range(0, 10_000_000, 20_000))
    legacy = {"target_times_us_by_direction": {"outgoing": before_minimum, "incoming": before_minimum},
        "scheduled_sizes_by_direction": {"outgoing": [1200] * 500, "incoming": [1200] * 500},
        "terminal_satisfactions": {"satisfied": 1000}}
    assert not fidelity._buflo_schedule_matches_canonical_parameters(legacy)
    legacy.update(incoming_credit_release_policy={**native[policy.FIELD], "policy": policy.POLICY},
        incoming_credit_release_window_us=10_000, incoming_credit_release_original_5000us_violations=0)
    assert not fidelity._buflo_schedule_matches_canonical_parameters(legacy)


@pytest.mark.parametrize("key,value", [("armed", False), ("armed_at_us", 22_000),
    ("armed_at_us", 20_000), ("startup_suppressed_opportunities", 3), ("ready_at_us", 20_999),
    ("request_stream_final_size", 0), ("eligible_exact_capacity_bytes", 1_199),
    ("ready_stream", True), ("ack_observed_at_us", 21_000.0), ("period_us", True)])
def test_v2_false_readiness_capacity_clock_and_scalar_types_are_rejected(key, value):
    dto = startup(); dto[key] = value
    with pytest.raises(ValueError, match="startup"):
        policy.validate_buflo_startup_receipt(dto)


def test_unarmed_failure_is_honest_but_cannot_be_accepted():
    dto = startup(); dto["armed"] = False
    for key in policy._STARTUP_NULLABLE:
        dto[key] = None
    dto["startup_suppressed_opportunities"] = 7
    assert policy.validate_buflo_startup_receipt(dto, require_armed=False) == dto
    with pytest.raises(ValueError, match="unarmed"):
        policy.validate_buflo_startup_receipt(dto)
    dto["ready_at_us"] = 0
    with pytest.raises(ValueError, match="fabricated"):
        policy.validate_buflo_startup_receipt(dto, require_armed=False)


@pytest.mark.parametrize("mutation", ["missing-original", "missing-reduction", "missing-ready", "gap", "no-fin",
    "wrong-role", "wrong-sequence", "future-clock", "wrong-ack-clock", "wrong-ready", "wrong-request-size",
    "incoming-before-arm", "missing-active-cell", "outgoing-before-zero", "boolean-role", "float-ready",
    "ack-before-open"])
def test_v2_reopened_raw_evidence_rejects_forged_startup(tmp_path, mutation):
    native, events, rows = fixture(tmp_path)
    if mutation == "missing-original":
        del events[1]
    elif mutation == "missing-reduction":
        del events[2]
    elif mutation == "missing-ready":
        events.pop()
    elif mutation in {"gap", "no-fin", "wrong-role", "wrong-sequence", "future-clock", "boolean-role"}:
        index = 4 if mutation in {"gap", "future-clock"} else 2
        binding = json.loads(events[index]["details"])
        if mutation == "gap": binding["observation"]["bytes"] = 99
        elif mutation == "no-fin": binding["observation"]["fin"] = False
        elif mutation == "wrong-role": binding["observation"]["role"]["chaff"]["resource_id"] = 15
        elif mutation == "wrong-sequence": binding["production_sequence"] = 99
        elif mutation == "future-clock": binding["controller_defense_elapsed_us"] = 23_000
        else: binding["observation"]["role"]["chaff"]["request_id"] = False
        events[index]["details"] = json.dumps(binding)
        if mutation in {"gap", "no-fin", "boolean-role"}:
            original = json.loads(events[index - 1]["details"])
            original.update(binding["observation"])
            events[index - 1]["details"] = json.dumps(original)
    elif mutation == "wrong-ack-clock":
        native["buflo_summary"]["incoming_startup"]["ack_observed_at_us"] = 20_000
        events[-1]["details"] = json.dumps(native["buflo_summary"]["incoming_startup"])
    elif mutation == "wrong-ready":
        events[-1]["details"] = json.dumps({**startup(), "ready_at_us": 23_000})
    elif mutation == "float-ready":
        events[-1]["details"] = json.dumps({**startup(), "ready_at_us": 22_000.0})
    elif mutation == "ack-before-open":
        opened = json.loads(events[0]["details"])
        opened["production_sequence"] = 99
        events[0]["details"] = json.dumps(opened)
    elif mutation == "wrong-request-size":
        native["chaff_responses"][0]["expected_request_stream_bytes"] = 184
    elif mutation == "incoming-before-arm":
        next(row for row in rows if row["direction"] == "incoming")["target_time_us"] = "20000"
    elif mutation == "missing-active-cell":
        rows.pop(5)
    else:
        rows[0]["target_time_us"] = "20000"
    save(tmp_path, native, events, rows)
    with pytest.raises(ValueError):
        policy.validate_buflo_startup_evidence(native, runner_directory=tmp_path)
    with pytest.raises(ValueError):
        fidelity._schedule_realization_metrics_from_path(tmp_path / "schedule.csv")


def test_v2_preparation_selector_and_other_mode_boundaries(tmp_path):
    native, _, _ = fixture(tmp_path)
    source = {"preparation": {policy.FIELD: policy.ACK_START_POLICY,
        "primary_document_identity_policy": "variable-primary-document-body-v1",
        "application_response_policy": "completed-terminal-http-errors-v1"}}
    with pytest.raises(ValueError, match="explicit rapid"):
        policy.validate_buflo_source_binding(source, native, runner_directory=tmp_path)
    source["preparation"]["qualified_chaff_origin_policy"] = "prepared-approved-origins-v1"
    assert policy.validate_buflo_preparation_policy(source["preparation"]) == policy.ACK_START_POLICY
    native["defense_parameters"]["kind"] = "tamaraw"
    with pytest.raises(ValueError, match="native rapid contract"):
        policy.buflo_incoming_release_window(native)
    native.pop(policy.FIELD); native["buflo_summary"] = None
    native["resolved_configuration"]["defense"]["kind"] = "tamaraw"
    with pytest.raises(ValueError, match="matching prepared V2"):
        policy.validate_buflo_source_binding(source, native, runner_directory=tmp_path)
    del native["defense_diagnostics"]["buflo_incoming_startup"]
    policy.validate_buflo_source_binding(source, native, runner_directory=tmp_path)


def test_v1_and_default_keep_equal_counts_and_tick_zero(tmp_path):
    native, _, _ = fixture(tmp_path)
    native[policy.FIELD]["policy"] = policy.POLICY
    with pytest.raises(ValueError, match="lacks its V2"):
        policy.buflo_incoming_release_window(native)
    legacy = _complete_buflo_run(scheduled_outgoing=501, scheduled_incoming=501, current_runner=False)
    assert fidelity.buflo_terminal_diagnostics_valid(legacy["defense_diagnostics"])
    unequal = _complete_buflo_run(scheduled_outgoing=501, scheduled_incoming=499, current_runner=False)
    assert not fidelity.buflo_terminal_diagnostics_valid(unequal["defense_diagnostics"])
    targets = list(range(0, 10_000_001, 20_000))
    metrics = {"target_times_us_by_direction": {"outgoing": targets, "incoming": targets},
        "scheduled_sizes_by_direction": {"outgoing": [1200] * 501, "incoming": [1200] * 501},
        "terminal_satisfactions": {"satisfied": 1002}}
    assert fidelity._buflo_schedule_matches_canonical_parameters(metrics)
    metrics["target_times_us_by_direction"]["incoming"] = targets[2:]
    metrics["scheduled_sizes_by_direction"]["incoming"] = [1200] * 499
    assert not fidelity._buflo_schedule_matches_canonical_parameters(metrics)


def prepared_source():
    resources = [{"id": 0, "url": "https://page.test/", "type": "Document", "depends_on": [],
                  "known_valid": True, "chaff_priority": False},
        {"id": 14, "url": "https://cdn.test/chaff", "type": "Script", "depends_on": [0], "known_valid": True,
         "headers": [["accept", "*/*"], ["accept-language", "en-US"], ["accept-encoding", "gzip"]]}]
    return {"id": "startup-page", "resources": resources, "preparation": {
        policy.FIELD: policy.ACK_START_POLICY, "application_response_policy": "completed-terminal-http-errors-v1",
        "primary_document_identity_policy": "variable-primary-document-body-v1",
        "qualified_chaff_origin_policy": "prepared-approved-origins-v1",
        "source_url": "https://page.test/", "final_url": "https://page.test/",
        "approved_origins": ["https://page.test", "https://cdn.test"], "max_response_bytes": 1_048_576,
        "coverage_admission": {"policy": "all-approved-origins-and-rendered-resources",
            "required_resources": [{"id": row["id"], "url": row["url"]} for row in resources]},
        "expected_responses": [{"resource_id": 0, "status": 200, "bytes": 2_000, "body_sha256": "a" * 64},
            {"resource_id": 14, "status": 200, "bytes": 24_064, "body_sha256": "b" * 64}]}}


def test_v2_binds_actual_ack_to_eligible_frozen_auxiliary_resource(tmp_path):
    native, _, _ = fixture(tmp_path)
    source = prepared_source()
    policy.validate_buflo_source_binding(source, native, runner_directory=tmp_path)
    with pytest.raises(ValueError, match="reopened"):
        policy.validate_buflo_source_binding(source, native)
    source["resources"][1]["headers"] = []
    with pytest.raises(ValueError, match="eligible|unqualified"):
        policy.validate_buflo_source_binding(source, native, runner_directory=tmp_path)
