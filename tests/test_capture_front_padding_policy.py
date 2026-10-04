"""FRONT V2 proves a combined budget of actual pure-padding omissions.

Raw fixture acceptance exercises the policy; it is not a sealed capture or a
promotion of the preserved failed FRONT011 recording.
"""
from copy import deepcopy
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from qcsd_lab import capture_acceptance_policy as policy, fidelity
from qcsd_lab.util import sha256_file
from tests.test_capture_front_policy import (
    eligible, fixture as legacy_fixture, marker as legacy_marker, persist,
    preparation as legacy_preparation,
)


def marker():
    value = legacy_marker()
    value.update(schema_version=2, policy=policy.FRONT_PADDING_POLICY,
        outgoing_omission_reasons=["CongestionLimited", "DeadlineExpired"], require_pure_padding=True)
    del value["outgoing_omission_reason"]
    return value


def preparation():
    value = legacy_preparation()
    value[policy.FRONT_FIELD] = policy.FRONT_PADDING_POLICY
    return value


def fixture(root, reasons=("DeadlineExpired",), outgoing=100):
    native, rows, packets, events = legacy_fixture(root, omissions=len(reasons))
    native[policy.FRONT_FIELD] = marker()
    if outgoing == 200:
        template_row, template_packet = deepcopy(rows[99]), deepcopy(packets[-1])
        for index in range(100, 200):
            target, slot = index * 20000, index + 100
            row, packet = deepcopy(template_row), deepcopy(template_packet)
            row.update(target_time_us=str(target), slot_id=str(slot), action_time_us=str(target + 1000),
                terminal_defense_elapsed_us=str(target + 500))
            packet.update(slot_id=str(slot), monotonic_us=str(target + 1500), terminal_defense_elapsed_us=str(target + 500))
            rows.append(row); packets.append(packet)
    actions = []
    for index, reason in enumerate(reasons):
        row = rows[index]
        row["miss_reason"] = reason
        details = json.loads(events[index]["details"])
        details["reason"] = {"CongestionLimited": "congestion_limited", "DeadlineExpired": "deadline_expired"}.get(reason, "other")
        events[index]["details"] = json.dumps(details)
        action = {"type": "send_packet", "endpoint": 1, "slot": int(row["slot_id"]),
            "packet": deepcopy(details["packet"]), "not_before_after_us": 0,
            "deadline_after_us": 5000, "allow_stream_data": False}
        actions.append({"monotonic_us": str(native["defense_start_monotonic_ns"] // 1000 + int(row["target_time_us"])),
            "connection": "1", "event": "action", "outcome": "applied", "details": json.dumps(action)})
    events = actions + events
    persist(root, native, rows, packets, events)
    return native, rows, packets, events


@pytest.mark.parametrize("reasons,outgoing,accepted", [
    ((), 100, True), (("DeadlineExpired",), 100, True),
    (("CongestionLimited",), 100, True),
    (("CongestionLimited", "DeadlineExpired"), 100, False),
    (("CongestionLimited", "DeadlineExpired"), 200, True),
])
def test_combined_budget_retains_raw_misses_and_never_counts_them_as_full(tmp_path, reasons, outgoing, accepted):
    native, _, _, _ = fixture(tmp_path, reasons, outgoing)
    policy.validate_front_source_binding({"preparation": preparation()}, native)
    metrics = fidelity._schedule_realization_metrics_from_path(tmp_path / "schedule.csv")
    assert metrics["missed_events"] == metrics["front_outgoing_padding_omissions"] == len(reasons)
    assert metrics["front_outgoing_congestion_omissions"] == reasons.count("CongestionLimited")
    assert metrics["front_outgoing_deadline_omissions"] == reasons.count("DeadlineExpired")
    assert metrics["satisfied_events"] == outgoing + 100 - len(reasons)
    assert metrics["front_outgoing_shaped_handoff_events"] == outgoing - len(reasons)
    assert eligible(native, metrics) is accepted


def test_no_minimum_one_or_rounding_allowance(tmp_path):
    native, rows, packets, events = fixture(tmp_path)
    rows.pop(99); packets.pop()
    persist(tmp_path, native, rows, packets, events)
    metrics = fidelity._schedule_realization_metrics_from_path(tmp_path / "schedule.csv")
    assert metrics["scheduled_outgoing_events"] == 99
    assert not eligible(native, metrics)


@pytest.mark.parametrize("production_after_start_ns,accepted", [(5_000_999, False), (5_001_000, True)])
def test_expiry_proof_covers_the_full_floored_action_time_interval(tmp_path, production_after_start_ns, accepted):
    native, rows, packets, events = fixture(tmp_path)
    miss = json.loads(events[1]["details"])
    stamp = native["defense_start_monotonic_ns"] + production_after_start_ns
    miss["production_monotonic_ns"] = stamp
    events[1].update(monotonic_us=str(stamp // 1000), details=json.dumps(miss))
    persist(tmp_path, native, rows, packets, events)
    if accepted:
        assert eligible(native, fidelity._schedule_realization_metrics_from_path(tmp_path / "schedule.csv"))
    else:
        with pytest.raises(ValueError, match="expiry deadline"):
            fidelity._schedule_realization_metrics_from_path(tmp_path / "schedule.csv")


@pytest.mark.parametrize("mutation", ["missing-action", "duplicate-action", "data", "policy", "wrong-endpoint",
    "wrong-connection", "wrong-target", "short", "incoming", "bool-slot", "missing-window", "wide-window",
    "before-defense", "early-expiry", "missing-miss", "duplicate-miss", "wrong-reason", "wrong-sequence",
    "fake-handoff", "late-production"])
def test_omission_requires_exact_applied_padding_action_native_miss_and_no_handoff(tmp_path, mutation):
    native, rows, packets, events = fixture(tmp_path)
    action, miss = json.loads(events[0]["details"]), json.loads(events[1]["details"])
    if mutation == "missing-action": events.pop(0)
    elif mutation == "duplicate-action": events.append(deepcopy(events[0]))
    elif mutation == "data": action["allow_stream_data"] = True
    elif mutation == "policy": action["send_policy"] = "partial"
    elif mutation == "wrong-endpoint": action["endpoint"] = 2
    elif mutation == "wrong-connection": events[0]["connection"] = "2"
    elif mutation == "wrong-target": action["packet"]["timestamp_us"] += 1
    elif mutation == "short": action["packet"]["length"] = 1199
    elif mutation == "incoming": action["packet"]["direction"] = "incoming"
    elif mutation == "bool-slot": action["slot"] = False
    elif mutation == "missing-window": action.pop("deadline_after_us")
    elif mutation == "wide-window": action["deadline_after_us"] = 10000
    elif mutation == "before-defense": events[0]["monotonic_us"] = "999"
    elif mutation == "early-expiry":
        stamp = native["defense_start_monotonic_ns"] + 4_999_999
        miss["production_monotonic_ns"] = stamp
        events[1]["monotonic_us"] = str(stamp // 1000)
    elif mutation == "missing-miss": events.pop(1)
    elif mutation == "duplicate-miss": events.append(deepcopy(events[1]))
    elif mutation == "wrong-reason": miss["reason"] = "congestion_limited"
    elif mutation == "wrong-sequence": miss["production_sequence"] = True
    elif mutation == "fake-handoff":
        fake = deepcopy(packets[0]); fake["slot_id"] = rows[0]["slot_id"]; packets.append(fake)
    else: miss["production_monotonic_ns"] += 1000
    if mutation not in {"missing-action", "missing-miss"}:
        events[0]["details"] = json.dumps(action)
        events[1]["details"] = json.dumps(miss)
    persist(tmp_path, native, rows, packets, events)
    with pytest.raises(ValueError, match="FRONT"):
        fidelity._schedule_realization_metrics_from_path(tmp_path / "schedule.csv")


@pytest.mark.parametrize("reason", ["PacingLimited", "TimerLate", "RunAborted", "EndpointClosed", "ReceiveCreditRetired"])
def test_other_terminal_reasons_remain_rejected(tmp_path, reason):
    native, rows, packets, events = fixture(tmp_path, (reason,))
    with pytest.raises(ValueError, match="FRONT"):
        fidelity._schedule_realization_metrics_from_path(tmp_path / "schedule.csv")


@pytest.mark.parametrize("mutation", ["incoming-miss", "missing-advertisement", "missing-consumption", "partial",
    "missing-outgoing", "short-outgoing"])
def test_other_physical_cells_and_packet_accounting_remain_required(tmp_path, mutation):
    native, rows, packets, events = fixture(tmp_path)
    if mutation == "incoming-miss": rows[100].update(satisfaction="missed", miss_reason="DeadlineExpired")
    elif mutation == "missing-advertisement": rows[100]["credit_advertised_at_us"] = rows[100]["credit_advertisement_delay_us"] = ""
    elif mutation == "missing-consumption": rows[100]["credit_consumed_at_us"] = rows[100]["credit_consumption_delay_us"] = ""
    elif mutation == "partial": rows[100]["size"] = rows[100]["desired_udp_bytes"] = "1199"
    elif mutation == "missing-outgoing": packets.pop()
    else: packets[0]["observed_udp_length"] = "1199"
    persist(tmp_path, native, rows, packets, events)
    try:
        metrics = fidelity._schedule_realization_metrics_from_path(tmp_path / "schedule.csv")
    except ValueError:
        return
    assert not eligible(native, metrics)


@pytest.mark.parametrize("key,value", [("schema_version", True), ("schema_version", 1),
    ("outgoing_omission_reasons", ["DeadlineExpired", "CongestionLimited"]),
    ("outgoing_omission_reasons", ["CongestionLimited", "PacingLimited"]),
    ("outgoing_omission_reasons", ("CongestionLimited", "DeadlineExpired")),
    ("require_pure_padding", 1), ("require_pure_padding", False),
    ("outgoing_omission_ratio_denominator", 99), ("rounding", "ceil"),
    ("packet_size", 1200.0), ("paper_equivalent", True), ("scientific_credit", True)])
def test_v2_marker_has_closed_fields_and_exact_types(key, value):
    current = marker(); current[key] = value
    with pytest.raises(ValueError): policy.validate_front_capture_marker(current)


def test_v1_remains_exact_and_policies_cannot_be_cross_bound(tmp_path):
    native, rows, packets, events = fixture(tmp_path)
    native[policy.FRONT_FIELD] = legacy_marker()
    persist(tmp_path, native, rows, packets, events)
    policy.validate_front_source_binding({"preparation": legacy_preparation()}, native)
    with pytest.raises(ValueError, match="FRONT"):
        fidelity._schedule_realization_metrics_from_path(tmp_path / "schedule.csv")
    with pytest.raises(ValueError, match="differs"):
        policy.validate_front_source_binding({"preparation": preparation()}, native)
    native[policy.FRONT_FIELD] = marker()
    with pytest.raises(ValueError, match="differs"):
        policy.validate_front_source_binding({"preparation": legacy_preparation()}, native)


@pytest.mark.parametrize("value", [None, True, 2, {}, "unknown"])
def test_invalid_present_flag_never_falls_back_to_legacy(value):
    prepared = preparation(); prepared[policy.FRONT_FIELD] = value
    with pytest.raises(ValueError): policy.validate_front_preparation_policy(prepared)


def test_source_graph_parameters_and_mode_stay_bound(tmp_path):
    native, _, _, _ = fixture(tmp_path)
    for mutation in ("source", "marker", "mode", "cell", "counts", "peaks", "control", "drop"):
        current, prepared = deepcopy(native), {"preparation": preparation()}
        if mutation == "source": prepared = {}
        elif mutation == "marker": current.pop(policy.FRONT_FIELD)
        elif mutation == "mode": current["resolved_configuration"]["defense"]["kind"] = "buflo"
        elif mutation == "cell": current["resolved_configuration"]["defense"]["packet_size"] = 1199
        elif mutation == "counts": current["resolved_configuration"]["defense"]["n_client_packets"] = 901
        elif mutation == "peaks": current["resolved_configuration"]["defense"]["peak_maximum_seconds"] = 2.6
        elif mutation == "control": current["resolved_configuration"]["control_interval_us"] = 10000
        else: current["resolved_configuration"]["drop_unsatisfied_events"] = True
        with pytest.raises(ValueError): policy.validate_front_source_binding(prepared, current)
    for mode in ("none", "tamaraw", "buflo", "cs_buflo"):
        current = deepcopy(native); current.pop(policy.FRONT_FIELD)
        current["resolved_configuration"]["defense"]["kind"] = mode
        policy.validate_front_source_binding({"preparation": preparation()}, current)


def test_production_collection_group_and_deep_reopen_exact_v2_source(tmp_path):
    from qcsd_lab import capture_session, orchestrator, verification
    from qcsd_lab.util import atomic_json
    from tests.test_campaign import _runtime_chaff_fixture
    from tests.test_fidelity import _primary_capture_clock
    from tests.test_primary_document_identity_policy import variable_workload

    directory = tmp_path / "samples/front"
    neqo = directory / "neqo"; neqo.mkdir(parents=True)
    native, rows, packets, events = fixture(neqo)
    prepared, responses = variable_workload()
    prepared["preparation"].update(preparation())
    source, runtime = tmp_path / "inputs/page.json", tmp_path / "inputs/page-runtime.json"
    atomic_json(source, prepared); atomic_json(runtime, {"resources": prepared["resources"]})
    chaff, receipt = _runtime_chaff_fixture(tmp_path)
    native.update(responses=responses[1]["responses"], completion_status="complete", error=None,
        error_class=None, terminal_evidence_render_errors=[], seed=7, request_policy="as-defined",
        workload_hash_sha256=sha256_file(runtime), max_response_bytes=4096,
        application_workload_source_hash_sha256=sha256_file(source), chaff_manifest_hash_sha256=sha256_file(chaff),
        chaff_responses=[receipt], defense_diagnostics={}, client_resource_usage={"schema_version": 1,
            "source": "test-fixture", "user_cpu_seconds": 0.1, "system_cpu_seconds": 0.05,
            "wall_time_seconds": 0.2, "maximum_rss_bytes": 4096, "voluntary_context_switches": 1,
            "involuntary_context_switches": 0, "timer_wakeups": None,
            "timer_wakeups_unavailable_reason": "engineering fixture", "rapl_energy_joules": None,
            "rapl_unavailable_reason": "engineering fixture"})
    persist(neqo, native, rows, packets, events)
    binding = {"manifest": runtime, "chaff_manifest": chaff, "application_workload_source": source,
        "workload_id": "page", "defense": capture_session.Defense("front", "front", False), "seed": 7,
        "context": SimpleNamespace(request_policy="as-defined", udp_payload_ceiling=1200,
            limits=capture_session.Limits(max_response_bytes=4096))}
    capture_session._validate_run_binding(native, **binding)
    diagnostics = {"scheduled_incoming_requested_bytes": 120000, "scheduled_incoming_advertised_bytes": 120000,
        "scheduled_incoming_consumed_bytes": 120000, "scheduled_incoming_retired_bytes": 0,
        "scheduled_incoming_unresolved_bytes": 0}
    capture = _primary_capture_clock(); capture["valid"] = True
    sample = {"sample_id": "page-front", "workload_id": "page", "state": "accepted", "baseline": False,
        "path": "samples/front", "defense": "front", "runtime_kind": "front",
        "diagnostics": {"capture": capture, "operationally_valid": True, "defense": diagnostics,
            "resolved_configuration": native["resolved_configuration"]}}
    result = {"views": [capture], "defense_diagnostics": diagnostics}
    assert orchestrator._intrinsic_fidelity_failure(sample, result, directory) is None
    experiment = {"configuration": {"workloads": [{"id": "page", "manifest": "inputs/page.json",
        "sha256": sha256_file(source)}]}, "samples": [sample]}
    orchestrator._compare_group(tmp_path, experiment, [sample], SimpleNamespace(id="page", data=prepared))
    assert sample["eligible"] and sample["diagnostics"]["schedule"]["front_outgoing_deadline_omissions"] == 1
    verification._validate_policy_application_responses(tmp_path, experiment)
    stale = deepcopy(prepared); stale["preparation"][policy.FRONT_FIELD] = policy.FRONT_POLICY
    atomic_json(source, stale)
    with pytest.raises(ValueError, match="input hash"):
        verification._validate_policy_application_responses(tmp_path, experiment)
    with pytest.raises(ValueError, match="FRONT"):
        capture_session._validate_run_binding(native, **binding)
    atomic_json(source, prepared)
    native["responses"].pop()
    persist(neqo, native, rows, packets, events)
    with pytest.raises(ValueError): verification._validate_policy_application_responses(tmp_path, experiment)


def test_retained_011_expiry_proves_opportunity_without_promoting_failed_trace(tmp_path):
    relative = Path("diagnostic-rehearsals/rapid-v12-capture-canary-20261003-001/actual-poki-011/execution-root/results/")
    thesis = next((parent for parent in Path(__file__).resolve().parents if (parent / relative).is_dir()), None)
    if thesis is None:
        pytest.skip("retained local FRONT011 engineering evidence is unavailable")
    candidates = list((thesis / relative).glob("*-front/20261003T231821.576173Z/failures/*/attempt-001/neqo"))
    assert len(candidates) == 1
    original = candidates[0]
    expected = {"run.json": "ac863f8c403720e505fbe02eac6823109e154b5c1fe3a72563f0e4e9000a6d32",
        "schedule.csv": "42e08354b77b98810a119ff6254d01c28019745ec963fee3cb15acbdafcd0d83",
        "events.csv": "f91eac261405f5186493e8b93795a99823913a9bbf00f9a7f9ee53713994c431",
        "packets.csv": "f7371edadb5c274a70d8b2b11e4f386519efc45e02b5bf17af7e2da03b4fadd7"}
    assert {name: sha256_file(original / name) for name in expected} == expected
    for name in expected: (tmp_path / name).write_bytes((original / name).read_bytes())
    with pytest.raises(ValueError, match="FRONT"):
        fidelity._schedule_realization_metrics_from_path(tmp_path / "schedule.csv")
    native = json.loads((tmp_path / "run.json").read_text())
    assert len(native["responses"]) == 260 and all(row["complete"] is True for row in native["responses"])
    native[policy.FRONT_FIELD] = marker()
    (tmp_path / "run.json").write_text(json.dumps(native))
    metrics = fidelity._schedule_realization_metrics_from_path(tmp_path / "schedule.csv")
    assert metrics["scheduled_outgoing_events"] == 438
    assert metrics["missed_events"] == metrics["front_outgoing_deadline_omissions"] == 1
    assert metrics["front_outgoing_shaped_handoff_events"] == 437
    assert metrics["front_outgoing_omissions_within_bound"]
    with pytest.raises(ValueError, match="differs"):
        policy.validate_front_source_binding({"preparation": legacy_preparation()}, native)
    assert {name: sha256_file(original / name) for name in expected} == expected
