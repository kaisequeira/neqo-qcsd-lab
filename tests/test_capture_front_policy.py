"""The prospective FRONT allowance proves actual omissions without hiding them."""
from copy import deepcopy
import json
from types import SimpleNamespace

import pytest

from qcsd_lab import capture_acceptance_policy as policy, fidelity
from tests.test_capture_tamaraw_policy import fixture as base_fixture, save
from tests.test_capture_buflo_ack_start import write_csv


def marker():
    return {"schema_version": 1, "source": "bound-preparation-v1", "policy": policy.FRONT_POLICY,
        "outgoing_omission_reason": "CongestionLimited", "outgoing_omission_ratio_numerator": 1,
        "outgoing_omission_ratio_denominator": 100, "rounding": "exact-cross-multiplication-no-minimum-one",
        "packet_size": 1200, "n_client_packets": 900, "n_server_packets": 1200,
        "paper_equivalent": False, "scientific_credit": False}


def preparation():
    return {policy.FRONT_FIELD: policy.FRONT_POLICY,
        "primary_document_identity_policy": "variable-primary-document-body-v1",
        "application_response_policy": "completed-terminal-http-errors-v1",
        "qualified_chaff_origin_policy": "prepared-approved-origins-v1"}


def fixture(root, omissions=1):
    native, rows, packets = base_fixture(root, 500)
    native.pop(policy.TAMARAW_FIELD)
    native[policy.FRONT_FIELD] = marker()
    native["resolved_configuration"]["defense"] = {"kind": "front", "packet_size": 1200,
        "n_client_packets": 900, "n_server_packets": 1200, "peak_minimum_seconds": 0.1, "peak_maximum_seconds": 2.5}
    events = []
    for index in range(omissions):
        row = rows[index]
        row.update(satisfaction="missed", miss_reason="CongestionLimited", observed_size="")
        for key in fidelity.SCHEDULE_QCSD_FIELDS[1:-1]: row[key] = ""
        row["terminal_defense_elapsed_us"] = str(int(row["target_time_us"]) + 6000)
        stamp = native["defense_start_monotonic_ns"] + int(row["terminal_defense_elapsed_us"]) * 1000 + 603
        details = {"type": "slot_missed", "endpoint": 1, "slot": int(row["slot_id"]),
            "packet": {"timestamp_us": int(row["target_time_us"]), "direction": "outgoing", "length": 1200},
            "reason": "congestion_limited", "production_monotonic_ns": stamp, "production_sequence": index + 1}
        events.append({"monotonic_us": str(stamp // 1000), "connection": "1", "event": "observation",
            "outcome": "recorded", "details": json.dumps(details)})
    packets = packets[omissions:]
    persist(root, native, rows, packets, events)
    return native, rows, packets, events


def persist(root, native, rows, packets, events):
    save(root, native, rows, packets)
    write_csv(root / "events.csv", ("monotonic_us", "connection", "event", "outcome", "details"), events)


def eligible(native, metrics):
    diagnostics = {"scheduled_incoming_requested_bytes": 120000, "scheduled_incoming_advertised_bytes": 120000,
        "scheduled_incoming_consumed_bytes": 120000, "scheduled_incoming_retired_bytes": 0,
        "scheduled_incoming_unresolved_bytes": 0}
    return fidelity.fidelity_eligible("front", diagnostics, sample_eligible=True,
        missed_events=metrics["missed_events"], outgoing_size_mismatches=metrics["outgoing_size_mismatch_events"],
        schedule_metrics=metrics, resolved_configuration=native["resolved_configuration"], require_defense_activation=True)


@pytest.mark.parametrize("omissions,accepted", [(0, True), (1, True), (2, False)])
def test_front_exact_one_percent_bound_retains_original_missed_counter(tmp_path, omissions, accepted):
    native, _, _, _ = fixture(tmp_path, omissions)
    policy.validate_front_source_binding({"preparation": preparation()}, native)
    metrics = fidelity._schedule_realization_metrics_from_path(tmp_path / "schedule.csv")
    assert metrics["missed_events"] == omissions
    assert metrics["satisfied_events"] == 200 - omissions
    assert metrics["front_outgoing_congestion_omissions"] == omissions
    assert metrics["front_outgoing_shaped_handoff_events"] == 100 - omissions
    assert eligible(native, metrics) is accepted
    if omissions:
        del native[policy.FRONT_FIELD]
        (tmp_path / "run.json").write_text(json.dumps(native))
        historical = fidelity._schedule_realization_metrics_from_path(tmp_path / "schedule.csv")
        assert policy.FRONT_FIELD not in historical and not eligible(native, historical)


def test_front_small_schedule_does_not_round_one_allowed_omission_up(tmp_path):
    native, rows, packets, events = fixture(tmp_path)
    rows.pop(99); packets.pop()
    persist(tmp_path, native, rows, packets, events)
    metrics = fidelity._schedule_realization_metrics_from_path(tmp_path / "schedule.csv")
    assert metrics["scheduled_outgoing_events"] == 99
    assert not metrics["front_outgoing_omissions_within_bound"] and not eligible(native, metrics)


@pytest.mark.parametrize("mutation", ["pacing", "deadline", "abort", "incoming", "missing-event", "duplicate-event",
    "wrong-endpoint", "wrong-target", "wrong-clock", "wrong-sequence-type", "fake-missed-packet", "short", "duplicate-packet"])
def test_front_omission_requires_actual_slot_direction_reason_clock_and_complete_packets(tmp_path, mutation):
    native, rows, packets, events = fixture(tmp_path)
    if mutation in {"pacing", "deadline", "abort"}:
        rows[0]["miss_reason"] = {"pacing": "PacingLimited", "deadline": "DeadlineExpired", "abort": "RunAborted"}[mutation]
    elif mutation == "incoming": rows[0]["direction"] = "incoming"
    elif mutation == "missing-event": events.clear()
    elif mutation == "duplicate-event": events.append(deepcopy(events[0]))
    elif mutation.startswith("wrong-"):
        event = json.loads(events[0]["details"])
        if mutation == "wrong-endpoint": event["endpoint"] = 2
        elif mutation == "wrong-target": event["packet"]["timestamp_us"] = 1
        elif mutation == "wrong-clock": event["production_monotonic_ns"] += 1000
        else: event["production_sequence"] = True
        events[0]["details"] = json.dumps(event)
    elif mutation == "fake-missed-packet":
        fake = deepcopy(packets[0]); fake["slot_id"] = "0"; packets.append(fake)
    elif mutation == "short": packets[0]["observed_udp_length"] = "1199"
    else: packets.append(deepcopy(packets[0]))
    persist(tmp_path, native, rows, packets, events)
    with pytest.raises(ValueError, match="FRONT"):
        fidelity._schedule_realization_metrics_from_path(tmp_path / "schedule.csv")


@pytest.mark.parametrize("mutation", ["missing-advertisement", "missing-consumption", "partial-cell", "invalid-terminal"])
def test_front_all_incoming_physical_cells_remain_required(tmp_path, mutation):
    native, rows, packets, events = fixture(tmp_path)
    row = rows[100]
    if mutation == "missing-advertisement": row["credit_advertised_at_us"] = row["credit_advertisement_delay_us"] = ""
    elif mutation == "missing-consumption": row["credit_consumed_at_us"] = row["credit_consumption_delay_us"] = ""
    elif mutation == "partial-cell": row["size"] = row["desired_udp_bytes"] = "1199"
    else: row["terminal_defense_elapsed_us"] = "-1"
    persist(tmp_path, native, rows, packets, events)
    assert not eligible(native, fidelity._schedule_realization_metrics_from_path(tmp_path / "schedule.csv"))


@pytest.mark.parametrize("key,bad", [("schema_version", True), ("outgoing_omission_reason", "PacingLimited"),
    ("outgoing_omission_ratio_denominator", 99), ("rounding", "ceil"), ("packet_size", 1200.0), ("scientific_credit", True)])
def test_front_marker_is_closed_and_preserves_exact_types(key, bad):
    value = marker(); value[key] = bad
    with pytest.raises(ValueError): policy.validate_front_capture_marker(value)


def test_front_source_mode_and_fixed_settings_cannot_be_substituted(tmp_path):
    native, _, _, _ = fixture(tmp_path)
    for mutation in ("source", "marker", "mode", "max", "counts", "peaks", "control", "drop"):
        current, prepared = deepcopy(native), {"preparation": preparation()}
        if mutation == "source": prepared = {}
        elif mutation == "marker": del current[policy.FRONT_FIELD]
        elif mutation == "mode": current["resolved_configuration"]["defense"]["kind"] = "tamaraw"
        elif mutation == "max": current["resolved_configuration"]["max_udp_payload_size"] = 1500
        elif mutation == "counts": current["resolved_configuration"]["defense"]["n_client_packets"] = 901
        elif mutation == "peaks": current["resolved_configuration"]["defense"]["peak_minimum_seconds"] = 0.2
        elif mutation == "control": current["resolved_configuration"]["control_interval_us"] = 10000
        else: current["resolved_configuration"]["drop_unsatisfied_events"] = True
        with pytest.raises(ValueError): policy.validate_front_source_binding(prepared, current)
    for kind in ("none", "tamaraw", "buflo", "cs_buflo"):
        current = deepcopy(native); del current[policy.FRONT_FIELD]
        current["resolved_configuration"]["defense"]["kind"] = kind
        policy.validate_front_source_binding({"preparation": preparation()}, current)


@pytest.mark.parametrize("bad", [None, True, 1, {}, "unknown"])
def test_front_present_malformed_preparation_does_not_become_legacy(bad):
    current = preparation(); current[policy.FRONT_FIELD] = bad
    with pytest.raises(ValueError): policy.validate_front_preparation_policy(current)


def test_front_collection_binding_intrinsic_and_ordinary_deep_reopen_same_policy(tmp_path):
    """Exercise production gates without replacing fidelity or source validation.

    The raw CSV/JSON fixture is engineering evidence; a fresh Native capture and
    sealed whole-result verification remain required before formal publication.
    """
    from qcsd_lab import capture_session, orchestrator, verification
    from qcsd_lab.util import atomic_json, sha256_file
    from tests.test_campaign import _runtime_chaff_fixture
    from tests.test_fidelity import _primary_capture_clock
    from tests.test_primary_document_identity_policy import variable_workload

    directory = tmp_path / "samples/front"
    neqo = directory / "neqo"
    neqo.mkdir(parents=True)
    native, rows, packets, events = fixture(neqo)
    prepared, responses = variable_workload()
    prepared["preparation"].update(preparation())
    source = tmp_path / "inputs/page.json"
    runtime = tmp_path / "inputs/page-runtime.json"
    atomic_json(source, prepared)
    atomic_json(runtime, {"resources": prepared["resources"]})
    chaff, receipt = _runtime_chaff_fixture(tmp_path)
    native.update(responses=responses[1]["responses"], completion_status="complete", error=None,
        error_class=None, terminal_evidence_render_errors=[], seed=7, request_policy="as-defined",
        workload_hash_sha256=sha256_file(runtime), max_response_bytes=4096,
        application_workload_source_hash_sha256=sha256_file(source), chaff_manifest_hash_sha256=sha256_file(chaff),
        chaff_responses=[receipt], defense_diagnostics={}, client_resource_usage={"schema_version": 1, "source": "test-fixture",
            "user_cpu_seconds": 0.1, "system_cpu_seconds": 0.05, "wall_time_seconds": 0.2,
            "maximum_rss_bytes": 4096, "voluntary_context_switches": 1, "involuntary_context_switches": 0,
            "timer_wakeups": None, "timer_wakeups_unavailable_reason": "engineering fixture",
            "rapl_energy_joules": None, "rapl_unavailable_reason": "engineering fixture"})
    persist(neqo, native, rows, packets, events)
    binding = {"manifest": runtime, "chaff_manifest": chaff, "application_workload_source": source,
        "workload_id": "page", "defense": capture_session.Defense("front", "front", False), "seed": 7,
        "context": SimpleNamespace(request_policy="as-defined", udp_payload_ceiling=1200,
            limits=capture_session.Limits(max_response_bytes=4096))}
    capture_session._validate_run_binding(native, **binding)
    diagnostics = {"scheduled_incoming_requested_bytes": 120000, "scheduled_incoming_advertised_bytes": 120000,
        "scheduled_incoming_consumed_bytes": 120000, "scheduled_incoming_retired_bytes": 0,
        "scheduled_incoming_unresolved_bytes": 0}
    capture = _primary_capture_clock()
    capture["valid"] = True
    sample = {"sample_id": "page-front", "workload_id": "page", "state": "accepted", "baseline": False,
        "path": "samples/front", "defense": "front", "runtime_kind": "front",
        "diagnostics": {"capture": capture, "operationally_valid": True, "defense": diagnostics,
            "resolved_configuration": native["resolved_configuration"]}}
    result = {"views": [capture], "defense_diagnostics": diagnostics}
    assert orchestrator._intrinsic_fidelity_failure(sample, result, directory) is None
    experiment = {"configuration": {"workloads": [{"id": "page", "manifest": "inputs/page.json",
        "sha256": sha256_file(source)}]}, "samples": [sample]}
    orchestrator._compare_group(tmp_path, experiment, [sample], SimpleNamespace(id="page", data=prepared))
    assert sample["eligible"] and sample["diagnostics"]["schedule"]["missed_events"] == 1
    verification._validate_policy_application_responses(tmp_path, experiment)

    # Neither a source edit nor a stale marker can survive the ordinary reopen.
    stale = deepcopy(prepared); stale["preparation"].pop(policy.FRONT_FIELD)
    atomic_json(source, stale)
    with pytest.raises(ValueError, match="input hash"):
        verification._validate_policy_application_responses(tmp_path, experiment)
    with pytest.raises(ValueError, match="FRONT"):
        capture_session._validate_run_binding(native, **binding)
    atomic_json(source, prepared)
    stale = deepcopy(native); stale["application_workload_source_hash_sha256"] = "f" * 64
    with pytest.raises(ValueError, match="application-source"):
        capture_session._validate_run_binding(stale, **binding)
    native.pop(policy.FRONT_FIELD)
    atomic_json(neqo / "run.json", native)
    with pytest.raises(ValueError, match="FRONT"):
        verification._validate_policy_application_responses(tmp_path, experiment)
    failure = orchestrator._intrinsic_fidelity_failure(sample, result, directory)
    assert failure["type"] == "StrictDefenseFidelityFailure"
