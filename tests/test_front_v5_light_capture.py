"""Engineering FrontV5 controls; no fixture grants a scientific capture credit."""
from copy import deepcopy
import json
from types import SimpleNamespace

import pytest

from qcsd_lab import capture_acceptance_policy as acceptance, capture_session as capture
from qcsd_lab import experiment, fidelity, front_fixed_configuration as fixed
from qcsd_lab.util import atomic_json, sha256_file
from tests.test_capture_front_reserve_policy import fixture as reserve_fixture, marker as reserve_marker
from tests.test_capture_front_policy import persist, eligible as front_eligible


def marker():
    value = reserve_marker()
    value.update(schema_version=5, policy=acceptance.FRONT_LIGHT_POLICY,
        n_client_packets=450, n_server_packets=600, peak_minimum_seconds=1.0,
        peak_maximum_seconds=4.0, control_interval_us=10000,
        incoming_release_window_us=10000, configuration_sha256=fixed.configuration_sha256())
    return value


def preparation():
    return {acceptance.FRONT_FIELD: acceptance.FRONT_LIGHT_POLICY,
        "primary_document_identity_policy": "variable-primary-document-body-v1",
        "application_response_policy": "completed-terminal-http-errors-v1",
        "qualified_chaff_origin_policy": "prepared-approved-origins-v1"}


def fixture(root, *, delay_us=6000, omissions=("DeadlineExpired",), preexpired=False):
    """Reuse actual-shaped action/CSV/nanosecond observations, with a new epoch."""
    native, rows, packets, events = reserve_fixture(root, omissions, preexpired=preexpired)
    native[acceptance.FRONT_FIELD] = marker()
    native["resolved_configuration"] = fixed.resolved_configuration()
    for event in events:
        if event["event"] == "front_padding_preparation_window":
            detail = json.loads(event["details"])
            detail["policy"] = acceptance.FRONT_LIGHT_POLICY
            event["details"] = json.dumps(detail)
    for row in rows:
        if row["direction"] == "incoming":
            action = int(row["action_time_us"])
            row.update(credit_advertised_at_us=str(action + delay_us),
                credit_advertisement_delay_us=str(delay_us),
                credit_consumed_at_us=str(action + max(delay_us, 0) + 500),
                credit_consumption_delay_us=str(max(delay_us, 0) + 500),
                terminal_defense_elapsed_us=str(int(row["target_time_us"]) + max(delay_us, 0) + 500))
    persist(root, native, rows, packets, events)
    return native, rows, packets, events


@pytest.mark.parametrize("delay,violations,old", [(4999, 0, 0), (5000, 0, 100),
    (9154, 0, 100), (9999, 0, 100), (10000, 100, 100), (-1, 100, 100)])
def test_source_bound_10ms_physical_credit_interval_keeps_old_5ms_measurement(tmp_path, delay, violations, old):
    native, _, _, _ = fixture(tmp_path, delay_us=delay)
    acceptance.validate_front_source_binding({"preparation": preparation()}, native)
    metrics = fidelity._schedule_realization_metrics_from_path(tmp_path / "schedule.csv")
    assert metrics["incoming_credit_release_window_us"] == 10000
    assert metrics["incoming_credit_release_window_violations"] == violations
    assert metrics["incoming_credit_release_original_5000us_violations"] == old
    assert metrics["incoming_credit_release_timing_events"] == 100
    assert metrics["front_incoming_credit_release_policy"] == marker()
    assert front_eligible(native, metrics) is (violations == 0)


@pytest.mark.parametrize("omissions,accepted", [((), True), (("DeadlineExpired",) * 10, True),
    (("CongestionLimited",) * 5 + ("DeadlineExpired",) * 6, False)])
def test_v5_keeps_all_outgoing_raw_misses_and_exact_combined_10_percent(tmp_path, omissions, accepted):
    native, _, _, _ = fixture(tmp_path, omissions=omissions)
    metrics = fidelity._schedule_realization_metrics_from_path(tmp_path / "schedule.csv")
    assert metrics["missed_events"] == len(omissions)
    assert metrics["front_outgoing_padding_omissions"] == len(omissions)
    assert metrics["front_outgoing_shaped_handoff_events"] == 100 - len(omissions)
    assert metrics["front_outgoing_preparation_window_events"] == 100
    assert front_eligible(native, metrics) is accepted


def test_v5_preexpired_padding_is_unbuilt_and_does_not_gain_a_send(tmp_path):
    native, _, _, _ = fixture(tmp_path, preexpired=True)
    metrics = fidelity._schedule_realization_metrics_from_path(tmp_path / "schedule.csv")
    assert metrics["front_outgoing_pre_registration_omissions"] == 1
    assert metrics["front_outgoing_shaped_handoff_events"] == 99
    assert front_eligible(native, metrics)


@pytest.mark.parametrize("mutation", ["source", "policy", "configuration", "counts", "peaks",
    "control", "automatic-window", "bool-value", "foreign-policy"])
def test_native_marker_and_complete_configuration_cannot_borrow_old_authority(tmp_path, mutation):
    native, _, _, _ = fixture(tmp_path)
    prepared = {"preparation": preparation()}
    if mutation == "source": prepared["preparation"][acceptance.FRONT_FIELD] = acceptance.FRONT_RESERVE_POLICY
    elif mutation == "policy": native[acceptance.FRONT_FIELD]["policy"] = acceptance.FRONT_RESERVE_POLICY
    elif mutation == "configuration": native[acceptance.FRONT_FIELD]["configuration_sha256"] = "0" * 64
    elif mutation == "counts": native["resolved_configuration"]["defense"]["n_client_packets"] = 900
    elif mutation == "peaks": native["resolved_configuration"]["defense"]["peak_maximum_seconds"] = 2.5
    elif mutation == "control": native["resolved_configuration"]["control_interval_us"] = 5000
    elif mutation == "automatic-window": native["resolved_configuration"]["automatic_receive_window"] += 1
    elif mutation == "bool-value": native["resolved_configuration"]["tail_wait_us"] = False
    else: native[acceptance.FIELD] = {"policy": acceptance.ACK_START_POLICY}
    with pytest.raises(ValueError):
        if mutation == "foreign-policy":
            persist(tmp_path, native, *fixture_parts(tmp_path))
            fidelity._schedule_realization_metrics_from_path(tmp_path / "schedule.csv")
        else:
            acceptance.validate_front_source_binding(prepared, native)


def fixture_parts(root):
    """Read only fixture CSVs, without changing the Native marker under test."""
    import csv
    def rows(path):
        with path.open(newline="") as stream:
            return list(csv.DictReader(stream))
    return rows(root / "schedule.csv"), rows(root / "packets.csv"), rows(root / "events.csv")


@pytest.mark.parametrize("mutation", ["old-window-policy", "missing-window", "physical-clock",
    "physical-proof", "socket-boundary", "credit-delay", "missing-credit", "missing-consumption"])
def test_v5_reopens_actual_windows_handoffs_and_complete_credit_ledger(tmp_path, mutation):
    native, rows, packets, events = fixture(tmp_path)
    window_event = next(event for event in events if event["event"] == "front_padding_preparation_window")
    if mutation == "old-window-policy":
        detail = json.loads(window_event["details"]); detail["policy"] = acceptance.FRONT_RESERVE_POLICY
        window_event["details"] = json.dumps(detail)
    elif mutation == "missing-window": events.remove(window_event)
    elif mutation in {"physical-clock", "physical-proof", "socket-boundary"}:
        event = next(event for event in events if json.loads(event["details"]).get("type") == "datagram")
        if mutation == "physical-proof": events.remove(event)
        else:
            detail = json.loads(event["details"])
            if mutation == "physical-clock": detail["production_monotonic_ns"] += 1000
            else:
                slot = detail["production_sequence"] - 1000
                ns = native["defense_start_monotonic_ns"] + (int(rows[slot]["target_time_us"]) + 10000) * 1000
                detail.update(production_monotonic_ns=ns,
                    timestamp_us=(ns - native["defense_start_monotonic_ns"]) // 1000)
                event["monotonic_us"] = str(ns // 1000)
                packet = next(item for item in packets if int(item["slot_id"]) == slot)
                packet["monotonic_us"] = str(ns // 1000)
                rows[slot]["terminal_defense_elapsed_us"] = str(detail["timestamp_us"])
            event["details"] = json.dumps(detail)
    elif mutation == "credit-delay": rows[100]["credit_advertisement_delay_us"] = "1"
    elif mutation == "missing-credit": rows[100]["credit_advertised_at_us"] = rows[100]["credit_advertisement_delay_us"] = ""
    else: rows[100]["credit_consumed_at_us"] = rows[100]["credit_consumption_delay_us"] = ""
    persist(tmp_path, native, rows, packets, events)
    try:
        metrics = fidelity._schedule_realization_metrics_from_path(tmp_path / "schedule.csv")
    except ValueError:
        return
    assert not front_eligible(native, metrics)


@pytest.mark.parametrize("key,value", [("schema_version", 4), ("schema_version", True),
    ("n_client_packets", 451), ("incoming_release_window_us", 10001), ("control_interval_us", 5000),
    ("configuration_sha256", "0" * 64), ("outgoing_preparation_reserve_us", 1000.0),
    ("outgoing_release_window_us", 10001), ("outgoing_omission_ratio_denominator", 9)])
def test_v5_marker_is_exact_and_does_not_relax_other_contracts(key, value):
    current = marker(); current[key] = value
    with pytest.raises(ValueError): acceptance.validate_front_capture_marker(current)


def test_capture_command_uses_only_full_frozen_config_and_retains_graph_chaff_and_caps(tmp_path):
    selected_preparation = {**preparation(), acceptance.TERMINAL_PRIMARY_FIELD: acceptance.TERMINAL_PRIMARY_POLICY}
    source = tmp_path / "prepared.json"; source.write_text(json.dumps({"preparation": selected_preparation}))
    config = tmp_path / fixed.INPUT; config.write_bytes(fixed.configuration_bytes())
    context = SimpleNamespace(limits=capture.Limits(max_response_bytes=16 * 1024 * 1024,
        timeout_seconds=120), qcsd_profile="research-1200", request_policy="as-defined",
        front_configuration_policy=fixed.POLICY, front_configuration_path=config)
    args = (tmp_path / "complete-runtime.json", tmp_path / "qualified-chaff.json", "whole-graph",
            capture.Defense("front", "front", False), 17, context, tmp_path / "out")
    command = capture._client_command(*args, application_workload_source=source)
    assert command[-2:] == ["--config", str(config)]
    assert "--profile" not in command and "--defense" not in command
    assert command[command.index("--workload") + 1] == str(args[0])
    assert command[command.index("--chaff-manifest") + 1] == str(args[1])
    assert command[command.index("--max-response-bytes") + 1] == str(16 * 1024 * 1024)
    assert command[command.index("--timeout-seconds") + 1] == "120"
    context.front_configuration_policy = None
    with pytest.raises(ValueError, match="launch selection"):
        capture._client_command(*args, application_workload_source=source)
    context.front_configuration_policy = fixed.POLICY
    context.tamaraw_configuration_policy = "rapid-tamaraw-initial8192-owned-bootstrap-v1"
    with pytest.raises(ValueError, match="mutually exclusive"):
        capture._client_command(*args, application_workload_source=source)
    del context.tamaraw_configuration_policy
    old = {"preparation": {**selected_preparation, acceptance.FRONT_FIELD: acceptance.FRONT_RESERVE_POLICY}}
    source.write_text(json.dumps(old))
    with pytest.raises(ValueError): capture._client_command(*args, application_workload_source=source)


def configuration():
    return {"campaign_sha256": "a" * 64, "profile": "research-1200",
        "request_policies": ["as-defined"], "workloads": [{"id": "page", "sha256": "b" * 64}],
        "defenses": [{"name": "front", "kind": "front", "baseline": False}],
        "limits": {"max_attempts": 3}, "application_body_identity_policy": "complete-current-application-delivery-v1",
        fixed.FIELD: fixed.POLICY, "front_configuration": "inputs/" + fixed.INPUT,
        "front_configuration_sha256": fixed.configuration_sha256()}


def test_experiment_configuration_authenticates_only_one_complete_front_condition():
    experiment._validate_configuration(configuration())


@pytest.mark.parametrize("mutation", ["missing", "digest", "path", "mode", "profile", "legacy-body", "mixed"])
def test_experiment_configuration_refuses_substitution_and_incomplete_selection(mutation):
    current = configuration()
    if mutation == "missing": del current["front_configuration_sha256"]
    elif mutation == "digest": current["front_configuration_sha256"] = "c" * 64
    elif mutation == "path": current["front_configuration"] = "inputs/other.toml"
    elif mutation == "mode": current["defenses"][0]["kind"] = "tamaraw"
    elif mutation == "profile": current["profile"] = "live"
    elif mutation == "legacy-body": del current["application_body_identity_policy"]
    else: current["tamaraw_configuration_policy"] = "rapid-tamaraw-initial8192-owned-bootstrap-v1"
    with pytest.raises(ValueError): experiment._validate_configuration(current)


def test_v4_fixture_and_failed_timing_measurement_remain_original(tmp_path):
    native, _, _, _ = reserve_fixture(tmp_path)
    metrics = fidelity._schedule_realization_metrics_from_path(tmp_path / "schedule.csv")
    assert native[acceptance.FRONT_FIELD] == reserve_marker()
    assert "front_incoming_credit_release_policy" not in metrics
    assert "incoming_credit_release_window_us" not in metrics
    assert front_eligible(native, metrics)


def collection(root):
    """Actual-shaped collection metadata with genuine validators and sealed local inputs."""
    from tests.test_campaign import _runtime_chaff_fixture
    from tests.test_primary_document_identity_policy import variable_workload
    directory = root / "samples/front"
    neqo = directory / "neqo"; neqo.mkdir(parents=True)
    native, rows, packets, events = fixture(neqo)
    prepared, responses = variable_workload()
    prepared["preparation"].update(preparation())
    prepared["preparation"][acceptance.TERMINAL_PRIMARY_FIELD] = acceptance.TERMINAL_PRIMARY_POLICY
    source = root / "inputs/page.json"; runtime = root / "inputs/page-runtime.json"
    atomic_json(source, prepared); atomic_json(runtime, {"resources": prepared["resources"]})
    config = root / "inputs" / fixed.INPUT; config.write_bytes(fixed.configuration_bytes())
    chaff, receipt = _runtime_chaff_fixture(root)
    complete_responses = deepcopy(responses[1]["responses"])
    for response in complete_responses:
        response.setdefault("response_headers", [["content-type", "application/json"]])
        response.setdefault("content_length", response["bytes"])
    native.update(responses=complete_responses, completion_status="complete", error=None,
        error_class=None, terminal_evidence_render_errors=[], seed=7, request_policy="as-defined",
        workload_hash_sha256=sha256_file(runtime), max_response_bytes=prepared["preparation"]["max_response_bytes"],
        endpoints=[{"id": 0, "origin": "https://page.test/", "negotiated_protocol": "h3"},
                   {"id": 1, "origin": "https://cdn.test/", "negotiated_protocol": "h3"}],
        application_workload_source_hash_sha256=sha256_file(source), chaff_manifest_hash_sha256=sha256_file(chaff),
        chaff_responses=[receipt], defense_diagnostics={}, client_resource_usage={"schema_version": 1, "source": "test-fixture",
            "user_cpu_seconds": 0.1, "system_cpu_seconds": 0.05, "wall_time_seconds": 0.2,
            "maximum_rss_bytes": 4096, "voluntary_context_switches": 1, "involuntary_context_switches": 0,
            "timer_wakeups": None, "timer_wakeups_unavailable_reason": "engineering fixture",
            "rapl_energy_joules": None, "rapl_unavailable_reason": "engineering fixture"})
    persist(neqo, native, rows, packets, events)
    context = SimpleNamespace(request_policy="as-defined", udp_payload_ceiling=1200,
        qcsd_profile="research-1200", limits=capture.Limits(max_response_bytes=prepared["preparation"]["max_response_bytes"]),
        front_configuration_policy=fixed.POLICY, front_configuration_path=config)
    binding = {"manifest": runtime, "chaff_manifest": chaff, "application_workload_source": source,
        "workload_id": "page", "defense": capture.Defense("front", "front", False), "seed": 7,
        "context": context}
    diagnostics = {"scheduled_incoming_requested_bytes": 120000, "scheduled_incoming_advertised_bytes": 120000,
        "scheduled_incoming_consumed_bytes": 120000, "scheduled_incoming_retired_bytes": 0,
        "scheduled_incoming_unresolved_bytes": 0}
    configured = configuration()
    configured["workloads"] = [{"id": "page", "manifest": "inputs/page.json", "sha256": sha256_file(source)}]
    sample = {"sample_id": "page-front", "workload_id": "page", "state": "accepted", "baseline": False,
        "path": "samples/front", "defense": "front", "runtime_kind": "front",
        "diagnostics": {"operationally_valid": True, "defense": diagnostics,
            "resolved_configuration": native["resolved_configuration"]}}
    return native, binding, {"configuration": configured, "samples": [sample]}, directory


def test_collection_intrinsic_and_deep_reopen_the_same_full_front_configuration(tmp_path):
    from qcsd_lab import orchestrator, verification
    from tests.test_fidelity import _primary_capture_clock
    native, binding, current, directory = collection(tmp_path)
    capture._validate_run_binding(native, **binding)
    sample = current["samples"][0]
    clock = _primary_capture_clock(); clock["valid"] = True
    sample["diagnostics"]["capture"] = clock
    result = {"views": [clock], "defense_diagnostics": sample["diagnostics"]["defense"]}
    assert orchestrator._intrinsic_fidelity_failure(sample, result, directory) is None
    verification._validate_policy_application_responses(tmp_path, current)
    assert fidelity._schedule_realization_metrics_from_path(directory / "neqo/schedule.csv")["missed_events"] == 1


@pytest.mark.parametrize("mutation", ["selection", "file", "source", "configuration", "marker", "input-hash"])
def test_collection_binding_and_deep_refuse_changed_source_file_or_campaign(tmp_path, mutation):
    from qcsd_lab import verification
    native, binding, current, directory = collection(tmp_path)
    if mutation == "selection":
        binding["context"].front_configuration_policy = None
        for key in (fixed.FIELD, "front_configuration", "front_configuration_sha256"):
            current["configuration"].pop(key)
    elif mutation == "file":
        binding["context"].front_configuration_path.write_bytes(fixed.configuration_bytes().replace(b"450", b"451"))
    elif mutation == "source":
        source = binding["application_workload_source"]
        prepared = json.loads(source.read_text()); prepared["preparation"][acceptance.FRONT_FIELD] = acceptance.FRONT_RESERVE_POLICY
        atomic_json(source, prepared)
    elif mutation == "configuration": native["resolved_configuration"]["control_interval_us"] = 5000
    elif mutation == "marker": native[acceptance.FRONT_FIELD]["configuration_sha256"] = "f" * 64
    else: native["application_workload_source_hash_sha256"] = "f" * 64
    atomic_json(directory / "neqo/run.json", native)
    with pytest.raises(ValueError): capture._validate_run_binding(native, **binding)
    if mutation != "input-hash":
        with pytest.raises(ValueError): verification._validate_policy_application_responses(tmp_path, current)


def test_optional_original_failed_front_v4_stays_uncredited():
    import os
    from pathlib import Path
    selected = os.environ.get("QCSD_FRONT_V4_FAILED_RUN_PATH")
    if not selected:
        pytest.skip("set QCSD_FRONT_V4_FAILED_RUN_PATH to the preserved genuine Source60 V4 run.json")
    run_path = Path(selected)
    expected = {"run.json": ("ea52fca92f7365be65d7e9cac492029277d67bb7b48280a8758c7952e2b85fb4", 0o600),
        "schedule.csv": ("2ece7bcec9d391642f49ddf37d912e7e80227b99b670bc0d35359b5af3651159", 0o644),
        "packets.csv": ("5505aafc2af926439a4dc4934bada027f9bb46ea9d8fd2172df7992a25217565", 0o644),
        "events.csv": ("db57faa8602b12f9735d830ab6b1026b266e1d31121a6b6dd4502459eb480209", 0o644)}
    assert run_path.name == "run.json"
    for name, (digest, mode) in expected.items():
        path = run_path.with_name(name)
        assert path.is_file() and not path.is_symlink()
        assert sha256_file(path) == digest and path.stat().st_mode & 0o7777 == mode
    native = json.loads(run_path.read_text())
    assert native["completion_status"] == "complete" and native["error_class"] is None
    assert native[acceptance.FRONT_FIELD]["policy"] == acceptance.FRONT_RESERVE_POLICY
    metrics = fidelity._schedule_realization_metrics_from_path(run_path.with_name("schedule.csv"))
    assert metrics["front_outgoing_padding_omissions"] == metrics["missed_events"] == 70
    assert metrics["front_outgoing_scheduled_events"] == 408
    assert metrics["incoming_credit_release_window_violations"] == 6
    assert metrics["incoming_credit_release_lateness_upper_bound_us_max"] == 9154
    assert "front_incoming_credit_release_policy" not in metrics
    assert not fidelity.fidelity_eligible("front", native["defense_diagnostics"], sample_eligible=True,
        missed_events=70, outgoing_size_mismatches=metrics["outgoing_size_mismatch_events"],
        schedule_metrics=metrics, resolved_configuration=native["resolved_configuration"], require_defense_activation=True)
