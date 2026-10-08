"""Prospective Lab acceptance controls; historical Native failures keep zero credit."""
from copy import deepcopy
from dataclasses import replace
import ast
import hashlib
from importlib import import_module
import json
import os
from pathlib import Path
import subprocess

import pytest
import yaml

from qcsd_lab import capture_acceptance_policy as native_policy
from qcsd_lab import capture_session as capture
from qcsd_lab import experiment, fidelity
from qcsd_lab import front_fixed_configuration as fixed
from qcsd_lab import front_incoming_acceptance as incoming
from qcsd_lab.util import atomic_json, sha256_file
from tests.test_capture_front_policy import persist
from tests.test_front_v5_light_capture import collection, configuration, fixture, fixture_parts, marker
from tests.test_rapid_mixed_implementation_target import case, epoch_case, front_epoch, front_setting, write


FIELD = "front_incoming_credit_acceptance_policy"
POLICY = "rapid-front-v5-local-credit-jitter50000us-acceptance-v1"
CONFIGURATION_SHA256 = "910c4988276b74e25cfba20bcaefdaf2f7b25032e6110711145e197ddb4d6996"
SOURCE66_COMMIT = "d92fbdc85c286fc8a19387af73c811b440539b55"
SOURCE_PAIRS = {
    "traffic": ("rapid_capture_traffic", "e6572e50928332ce97a7470c56fb9e1f6dbab018a06737eba9bd5d1d90a3f2c2",
        "b525c043eb465d51f7f75e35181e02010102b4da01a04801bb2b9f6221bcae4f"),
    "capture_plan": ("rapid_capture_plan", "4382ae162d65c3383ce87c055a64e503dd8c5c57c6c386a2eec4840675c87178",
        "3026e0687072a406160e6de25897306702dc255dcba173641a5caf43d56c2cb7"),
    "chunks": ("rapid_slot_chunks", "c0eced6275b929cb7b75ccf37e8e8105839bd64ac1566474db3e010c774622f0",
        "f69f212f29f8507246f9aa1136e169723afcf541e51dafee55c19c919fe1c06c"),
    "rolling": ("rapid_rolling_capture", "6f5fc34f6d8ee14390378200d2ebba55d4de9fc205d6788453c960739f138881",
        "d0c7b2132fc1a15809a10605567b2cc21c5d41522ddab1ae8f2c0a6b7bd1fc26"),
}
ORIGINAL_FIXED_SHA256 = "096362d42f28bad11bf698948e93d9078534718ce5f6a04ab97ff30156a78593"
CURRENT_FIXED_SHA256 = "529e4b7506b8889c01b3399e932502892cdfc634f39eb1c514b01259e0b7cf7c"


def selected_metrics(path):
    return fidelity._schedule_realization_metrics_from_path(
        path, front_incoming_credit_acceptance_policy=POLICY)


def eligible(native, metrics, selected_policy=None):
    diagnostics = {"scheduled_incoming_requested_bytes": 120000,
        "scheduled_incoming_advertised_bytes": 120000,
        "scheduled_incoming_consumed_bytes": 120000,
        "scheduled_incoming_retired_bytes": 0,
        "scheduled_incoming_unresolved_bytes": 0}
    return fidelity.fidelity_eligible("front", diagnostics, sample_eligible=True,
        missed_events=metrics["missed_events"],
        outgoing_size_mismatches=metrics["outgoing_size_mismatch_events"],
        schedule_metrics=metrics, resolved_configuration=native["resolved_configuration"],
        require_defense_activation=True,
        front_incoming_credit_acceptance_policy=selected_policy)


def campaign_kwargs():
    return {"selected_policy": POLICY, "profile": "research-1200",
        "defenses": [capture.Defense(name="front", kind="front", baseline=False)],
        "body_policy": "complete-current-application-delivery-v1",
        "front_configuration_policy": fixed.POLICY}


def lab_collection(root, delay_us=25510):
    native, binding, current, directory = collection(root)
    binding["context"].front_incoming_credit_acceptance_policy = POLICY
    current["configuration"][FIELD] = POLICY
    rows, packets, events = fixture_parts(directory / "neqo")
    for row in rows:
        if row["direction"] == "incoming":
            action = int(row["action_time_us"])
            row.update(credit_advertised_at_us=str(action + delay_us),
                credit_advertisement_delay_us=str(delay_us),
                credit_consumed_at_us=str(action + max(delay_us, 0) + 500),
                credit_consumption_delay_us=str(max(delay_us, 0) + 500),
                terminal_defense_elapsed_us=str(int(row["target_time_us"]) + max(delay_us, 0) + 500))
    persist(directory / "neqo", native, rows, packets, events)
    return native, binding, current, directory


def test_lab_policy_and_marker_are_distinct_from_the_native_condition():
    assert incoming.FIELD == FIELD and incoming.POLICY == POLICY
    assert incoming.policy({}) is None
    assert incoming.policy({FIELD: POLICY}) == POLICY
    assert incoming.validate_policy(POLICY) == POLICY
    assert incoming.marker() == {"schema_version": 1, "policy": POLICY,
        "configuration_sha256": CONFIGURATION_SHA256, "native_policy": fixed.POLICY,
        "native_window_us": 10000, "acceptance_window_us": 50000,
        "time_basis": "process-CLOCK_MONOTONIC-credit-advertisement-interval-v1",
        "paper_equivalent": False, "scientific_credit": False}
    assert marker()["control_interval_us"] == marker()["incoming_release_window_us"] == 10000
    assert marker()["configuration_sha256"] == CONFIGURATION_SHA256


@pytest.mark.parametrize("value", [None, True, False, 50000, 50000.0, float("inf"),
    float("nan"), {}, [], "unknown", fixed.POLICY, native_policy.FRONT_RESERVE_POLICY])
def test_present_lab_policy_is_a_closed_string_choice(value):
    with pytest.raises(ValueError):
        incoming.policy({FIELD: value})


def test_empty_front_selection_cannot_infer_lab_acceptance():
    assert incoming.configured({}, mode="front") is None
    current = configuration()
    assert incoming.configured(current, mode="front") is None
    with pytest.raises(ValueError):
        incoming.configured({FIELD: POLICY}, mode="front")
    current[FIELD] = POLICY
    assert incoming.configured(current, mode="front") == POLICY


@pytest.mark.parametrize("mutation", ["mode", "native-selection", "native-policy", "body",
    "tamaraw", "buflo", "qualification"])
def test_front_selection_refuses_incompatible_or_incomplete_lab_condition(mutation):
    current = configuration(); current[FIELD] = POLICY
    mode = "front"
    if mutation == "mode": mode = "tamaraw"
    elif mutation == "native-selection": current.pop(fixed.FIELD)
    elif mutation == "native-policy": current[fixed.FIELD] = native_policy.FRONT_RESERVE_POLICY
    elif mutation == "body": current.pop("application_body_identity_policy")
    elif mutation == "tamaraw": current["tamaraw_configuration_policy"] = "rapid-tamaraw-initial8192-owned-bootstrap-v1"
    elif mutation == "buflo": current["buflo_duration_policy"] = "rapid-v7-fixed-64ms-640s-duration-budget-v1"
    else: current["qualification_delivery_compatibility"] = {}
    with pytest.raises(ValueError):
        incoming.configured(current, mode=mode)


@pytest.mark.parametrize("change", [
    {"selected_policy": "unknown"}, {"profile": "live"},
    {"body_policy": "exact-prepared-application-body-v1"},
    {"front_configuration_policy": None},
    {"front_configuration_policy": native_policy.FRONT_RESERVE_POLICY},
    {"defenses": []},
    {"defenses": [capture.Defense(name="tamaraw", kind="tamaraw", baseline=False)]},
    {"defenses": [capture.Defense(name="front", kind="front", baseline=True)]},
    {"defenses": [capture.Defense(name="front", kind="front", baseline=False),
        capture.Defense(name="buflo", kind="buflo", baseline=False)]},
    {"qualification_compatibility": {}},
])
def test_lab_campaign_requires_the_complete_front_condition(change):
    incoming.validate_campaign(**campaign_kwargs())
    with pytest.raises(ValueError):
        incoming.validate_campaign(**{**campaign_kwargs(), **change})


@pytest.mark.parametrize("delay,violations50,violations10,violations5", [
    (-1, 100, 100, 100), (0, 0, 0, 0), (4999, 0, 0, 0),
    (5000, 0, 0, 100), (9999, 0, 0, 100), (10000, 0, 100, 100),
    (25510, 0, 100, 100), (49999, 0, 100, 100), (50000, 100, 100, 100),
])
def test_local_advertisement_interval_has_a_strict_separate_50ms_boundary(
        tmp_path, delay, violations50, violations10, violations5):
    native, _, _, _ = fixture(tmp_path, delay_us=delay, omissions=())
    run_bytes = (tmp_path / "run.json").read_bytes()
    original = fidelity._schedule_realization_metrics_from_path(tmp_path / "schedule.csv")
    metrics = selected_metrics(tmp_path / "schedule.csv")
    assert FIELD not in original
    assert metrics[FIELD] == incoming.marker()
    assert metrics["front_incoming_credit_acceptance_window_us"] == 50000
    assert metrics["front_incoming_credit_acceptance_timing_events"] == 100
    assert metrics["front_incoming_credit_acceptance_window_violations"] == violations50
    assert metrics["front_incoming_credit_acceptance_schedule_sha256"] == sha256_file(tmp_path / "schedule.csv")
    assert metrics["incoming_credit_release_window_us"] == 10000
    assert metrics["incoming_credit_release_window_violations"] == violations10
    assert metrics["incoming_credit_release_original_5000us_violations"] == violations5
    assert incoming.validate_schedule(metrics, selected_policy=POLICY) is (violations50 == 0)
    for key in original:
        assert metrics[key] == original[key]
    assert eligible(native, metrics, POLICY) is (violations50 == 0)
    assert eligible(native, original) is (violations10 == 0)
    assert (tmp_path / "run.json").read_bytes() == run_bytes
    assert native[native_policy.FRONT_FIELD] == marker()
    assert FIELD not in native


def test_acceptance_claims_without_explicit_selection_cannot_credit_a_native_failure(tmp_path):
    native, _, _, _ = fixture(tmp_path, delay_us=25510, omissions=())
    metrics = selected_metrics(tmp_path / "schedule.csv")
    assert metrics["incoming_credit_release_window_violations"] == 100
    assert metrics["front_incoming_credit_acceptance_window_violations"] == 0
    assert not eligible(native, metrics)
    original = fidelity._schedule_realization_metrics_from_path(tmp_path / "schedule.csv")
    original.update({key: value for key, value in metrics.items()
        if key == FIELD or key.startswith("front_incoming_credit_acceptance_")})
    assert not eligible(native, original)
    with pytest.raises(ValueError):
        fidelity._schedule_realization_metrics_from_path(
            tmp_path / "schedule.csv", front_incoming_credit_acceptance_policy="unknown")


@pytest.mark.parametrize("mutation", ["native-policy", "schema", "native-window", "control",
    "configuration-digest", "resolved-control", "resolved-tail", "missing-marker", "foreign-source",
    "lab-native-marker", "buflo-marker"])
def test_lab_run_cannot_borrow_another_native_policy_or_configuration(tmp_path, mutation):
    native, rows, packets, events = fixture(tmp_path, delay_us=25510, omissions=())
    incoming.validate_run(native, selected_policy=POLICY)
    if mutation == "native-policy": native[native_policy.FRONT_FIELD]["policy"] = native_policy.FRONT_RESERVE_POLICY
    elif mutation == "schema": native[native_policy.FRONT_FIELD]["schema_version"] = 4
    elif mutation == "native-window": native[native_policy.FRONT_FIELD]["incoming_release_window_us"] = 50000
    elif mutation == "control": native[native_policy.FRONT_FIELD]["control_interval_us"] = 50000
    elif mutation == "configuration-digest": native[native_policy.FRONT_FIELD]["configuration_sha256"] = "0" * 64
    elif mutation == "resolved-control": native["resolved_configuration"]["control_interval_us"] = 50000
    elif mutation == "resolved-tail": native["resolved_configuration"]["tail_wait_us"] = False
    elif mutation == "missing-marker": del native[native_policy.FRONT_FIELD]
    elif mutation == "foreign-source": native[native_policy.FRONT_FIELD]["source"] = "unbound-source"
    elif mutation == "lab-native-marker": native[FIELD] = incoming.marker()
    else: native[native_policy.FIELD] = {"policy": native_policy.ACK_START_POLICY}
    with pytest.raises(ValueError):
        incoming.validate_run(native, selected_policy=POLICY)
    persist(tmp_path, native, rows, packets, events)
    with pytest.raises(ValueError):
        selected_metrics(tmp_path / "schedule.csv")


@pytest.mark.parametrize("mutation", ["missing-marker", "marker-policy", "marker-window",
    "marker-native-policy", "marker-scientific-credit", "window", "timing-count", "bool-count",
    "float-count", "negative-violations", "missing-digest", "malformed-digest"])
def test_selected_lab_rejects_incomplete_or_mutated_acceptance_metrics(tmp_path, mutation):
    native, _, _, _ = fixture(tmp_path, delay_us=25510, omissions=())
    metrics = deepcopy(selected_metrics(tmp_path / "schedule.csv"))
    if mutation == "missing-marker": del metrics[FIELD]
    elif mutation == "marker-policy": metrics[FIELD]["policy"] = fixed.POLICY
    elif mutation == "marker-window": metrics[FIELD]["acceptance_window_us"] = 50001
    elif mutation == "marker-native-policy": metrics[FIELD]["native_policy"] = native_policy.FRONT_RESERVE_POLICY
    elif mutation == "marker-scientific-credit": metrics[FIELD]["scientific_credit"] = True
    elif mutation == "window": metrics["front_incoming_credit_acceptance_window_us"] = 10000
    elif mutation == "timing-count": metrics["front_incoming_credit_acceptance_timing_events"] = 99
    elif mutation == "bool-count": metrics["front_incoming_credit_acceptance_timing_events"] = True
    elif mutation == "float-count": metrics["front_incoming_credit_acceptance_timing_events"] = 100.0
    elif mutation == "negative-violations": metrics["front_incoming_credit_acceptance_window_violations"] = -1
    elif mutation == "missing-digest": del metrics["front_incoming_credit_acceptance_schedule_sha256"]
    else: metrics["front_incoming_credit_acceptance_schedule_sha256"] = "x" * 64
    assert not incoming.validate_schedule(metrics, selected_policy=POLICY)
    assert not eligible(native, metrics, POLICY)


def test_lab_selection_does_not_relax_outgoing_omissions_or_credit_completeness(tmp_path):
    native, _, _, _ = fixture(tmp_path, delay_us=25510, omissions=("DeadlineExpired",) * 11)
    metrics = selected_metrics(tmp_path / "schedule.csv")
    assert metrics["front_outgoing_padding_omissions"] == metrics["missed_events"] == 11
    assert metrics["front_incoming_credit_acceptance_window_violations"] == 0
    assert not eligible(native, metrics, POLICY)
    native, rows, packets, events = fixture(tmp_path, delay_us=25510, omissions=())
    rows[100]["credit_consumed_at_us"] = rows[100]["credit_consumption_delay_us"] = ""
    persist(tmp_path, native, rows, packets, events)
    try:
        metrics = selected_metrics(tmp_path / "schedule.csv")
    except ValueError:
        return
    assert not eligible(native, metrics, POLICY)


def test_experiment_acceptance_selection_is_explicit_and_keeps_native_input_identity():
    current = configuration()
    current[FIELD] = POLICY
    experiment._validate_configuration(current)
    assert current[fixed.FIELD] == fixed.POLICY
    assert current["front_configuration_sha256"] == CONFIGURATION_SHA256


@pytest.mark.parametrize("mutation", ["unknown", "native-selection", "mode", "mixed-mode", "digest", "body"])
def test_experiment_refuses_unbound_lab_acceptance_selection(mutation):
    current = configuration(); current[FIELD] = POLICY
    if mutation == "unknown": current[FIELD] = "unknown"
    elif mutation == "native-selection": current.pop(fixed.FIELD)
    elif mutation == "mode": current["defenses"][0]["kind"] = "tamaraw"
    elif mutation == "mixed-mode": current["defenses"].append({"name": "buflo", "kind": "buflo", "baseline": False})
    elif mutation == "digest": current["front_configuration_sha256"] = "0" * 64
    else: current.pop("application_body_identity_policy")
    with pytest.raises(ValueError):
        experiment._validate_configuration(current)


def test_capture_and_deep_verification_use_lab_selection_and_reopen_the_frozen_config(tmp_path):
    from qcsd_lab import verification
    native, binding, current, directory = lab_collection(tmp_path)
    prepared_path = binding["application_workload_source"]
    prepared_bytes = prepared_path.read_bytes()
    capture._validate_run_binding(native, **binding)
    verification._validate_policy_application_responses(tmp_path, current)
    metrics = selected_metrics(directory / "neqo/schedule.csv")
    assert metrics["incoming_credit_release_window_violations"] == 100
    assert metrics["front_incoming_credit_acceptance_window_violations"] == 0
    assert json.loads(prepared_bytes)["preparation"][native_policy.FRONT_FIELD] == fixed.POLICY
    assert FIELD not in json.loads(prepared_bytes)["preparation"]
    assert prepared_path.read_bytes() == prepared_bytes
    assert native[native_policy.FRONT_FIELD] == marker()


def test_lab_selection_keeps_the_same_complete_native_launch_command(tmp_path):
    _, binding, _, _ = lab_collection(tmp_path)
    args = (binding["manifest"], binding["chaff_manifest"], "whole-graph", binding["defense"],
        binding["seed"], binding["context"], tmp_path / "out")
    selected = capture._client_command(*args,
        application_workload_source=binding["application_workload_source"])
    binding["context"].front_incoming_credit_acceptance_policy = None
    original = capture._client_command(*args,
        application_workload_source=binding["application_workload_source"])
    assert selected == original
    assert selected[-2:] == ["--config", str(binding["context"].front_configuration_path)]
    assert selected[selected.index("--workload") + 1] == str(binding["manifest"])
    assert selected[selected.index("--chaff-manifest") + 1] == str(binding["chaff_manifest"])


def test_intrinsic_capture_requires_explicit_lab_selection_for_native_late_credits(tmp_path):
    from qcsd_lab import orchestrator
    from tests.test_fidelity import _primary_capture_clock
    _, _, current, directory = lab_collection(tmp_path)
    sample = current["samples"][0]
    clock = _primary_capture_clock(); clock["valid"] = True
    sample["diagnostics"]["capture"] = clock
    result = {"views": [clock], "defense_diagnostics": sample["diagnostics"]["defense"]}
    failure = orchestrator._intrinsic_fidelity_failure(sample, deepcopy(result), directory)
    assert failure["type"] == "StrictDefenseFidelityFailure"
    assert failure["details"][0]["schedule"]["incoming_credit_release_window_violations"] == 100
    assert orchestrator._intrinsic_fidelity_failure(sample, result, directory,
        front_incoming_credit_acceptance_policy=POLICY) is None


def test_intrinsic_capture_recomputes_actual_50ms_failure_despite_stored_claims(tmp_path):
    from qcsd_lab import orchestrator
    from tests.test_fidelity import _primary_capture_clock
    _, _, current, directory = lab_collection(tmp_path, delay_us=50000)
    sample = current["samples"][0]
    clock = _primary_capture_clock(); clock["valid"] = True
    sample["diagnostics"]["capture"] = clock
    claims = selected_metrics(directory / "neqo/schedule.csv")
    assert claims["front_incoming_credit_acceptance_window_violations"] == 100
    claims["front_incoming_credit_acceptance_window_violations"] = 0
    result = {"views": [clock], "defense_diagnostics": sample["diagnostics"]["defense"],
        "schedule_realization": claims}
    failure = orchestrator._intrinsic_fidelity_failure(sample, result, directory,
        front_incoming_credit_acceptance_policy=POLICY)
    assert failure["type"] == "StrictDefenseFidelityFailure"
    recomputed = failure["details"][0]["schedule"]
    assert recomputed["front_incoming_credit_acceptance_window_violations"] == 100
    assert recomputed["front_incoming_credit_acceptance_schedule_sha256"] == sha256_file(directory / "neqo/schedule.csv")


@pytest.mark.parametrize("mutation", ["source", "file", "resolved-config", "native-marker", "lab-selection"])
def test_capture_and_deep_verification_refuse_changed_native_condition(tmp_path, mutation):
    from qcsd_lab import verification
    native, binding, current, directory = lab_collection(tmp_path)
    if mutation == "source":
        source = binding["application_workload_source"]
        prepared = json.loads(source.read_text())
        prepared["preparation"][native_policy.FRONT_FIELD] = native_policy.FRONT_RESERVE_POLICY
        atomic_json(source, prepared)
    elif mutation == "file":
        binding["context"].front_configuration_path.write_bytes(
            fixed.configuration_bytes().replace(b"n_client_packets = 450", b"n_client_packets = 451"))
    elif mutation == "resolved-config": native["resolved_configuration"]["control_interval_us"] = 50000
    elif mutation == "native-marker": native[native_policy.FRONT_FIELD]["incoming_release_window_us"] = 50000
    else:
        binding["context"].front_incoming_credit_acceptance_policy = "unknown"
        current["configuration"][FIELD] = "unknown"
    atomic_json(directory / "neqo/run.json", native)
    with pytest.raises(ValueError):
        capture._validate_run_binding(native, **binding)
    with pytest.raises(ValueError):
        verification._validate_policy_application_responses(tmp_path, current)


def condition_fixture(root):
    native, _, _, _ = fixture(root, delay_us=25510, omissions=())
    native.update(application_response_policy="completed-terminal-http-errors-v1",
        primary_document_identity_policy="variable-primary-document-body-v1")
    return configuration(), native


def test_fixed_target_identity_adds_only_the_explicit_lab_condition(tmp_path):
    from qcsd_lab import rapid_fixed_condition_target as target
    current, native = condition_fixture(tmp_path)
    original = target.condition_identity(current, native, "front")
    assert FIELD not in original and FIELD not in original["capture_policies"]
    current[FIELD] = POLICY
    selected = target.condition_identity(current, native, "front")
    assert selected[FIELD] == POLICY
    assert FIELD not in selected["capture_policies"]
    assert selected["capture_policies"] == original["capture_policies"]
    assert selected["capture_policies"][native_policy.FRONT_FIELD] == marker()
    assert {key: value for key, value in selected.items() if key != FIELD} == original
    encode = lambda value: json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    assert hashlib.sha256(encode(selected)).hexdigest() != hashlib.sha256(encode(original)).hexdigest()
    current.pop(FIELD)
    assert target.condition_identity(current, native, "front") == original
    assert FIELD not in native and native[native_policy.FRONT_FIELD] == marker()


@pytest.mark.parametrize("mutation", ["null", "bool", "unknown", "non-front", "missing-native", "changed-native",
    "missing-configuration-digest", "wrong-configuration-digest"])
def test_fixed_target_refuses_malformed_or_non_front_lab_condition(tmp_path, mutation):
    from qcsd_lab import rapid_fixed_condition_target as target
    current, native = condition_fixture(tmp_path)
    current[FIELD] = POLICY; mode = "front"
    if mutation == "null": current[FIELD] = None
    elif mutation == "bool": current[FIELD] = True
    elif mutation == "unknown": current[FIELD] = "unknown"
    elif mutation == "non-front":
        mode = "buflo"
        current["defenses"] = [{"name": "buflo", "kind": "buflo", "baseline": False}]
    elif mutation == "missing-native": current.pop(fixed.FIELD)
    elif mutation == "changed-native": native["resolved_configuration"]["control_interval_us"] = 50000
    elif mutation == "missing-configuration-digest": current.pop("front_configuration_sha256")
    else: current["front_configuration_sha256"] = "0" * 64
    with pytest.raises(ValueError):
        target.condition_identity(current, native, mode)


def traffic_plan(selected=True):
    current = configuration()
    current.update(study_version=6,
        static_capture_amendment={"path": "/synthetic/zero-credit", "sha256": "0" * 64},
        campaigns=[{"mode": "front"}])
    if selected: current[FIELD] = POLICY
    return current


def test_plan_and_canary_files_freeze_native_config_and_selected_lab_source():
    from qcsd_lab import rapid_capture_traffic as traffic
    helper_key = "front_incoming_credit_acceptance_source_sha256"
    original = traffic.plan_files(traffic_plan(selected=False))
    selected = traffic.plan_files(traffic_plan())
    canary = traffic.canary_files(traffic_plan(), "front")
    assert selected == canary
    assert helper_key not in original
    assert selected[helper_key] == (incoming.SOURCE_PATH, sha256_file(Path(incoming.__file__)))
    assert selected["front_configuration_sha256"] == (fixed.CONFIGURATION_PATH, CONFIGURATION_SHA256)
    assert selected["front_configuration_provenance_sha256"] == (fixed.PROVENANCE_PATH, fixed.PROVENANCE_SHA256)
    assert {key: value for key, value in selected.items() if key != helper_key} == original
    assert traffic.canary_files(traffic_plan(selected=False), "front") == original


@pytest.mark.parametrize("mutation", ["unknown", "missing-native", "body", "mixed-mode"])
def test_canary_traffic_refuses_unbound_or_mixed_lab_selection(mutation):
    from qcsd_lab import rapid_capture_traffic as traffic
    current = traffic_plan()
    if mutation == "unknown": current[FIELD] = "unknown"
    elif mutation == "missing-native": current.pop(fixed.FIELD)
    elif mutation == "body": current.pop("application_body_identity_policy")
    else: current["campaigns"] = [{"mode": "front"}, {"mode": "buflo"}]
    with pytest.raises(ValueError):
        traffic.canary_files(current, "front")
    if mutation != "mixed-mode":
        with pytest.raises(ValueError):
            traffic.plan_files(current)


def rendering_fixture(root):
    from qcsd_lab import rapid_capture_plan as plan
    from qcsd_lab.supplied_static_admission import capture_limits
    _, binding, _, _ = collection(root)
    site = plan.Site(candidate_id="page", workload_id="page",
        workload_sha256=sha256_file(binding["application_workload_source"]),
        primary_origin="https://page.test", qualification_set="qualified",
        qualification_set_manifest_sha256=sha256_file(binding["chaff_manifest"]))
    lane = plan.Lane("formal", 1, 1, "front", plan._campaign_name("formal", 1, 1, "front", 1, 6),
        ("page",), 4, "qualified", 1, 6)
    options = {"static_capture_limits": capture_limits(16 * 1024 * 1024, 64),
        "application_body_identity_policy": "complete-current-application-delivery-v1",
        "front_configuration_policy": fixed.POLICY}
    return (site,), lane, options


def test_lane_campaign_retains_exact_selected_and_absent_lab_field(tmp_path):
    from qcsd_lab import rapid_capture_plan as plan
    sites, lane, options = rendering_fixture(tmp_path)
    original = yaml.safe_load(plan.render_lane_campaign(lane, sites, **options))
    selected = yaml.safe_load(plan.render_lane_campaign(lane, sites, **options,
        front_incoming_credit_acceptance_policy=POLICY))
    assert FIELD not in original
    assert selected[FIELD] == POLICY and selected[fixed.FIELD] == fixed.POLICY
    assert {key: value for key, value in selected.items() if key != FIELD} == original
    with pytest.raises(ValueError):
        plan.render_lane_campaign(lane, sites, **options,
            front_incoming_credit_acceptance_policy="unknown")


def test_chunk_and_rolling_render_forward_the_frozen_selection_and_keep_other_modes_absent(tmp_path):
    from qcsd_lab import rapid_capture_plan as plan, rapid_rolling_capture as rolling
    from qcsd_lab import rapid_slot_chunks as chunks
    sites, lane, options = rendering_fixture(tmp_path)
    current = configuration()
    current.update(capture_limits=options["static_capture_limits"])
    absent_options = chunks._render_options(current)
    current[FIELD] = POLICY
    selected_options = chunks._render_options(current)
    assert absent_options[FIELD] is None and selected_options[FIELD] == POLICY
    chunk = chunks.ChunkLane("formal", 1, 1, "front", "", ("page",), 2, "qualified", 4, "a" * 64)
    chunk = replace(chunk, campaign_name=chunks.name(chunk, 1))
    original = yaml.safe_load(plan.render_lane_campaign(chunk, sites, **absent_options))
    selected = yaml.safe_load(plan.render_lane_campaign(chunk, sites, **selected_options))
    assert selected[FIELD] == POLICY and FIELD not in original
    assert {key: value for key, value in selected.items() if key != FIELD} == original
    assert selected["workloads"] == {"page": 2}
    other_chunk = replace(chunk, mode="buflo", campaign_name="")
    other_chunk = replace(other_chunk, campaign_name=chunks.name(other_chunk, 1))
    other = yaml.safe_load(plan.render_lane_campaign(other_chunk, sites, **selected_options))
    assert FIELD not in other and fixed.FIELD not in other
    policy = {"contract": rolling.STATIC_CONTRACT, "capture_limits": options["static_capture_limits"]}
    rolling_options = {"application_body_identity_policy": options["application_body_identity_policy"],
        "front_configuration_policy": fixed.POLICY}
    original_rolling = yaml.safe_load(rolling._render_campaign(lane, sites, policy, **rolling_options))
    selected_rolling = yaml.safe_load(rolling._render_campaign(lane, sites, policy, **rolling_options,
        front_incoming_credit_acceptance_policy=POLICY))
    assert selected_rolling == yaml.safe_load(plan.render_lane_campaign(lane, sites, **options,
        front_incoming_credit_acceptance_policy=POLICY))
    assert FIELD not in original_rolling
    other_lane = replace(lane, mode="buflo",
        campaign_name=plan._campaign_name("formal", 1, 1, "buflo", 1, 6))
    other_rolling = yaml.safe_load(rolling._render_campaign(other_lane, sites, policy, **rolling_options,
        front_incoming_credit_acceptance_policy=POLICY))
    assert FIELD not in other_rolling and fixed.FIELD not in other_rolling


def authenticated_source(path, expected_sha256):
    assert path.is_file() and not path.is_symlink()
    assert path.stat().st_mode & 0o7777 == 0o644
    raw = path.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == expected_sha256
    return raw


def predecessor_source(module, digest):
    selected = os.environ.get("QCSD_FRONT50_PREDECESSOR_SOURCE_ROOT")
    if selected:
        return authenticated_source(Path(selected) / "src/qcsd_lab" / (module + ".py"), digest)
    # A normal clone carries its authentic predecessor in Git history; it does
    # not need the author's checkout or an absolute machine path.
    root = Path(__file__).resolve().parents[1]
    result = subprocess.run(["git", "-C", str(root), "show",
        SOURCE66_COMMIT + ":src/qcsd_lab/" + module + ".py"],
        capture_output=True, check=False)
    assert result.returncode == 0, "historical reader controls require the repository's full Git history"
    assert hashlib.sha256(result.stdout).hexdigest() == digest
    return result.stdout


def source_pair(role):
    from qcsd_lab import rapid_mixed_implementation_target as mixed
    module, old_sha, new_sha = SOURCE_PAIRS[role]
    assert mixed._FRONT_INCOMING_ACCEPTANCE_INVERSES[role][:2] == (old_sha, new_sha)
    original = predecessor_source(module, old_sha)
    current = authenticated_source(Path(import_module("qcsd_lab." + module).__file__), new_sha)
    return original, current


@pytest.mark.parametrize("role", list(SOURCE_PAIRS))
def test_registered_front50_source_inverse_restores_whole_source66_bytes(role):
    from qcsd_lab import rapid_mixed_implementation_target as mixed
    original, current = source_pair(role)
    assert mixed.front_incoming_acceptance_source_projection(role, original) == original
    assert mixed.front_incoming_acceptance_source_projection(role, current) == original
    for changed in (current + b"# unregistered change\n", original + b"# unregistered change\n"):
        with pytest.raises(ValueError):
            mixed.front_incoming_acceptance_source_projection(role, changed)
    with pytest.raises(ValueError):
        mixed.front_incoming_acceptance_source_projection("not-registered", current)
    with pytest.raises(ValueError):
        mixed.front_incoming_acceptance_source_projection(role, bytearray(current))


@pytest.mark.parametrize("role", list(SOURCE_PAIRS))
def test_registered_legacy_reader_requires_authenticated_bytes_and_typed_full_modes(tmp_path, role):
    from qcsd_lab import rapid_fixed_condition_target as target, rapid_mixed_implementation_target as mixed
    original, current = source_pair(role)
    before_path = tmp_path / (role + "-before.py")
    current_path = tmp_path / (role + "-current.py")
    before_path.write_bytes(original); before_path.chmod(0o644)
    current_path.write_bytes(current); current_path.chmod(0o644)
    before, after = target.reference(before_path), target.reference(current_path)
    assert mixed.compatible_legacy_reader(role, before, after)
    for path in (before_path, current_path):
        path.chmod(0o600)
        with pytest.raises(ValueError, match="mode"):
            mixed.compatible_legacy_reader(role, target.reference(before_path), target.reference(current_path))
        path.chmod(0o644)
    malformed = {**before, "mode": True}
    with pytest.raises(ValueError):
        mixed.compatible_legacy_reader(role, malformed, after)
    wrong_role = "chunks" if role != "chunks" else "traffic"
    assert not mixed.compatible_legacy_reader(wrong_role, before, after)
    current_path.write_bytes(current + b"# unregistered current bytes\n")
    with pytest.raises(ValueError):
        mixed.compatible_legacy_reader(role, before, after)
    assert not mixed.compatible_legacy_reader(role, before, target.reference(current_path))
    current_path.write_bytes(current)
    before_path.write_bytes(original + b"# unregistered predecessor bytes\n")
    assert not mixed.compatible_legacy_reader(role, target.reference(before_path), target.reference(current_path))


def function_bytes(raw, name):
    nodes = [node for node in ast.parse(raw).body if isinstance(node, ast.FunctionDef) and node.name == name]
    assert len(nodes) == 1
    node = nodes[0]
    return b"".join(raw.splitlines(keepends=True)[node.lineno - 1:node.end_lineno])


def independent_science_fingerprint(raw, target):
    tree = ast.parse(raw)
    compatible_helpers = set(target._READER_COMPATIBILITY_HELPERS["target"])
    assert "_front_incoming_acceptance_condition_projection" in compatible_helpers
    assert "_front_incoming_acceptance" in compatible_helpers
    tree.body = [node for node in tree.body
        if not (isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in compatible_helpers)
        and not (isinstance(node, ast.Assign) and any(isinstance(name, ast.Name)
            and name.id == "_READER_COMPATIBILITY_HELPERS" for name in node.targets))]
    return hashlib.sha256(ast.dump(tree, include_attributes=False).encode()).hexdigest()


def fixed_source_pair():
    from qcsd_lab import rapid_fixed_condition_target as target
    original = predecessor_source("rapid_fixed_condition_target", ORIGINAL_FIXED_SHA256)
    current = authenticated_source(Path(target.__file__), CURRENT_FIXED_SHA256)
    return original, current


def test_whole_target_projection_restores_exact_original_condition_and_science_fingerprint():
    from qcsd_lab import rapid_fixed_condition_target as target
    original, current = fixed_source_pair()
    restored = target._front_incoming_acceptance_condition_projection(current)
    assert target._front_incoming_acceptance_condition_projection(original) == original
    assert function_bytes(restored, "condition_identity") == function_bytes(original, "condition_identity")
    assert independent_science_fingerprint(restored, target) == independent_science_fingerprint(original, target)


@pytest.mark.parametrize("mutation", ["condition", "science-constant", "additional-science-function"])
def test_target_projection_preserves_unknown_scientific_changes_in_fingerprint(mutation):
    from qcsd_lab import rapid_fixed_condition_target as target
    original, current = fixed_source_pair()
    if mutation == "condition":
        definition = function_bytes(current, "condition_identity")
        changed = definition.replace(b"'request_policy':'as-defined'", b"'request_policy':'science-drift'", 1)
        assert definition != changed
        changed = current.replace(definition, changed, 1)
    elif mutation == "science-constant":
        before = b"CLASSES, SLOTS, TOTAL = 50, 64, 16000"
        assert current.count(before) == 1
        changed = current.replace(before, b"CLASSES, SLOTS, TOTAL = 50, 64, 16001", 1)
    else:
        changed = current + b"\ndef unregistered_scientific_unit():\n    return True\n"
    restored = target._front_incoming_acceptance_condition_projection(changed)
    assert independent_science_fingerprint(restored, target) != independent_science_fingerprint(original, target)


@pytest.mark.parametrize("selected", [False, True])
def test_fixed_condition_authenticates_policy_helper_in_selected_and_absent_branches(tmp_path, monkeypatch, selected):
    from qcsd_lab import rapid_fixed_condition_target as target
    current, native = condition_fixture(tmp_path)
    if selected: current[FIELD] = POLICY
    foreign = tmp_path / "foreign-package/front_incoming_acceptance.py"
    foreign.parent.mkdir()
    foreign.write_bytes(Path(incoming.__file__).read_bytes()); foreign.chmod(0o644)
    monkeypatch.setattr(incoming, "__file__", str(foreign))
    with pytest.raises(ValueError, match="exact current Source"):
        target.condition_identity(current, native, "front")


def test_flight_front_config_validation_loop_precedes_incoming_selection_join():
    root = Path(incoming.__file__).resolve().parents[2]
    tree = ast.parse((root / "tools/_rapid_class_mode_flight/flight/operator.py").read_bytes())
    function = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "checked_plan")
    fronts = [node for node in function.body if isinstance(node, ast.If)
        and isinstance(node.test, ast.Compare) and isinstance(node.test.left, ast.Name)
        and node.test.left.id == "fixed_front" and len(node.test.ops) == 1
        and isinstance(node.test.ops[0], ast.IsNot) and isinstance(node.test.comparators[0], ast.Constant)
        and node.test.comparators[0].value is None]
    assert len(fronts) == 1
    front = fronts[0]
    roots = [node for node in front.body if isinstance(node, ast.For)
        and isinstance(node.target, ast.Name) and node.target.id == "root"]
    assert len(roots) == 1
    roots_loop = roots[0]
    assert isinstance(roots_loop.iter, ast.Tuple)
    assert [node.id for node in roots_loop.iter.elts] == ["clean", "execution"]
    inner = [node for node in roots_loop.body if isinstance(node, ast.For)]
    assert len(inner) == 1
    source_fields = {node.attr for node in ast.walk(inner[0].iter) if isinstance(node, ast.Attribute)}
    assert {"CONFIGURATION_PATH", "CONFIGURATION_SHA256", "PROVENANCE_PATH", "PROVENANCE_SHA256"} <= source_fields
    checks = [node for node in inner[0].body if isinstance(node, ast.If)]
    assert len(checks) == 1 and any(isinstance(node, ast.Raise) for node in checks[0].body)
    constants = {node.value for node in ast.walk(checks[0].test) if isinstance(node, ast.Constant)}
    attributes = {node.attr for node in ast.walk(checks[0].test) if isinstance(node, ast.Attribute)}
    calls = {node.func.id for node in ast.walk(checks[0].test) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)}
    assert {0o7777, 0o644} <= constants and "st_mode" in attributes and {"digest", "read"} <= calls
    joins = [node for node in function.body if isinstance(node, ast.Assign)
        and any(isinstance(name, ast.Name) and name.id == "selected_incoming" for name in node.targets)]
    assert len(joins) == 1 and function.body.index(front) < function.body.index(joins[0])
    assert roots_loop.end_lineno < joins[0].lineno


def test_target_chunk_sources_keep_exact_helper_resolution_and_closed_module_set():
    from qcsd_lab import rapid_target_chunks as chunks
    root = Path(incoming.__file__).absolute().parents[2]
    runtime = {"module_root": str(root)}
    assert incoming.SOURCE_PATH in chunks.CONTROL_FILENAMES
    assert chunks._executing_source_path(incoming.SOURCE_PATH, runtime) == Path(incoming.__file__)
    for relative in chunks.CONTROL_FILENAMES:
        assert chunks._executing_source_path(relative, runtime) == root / relative
    with pytest.raises(ValueError, match="closed installed set"):
        chunks._executing_source_path("src/qcsd_lab/not_registered.py", runtime)


def front50_condition(epoch):
    from qcsd_lab import rapid_fixed_condition_target as target
    cfg, run = front_setting(prospective=True)
    cfg[FIELD] = POLICY
    return target.describe_condition(write(epoch.case.root / "front50-config.json", cfg),
        write(epoch.case.root / "front50-run.json", run), "front", epoch.case.root / "front50-condition.json")


def test_empty_front50_target_imports_original_rows_proofs_and_unchanged_conditions(front_epoch):
    from qcsd_lab import rapid_fixed_condition_target as target, rapid_mixed_implementation_target as mixed
    condition = front50_condition(front_epoch)
    declared = mixed.publish_target(namespace="prospective-front50-original-progress", retained_progress=front_epoch.old_progress,
        buflo_condition=front_epoch.condition, front_condition=condition, implementations=front_epoch.binding_refs,
        output=front_epoch.case.root / "front50-mixed-target.json")
    original_progress = target.validate_progress(front_epoch.old_progress)
    original_target = target.validate_target(original_progress["target"])
    progress = target.initialize_progress(target=declared, proofs=original_progress["proofs"],
        output=front_epoch.case.root / "front50-mixed-progress.json")
    current_progress = target.validate_progress(progress)
    current_target = target.validate_target(declared)
    assert current_progress["accepted_rows"] == original_progress["accepted_rows"]
    assert current_progress["proofs"] == original_progress["proofs"]
    assert not any(row["mode"] == "front" for row in original_progress["accepted_rows"])
    assert current_target["classes"] == original_target["classes"]
    for mode in mixed.UNCHANGED:
        if mode == "front": continue
        assert current_target["conditions"][mode] == original_target["conditions"][mode]
        identity = target.mode_implementation(current_target, mode)
        assert identity["native_head"] == original_target["target_identity"]["native_head"]
        assert identity["client_sha256"] == original_target["target_identity"]["client_sha256"]
    identity = current_target["conditions"]["front"]["identity"]
    previous = target.validate_target(front_epoch.target)
    assert identity[FIELD] == POLICY and FIELD not in identity["capture_policies"]
    assert {key: value for key, value in identity.items() if key != FIELD} == previous["conditions"]["front"]["identity"]
    assert target.mode_implementation(current_target, "front") == target.mode_implementation(previous, "front")


def test_original_front_credit_still_refuses_front50_target_before_publication(front_epoch, monkeypatch):
    from qcsd_lab import rapid_fixed_condition_target as target, rapid_mixed_implementation_target as mixed
    condition = front50_condition(front_epoch)
    original_retained = mixed._retained
    def with_original_front_credit(reference):
        assert reference == front_epoch.old_progress
        progress, original = original_retained(reference)
        progress = deepcopy(progress)
        # Exercise the empty gate after authenticating the actual original V1
        # progress and its bindings, without changing its sealed file or proof.
        progress["accepted_rows"][0]["mode"] = "front"
        progress["accepted_rows"][0]["condition"] = deepcopy(original["conditions"]["front"]["identity"])
        return progress, original
    monkeypatch.setattr(mixed, "_retained", with_original_front_credit)
    output = front_epoch.case.root / "front50-old-front-refused.json"
    with pytest.raises(ValueError, match="Front empty"):
        mixed.publish_target(namespace="refused-front50-old-front-credit", retained_progress=front_epoch.old_progress,
            buflo_condition=front_epoch.condition, front_condition=condition,
            implementations=front_epoch.binding_refs, output=output)
    assert not output.exists()


@pytest.mark.parametrize("mutation", ["unknown-policy", "native-window"])
def test_front50_condition_refuses_unknown_selection_or_changed_native_window(tmp_path, mutation):
    from qcsd_lab import rapid_fixed_condition_target as target
    cfg, run = front_setting(prospective=True)
    cfg[FIELD] = "unknown" if mutation == "unknown-policy" else POLICY
    if mutation == "native-window": run[native_policy.FRONT_FIELD]["incoming_release_window_us"] = 50000
    output = tmp_path / "invalid-front50-condition.json"
    with pytest.raises(ValueError):
        target.describe_condition(write(tmp_path / "invalid-front50-config.json", cfg),
            write(tmp_path / "invalid-front50-run.json", run), "front", output)
    assert not output.exists()


def test_optional_original_failed_source66_front_v5_stays_uncredited():
    import os
    selected = os.environ.get("QCSD_FRONT_V5_FAILED_RUN_PATH")
    if not selected:
        pytest.skip("set QCSD_FRONT_V5_FAILED_RUN_PATH to the preserved genuine Source66 V5 run.json")
    run_path = Path(selected)
    assert run_path.name == "run.json" and "failures" in run_path.parts
    expected = {"run.json": ("78a2c39dfb33e10548386bd6a123463290bb7977858c03e784c5fbc38cecbec1", 0o600),
        "schedule.csv": ("126cb2eafc62a6cdc10c82cb2a7bbbbd7dc69279db77d37292d3e1dfac3d0926", 0o644),
        "packets.csv": ("bd8796cdb0ecdd22542664a5b56a3f4f8499b9d26fd92b6fb0b33dbc03d80150", 0o644),
        "events.csv": ("b57463558b5a9ee0d71b5631a07496f006529e752c90788926384c69bbc34444", 0o644)}
    for name, (digest, mode) in expected.items():
        path = run_path.with_name(name)
        assert path.is_file() and not path.is_symlink()
        assert sha256_file(path) == digest and path.stat().st_mode & 0o7777 == mode
    native = json.loads(run_path.read_text())
    assert native["completion_status"] == "complete"
    assert native[native_policy.FRONT_FIELD] == marker()
    assert FIELD not in native
    metrics = fidelity._schedule_realization_metrics_from_path(run_path.with_name("schedule.csv"))
    assert metrics["scheduled_events"] == 791
    assert metrics["scheduled_incoming_events"] == 379
    assert metrics["scheduled_outgoing_events"] == 412
    assert metrics["front_outgoing_padding_omissions"] == metrics["missed_events"] == 0
    assert metrics["front_outgoing_shaped_handoff_events"] == 412
    assert metrics["incoming_credit_release_window_us"] == 10000
    assert metrics["incoming_credit_release_window_violations"] == 2
    assert metrics["incoming_credit_release_original_5000us_violations"] == 3
    assert metrics["incoming_credit_release_lateness_upper_bound_us_max"] == 25510
    assert FIELD not in metrics
    assert not fidelity.fidelity_eligible("front", native["defense_diagnostics"], sample_eligible=True,
        missed_events=0, outgoing_size_mismatches=metrics["outgoing_size_mismatch_events"],
        schedule_metrics=metrics, resolved_configuration=native["resolved_configuration"],
        require_defense_activation=True)
