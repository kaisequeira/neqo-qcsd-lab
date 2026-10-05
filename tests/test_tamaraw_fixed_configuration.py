"""HOST-only prospective setting controls; actual diagnostic facts grant no credit.

The required external facts file binds the retained successful zero-credit 8192
probe. Original GET/qualification/installed/capture acceptance are not replaced.
"""
from copy import deepcopy
from dataclasses import replace
import hashlib
import importlib.util
import json
import os
from pathlib import Path
from types import SimpleNamespace
import tomllib

import pytest
import yaml

from qcsd_lab import application_response_policy as app
from qcsd_lab import capture_acceptance_policy as acceptance
from qcsd_lab import capture_session as capture
from qcsd_lab import experiment, orchestrator, verification
from qcsd_lab import rapid_capture_plan as planner, rapid_slot_chunks as chunks
from qcsd_lab import tamaraw_fixed_configuration as fixed


@pytest.fixture(scope="module")
def actual():
    declaration = Path(os.environ["QCSD_TAM_FIXED_HOST_FACTS"])
    refs = json.loads(declaration.read_bytes())
    def close():
        for record in refs.values():
            path = Path(record["path"])
            if path.is_symlink() or not path.is_file():
                raise AssertionError("actual HOST contract input is not regular")
            if (hashlib.sha256(path.read_bytes()).hexdigest() != record["sha256"]
                or path.stat().st_mode & 0o777 != record["mode"]):
                raise AssertionError("actual HOST contract input changed")
    close()
    run_path = Path(refs["run"]["path"])
    prepared = json.loads(Path(refs["prepared"]["path"]).read_bytes())
    run = json.loads(run_path.read_bytes())
    yield prepared, run, run_path.parent
    close()


@pytest.mark.parametrize("bad", [None, True, "unknown"])
def test_present_invalid_policy_never_selects_the_historical_default(bad):
    with pytest.raises(ValueError):
        fixed.policy({fixed.FIELD: bad})
    assert fixed.policy({}) is None


def test_full_config_matches_actual8192_and_changes_only_initial_credit(actual):
    _, run, _ = actual
    fixed.validate_run(run, selected_policy=fixed.POLICY)
    assert tomllib.loads(fixed.configuration_bytes().decode()) == run["resolved_configuration"]
    prior = deepcopy(run["resolved_configuration"])
    prior["initial_max_stream_data"] = 16
    changed = {key for key in prior if prior[key] != fixed.resolved_configuration()[key]}
    assert changed == {"initial_max_stream_data"}
    identity = fixed.target_identity()
    assert identity["historical_tamaraw_condition_carried"] is False
    assert identity["scientific_credit"] is False


@pytest.mark.parametrize("change", ["initial4096", "excess", "interval", "bool", "extra"])
def test_complete_config_refuses_any_unregistered_setting(change, actual):
    _, current, _ = actual
    run = deepcopy(current)
    value = run["resolved_configuration"]
    if change == "initial4096": value["initial_max_stream_data"] = 4096
    elif change == "excess": value["max_stream_data_excess"] = 8192
    elif change == "interval": value["defense"]["incoming_interval_us"] = 6000
    elif change == "bool": value["tail_wait_us"] = False
    else: value["undeclared"] = 1
    with pytest.raises(ValueError): fixed.validate_run(run, selected_policy=fixed.POLICY)


def test_native_config_removes_only_conflicting_selectors_and_preserves_graph_chaff_caps(tmp_path, actual):
    prepared, _, _ = actual
    source = tmp_path / "prepared.json"
    source.write_text(json.dumps(prepared))
    config = tmp_path / fixed.INPUT
    config.write_bytes(fixed.configuration_bytes())
    context = SimpleNamespace(limits=capture.Limits(max_response_bytes=16 * 1024 * 1024,
        timeout_seconds=120), qcsd_profile="research-1200", request_policy="as-defined")
    arguments = (tmp_path / "complete-runtime.json", tmp_path / "qualified-chaff.json",
                 "whole-graph", capture.Defense("tamaraw", "tamaraw", False), 17, context, tmp_path / "out")
    old = capture._client_command(*arguments, application_workload_source=source)
    context.tamaraw_configuration_policy, context.tamaraw_configuration_path = fixed.POLICY, config
    current = capture._client_command(*arguments, application_workload_source=source)
    expected, index = [], 0
    while index < len(old):
        if old[index] in {"--profile", "--defense", "--workload-id"}: index += 2
        else: expected.append(old[index]); index += 1
    assert current == expected + ["--config", str(config)]
    assert "--workload" in current and "--chaff-manifest" in current
    assert "--max-response-bytes" in current and "--timeout-seconds" in current


@pytest.mark.parametrize("change", ["bytes", "symlink"])
def test_native_config_refuses_changed_or_indirect_files(change, tmp_path):
    config = tmp_path / fixed.INPUT
    config.write_bytes(fixed.configuration_bytes())
    if change == "bytes": config.write_bytes(config.read_bytes().replace(b"8192", b"4096"))
    else:
        original = tmp_path / "original.toml"
        config.rename(original)
        config.symlink_to(original)
    with pytest.raises(ValueError): fixed.validate_configuration(config)


def test_actual_owned_terminal_proof_requires_explicit_new_condition(actual):
    prepared, run, directory = actual
    with pytest.raises(ValueError): acceptance.validate_terminal_primary_source_binding(prepared, run)
    acceptance.validate_terminal_primary_source_binding(prepared, run, runner_directory=directory,
        tamaraw_configuration_policy=fixed.POLICY)
    metrics = acceptance.validate_terminal_primary_partial_evidence(run, runner_directory=directory,
        prepared=prepared, tamaraw_configuration_policy=fixed.POLICY)
    assert metrics["terminal_primary_partial_cells"] == 1
    assert metrics["terminal_primary_partial_consumed_bytes"] + metrics["terminal_primary_partial_retired_bytes"] == 1200
    malformed = deepcopy(run)
    malformed[acceptance.TERMINAL_PRIMARY_PROOF_FIELD]["retired_bytes"] += 1
    with pytest.raises(ValueError):
        acceptance.validate_terminal_primary_source_binding(prepared, malformed, runner_directory=directory,
            tamaraw_configuration_policy=fixed.POLICY)


def test_actual70_graph_status_headers_and_observed_cap_remain_complete(actual):
    prepared, run, _ = actual
    facts = app.validate_application_responses(prepared, run,
        body_identity_policy=app.COMPLETE_APPLICATION_DELIVERY_POLICY)
    assert len(facts["observed_responses"]) == 70
    assert facts["content_equality_across_visits_claimed"] is False
    malformed = deepcopy(run)
    malformed["max_response_bytes"] = True
    with pytest.raises(ValueError): app.validate_application_responses(prepared, malformed,
        body_identity_policy=app.COMPLETE_APPLICATION_DELIVERY_POLICY)


@pytest.mark.parametrize("change", ["other-mode", "body-policy", "old-witness"])
def test_fixed_campaign_refuses_other_modes_or_old_qualification_waivers(change):
    defense = capture.Defense("tamaraw", "tamaraw", False)
    body, witness = app.COMPLETE_APPLICATION_DELIVERY_POLICY, None
    if change == "other-mode": defense = capture.Defense("none", "none", True)
    elif change == "body-policy": body = None
    else: witness = {"path": "/historical", "sha256": "a" * 64}
    with pytest.raises(ValueError): fixed.validate_campaign(selected_policy=fixed.POLICY,
        profile="research-1200", defenses=(defense,), body_policy=body, qualification_compatibility=witness)


def test_public_campaign_and_frozen_configuration_bind_exact_file_hash(tmp_path, monkeypatch, actual):
    prepared, _, _ = actual
    path = tmp_path / "config/campaigns/fixed-case.yml"
    path.parent.mkdir(parents=True)
    workload_path = tmp_path / "config/workloads/whole.json"
    workload_path.parent.mkdir()
    raw = json.dumps(prepared).encode()
    workload_path.write_bytes(raw)
    workload = orchestrator.Workload("whole", 1, workload_path, raw, hashlib.sha256(raw).hexdigest(),
        prepared, 70, 3)
    # Old full GET and current qualification authority remain external genuine
    # prerequisites. This control isolates the public campaign/frozen schema.
    monkeypatch.setattr(orchestrator, "_load_workloads", lambda *args, **kwargs: (workload,))
    monkeypatch.setattr(orchestrator, "_load_qualified_chaff_inputs", lambda path, values, **kwargs: values)
    monkeypatch.setattr(orchestrator, "validate_research_preparation", lambda *args, **kwargs: None)
    value = {"schema": 1, "name": "fixed-case", "purpose": "smoke", "seed": 17,
        "profile": "research-1200", "workloads": {"whole": 1}, "request_policies": ["as-defined"],
        "defenses": ["tamaraw"], "chaff_qualification_set": "current-new-condition",
        "application_body_identity_policy": app.COMPLETE_APPLICATION_DELIVERY_POLICY, fixed.FIELD: fixed.POLICY}
    path.write_text(yaml.safe_dump(value))
    campaign = orchestrator.load_campaign(path)
    assert campaign.tamaraw_configuration_policy == fixed.POLICY
    root = tmp_path / "result"
    (root / "inputs/workloads").mkdir(parents=True)
    frozen_workload = root / "inputs/workloads/whole.json"
    frozen_workload.write_bytes(raw)
    frozen_campaign = root / "inputs/campaign.yml"
    frozen_campaign.write_bytes(path.read_bytes())
    config = root / "inputs" / fixed.INPUT
    config.write_bytes(fixed.configuration_bytes())
    campaign = replace(campaign, path=frozen_campaign, workloads=(replace(workload, path=frozen_workload),),
        tamaraw_configuration_path=config)
    fields = orchestrator._frozen_configuration(root, campaign)
    experiment._validate_configuration(fields)
    assert fields["tamaraw_configuration_sha256"] == fixed.configuration_sha256()
    assert fields["tamaraw_configuration"] == "inputs/" + fixed.INPUT
    config.write_bytes(config.read_bytes().replace(b"8192", b"4096"))
    with pytest.raises(ValueError): orchestrator._frozen_configuration(root, campaign)


def test_public_serial_render_has_new_tag_and_old_render_is_unchanged():
    site = planner.Site("candidate", "whole", "a" * 64, "https://host.example", "current-set", "b" * 64)
    lane = next(row for row in planner.plan_lanes((site,), final=True, study_version=6, rolling_batch=1)
                if row.mode == "tamaraw")
    from qcsd_lab.supplied_static_admission import capture_limits
    options = {"static_capture_limits": capture_limits(16 * 1024 * 1024, 64),
        "application_body_identity_policy": app.COMPLETE_APPLICATION_DELIVERY_POLICY}
    strict = planner.render_lane_campaign(lane, (site,), **options)
    current = yaml.safe_load(planner.render_lane_campaign(lane, (site,), **options,
        tamaraw_configuration_policy=fixed.POLICY))
    assert fixed.FIELD not in yaml.safe_load(strict)
    assert current.pop(fixed.FIELD) == fixed.POLICY and current == yaml.safe_load(strict)


def test_old_progress_cannot_subtract_historical_tam_slots_from_new_condition(monkeypatch, tmp_path):
    from qcsd_lab import rapid_rolling_capture as rolling
    monkeypatch.setattr(chunks, "_base_spec", lambda value: SimpleNamespace(serializable=lambda: {}))
    monkeypatch.setattr(rolling, "verify_capture_plan", lambda *args: ((), {fixed.FIELD: fixed.POLICY}))
    monkeypatch.setattr(chunks, "prior_progress", lambda *args: pytest.fail("old TAM slots were replayed"))
    with pytest.raises(ValueError, match="distinct condition target map"):
        chunks.publish_policy(SimpleNamespace(serializable=lambda: {}), {}, tmp_path / "new.json", modes=["tamaraw"])
    assert not (tmp_path / "new.json").exists()


def test_portable_opt_in_refuses_non_tam_before_staging_effects(monkeypatch, tmp_path):
    source = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location("fixed_tam_portable", source / "tools/_rapid_class_mode_flight/flight/operator.py")
    portable = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(portable)
    monkeypatch.setattr(portable, "checked_runtime", lambda args: ({}, {}, source))
    monkeypatch.setattr(portable, "host_imports", lambda root: None)
    monkeypatch.setattr(portable, "selected_inputs", lambda *args, **kwargs: pytest.fail("staging crossed its mode guard"))
    args = SimpleNamespace(name="new-condition", campaign_seed=17, mode="undefended",
        application_body_identity_policy=app.COMPLETE_APPLICATION_DELIVERY_POLICY,
        tamaraw_configuration_policy=fixed.POLICY)
    with pytest.raises(ValueError, match="own fresh current response qualification"): portable.stage(args)


def test_independent_deep_refuses_missing_fixed_config_before_sample_reads(tmp_path):
    configuration = {fixed.FIELD: fixed.POLICY, "tamaraw_configuration": "inputs/" + fixed.INPUT,
        "application_body_identity_policy": app.COMPLETE_APPLICATION_DELIVERY_POLICY, "workloads": []}
    with pytest.raises(ValueError, match="configuration file differs"):
        verification._validate_policy_application_responses(tmp_path, {"configuration": configuration, "samples": []})
