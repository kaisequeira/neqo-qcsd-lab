from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path

import pytest

from qcsd_lab import buflo_duration_budget as budget, fidelity, parameters

ROOT = Path(__file__).resolve().parents[1]
NEW = ROOT / budget.PARAMETER_PATH
OLD = ROOT / "config/defense-params/buflo-live.json"


def _run(raw: bytes, *, path: str = "/lab/config/defense-params/buflo-duration200.json"):
    return {"method": "GET", "resolved_configuration": {
        "schema_version": 2, "control_interval_us": 5_000,
        "initial_max_stream_data": 16, "automatic_receive_window": 1_048_576,
        "max_chaff_streams": 5, "low_watermark": 1_000_000,
        "use_empty_resources": False, "max_stream_data_excess": 1_000,
        "max_udp_payload_size": 1_200, "drop_unsatisfied_events": False,
        "keep_alive_lead_time_us": 100_000, "tail_wait_us": 0,
        "defense": {"kind": "buflo", "parameters": path}},
        "defense_parameters": {"kind": "buflo", "path": path,
            "sha256": hashlib.sha256(raw).hexdigest(), "implementation_scope": "client_only_quic",
            "paper_equivalent": False, budget.RUN_FIELD: dict(budget.RECEIPT)}}


def _schedule(count: int, extra=None):
    targets = list(range(0, count * 20_000, 20_000))
    return {"target_times_us_by_direction": {direction: list(targets) for direction in ("incoming", "outgoing")},
            "scheduled_sizes_by_direction": {direction: [1_200] * count for direction in ("incoming", "outgoing")},
            "terminal_satisfactions": {"satisfied": count * 2}, **(extra or {})}


def test_checked_in_parameter_bytes_and_public_artifact_are_bound(monkeypatch):
    monkeypatch.setattr(parameters, "LAB_ROOT", ROOT)
    assert NEW.read_bytes() == budget.parameter_bytes()
    assert hashlib.sha256(NEW.read_bytes()).hexdigest() == budget.PARAMETER_SHA256
    actual = parameters.validate_parameter_artifact(NEW, expected_kind="buflo",
        allow_study_candidate=True, expected_qcsd_profile="research-1200", expected_udp_payload_ceiling=1_200)
    assert actual.sha256 == budget.PARAMETER_SHA256
    assert actual.input_policy == budget.INPUT_POLICY
    original = parameters.validate_parameter_artifact(OLD, expected_kind="buflo",
        allow_study_candidate=True, expected_qcsd_profile="research-1200", expected_udp_payload_ceiling=1_200)
    assert original.input_policy == parameters.BUFLO_STUDY_PARAMETER_INPUT_POLICY
    assert hashlib.sha256(OLD.read_bytes()).hexdigest() == "8ba1b822d512e87382b25d83460e0cfe1ecf1f47aa66c17ee9dabb28999596e2"


def test_public_artifact_still_requires_explicit_candidate_permission(monkeypatch):
    monkeypatch.setattr(parameters, "LAB_ROOT", ROOT)
    with pytest.raises(ValueError, match="explicit study-campaign"):
        parameters.validate_parameter_artifact(NEW, expected_kind="buflo")


@pytest.mark.parametrize(("field", "value"), [
    ("schema_version", True), ("interval_us", 10_000), ("interval_us", 20_000.0),
    ("minimum_duration_us", 20_000_000), ("packet_size", 600), ("max_events", 9_999),
    ("max_events", 10_001), ("duration_budget_policy", None), ("duration_budget_policy", "custom"),
    ("duration_budget_policy", True), ("paper_equivalent", True), ("implementation_scope", "bilateral"),
])
def test_fixed_parameter_mutations_cannot_select_budget(field, value):
    actual = dict(budget.PARAMETERS); actual[field] = value
    with pytest.raises(ValueError):
        parameters._validate_buflo(actual, 1_200, NEW)


def test_absent_and_null_policy_keep_the_original_runtime_guard():
    old = json.loads(OLD.read_bytes())
    parameters._validate_buflo(old, 1_200, OLD)
    parameters._validate_buflo({**old, budget.PARAMETER_FIELD: None}, 1_200, OLD)
    for count in (6_001, 10_000):
        for extra in ({}, {budget.PARAMETER_FIELD: None}):
            with pytest.raises(ValueError):
                parameters._validate_buflo({**old, "max_events": count, **extra}, 1_200, OLD)


def test_duplicate_parameter_key_is_not_a_new_receipt():
    raw = NEW.read_bytes().replace(b'"max_events": 10000,', b'"max_events": 6000, "max_events": 10000,')
    with pytest.raises(ValueError, match="duplicate"):
        budget.validate_native_receipt(_run(raw), raw)


def test_new_raw_marker_joins_same_hashed_parameter_bytes():
    raw = NEW.read_bytes(); run = _run(raw)
    actual = budget.validate_native_receipt(run, raw)
    assert actual == {budget.RUN_FIELD: budget.RECEIPT,
                      "buflo_duration_budget_parameter_sha256": budget.PARAMETER_SHA256}
    budget.validate_native_receipt(run, raw, expected_path=run["defense_parameters"]["path"])
    with pytest.raises(ValueError):
        budget.validate_native_receipt(run, raw, expected_path="/different/parameters.json")
    with pytest.raises(ValueError):
        budget.validate_native_receipt(run, OLD.read_bytes())


@pytest.mark.parametrize("wrong_method", ["POST", "buflo"])
def test_budget_receipt_requires_native_http_get(wrong_method):
    raw = NEW.read_bytes(); run = _run(raw)
    run["method"] = wrong_method
    with pytest.raises(ValueError):
        budget.validate_native_receipt(run, raw)


@pytest.mark.parametrize("mutation", ["missing", "null", "bool", "counter", "budget", "hash", "path", "method", "defense_kind", "kind", "scope", "extra"])
def test_new_raw_marker_mutations_reject(mutation):
    raw = NEW.read_bytes(); run = _run(raw); marker = run["defense_parameters"][budget.RUN_FIELD]
    if mutation == "missing": del run["defense_parameters"][budget.RUN_FIELD]
    elif mutation == "null": run["defense_parameters"][budget.RUN_FIELD] = None
    elif mutation == "bool": marker["schema_version"] = True
    elif mutation == "counter": marker["max_events"] = 6_000
    elif mutation == "budget": marker["duration_budget_us"] = 120_000_000
    elif mutation == "hash": run["defense_parameters"]["sha256"] = "0" * 64
    elif mutation == "path": run["resolved_configuration"]["defense"]["parameters"] = "/other/parameters.json"
    elif mutation == "method": run["method"] = "POST"
    elif mutation == "defense_kind": run["resolved_configuration"]["defense"]["kind"] = "cs_buflo"
    elif mutation == "kind": run["defense_parameters"]["kind"] = "cs_buflo"
    elif mutation == "scope": run["defense_parameters"]["implementation_scope"] = "bilateral"
    else: marker["omissions_allowed"] = True
    with pytest.raises(ValueError): budget.validate_native_receipt(run, raw)


def test_sample_run_binding_reopens_parameters_and_missing_marker_rejects():
    raw = NEW.read_bytes(); run = _run(raw, path=str(NEW))
    parameters.validate_run_parameter_binding(run, kind="buflo", sha256=budget.PARAMETER_SHA256, expected_path=NEW)
    del run["defense_parameters"][budget.RUN_FIELD]
    with pytest.raises(ValueError):
        parameters.validate_run_parameter_binding(run, kind="buflo", sha256=budget.PARAMETER_SHA256, expected_path=NEW)


def test_frozen_schedule_metrics_bind_raw_receipt_and_refuse_missing_or_changed_bytes(tmp_path):
    schedule = tmp_path / "schedule.csv"; raw = NEW.read_bytes()
    (tmp_path / "run.json").write_text(json.dumps(_run(raw)))
    assert not schedule.exists()
    with pytest.raises(ValueError, match="frozen regular"):
        fidelity._buflo_duration_budget_metrics(schedule)
    (tmp_path / "defense-parameters.json").write_bytes(raw)
    joined = fidelity._buflo_duration_budget_metrics(schedule)
    assert budget.schedule_bounds(joined) == (10_000, 200_000_000)
    (tmp_path / "defense-parameters.json").write_bytes(raw + b"\n")
    with pytest.raises(ValueError, match="hashed"):
        fidelity._buflo_duration_budget_metrics(schedule)
    (tmp_path / "defense-parameters.json").write_bytes(raw)
    run = _run(raw); del run["defense_parameters"][budget.RUN_FIELD]
    (tmp_path / "run.json").write_text(json.dumps(run))
    with pytest.raises(ValueError, match="no actual Native"):
        fidelity._buflo_duration_budget_metrics(schedule)


def test_complete_schedule_counts_need_actual_new_budget():
    assert fidelity._buflo_schedule_matches_canonical_parameters(_schedule(6_000))
    assert not fidelity._buflo_schedule_matches_canonical_parameters(_schedule(6_001))
    joined = budget.validate_native_receipt(_run(NEW.read_bytes()), NEW.read_bytes())
    assert fidelity._buflo_schedule_matches_canonical_parameters(_schedule(10_000, joined))
    assert not fidelity._buflo_schedule_matches_canonical_parameters(_schedule(10_001, joined))
    for digest in (None, "bad", ""):
        assert not fidelity._buflo_schedule_matches_canonical_parameters(_schedule(6_001,
            {budget.RUN_FIELD: dict(budget.RECEIPT), "buflo_duration_budget_parameter_sha256": digest}))
    for direction in ("outgoing", "incoming"):
        bad = _schedule(10_000, joined); bad["scheduled_sizes_by_direction"][direction][0] = 600
        assert not fidelity._buflo_schedule_matches_canonical_parameters(bad)
        bad = _schedule(10_000, joined); bad["target_times_us_by_direction"][direction][-1] = 200_000_000
        assert not fidelity._buflo_schedule_matches_canonical_parameters(bad)


@pytest.mark.parametrize("parameter", [None, [], "missing", {}, {"kind": "cs_buflo"}])
def test_frozen_opt_in_cannot_fall_back_when_whole_raw_parameter_receipt_is_missing(tmp_path, parameter):
    run = _run(NEW.read_bytes())
    if parameter == "missing": del run["defense_parameters"]
    else: run["defense_parameters"] = parameter
    (tmp_path / "run.json").write_text(json.dumps(run))
    (tmp_path / "defense-parameters.json").write_bytes(NEW.read_bytes())
    with pytest.raises(ValueError, match="no actual Native"):
        fidelity._buflo_duration_budget_metrics(tmp_path / "schedule.csv")
    (tmp_path / "defense-parameters.json").write_bytes(OLD.read_bytes())
    assert fidelity._buflo_duration_budget_metrics(tmp_path / "schedule.csv") == {}


def test_new_artifact_without_run_never_implicitly_uses_legacy_schedule(tmp_path):
    (tmp_path / "defense-parameters.json").write_bytes(NEW.read_bytes())
    with pytest.raises(ValueError, match="no actual Native run"):
        fidelity._buflo_duration_budget_metrics(tmp_path / "schedule.csv")
    (tmp_path / "defense-parameters.json").write_bytes(OLD.read_bytes())
    assert fidelity._buflo_duration_budget_metrics(tmp_path / "schedule.csv") == {}


@pytest.mark.parametrize("mode", ["undefended", "front", "tamaraw", "buflo", "cs-buflo"])
def test_limits_change_only_the_explicit_buflo_mode(mode):
    from qcsd_lab.supplied_static_admission import capture_limits
    original = capture_limits(16_777_216, 64); frozen = copy.deepcopy(original)
    actual = budget.capture_limits(mode, original, policy=budget.POLICY)
    assert original == frozen
    assert actual == ({**frozen, "timeout_seconds": 240, "capture_seconds": 300} if mode == "buflo" else frozen)
    assert budget.capture_limits(mode, original, policy=None) == frozen
    with pytest.raises(ValueError): budget.capture_limits(mode, original, policy="generic-long-timeout")


def test_body_headroom_is_prospective_and_grants_no_capture_evidence():
    below = budget.final_cohort_body_screen(10_000_000, policy=budget.FINAL_COHORT_POLICY)
    above = budget.final_cohort_body_screen(10_000_001, policy=budget.FINAL_COHORT_POLICY)
    assert below["within_declared_headroom"] is True
    assert above["within_declared_headroom"] is False
    assert below["capture_viability_proven"] is above["capture_viability_proven"] is False
    assert below["scientific_credit"] is above["scientific_credit"] is False
    with pytest.raises(ValueError): budget.final_cohort_body_screen(True, policy=budget.FINAL_COHORT_POLICY)
    with pytest.raises(ValueError): budget.final_cohort_body_screen(1, policy="legacy-admission")


def test_exact_held_native_policy_and_receipt_oracle():
    native = Path(os.environ["QCSD_DURATION_NATIVE_SOURCE"])
    runner = native / "neqo-bin/src/qcsd/mod.rs"
    config = native / "neqo-csdef/src/config.rs"
    assert hashlib.sha256(runner.read_bytes()).hexdigest() == "60d8b59f85818d5e40c70e5d3c539253cd2b3180dc14002ad667a756ecb24f53"
    assert hashlib.sha256(config.read_bytes()).hexdigest() == "f58b9d46f28057aafd406f6b641464a17c4539b011c7a1ddfa497f425a466c95"
    source = runner.read_text(); start = source.index("fn buflo_duration_budget_evidence(")
    function = source[start:source.index("\n#[derive", start)]
    for field in ("interval_us", "minimum_duration_us", "packet_size", "max_events"):
        assert f"parameters.{field} != {budget.PARAMETERS[field]:_}" in function
    assert "duration_budget_us != 200_000_000" in function
    assert budget.POLICY in config.read_text()
