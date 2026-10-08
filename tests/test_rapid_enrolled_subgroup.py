"""HOST subgroup controls; physical admission/qualification/canary are labeled fixtures."""
from copy import deepcopy
from dataclasses import asdict
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from qcsd_lab import rapid_enrolled_subgroup as subgroup
from qcsd_lab import rapid_rolling_capture as rolling
from qcsd_lab import rapid_lane_evidence as lanes
from qcsd_lab import rapid_additive_static_enrollment as additive
from tests.test_rapid_rolling_capture import rolling_setup
from tests.test_rapid_lane_evidence import setup
from tests.test_class_mode_flight_control import recipe
from tests.test_selected_capture_input import selected_graph, additive_case, qualifier_fixture, forbid_history
from tests.test_supplied_static_preparation import fixed_graph
from tests.test_supplied_static_get import actual_contract_fixture


def metadata(tmp_path):
    enrollment = tmp_path / "enrollment.json"
    enrollment.write_text('{"controlled_original_enrollment":true}\n')
    batch = {"ordinal": 5, "selected_candidate_ids": ["candidate-17", "candidate-18"]}
    caps = {"capture_megabytes": 64, "capture_seconds": 180, "max_attempts": 3,
        "max_response_bytes": 16777216, "per_origin_cooldown_seconds": 0,
        "settle_seconds": 2, "timeout_seconds": 120}
    rows = [{"class_index": index, "candidate_id": f"candidate-{index}",
        "workload_id": f"whole-graph-{index}", "capture_limits": dict(caps),
        "prepared_workload": {"path": str(tmp_path / f"graph-{index}.json"), "sha256": str(index)*32}}
        for index in (16, 17, 18)]
    return enrollment, batch, rows


@pytest.mark.parametrize("indices", [[], [16], [17, 17], [18, 17], [True], [17.0], [19]])
def test_unknown_duplicate_reordered_or_untyped_classes_are_refused(tmp_path, indices):
    enrollment, batch, rows = metadata(tmp_path)
    with pytest.raises(ValueError):
        subgroup.declare(enrollment, batch, rows, indices)


@pytest.mark.parametrize("mutation", ["graph", "caps", "ordinal", "enrollment", "extra"])
def test_subgroup_keeps_original_graph_caps_enrollment_and_closed_fields(tmp_path, mutation):
    enrollment, batch, rows = metadata(tmp_path)
    value = subgroup.declare(enrollment, batch, rows, [17])
    changed = deepcopy(rows)
    if mutation == "graph":
        changed[1]["prepared_workload"]["sha256"] = "f"*64
    elif mutation == "caps":
        changed[1]["capture_limits"]["max_response_bytes"] += 1
    elif mutation == "ordinal":
        value["batch_ordinal"] = 5.0
    elif mutation == "enrollment":
        enrollment.write_text('{"changed":true}\n')
    else:
        value["unregistered"] = True
    with pytest.raises(ValueError):
        subgroup.validate(value, enrollment, batch, changed)


def test_portable_flight_selects_complete_graph_and_keeps_full_dependency_roots(tmp_path, recipe, monkeypatch):
    enrollment, batch, rows = metadata(tmp_path)
    manifests = [{"resources": [{"id": 0, "url": "https://primary.example/", "request_headers": [["x-repeat", "a"], ["x-repeat", "b"]]},
        {"id": 1, "url": "https://cdn.example/one", "after": [0]},
        {"id": 2, "url": "https://cdn.example/two", "after": [0, 1]}], "preparation": {"fixture": True}}
        for _ in (17, 18)]
    bindings = [{"candidate_id": row["candidate_id"], "class_index": row["class_index"],
        "workload_id": row["workload_id"], "full_graph": recipe.graph(manifest)}
        for row, manifest in zip(rows[1:], manifests)]
    policy = {"contract": additive.CONTRACT}
    original = (batch, policy, bindings, manifests, [str(tmp_path / "all-original-raw")], {"max_attempts": 1})
    monkeypatch.setattr(rolling, "_verify_enrollment", lambda path: (batch, rows, policy))
    monkeypatch.setattr(recipe, "_selected_inputs", lambda *args, **kwargs: original)
    from qcsd_lab import selected_capture_amendment as amendment
    monkeypatch.setattr(amendment, "metadata_inputs", lambda *args: ({enrollment}, {tmp_path / "all-source"}))
    selected = recipe.selected_inputs(enrollment, tmp_path, class_indices=[17])
    assert selected[2] == bindings[:1] and selected[3] == manifests[:1]
    assert selected[3][0]["resources"] == manifests[0]["resources"]
    assert set(selected[4]) == {str(tmp_path), str(tmp_path / "all-source"), str(tmp_path / "all-original-raw")}
    assert recipe.selected_inputs(enrollment, tmp_path) is original
    with pytest.raises(ValueError, match="ordinary-only"):
        recipe.selected_inputs(enrollment, tmp_path, class_indices=[17], ordinary_renewal={"fixture": True})


def second_batch(case):
    rolling.enroll(case.root)
    case.status["terminal_prefix"] = case.terminals[:3]
    enrollment = rolling.enroll(case.root, count=2)
    batch, classes = rolling.verify_enrollment(enrollment)
    return enrollment, batch, classes


def canary(tmp_path, value):
    path = tmp_path / "selected-canary-plan.json"
    path.write_bytes(lanes._json({subgroup.FIELD: value, "controlled_physical_canary_boundary": True}))
    return {"plan": rolling._ref(path)}


def test_public_plan_and_real_verifier_keep_only_selected_full_graph(rolling_setup, tmp_path, monkeypatch):
    from tools import rapid_rolling_capture as cli
    case = rolling_setup
    from qcsd_lab.rapid_operation_facts import OperationFacts
    # The fixture has no physical canary receipt. Only that external proof's
    # dependency binding is substituted, alongside its existing validator.
    monkeypatch.setattr(OperationFacts, "bind_canary", lambda *args, **kwargs: None)
    enrollment, batch, classes = second_batch(case)
    value = subgroup.declare(enrollment, batch, classes, [2])
    reference = canary(tmp_path, value)
    ready = tmp_path / "ready.json"
    ready.write_bytes(lanes._json({"tamaraw": reference}))
    qualified = []
    monkeypatch.setattr(rolling, "validate_named_qualification_set_manifest",
        lambda *args, **kwargs: qualified.append(kwargs["expected_workload_ids"]))
    output, spec_path = case.root / "subgroup-plan.json", case.root / "subgroup-spec.json"
    args = cli._parser().parse_args(["plan", "--evidence-root", str(case.root),
        "--enrollment", str(enrollment), "--qualification-spec", str(case.base.spec.qualification_spec),
        "--readiness", str(ready), "--class-indices", "2", "--output", str(output),
        "--spec-output", str(spec_path)])
    result = cli.run(args)
    spec = lanes.load_capture_spec(spec_path)
    sites, payload = rolling.verify_capture_plan(spec)
    assert result["planned_traces"] == 320 and len(sites) == 1
    assert sites[0].candidate_id == classes[1]["candidate_id"]
    assert payload[subgroup.FIELD] == value
    assert qualified and all(ids == [sites[0].workload_id] for ids in qualified)
    lane = payload["lanes"][0]
    campaign = yaml.safe_load((spec.campaign_dir / (lane["campaign_name"] + ".yml")).read_bytes())
    assert campaign["workloads"] == {sites[0].workload_id: 4}
    original = rolling._prepared_workload(case.context, rolling._open_ref(classes[1]["terminal"]))[0]
    assert (spec.workload_root / (sites[0].workload_id + ".json")).read_bytes() == original.read_bytes()
    altered = lanes._load(lanes._read(output))
    altered["payload"][subgroup.FIELD]["classes"][0]["workload_id"] = "different-graph"
    output.write_bytes(lanes._json(rolling.admission._bind(lanes.PLAN_TYPE, altered["payload"])))
    with pytest.raises(ValueError, match="subgroup"):
        rolling.verify_capture_plan(spec)


def test_wrong_group_canary_and_missing_selected_qualification_refuse(rolling_setup, tmp_path, monkeypatch):
    case = rolling_setup
    enrollment, batch, classes = second_batch(case)
    wrong = canary(tmp_path, subgroup.declare(enrollment, batch, classes, [3]))
    with pytest.raises(ValueError, match="canary"):
        rolling.publish_plan(case.root, enrollment, case.base.spec.qualification_spec, case.root / "wrong.json",
            readiness={"tamaraw": wrong}, class_indices=[2])
    correct = canary(tmp_path, subgroup.declare(enrollment, batch, classes, [2]))
    def missing(*args, **kwargs):
        assert kwargs["expected_workload_ids"] == [classes[1]["workload_id"]]
        raise ValueError("selected workload has no complete qualification")
    monkeypatch.setattr(rolling, "validate_named_qualification_set_manifest", missing)
    with pytest.raises(ValueError, match="no complete qualification"):
        rolling.publish_plan(case.root, enrollment, case.base.spec.qualification_spec, case.root / "missing.json",
            readiness={"tamaraw": correct}, class_indices=[2])


def test_selected_input_caps_and_full_graph_reach_subgroup_formal_verifier(additive_case, tmp_path, monkeypatch):
    case = additive_case
    qualification = qualifier_fixture(case, monkeypatch)
    forbid_history(monkeypatch)
    enrollment = case["new_enrollment"]
    batch, classes = rolling.verify_enrollment(enrollment)
    value = subgroup.declare(enrollment, batch, classes, [2])
    reference = canary(tmp_path, value)
    output = case["new_study"] / "subgroup-plan.json"
    rolling.publish_plan(case["new_study"], enrollment, qualification, output,
        readiness={"tamaraw": reference}, class_indices=[2])
    spec = rolling.capture_spec(case["new_study"], enrollment, qualification, output)
    sites, payload = rolling.verify_capture_plan(spec)
    assert len(sites) == 1 and payload["capture_limits"] == case["policy"]["capture_limits"]
    assert payload[subgroup.FIELD] == value
    original = case["second"]["prepared"]
    assert (spec.workload_root / original.name).read_bytes() == original.read_bytes()
    assert payload["planned_trace_count"] == 320 and payload["formal_accepted_trace_count"] == 0


def test_public_stage_parser_accepts_explicit_ordered_selection(tmp_path, recipe, monkeypatch):
    import sys
    argv = ["rapid_class_mode_flight.py", "stage"]
    for flag in ("runtime-build-root", "clean-runtime-root", "study-root", "enrollment", "output", "python"):
        argv += ["--"+flag, str(tmp_path / flag)]
    argv += ["--canonical-sha256", "a"*64, "--expected-lab-commit", "b"*40,
        "--expected-native-commit", "c"*40, "--name", "selected-peer", "--campaign-seed", "20261007",
        "--mode", "tamaraw", "--class-indices", "17"]
    observed = []
    monkeypatch.setattr(sys, "argv", argv)
    # This parser fixture controls SDK binding and stage; it supplies no runtime proof.
    monkeypatch.setattr(recipe, "_bind_host_sdk", lambda args: None)
    monkeypatch.setattr(recipe, "stage", lambda args: observed.append(args.class_indices))
    recipe.main()
    assert observed == [[17]]
