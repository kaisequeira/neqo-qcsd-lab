"""Optional exact-evidence intake checks for the external V10 browser producer.

Set QCSD_V10_PLAN_PATH to an actual reviewed declaration. An actual completed
batch may also be supplied as QCSD_V10_BATCH_CLOSURE. The tests create no browser,
GET, admission, or capture output and cannot turn a failed attempt into credit.
"""
from copy import deepcopy
import json
import os
from pathlib import Path

import pytest

from qcsd_lab import whole_graph_input as inputs


def _actual_path(name: str) -> Path:
    raw = os.environ.get(name)
    if not raw:
        pytest.skip(f"{name} is not bound to an actual immutable artifact")
    path = Path(raw).absolute()
    if not path.is_file():
        pytest.skip(f"{name} has no complete actual artifact")
    return path


def _actual_plan() -> tuple[Path, dict]:
    path = _actual_path("QCSD_V10_PLAN_PATH")
    return path, inputs.load_plan(path)


def test_v10_abi_keeps_v9_distinct_and_exactly_pins_action_readers():
    assert inputs.VERSIONS[inputs.V9_CONTINUATION_PLAN_TYPE][0] == 9
    assert inputs.VERSIONS[inputs.V10_CONTINUATION_PLAN_TYPE] == (
        10, inputs.V10_CONTRACT, inputs.V10_INPUT_TYPE, inputs.V10_PRODUCERS)
    assert inputs.V10_PRODUCERS != inputs.V9_PRODUCERS
    assert inputs.V10_ACTION_SOURCES != inputs.V9_ACTION_SOURCES
    assert inputs.CONTROL_SOURCES[10] == inputs.CONTROL_SOURCES[8]


def test_genuine_v10_plan_reopens_v8_reservations_and_v9_prebirth_raw():
    path, plan = _actual_plan()
    old = inputs.load_plan(inputs.reopen(plan["original_plan"]))
    failed = inputs.load_plan(inputs.reopen(plan["prebirth_failure"]["plan"]))
    assert old["schema_version"] == 8 and failed["schema_version"] == 9
    assert plan["candidates"] == old["candidates"][1:] == failed["candidates"]
    assert plan["reserved_candidates"] == failed["reserved_candidates"]
    assert plan["original_candidate_indices"] == [2, 3, 4, 5]
    assert plan["source"] == old["source"] == failed["source"]
    assert plan["source_metadata"] == old["source_metadata"] == failed["source_metadata"]
    assert plan["browser_image"] == old["browser_image"] == failed["browser_image"]
    refusal = plan["prebirth_failure"]
    assert refusal["candidate_attempt_born"] is False
    assert refusal["candidate32_site_rejected"] is False
    assert inputs.zero(refusal) and inputs.zero(plan)
    assert len(refusal["tree"]["files"]) == 9
    files, roots = inputs.plan_files(path)
    files, roots = set(files), set(roots)
    assert inputs.reopen(refusal["plan"]) in files
    assert Path(refusal["root"]) in roots
    assert {inputs.reopen(ref) for ref in refusal["tree"]["files"].values()} <= files
    for operation in ("before_actors", "discover"):
        assert {inputs.reopen(ref) for ref in refusal[operation].values()} <= files
    retained = json.loads(inputs.reopen(plan["retained_interruption"]).read_text())
    original_inputs = json.loads(inputs.reopen(retained["original_root_inputs"]).read_text())
    driver = inputs.reopen(original_inputs["driver"])
    assert driver in files and driver.with_name("authorities.json") in files
    assert {inputs.reopen(original_inputs[key]) for key in ("producer_closure", "producer_review")} <= files


def test_genuine_v10_plan_rejects_substituted_producer_and_action_reader():
    _, plan = _actual_plan()
    for group, key in (("producer_sources", "graph_input.py"),
                       ("action_local_sources", "controller.py")):
        altered = deepcopy(plan)
        altered[group][key]["sha256"] = "0" * 64
        with pytest.raises(ValueError):
            inputs._producer(altered)


def test_genuine_v10_batch_inputs_and_typed_failures_remain_distinct():
    plan_path, plan = _actual_plan()
    root = _actual_path("QCSD_V10_BATCH_CLOSURE")
    batch = json.loads(root.read_text())
    if root.name != "batch-closed.json" or batch["plan"] != inputs.reference(plan_path):
        raise AssertionError("V10 batch is not the bound complete ordered result")
    assert len(batch["candidates"]) == len(plan["candidates"])
    for local, row in enumerate(batch["candidates"], 1):
        assert row["local_index"] == local
        assert row["candidate"] == plan["candidates"][local - 1]
        assert inputs.zero(row)
        evidence = inputs.reopen(row["evidence"])
        assert evidence.parent == root.parent / "attempts" / f"candidate-{local:06d}"
        if row["discovery_returncode"] == 0:
            graph, neutral = inputs.load_input(evidence)
            assert evidence.name == "whole-graph-input.json"
            assert graph["candidate"] == row["candidate"]
            assert graph["plan"] == inputs.reference(plan_path)
            assert graph["http3_get_performed"] is False and inputs.zero(graph)
            assert neutral["resources"]
            files, _ = inputs.input_files(evidence)
            assert evidence in files
        elif row["discovery_returncode"] == 1:
            failure = inputs.load_failure(evidence)
            assert evidence.name == "failed.json"
            assert failure["candidate"] == row["candidate"]
            assert failure["plan"] == inputs.reference(plan_path)
            assert failure["outcome"] == "operational-discovery-failure-no-admission"
            assert inputs.zero(failure)
        else:
            raise AssertionError("incomplete or prebirth V10 attempt is not a closed row")
