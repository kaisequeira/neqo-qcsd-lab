"""V11 reader and exact Source53 compatibility; no browser, GET or capture.

QCSD_V11_PLAN_PATH binds an actual declared next batch. Its external verifier
reconstructs the completed predecessor, V8 interruption and V9 prebirth refusal.
"""
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path

import pytest

from qcsd_lab import whole_graph_input as inputs
from qcsd_lab import rapid_fixed_condition_target as fixed
from tests.test_supplemental_cohort_reader_compatibility import membership_case, source44


def _actual_plan():
    raw = os.environ.get("QCSD_V11_PLAN_PATH")
    if not raw:
        pytest.skip("QCSD_V11_PLAN_PATH is not bound to an actual declaration")
    path = Path(raw).absolute()
    return path, inputs.load_plan(path)


def test_v11_registration_is_distinct_and_retains_historical_control():
    assert inputs.VERSIONS[inputs.V11_PLAN_TYPE] == (
        11, inputs.V11_CONTRACT, inputs.V11_INPUT_TYPE, inputs.V11_PRODUCERS)
    assert inputs.VERSIONS[inputs.V10_CONTINUATION_PLAN_TYPE][0] == 10
    assert inputs.V11_PRODUCERS != inputs.V10_PRODUCERS
    assert inputs.V11_ACTION_SOURCES != inputs.V10_ACTION_SOURCES
    assert inputs.CONTROL_SOURCES[11] == inputs.CONTROL_SOURCES[8]


def test_source53_v11_projection_retains_every_original_byte(tmp_path):
    current = Path(inputs.__file__)
    before_raw = fixed._v11_input_reader_source_projection(current.read_bytes())
    assert hashlib.sha256(before_raw).hexdigest() == (
        "455aa51a397f025d4a6b0145c5a963d6455c0af51159b03535c69b506150d47b")
    before = tmp_path / "whole_graph_input.py"
    before.write_bytes(before_raw); before.chmod(0o644)
    assert fixed._compatible_acquisition_code("src/qcsd_lab/whole_graph_input.py",
        fixed.reference(before), fixed.reference(current))
    with pytest.raises(ValueError):
        fixed._v11_input_reader_source_projection(current.read_bytes() + b"\n# changed\n")
    before.write_bytes(before_raw + b"\n# changed historical source\n")
    with pytest.raises(ValueError):
        fixed._compatible_acquisition_code("src/qcsd_lab/whole_graph_input.py",
            fixed.reference(before), fixed.reference(current))


def test_bound_source53_reader_can_reopen_without_rewriting_membership(membership_case):
    old, current, sources, package, _ = membership_case
    previous = Path(sources["target"]["path"]).parent / "whole_graph_input.py"
    previous.write_bytes(fixed._v11_input_reader_source_projection(
        (package / "whole_graph_input.py").read_bytes()))
    previous.chmod(0o644)
    old["files"].append(fixed.reference(previous))
    snapshot = deepcopy((old, current))
    assert fixed._compatible_membership(old, current, sources)
    assert (old, current) == snapshot
    previous.chmod(0o444)
    old["files"][-1] = fixed.reference(previous)
    with pytest.raises(ValueError):
        fixed._compatible_membership(old, current, sources)


def test_genuine_v11_plan_keeps_completed_predecessor_and_all_retained_proofs():
    path, plan = _actual_plan()
    previous = inputs.load_plan(inputs.reopen(plan["previous_plan"]))
    batch_path = inputs.reopen(plan["previous_batch"])
    batch = json.loads(batch_path.read_bytes())
    assert previous["schema_version"] in (10, 11)
    assert batch["plan"] == plan["previous_plan"] and inputs.zero(batch)
    assert plan["original_plan"] == previous["original_plan"]
    assert plan["retained_interruption"] == previous["retained_interruption"]
    assert plan["prebirth_failure"] == previous["prebirth_failure"]
    assert [(row["catalogue_position"], row["candidate_id"]) for row in plan["candidates"]] == [
        (36, "tranco-0000516"), (37, "tranco-0000008"),
        (38, "tranco-0000901"), (39, "tranco-0000976"), (40, "tranco-0000094")]
    assert inputs.zero(plan) and inputs.zero(plan["prebirth_failure"])
    files, roots = inputs.plan_files(path)
    files, roots = set(files), set(roots)
    assert inputs.reopen(plan["previous_plan"]) in files and batch_path in files
    assert batch_path.parent in roots
    assert {p for p in batch_path.parent.rglob("*") if p.is_file()} <= files
    refusal = plan["prebirth_failure"]
    assert inputs.reopen(refusal["plan"]) in files and Path(refusal["root"]) in roots
    assert {inputs.reopen(ref) for ref in refusal["tree"]["files"].values()} <= files
    retained = json.loads(inputs.reopen(plan["retained_interruption"]).read_bytes())
    original = json.loads(inputs.reopen(retained["original_root_inputs"]).read_bytes())
    driver = inputs.reopen(original["driver"])
    assert driver in files and driver.with_name("authorities.json") in files
    assert {inputs.reopen(original[key]) for key in ("producer_closure", "producer_review")} <= files


@pytest.mark.parametrize("group,key", [("producer_sources", "graph_input.py"),
    ("action_local_sources", "controller.py")])
def test_genuine_v11_plan_refuses_substituted_reader_before_external_execution(monkeypatch, group, key):
    _, plan = _actual_plan()
    altered = deepcopy(plan)
    altered[group][key]["sha256"] = "0" * 64
    monkeypatch.setattr(inputs.subprocess, "run", lambda *a, **k: pytest.fail("must refuse before subprocess"))
    with pytest.raises(ValueError):
        inputs._producer(altered)
