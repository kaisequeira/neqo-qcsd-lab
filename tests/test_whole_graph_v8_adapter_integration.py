"""Exact V8 adapter/transport; reviewed external history reconstruction is controlled."""
import json
from pathlib import Path

import pytest
from qcsd_lab import whole_graph_input as inputs
from tests.test_whole_graph_external_controls import plan, failed, write


def test_exact_v8_pair_failure_runtime_and_old_v7_pair(tmp_path, monkeypatch):
    value = plan(8)
    operator = inputs._producer(value)
    assert operator.parent.name == "whole_graph_discovery_v8"
    assert inputs._producer(plan(7)).parent.name == "whole_graph_discovery_v7"
    root, value, _ = failed(tmp_path, monkeypatch, 8)
    assert inputs.load_failure(root / "failed.json") == value


@pytest.mark.parametrize("mutation", ["pair", "mode"])
def test_v8_cannot_substitute_a_pair_or_control_mode(mutation, monkeypatch):
    value = plan(8)
    if mutation == "pair":
        value["producer_sources"]["graph_input.py"] = plan(7)["producer_sources"]["graph_input.py"]
    else:
        value["discovery_control"]["sources"]["navigation_control.py"]["mode"] = "0755"
    monkeypatch.setattr(inputs.subprocess, "run", lambda *args, **kwargs: pytest.fail("must refuse before external execution"))
    with pytest.raises(ValueError): inputs._producer(value)


@pytest.mark.parametrize("changed", [False, True])
def test_v8_transport_retains_original_failure_retirement_refs(tmp_path, monkeypatch, changed):
    declaration = plan(8)
    source = tmp_path / "source"; source.mkdir()
    files = {}
    for name in ("catalogue", "source-metadata", "context", "source-list", "profile", "order", "retained-failure", "retained-raw"):
        target = tmp_path / (name + ".json"); write(target, {"synthetic": name})
        files[name] = inputs.reference(target)
    declaration.update(catalogue=files["catalogue"], source_metadata=files["source-metadata"],
        original_prefix={key: files[name] for key, name in (("context", "context"), ("source_list", "source-list"),
            ("profile", "profile"), ("candidate_order", "order"))},
        source={"root": str(source), "files": {}}, previous_plans=[], history=[], history_batches=[],
        reservation_retirements=[{"candidate11_failure": {"binding": files["retained-failure"],
            "refs": {"raw": files["retained-raw"]}}, "original_aggregate_batch_claimed_complete": False}])
    path = tmp_path / "plan.json"; write(path, declaration)
    monkeypatch.setattr(inputs, "load_plan", lambda *args: declaration)
    if changed:
        Path(files["retained-raw"]["path"]).chmod(0o600)
        with pytest.raises(ValueError): inputs.plan_files(path)
    else:
        declared, _ = inputs.plan_files(path)
        assert {Path(files[name]["path"]) for name in ("retained-failure", "retained-raw")} <= set(declared)
