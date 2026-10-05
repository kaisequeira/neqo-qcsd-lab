"""Portable HOST checks of qualification controls; no image or Native effects.

The authenticated scientific plan and physical qualifier/publisher are synthetic
boundaries. The actual portable operator constructs argv, reopens its reuse
reference, forwards declared limits and writes its zero-credit completion.
"""
from importlib import util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest


RECIPE = Path(__file__).resolve().parents[1] / "tools/_rapid_class_mode_flight/flight/operator.py"


@pytest.fixture
def recipe():
    spec = util.spec_from_file_location("portable_flight_control_recipe", RECIPE)
    module = util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def image_plan(tmp_path, recipe, reuse=None):
    output = tmp_path / "output"
    output.mkdir()
    recipe.create(output / "plan.json", b"{}\n")
    return {"name": "fixture-flight", "reuse": reuse,
        "canonical_runtime": {"collection_image_digest": "sha256:" + "a" * 64},
        "clean_runtime_root": str(tmp_path / "source"),
        "execution_root": str(tmp_path / "execution"),
        "helper_path": str(tmp_path / "helpers.py"),
        "static_preparation_roots": [str(tmp_path / "selected-raw")],
        "group_preparation_roots": [str(tmp_path / "group-raw")]}, output


def volumes(argv):
    return [argv[index + 1] for index, token in enumerate(argv) if token == "--volume"]


def common_volumes(plan, output, action):
    return [plan["clean_runtime_root"] + ":/runtime-src:ro",
        plan["execution_root"] + ":/lab:" + ("rw" if action == "qualify-image" else "ro"),
        str(output) + ":/diagnostic:rw", str(RECIPE) + ":/recipe.py:ro",
        plan["helper_path"] + ":/helpers.py:ro"]


@pytest.mark.parametrize("cap", [16 * 1024 * 1024, 64 * 1024 * 1024])
def test_qualification_forwards_declared_deadline_and_cap(cap, tmp_path, recipe, monkeypatch):
    from qcsd_lab import response_budget_qualification as budget

    execution, output = tmp_path / "execution", tmp_path / "output"
    output.mkdir()
    plan = {"selected_classes": [{"workload_id": "site-one"}, {"workload_id": "site-two"}],
        "capture_limits": {"max_response_bytes": cap, "timeout_seconds": 120}, "reuse": None,
        "group_qualification_set": "fixture-group", "qualification_set": "fixture-single",
        "workload_id": "site-one", "workload_sha256": "a" * 64}
    monkeypatch.setattr(recipe, "checked_plan", lambda args, image=False: (plan, output, execution))
    qualified, published = [], []

    def qualify(workload_id, **kwargs):
        qualified.append((workload_id, kwargs))
        recipe.create(kwargs["qualification_root"] / (workload_id + ".json"), b"{}\n")

    def publish(ids, **kwargs):
        published.append((list(ids), kwargs))
        return SimpleNamespace(manifest_sha256="b" * 64, qualification_set=kwargs["qualification_set"])

    monkeypatch.setattr(budget, "qualify_response_chaff_v2", qualify)
    monkeypatch.setattr(budget, "publish_named_qualification_set", publish)
    recipe.image_action(SimpleNamespace(command="qualify-image", plan_sha256="c" * 64))
    assert [identifier for identifier, _ in qualified] == ["site-one", "site-two"]
    for _, kwargs in qualified:
        assert kwargs["timeout_seconds"] == 120
        assert kwargs["max_response_bytes"] == cap
        assert kwargs["workload_root"] == execution / "config/workloads"
    assert [ids for ids, _ in published] == [["site-one", "site-two"], ["site-one"]]
    for _, kwargs in published:
        assert kwargs["qualification_sidecar_schema_version"] == budget.SIDECAR_SCHEMA_VERSION == 3
        assert kwargs["qualification_scope"] == "response-only"
    completion = json.loads((output / "qualification-complete.json").read_bytes())
    assert completion["reused_same_current_evidence"] is False
    assert completion["formal_accepted_trace_count"] == 0
    assert completion["scientific_credit"] is False


def test_reuse_qualifier_mounts_only_exact_authenticated_readonly_file(tmp_path, recipe):
    named = tmp_path / "retained-named" / "_qualification-set.json"
    named.parent.mkdir()
    named.write_bytes(b'{"qualification_sidecar_schema_version":3}\n')
    plan, output = image_plan(tmp_path, recipe, {"manifest": recipe.ref(named)})
    argv = recipe.image_argv(plan, output, "qualify-image")
    assert volumes(argv) == common_volumes(plan, output, "qualify-image") + [
        str(named) + ":" + str(named) + ":ro",
        plan["group_preparation_roots"][0] + ":" + plan["group_preparation_roots"][0] + ":ro"]
    assert argv[argv.index("--network") + 1] == "none"
    assert not any(value.startswith(str(named.parent) + ":") for value in volumes(argv))
    assert named.read_bytes() == b'{"qualification_sidecar_schema_version":3}\n'


@pytest.mark.parametrize("action", ["preamble-image", "verify-image"])
def test_other_actions_preserve_mounts_and_have_no_reuse_volume(action, tmp_path, recipe):
    named = tmp_path / "named.json"
    named.write_bytes(b"{}\n")
    plan, output = image_plan(tmp_path, recipe, {"manifest": recipe.ref(named)})
    argv = recipe.image_argv(plan, output, action)
    roots = plan["static_preparation_roots"] if action == "verify-image" else plan["group_preparation_roots"]
    assert volumes(argv) == common_volumes(plan, output, action) + [root + ":" + root + ":ro" for root in roots]
    assert argv[argv.index("--network") + 1] == "none"
    assert not any(str(named) in volume for volume in volumes(argv))


@pytest.mark.parametrize("mutation", ["bytes", "symlink", "volume-delimiter"])
def test_reuse_manifest_refuses_mutation_before_returning_argv(mutation, tmp_path, recipe):
    named = tmp_path / ("bad:name.json" if mutation == "volume-delimiter" else "named.json")
    named.write_bytes(b"{}\n")
    record = recipe.ref(named)
    if mutation == "bytes":
        named.write_bytes(b'{"changed":true}\n')
    elif mutation == "symlink":
        target = tmp_path / "target.json"
        target.write_bytes(named.read_bytes())
        named.unlink()
        named.symlink_to(target)
    plan, output = image_plan(tmp_path, recipe, {"manifest": record})
    with pytest.raises(ValueError):
        recipe.image_argv(plan, output, "qualify-image")


def test_fresh_qualification_preserves_bridge_and_adds_no_reuse_mount(tmp_path, recipe):
    plan, output = image_plan(tmp_path, recipe)
    argv = recipe.image_argv(plan, output, "qualify-image")
    root = plan["group_preparation_roots"][0]
    assert volumes(argv) == common_volumes(plan, output, "qualify-image") + [root + ":" + root + ":ro"]
    assert argv[argv.index("--network") + 1] == "bridge"
