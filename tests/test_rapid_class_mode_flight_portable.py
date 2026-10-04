"""Portable entry point checks; the optional real-input case performs HOST staging only."""
from hashlib import sha256
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

from tests.test_supplied_static_get import actual_contract_fixture
from tests.test_supplied_static_preparation import fixed_graph
from tests.test_static_budget_successor import budget_fixture
from tests.test_static_budget_capture import admitted_budget


ROOT = Path(__file__).resolve().parents[1]
ENTRY = ROOT / "tools/rapid_class_mode_flight.py"
BUNDLE = ROOT / "tools/_rapid_class_mode_flight"
FILES = {
    "flight/operator.py": "93244dfb93ba9331d859faf8806c489715ed8594db773b7ed50ca54f7800129a",
    "rapid-v6-first-site-operator-20261004-001/operator.py":
        "f50d4781cde87ee78d6d5ee6efa85ebf586d680068ec9569342fb16df111b8f1",
    "application-response-policy-runtime-20261003-001/runtime_recipe.py":
        "7e7653fe26a89ecc512a2b17b37438f6af6f3c97ea4f95ee77ea995e27594af7",
}


def load_recipe():
    spec = importlib.util.spec_from_file_location("portable_flight_test", BUNDLE / "flight/operator.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run_entry(entry, *args, cwd):
    return subprocess.run([sys.executable, "-I", "-B", str(entry), *map(str, args)],
                          cwd=cwd, text=True, capture_output=True, check=False)


def test_exact_bundled_producers_and_helper_tamper_refusal(tmp_path):
    for relative, digest in FILES.items():
        assert sha256((BUNDLE / relative).read_bytes()).hexdigest() == digest
    recipe = load_recipe()
    assert recipe.FIRST_HELPER.is_relative_to(BUNDLE)
    assert recipe.RECORDER.is_relative_to(BUNDLE)
    recipe.module(recipe.FIRST_HELPER, recipe.FIRST_HELPER_SHA, "portable_first_helper")
    recipe.module(recipe.RECORDER, recipe.RECORDER_SHA, "portable_flight_recorder")
    changed = tmp_path / "changed-helper.py"
    changed.write_bytes(recipe.FIRST_HELPER.read_bytes() + b"\n")
    with pytest.raises(ValueError, match="immutable helper changed"):
        recipe.module(changed, recipe.FIRST_HELPER_SHA, "must_not_execute")


def test_relocated_clone_cli_has_no_parent_workspace_dependency(tmp_path):
    clone = tmp_path / "clone with spaces"
    (clone / "tools").mkdir(parents=True)
    shutil.copy2(ENTRY, clone / "tools" / ENTRY.name)
    shutil.copytree(BUNDLE, clone / "tools" / BUNDLE.name)
    entry = clone / "tools" / ENTRY.name
    result = run_entry(entry, "--help", cwd=tmp_path)
    assert result.returncode == 0, result.stderr
    assert "stage" in result.stdout and "finalize" in result.stdout
    stage = run_entry(entry, "stage", "--help", cwd=tmp_path)
    assert stage.returncode == 0, stage.stderr
    assert "--expected-native-commit" in stage.stdout
    assert "{undefended,front,tamaraw,buflo,cs-buflo}" in stage.stdout
    assert not (tmp_path / "diagnostic-rehearsals").exists()


def test_portable_typed_budget_uses_manifest_context_without_image_enrollment(admitted_budget, monkeypatch):
    """Synthetic complete GET emitter fixture; no installed/image or site credit."""
    from copy import deepcopy
    from qcsd_lab import static_budget_capture as capture
    from qcsd_lab import supplied_static_budget_successor as budget
    from qcsd_lab import supplied_static_admission as static
    from qcsd_lab import rapid_rolling_capture as rolling
    context, terminal, _, _ = admitted_budget
    _, manifest = capture.prepared_workload(context, terminal)
    original_graph = deepcopy(manifest["resources"])
    recipe = load_recipe()

    def unavailable_enrollment(*args, **kwargs):
        raise AssertionError("image cap checks cannot replay an unmounted enrollment")

    monkeypatch.setattr(rolling, "_verify_enrollment", unavailable_enrollment)
    limits = recipe.typed_canary_limits([manifest], None, "tamaraw", None)
    assert limits == {**static.capture_limits(67_108_864, 256), "max_attempts": 1}
    assert capture.context_limits(context) == static.capture_limits(16_777_216, 64)
    assert manifest["resources"] == original_graph
    changed = deepcopy(manifest)
    changed["preparation"][budget.FIELD]["capture_limits"]["max_response_bytes"] //= 2
    with pytest.raises(ValueError):
        recipe.typed_canary_limits([changed], None, "tamaraw", None)


def test_actual_closed_inputs_stage_finalize_and_full_graph(tmp_path):
    names = ("RUNTIME_BUILD", "CLEAN_SOURCE", "STUDY_ROOT", "ENROLLMENT", "OUTPUT")
    env = {name: os.environ.get("QCSD_PORTABLE_TEST_" + name) for name in names}
    if not all(env.values()):
        pytest.skip("Supply QCSD_PORTABLE_TEST_* closed inputs for the HOST-only integration check")
    build, clean, study, enrollment, output = (Path(env[name]) for name in names)
    canonical_path = build / "canonical-runtime.json"
    canonical_raw = canonical_path.read_bytes()
    canonical = json.loads(canonical_raw)
    exported_results = build / "image-context/source/results"
    expected_results = {path.relative_to(exported_results).as_posix(): path.read_bytes()
                        for path in exported_results.rglob("*") if path.is_file()}
    assert not output.exists()
    stage = run_entry(ENTRY, "stage", "--runtime-build-root", build,
        "--clean-runtime-root", clean, "--study-root", study, "--enrollment", enrollment,
        "--output", output, "--python", sys.executable,
        "--canonical-sha256", sha256(canonical_raw).hexdigest(),
        "--expected-lab-commit", canonical["source"]["lab_commit"],
        "--expected-native-commit", canonical["source"]["neqo_commit"],
        "--name", "portable-host-flight", "--campaign-seed", "43", "--mode", "undefended",
        cwd=tmp_path)
    assert stage.returncode == 0, stage.stderr
    staged = json.loads(stage.stdout)
    assert staged["physical_actions_performed"] is False
    assert staged["formal_accepted_trace_count"] == 0
    setup = json.loads((output / "setup.json").read_bytes())
    assert Path(setup["recipe"]["path"]).is_relative_to(BUNDLE)
    final = run_entry(ENTRY, "finalize", "--setup", output / "setup.json",
                      "--setup-sha256", staged["setup"]["sha256"], cwd=tmp_path)
    assert final.returncode == 0, final.stderr
    finalized = json.loads(final.stdout)
    assert finalized["physical_actions_performed"] is False
    assert finalized["formal_accepted_trace_count"] == 0
    plan = json.loads((output / "plan.json").read_bytes())
    assert plan["recipe_sha256"] == FILES["flight/operator.py"]
    assert Path(plan["helper_path"]).is_relative_to(BUNDLE)
    assert plan["campaigns"][0]["mode"] == "undefended"
    assert plan["campaigns"][0]["visits"] == 1
    for row in plan["selected_classes"]:
        original = Path(row["original_workload"]["path"]).read_bytes()
        copied = Path(row["capture_manifest"]["path"]).read_bytes()
        assert copied == original
        assert len(json.loads(copied)["resources"]) == row["full_graph"]["resource_count"]
    commands = json.loads((output / "commands.json").read_bytes())
    assert f"{BUNDLE / 'flight/operator.py'}:/recipe.py:ro" in commands["preamble"]
    assert f"{plan['helper_path']}:/helpers.py:ro" in commands["preamble"]
    assert not list((output / "logs").iterdir())
    # The exported repository has a results README; staging creates no result.
    results = output / "execution-root/results"
    assert {path.relative_to(results).as_posix(): path.read_bytes()
            for path in results.rglob("*") if path.is_file()} == expected_results
    assert not (results / plan["campaigns"][0]["name"]).exists()
