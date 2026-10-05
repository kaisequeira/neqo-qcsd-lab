"""One portable action owns facts; the optional actual witness has zero credit.

Dispatch boundaries in the small owner/fence cases are synthetic. The bound
five-sidecar case executes the unchanged real witness derivation and all its
current Source/runtime/group/raw validators; only the stage output work is
substituted, so no capture or other physical action is performed.
"""
from importlib import util
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from qcsd_lab import rapid_operation_facts as facts

ROOT = Path(__file__).resolve().parents[1]
RECIPE = ROOT / "tools/_rapid_class_mode_flight/flight/operator.py"


@pytest.fixture
def recipe():
    spec = util.spec_from_file_location("portable_action_facts_recipe", RECIPE)
    value = util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def invoke(recipe, monkeypatch, tmp_path):
    monkeypatch.setattr(sys, "argv", [str(RECIPE), "finalize", "--setup",
        str(tmp_path / "unused-setup.json"), "--setup-sha256", "a" * 64])
    return recipe.main()


def test_action_owns_facts_and_permits_disjoint_output(tmp_path, recipe, monkeypatch, capsys):
    raw = tmp_path / "retained" / "raw.json"
    raw.parent.mkdir()
    raw.write_bytes(b"retained raw\n")
    observed = []

    def finalize(args):
        context = facts.current_context()
        observed.append(context)
        context.watch_tree(raw.parent)
        context.remember("selected", {"complete": True})
        output = tmp_path / "fresh-output"
        output.mkdir()
        (output / "setup.json").write_bytes(b"new output\n")
        return {"retained_complete": context.get("selected")["complete"]}

    monkeypatch.setattr(recipe, "finalize", finalize)
    invoke(recipe, monkeypatch, tmp_path)
    assert isinstance(observed[0], facts.OperationFacts)
    assert facts.current_context() is None
    assert json.loads(capsys.readouterr().out) == {"retained_complete": True}


def test_existing_context_stays_caller_owned(tmp_path, recipe, monkeypatch, capsys):
    parent = facts.OperationFacts()
    parent.remember("prior", {"value": 1})
    raw = tmp_path / "raw.json"
    raw.write_bytes(b"first\n")
    parent.watch_file(raw)
    checks = []
    original_check = parent.check
    monkeypatch.setattr(parent, "check", lambda: checks.append(True))

    def finalize(args):
        assert facts.current_context() is parent
        assert parent.get("prior") == {"value": 1}
        return {"borrowed": True}

    monkeypatch.setattr(recipe, "finalize", finalize)
    with parent.scope():
        invoke(recipe, monkeypatch, tmp_path)
        assert facts.current_context() is parent
        assert not checks
    assert facts.current_context() is None
    raw.write_bytes(b"changed\n")
    with pytest.raises(ValueError, match="bytes or mode"):
        original_check()
    assert json.loads(capsys.readouterr().out) == {"borrowed": True}


@pytest.mark.parametrize("mutation", ["bytes", "mode", "membership"])
def test_owned_fence_rejects_post_read_mutation_before_success(mutation, tmp_path, recipe, monkeypatch, capsys):
    raw = tmp_path / "retained" / "raw.json"
    raw.parent.mkdir()
    raw.write_bytes(b"complete raw\n")
    raw.chmod(0o600)

    def finalize(args):
        context = facts.current_context()
        context.watch_tree(raw.parent)
        if mutation == "bytes":
            raw.write_bytes(b"changed raw\n")
        elif mutation == "mode":
            raw.chmod(0o644)
        else:
            (raw.parent / "unexpected.json").write_bytes(b"extra\n")
        return {"must_not_print": True}

    monkeypatch.setattr(recipe, "finalize", finalize)
    with pytest.raises(ValueError, match="tree bytes, mode or membership"):
        invoke(recipe, monkeypatch, tmp_path)
    assert facts.current_context() is None
    assert capsys.readouterr().out == ""


def test_exception_restores_context_and_prints_no_success(tmp_path, recipe, monkeypatch, capsys):
    def finalize(args):
        assert isinstance(facts.current_context(), facts.OperationFacts)
        raise ValueError("public boundary refused")

    monkeypatch.setattr(recipe, "finalize", finalize)
    with pytest.raises(ValueError, match="public boundary refused"):
        invoke(recipe, monkeypatch, tmp_path)
    assert facts.current_context() is None
    assert capsys.readouterr().out == ""


def test_two_public_actions_get_independent_memos(tmp_path, recipe, monkeypatch, capsys):
    contexts = []

    def finalize(args):
        context = facts.current_context()
        assert not context.has("action")
        context.remember("action", len(contexts))
        contexts.append(context)
        return {"action": len(contexts)}

    monkeypatch.setattr(recipe, "finalize", finalize)
    invoke(recipe, monkeypatch, tmp_path)
    invoke(recipe, monkeypatch, tmp_path)
    assert contexts[0] is not contexts[1]
    assert facts.current_context() is None
    assert [json.loads(row) for row in capsys.readouterr().out.splitlines()] == [{"action": 1}, {"action": 2}]


def test_isolated_public_wrapper_loads_relative_source_before_guard(tmp_path):
    setup = tmp_path / "setup.json"
    setup.write_bytes(b"{}\n")
    environment = {key: value for key, value in os.environ.items()
                   if key not in {"PYTHONPATH", "QCSD_RAPID_COLLECTION_COMPATIBILITY"}}
    result = subprocess.run([sys.executable, "-I", "-B", str(ROOT / "tools/rapid_class_mode_flight.py"),
        "finalize", "--setup", str(setup), "--setup-sha256", "a" * 64],
        cwd=tmp_path, env=environment, text=True, capture_output=True)
    assert result.returncode == 1
    assert "prospective setup changed" in result.stderr
    assert "ModuleNotFoundError" not in result.stderr
    assert result.stdout == ""


def test_bound_actual_five_sidecars_share_one_real_witness_derivation(tmp_path, recipe, monkeypatch, capsys):
    path_text = os.environ.get("QCSD_TEST_ACTION_WITNESS")
    expected = os.environ.get("QCSD_TEST_ACTION_WITNESS_SHA256")
    if path_text is None or expected is None:
        pytest.skip("provide an actual hash-bound current qualification witness")
    path = Path(path_text)
    raw = path.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == expected
    witness = json.loads(raw)
    assert witness["scientific_credit"] is False and witness["formal_accepted_trace_count"] == 0
    assert len(witness["workloads"]) == 5
    canonical_ref = witness["consumer"]["canonical"]
    canonical_raw = Path(canonical_ref["path"]).read_bytes()
    assert hashlib.sha256(canonical_raw).hexdigest() == canonical_ref["sha256"]
    canonical = json.loads(canonical_raw)
    from qcsd_lab import qualification_delivery_compatibility as compatibility
    original = compatibility._derive
    calls = []

    def counted(*args, **kwargs):
        calls.append(True)
        return original(*args, **kwargs)

    monkeypatch.setattr(compatibility, "_derive", counted)

    def finalize(args):
        for row in witness["workloads"]:
            sidecar_raw = Path(row["sidecar"]["path"]).read_bytes()
            assert hashlib.sha256(sidecar_raw).hexdigest() == row["sidecar"]["sha256"]
            recipe.current_sidecar(json.loads(sidecar_raw), canonical,
                workload_id=row["workload_id"], workload_sha256=row["base_manifest"]["sha256"],
                delivery_compatibility={"path": str(path), "sha256": expected},
                body_policy=witness["application_body_identity_policy"])
        return {"five_original_sidecars_reopened": True, "scientific_credit": False}

    monkeypatch.setattr(recipe, "finalize", finalize)
    invoke(recipe, monkeypatch, tmp_path)
    assert len(calls) == 1
    assert facts.current_context() is None
    assert json.loads(capsys.readouterr().out) == {"five_original_sidecars_reopened": True, "scientific_credit": False}
