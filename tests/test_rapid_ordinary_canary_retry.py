"""HOST control proofs; original deep/capture semantics are explicit boundaries.

The opt-in actual case reads only command/declaration/runtime Source metadata.
It neither replays the original verifier nor reopens the result/raw GET tree.
"""
import copy
import json
import os
from pathlib import Path

import pytest

from qcsd_lab import rapid_ordinary_canary_retry as retry
from qcsd_lab import rapid_rolling_readiness as old
from qcsd_lab import static_evidence_transport as transport
from qcsd_lab.rapid_operation_facts import OperationFacts

ROOT = Path(__file__).resolve().parents[1]


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(old._encoded(value))
    return ref(path)


def ref(path):
    return {"path": str(path), "sha256": old._sha(path.read_bytes())}


def records(parent, command, code, at):
    parent.mkdir(parents=True, exist_ok=True)
    stdout, stderr = parent / "undefended-deep.stdout.log", parent / "undefended-deep.stderr.log"
    stdout.write_bytes(b"controlled metadata only\n")
    stderr.write_bytes(b"controlled retained error\n" if code else b"")
    return {"started": write(parent / "undefended-deep-started.json", {"command": command, "started_at": at}),
        "completed": write(parent / "undefended-deep-completed.json", {"returncode": code,
            "invocation_error": None, "elapsed_seconds": 1,
            "stdout_sha256": old._sha(stdout.read_bytes()), "stderr_sha256": old._sha(stderr.read_bytes()),
            "completed_at": at.replace("00Z", "01Z")}), "stdout": ref(stdout), "stderr": ref(stderr)}


def fixture(tmp_path, monkeypatch):
    directory = tmp_path / "flight"
    directory.mkdir()
    source, execution = tmp_path / "source", tmp_path / "execution"
    source.mkdir(); execution.mkdir()
    recipe, helper = tmp_path / "recipe.py", tmp_path / "helper.py"
    recipe.write_bytes(b"controlled unchanged verifier program")
    helper.write_bytes(b"controlled unchanged helper")
    roots = [str(tmp_path / "own-audit"), str(tmp_path / "peer-audit")]
    for root in roots:
        Path(root).mkdir()
    renewal = write(tmp_path / "renewal.json", {"controlled": "already authenticated renewal boundary"})
    original = write(directory / "lineage/original-manifest.json", {"resources": [{"id": 0}, {"id": 1}]})
    plan = {"name": "controlled-ordinary", "recipe_sha256": ref(recipe)["sha256"], "helper_sha256": ref(helper)["sha256"],
        "clean_runtime_root": str(source), "execution_root": str(execution),
        "canonical_runtime": {"collection_image_digest": "sha256:" + "a" * 64},
        "original_workload_sha256": original["sha256"], "ordinary_renewal": renewal,
        "group_preparation_roots": roots, "campaigns": [{"mode": "undefended"}], "reuse": None}
    plan_ref = write(directory / "plan.json", plan)
    receipt = write(directory / "undefended-deep-verification.json", {"root": "/lab/results/controlled/result"})
    # Only immutable original admission/deep semantic authorities are controlled.
    monkeypatch.setattr(retry, "group_roots", lambda p, d: p["group_preparation_roots"])
    monkeypatch.setattr(transport, "manifest_roots", lambda manifest: [Path(roots[0])])
    exemplar = ["docker", "run", "--user", "1000:1000", "--volume", str(recipe) + ":/recipe.py:ro",
                "--volume", str(helper) + ":/helpers.py:ro"]
    first = old._deep_command(plan, directory, plan_ref["sha256"], "undefended", "/lab/results/controlled/result",
                              exemplar, ordinary_transport="first")
    complete = old._deep_command(plan, directory, plan_ref["sha256"], "undefended", "/lab/results/controlled/result",
                                 exemplar, ordinary_transport="group")
    complete[complete.index("--name") + 1] += "-transport-recovery001"
    failed = records(directory / "logs", first, 1, "2026-10-06T00:00:00Z")
    retry_root = tmp_path / "retry"
    deep = records(retry_root / "operations", complete, 0, "2026-10-06T00:00:02Z")
    declaration = write(retry_root / "transport-declaration.json", {
        "original_plan": plan_ref, "original_failed_deep": failed["completed"],
        "added_declared_readonly_group_roots": [roots[1] + ":" + roots[1] + ":ro"],
        "original_verifier_program_and_image_unchanged": True, "capture_reexecuted": False,
        "readiness_authority_claimed": False, "formal_credit": 0})
    reference = {"schema_version": 4, "artifact_type": retry.TYPE, "plan": plan_ref, "deep_receipt": receipt,
        "failed_deep": failed, "deep": deep, "capture": failed, "transport_declaration": declaration,
        "reader_sources": retry._sources()}
    return reference, plan, directory, first, complete


def test_retry_command_and_legacy_command_remain_distinct(tmp_path, monkeypatch):
    reference, plan, directory, first, complete = fixture(tmp_path, monkeypatch)
    actual = retry._transport(reference, plan, directory, reference["plan"]["sha256"], "undefended", "/lab/results/controlled/result")
    assert actual["command"] == actual["expected_command"] == complete
    legacy = old._deep_command(plan, directory, reference["plan"]["sha256"], "undefended", "/lab/results/controlled/result", first)
    assert legacy != first
    assert len(complete) == len(first) + 2
    assert complete[complete.index("--network") + 1] == "none"


@pytest.mark.parametrize("change", ["extra-rw-mount", "nonzero-success"])
def test_retry_rejects_changed_transport_or_status(tmp_path, monkeypatch, change):
    reference, plan, directory, _, _ = fixture(tmp_path, monkeypatch)
    key = "started" if change == "extra-rw-mount" else "completed"
    path = Path(reference["deep"][key]["path"])
    value = json.loads(path.read_bytes())
    if change == "extra-rw-mount":
        index = value["command"].index("--workdir")
        value["command"][index:index] = ["--volume", f"{tmp_path}:{tmp_path}:rw"]
    else:
        value["returncode"] = 1
    reference["deep"][key] = write(path, value)
    with pytest.raises(ValueError):
        retry._transport(reference, plan, directory, reference["plan"]["sha256"], "undefended", "/lab/results/controlled/result")


def test_public_schema_dispatch_and_final_mode_fence(tmp_path, monkeypatch):
    reference, _, _, _, _ = fixture(tmp_path, monkeypatch)
    runtime = {key: str(tmp_path) for key in old.RUNTIME_KEYS}
    runtime["module_root"] = str(ROOT)
    monkeypatch.setattr(OperationFacts, "bind_canary", lambda self, ref, runtime: None)
    monkeypatch.setattr(retry, "validate_overlay", lambda *args: None)
    calls = []
    def original(ref, **kwargs):
        assert ref["schema_version"] == 1
        assert kwargs["_transport_recovery"]["command"] == kwargs["_transport_recovery"]["expected_command"]
        calls.append(ref)
        return {"source": {"controlled": "original capture/deep semantic authority"}, **old.ZERO}
    monkeypatch.setattr(old, "_validate_canary", original)
    with OperationFacts().scope() as context:
        facts = old.validate_canary(reference, runtime=runtime, mode="undefended")
        assert facts["capture_reexecuted"] is False and facts["formal_accepted_trace_count"] == 0
        assert len(calls) == 1
        path = Path(reference["deep"]["stderr"]["path"])
        path.chmod(path.stat().st_mode ^ 0o100)
        with pytest.raises(ValueError):
            context.check()


def test_actual_closed_retry_metadata_and_exact_overlay(monkeypatch):
    value = os.environ.get("QCSD_ORDINARY_RETRY_ACTUAL_ROOT")
    if value is None:
        pytest.skip("optional actual metadata fixture; no network or deep replay")
    root = Path(value)
    declaration = old._json(old._read(root / "transport-declaration.json"))
    directory = Path(declaration["original_plan"]["path"]).parent
    plan = old._json(old._read(directory / "plan.json"))
    receipt = old._json(old._read(directory / "undefended-deep-verification.json"))
    def existing(parent):
        return {key: ref(parent / ("undefended-deep" + suffix)) for key, suffix in
            (("started", "-started.json"), ("completed", "-completed.json"), ("stdout", ".stdout.log"), ("stderr", ".stderr.log"))}
    reference = {"plan": ref(directory / "plan.json"), "failed_deep": existing(directory / "logs"),
        "deep": existing(root / "operations"), "transport_declaration": ref(root / "transport-declaration.json")}
    # Original full-group admission has an independent actual renewal receipt.
    # This control tests genuine outer command ABI, not another admission replay.
    monkeypatch.setattr(retry, "group_roots", lambda p, d: p["group_preparation_roots"])
    monkeypatch.setattr(transport, "manifest_roots", lambda manifest: list(map(Path, plan["static_preparation_roots"])))
    result = retry._transport(reference, plan, directory, reference["plan"]["sha256"], "undefended", receipt["root"])
    assert result["command"] == result["expected_command"]
    runtime = old._json(old._read(directory / "runtime-spec.json"))["inputs"]
    retry.validate_overlay({**runtime, "module_root": str(ROOT)}, plan, directory)
    assert plan["canonical_runtime"]["collection_image_digest"] == runtime["collection_image_digest"]
