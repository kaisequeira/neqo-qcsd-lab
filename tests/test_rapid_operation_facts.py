"""Operation-local reuse retains raw dependencies and real effect boundaries.

The scheduling derivation is the closed external runtime/qualification seam in
the small fixtures below. Capsule parsing, reference checks, context propagation,
file/tree observations and the public preparation boundary execute real code.
These HOST fixtures claim no installed image pass or accepted traffic.
"""
from __future__ import annotations

import ast
import base64
import copy
import hashlib
import importlib.util
import json
import os
import shutil
import zlib
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from qcsd_lab import rapid_formal_parallel as formal
from qcsd_lab import rapid_lane_evidence as ordinary
from qcsd_lab import rapid_operation_facts as operations
from qcsd_lab import rapid_parallel_capture as parallel
from qcsd_lab import rapid_rolling_capture as rolling
from qcsd_lab import rapid_rolling_readiness as evidence
from qcsd_lab import rapid_rolling_schedule as schedule
from qcsd_lab import chaff_qualification as qualification
from tests.test_rapid_lane_evidence import setup as ordinary_setup
from tests.test_rapid_formal_parallel import formal_setup, _prepare
from tests.test_rapid_rolling_schedule import response_sidecar
from tests.test_rapid_rolling_schedule_source import source_bytes


ROOT = Path(__file__).resolve().parents[1]
V4_FIXTURE_SHA256 = "7f71acd9221eef7d92e359890b33b8f5fa6f676a2500ea70422d9fea1e832141"
V4_HELPER_SHA256 = "18afc767c2c08066b4f547b19af414ef00373456bbd97964c50bbcf769e8f6b0"


def _write(path: Path, value) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(value if isinstance(value, bytes) else evidence._encoded(value))
    return path


def _ref(path: Path) -> dict[str, str]:
    return {"path": str(path), "sha256": evidence._sha(path.read_bytes())}


def _implementation(client_sha256: str, *, successor=False) -> dict:
    files = {name: evidence._sha((ROOT / name).read_bytes()) for name in qualification.IMPLEMENTATION_FILES}
    source = {"image_digest": None, "lab_commit": ("d" if successor else "b") * 40,
        "lab_dirty": False, "lab_patch_sha256": qualification.EMPTY_SHA256,
        "neqo_commit": "c" * 40, "neqo_pinned_commit": "c" * 40,
        "neqo_dirty": False, "neqo_patch_sha256": qualification.EMPTY_SHA256}
    value = {"schema_version": qualification.IMPLEMENTATION_RECEIPT_SCHEMA_VERSION,
        "artifact_type": "qcsd-chaff-qualification-implementation", "domain": qualification.IMPLEMENTATION_RECEIPT_DOMAIN,
        "source": source, "source_files": files,
        "installed_modules": {name: {"path": "/installed/" + name, "sha256": digest}
            for name, digest in files.items() if name in qualification.IMPLEMENTATION_PYTHON_FILES},
        "installed_entrypoint": {"path": "/installed/qcsd-lab", "sha256": files["qcsd-lab"]},
        "neqo_qcsd_client": {"path": "/usr/local/bin/neqo-qcsd-client", "sha256": client_sha256}}
    value["sha256"] = qualification._implementation_aggregate(value)
    qualification._validate_implementation_receipt(value, require_current=False)
    return value


@pytest.fixture
def scheduled(tmp_path, monkeypatch):
    """A real referenced graph; only the expensive external closure is stubbed."""
    data = tmp_path / "study"
    sources = [tmp_path / "original-source", tmp_path / "current-source"]
    runtimes = [tmp_path / "original-runtime", tmp_path / "current-runtime"]
    executions = [data / "original-execution", data / "current-execution"]
    for root in sources:
        _write(root / "qcsd-lab", b"#!/bin/sh\n")
        _write(root / "src/module.py", b"unchanged scientific fixture\n")
    for root in runtimes:
        _write(root / "source.json", {"fixture": "closed runtime identity"})
        _write(root / "client", b"closed executable fixture\n").chmod(0o555)
        _write(root / "raw-operation.stderr", b"")
        _write(root / "canonical.json", {"verified_at": "2000-01-01T00:00:00+00:00"})
    for root in executions:
        _write(root / "qcsd-lab", b"#!/bin/sh\n")
        (root / "config/campaigns").mkdir(parents=True)
        _write(root / "config/campaigns/fixture-formal.yml", b"fixed campaign fixture\n")
        for relative, _ in ordinary.TRAFFIC_FILES.values():
            _write(root / relative, b"fixed traffic fixture\n")
        _write(root / ordinary.STUDY_PROFILE_FILE, (ROOT / ordinary.STUDY_PROFILE_FILE).read_bytes())
        _write(root / "config/workloads/site.json", {"resources": ["unchanged fixture"]})
        _write(root / "config/workloads/site-application-response-evidence/raw.json", {"fixture": True})
    admission = data / "admission"
    admission.mkdir()
    initial = data / "initial-admission"
    initial.mkdir()
    nested_raw = _write(data / "retained-admission-raw.json", {"retained": "raw admission dependency"})
    nested_receipt = _write(data / "nested-admission-receipt.json",
        ordinary.admission._bind("qcsd-operation-test-admission-dependency", {"raw": _ref(nested_raw)}))
    provenance = _write(admission / "provenance.json", {"dependency": _ref(nested_receipt)})
    initial_provenance = _write(initial / "provenance.json", {"dependency": _ref(nested_receipt)})
    policy = _write(data / "policy.json", ordinary.admission._bind(rolling.POLICY_TYPE,
        {"initial_admission_root": str(initial), "dependency": _ref(nested_receipt)}))
    terminal = _write(admission / "sites/site/terminal.json",
        ordinary.admission._bind(ordinary.admission.TERMINAL_TYPE, {"raw": _ref(nested_raw)}))
    parent = _write(data / "parent-enrollment.json", ordinary.admission._bind(rolling.ENROLLMENT_TYPE,
        {"admission_root": str(initial), "admission_provenance": _ref(initial_provenance),
         "policy": _ref(policy), "parent": None, "decisions": []}))
    cohort = _write(data / "cohort.json", ordinary.admission._bind(rolling.ENROLLMENT_TYPE,
        {"admission_root": str(admission), "admission_provenance": _ref(provenance),
         "policy": _ref(policy), "parent": _ref(parent), "decisions": [{"terminal": _ref(terminal)}]}))
    sidecars = data / "sidecars"
    manifest = _write(sidecars / "_qualification-set.json", {"fixture": "named 120-response closure"})
    _write(sidecars / "site.json", {"fixture": "complete retained sidecar"})
    qualifier = _write(data / "qualification.json", {"qualification_sets": [{
        "manifest": str(manifest), "sidecar_root": str(sidecars),
        "qualification_set": "fixture", "prefix_spec_root": None}]})
    canary_root = data / "canary"
    canary_source = tmp_path / "canary-source"
    canary_execution = data / "canary-execution"
    relative = "src/measurement.py"
    source_file = _write(canary_source / relative, b"retained canary measurement source\n")
    _write(canary_execution / relative, source_file.read_bytes())
    _write(canary_root / "source-inventory.json", {
        relative: {"sha256": evidence._sha(source_file.read_bytes()), "executable": False}})
    canary_campaign = _write(canary_execution / "config/campaigns/canary.yml", b"complete frozen canary campaign\n")
    canary_workload = _write(canary_execution / "config/workloads/canary-site.json", {"fixture": "full canary graph"})
    canary_application = canary_execution / "config/workloads/canary-site-application-response-evidence"
    _write(canary_application / "raw.json", {"fixture": "actual canary response bytes"})
    canary_qualification = canary_execution / "config/chaff-response-qualification-store/sets/canary-fixture"
    _write(canary_qualification / "_qualification-set.json", {"fixture": "named canary set"})
    _write(canary_qualification / "canary-site.json", {"fixture": "full canary response qualification"})
    for traffic_relative, _ in ordinary.TRAFFIC_FILES.values():
        _write(canary_execution / traffic_relative, (ROOT / traffic_relative).read_bytes())
    canary_recipe = _write(tmp_path / "external-canary-recipe.py", b"closed original installed deep recipe\n")
    canary_helper = _write(tmp_path / "external-canary-helper.py", b"closed original installed deep helper\n")
    canary_plan = _write(canary_root / "plan.json", {"fixture": "complete canary",
        "clean_runtime_root": str(canary_source), "execution_root": str(canary_execution),
        "workload_id": "canary-site", "qualification_set": "canary-fixture",
        "campaigns": [{"mode": "undefended", "campaign_relative": str(canary_campaign.relative_to(canary_execution))}]})
    canary_result = canary_execution / "results/canary/attempt-001"
    experiment = _write(canary_result / "experiment.json", {"fixture": "closed canary result primitive"})
    _write(canary_result / "evidence.sha256",
        (evidence._sha(experiment.read_bytes()) + "  experiment.json\n").encode())
    canary_deep = _ref(_write(canary_root / "deep-receipt.json", {"root": "/lab/results/canary/attempt-001"}))
    canary_record = _ref(_write(canary_root / "closed.json", {"fixture": "closed actual primitive"}))
    canary_deep_start = _ref(_write(canary_root / "deep-started.json", {"command": [
        "docker", "run", "--volume", str(canary_recipe) + ":/recipe.py:ro",
        "--volume", str(canary_helper) + ":/helpers.py:ro"]}))
    canary = {"plan": _ref(canary_plan), "deep_receipt": canary_deep,
        "capture": {"started": canary_record, "completed": canary_record},
        "deep": {"started": canary_deep_start, "completed": canary_record}}
    plan = _write(data / "plan.json", ordinary.admission._bind(ordinary.PLAN_TYPE, {
        "study_version": 6, "sites": [{"workload_id": "site"}], "readiness": {"undefended": canary},
        "lanes": [{"campaign_name": "fixture-formal"}]}))
    base = ordinary.CaptureSpec(data_root=data, runtime_source_root=sources[0],
        module_root=sources[0], execution_root=executions[0], acquisition_root=admission,
        cohort=cohort, qualification_spec=qualifier, workload_root=executions[0] / "config/workloads",
        campaign_dir=executions[0] / "config/campaigns", plan_receipt=plan,
        source_manifest=runtimes[0] / "source.json", client_binary=runtimes[0] / "client",
        base_launcher=sources[0] / "qcsd-lab", host_launcher=executions[0] / "qcsd-lab",
        collection_image_digest="sha256:" + "a" * 64, execution_generation="fixture-001")
    current = replace(base, runtime_source_root=sources[1], module_root=sources[1],
        execution_root=executions[1], workload_root=executions[1] / "config/workloads",
        campaign_dir=executions[1] / "config/campaigns", source_manifest=runtimes[1] / "source.json",
        client_binary=runtimes[1] / "client", base_launcher=sources[1] / "qcsd-lab",
        host_launcher=executions[1] / "qcsd-lab", execution_generation="fixture-002")
    runtime = {key: current.serializable()[key] for key in rolling.RUNTIME_FIELDS}
    derived = {"qualified_inputs": {"fixture": "retained exact graph and qualification"},
               "source_comparison": {"fixture": "control-only source change"}}
    payload = {"schema_version": 1, "artifact_type": schedule.CAPSULE_TYPE,
        "contract": schedule.CONTRACT, "base_spec": base.serializable(), "runtime": runtime,
        "qualification_spec": _ref(qualifier), "original_canonical": _ref(runtimes[0] / "canonical.json"),
        "current_canonical": _ref(runtimes[1] / "canonical.json"), **derived,
        "reason": "Offline boundary fixture", "published_at": "2000-01-01T00:01:00+00:00",
        "limits": dict(schedule.LIMITS), "formal_accepted_trace_count": 0, "scientific_credit": False}
    capsule = _write(data / "schedule.json", payload)
    calls = []
    def derive(*args, **kwargs):
        calls.append((args, kwargs))
        return copy.deepcopy(derived)
    monkeypatch.setattr(schedule, "_derive", derive)
    return SimpleNamespace(reference=_ref(capsule), capsule=capsule, payload=payload,
        current=current, base=base, runtime=runtime, runtimes=runtimes, sources=sources,
        sidecars=sidecars, executions=executions, canary=canary, calls=calls,
        nested_raw=nested_raw, initial_provenance=initial_provenance,
        canary_source=canary_source, canary_execution=canary_execution, canary_result=canary_result,
        canary_campaign=canary_campaign, canary_workload=canary_workload,
        canary_application=canary_application, canary_qualification=canary_qualification,
        canary_recipe=canary_recipe, canary_helper=canary_helper)


def test_one_context_derives_once_across_real_schedule_consumers(scheduled, monkeypatch):
    context = operations.OperationFacts()
    original = schedule.validate_schedule(scheduled.reference, _context=context)
    required = schedule.require_schedule(scheduled.reference, scheduled.current,
        declared_at="2000-01-01T00:02:00+00:00", _context=context)
    roots = schedule.mount_roots(scheduled.reference, _context=context)
    monkeypatch.setattr(evidence, "validate_canary", lambda *args, **kwargs: {"fixture": "closed canary"})
    canary = schedule.validate_ready_canary(scheduled.canary, scheduled.reference,
        mode="undefended", before="2000-01-01T00:02:00+00:00", _context=context)
    context.check()
    assert original == required == scheduled.payload
    assert Path(scheduled.reference["path"]).parent in roots
    assert canary == {"fixture": "closed canary"}
    assert len(scheduled.calls) == 1


def test_new_operation_recomputes_instead_of_using_process_global_facts(scheduled):
    for _ in range(2):
        context = operations.OperationFacts()
        schedule.validate_schedule(scheduled.reference, _context=context)
        schedule.validate_schedule(scheduled.reference, _context=context)
        context.check()
    assert len(scheduled.calls) == 2
    schedule.validate_schedule(scheduled.reference)
    schedule.validate_schedule(scheduled.reference)
    assert len(scheduled.calls) == 4


def test_new_action_discards_prior_semantic_memo(scheduled):
    context = operations.OperationFacts()
    schedule.validate_schedule(scheduled.reference, _context=context)
    schedule.validate_schedule(scheduled.reference, _context=context)
    context.begin_action()
    schedule.validate_schedule(scheduled.reference, _context=context)
    schedule.validate_schedule(scheduled.reference, _context=context)
    context.check()
    assert len(scheduled.calls) == 2


def test_cache_hit_still_checks_requested_runtime_and_chronology(scheduled):
    context = operations.OperationFacts()
    schedule.validate_schedule(scheduled.reference, _context=context)
    with pytest.raises(ValueError, match="different runtime"):
        schedule.validate_schedule(scheduled.reference,
            runtime={**scheduled.runtime, "execution_generation": "another-runtime"}, _context=context)
    with pytest.raises(ValueError, match="precede"):
        schedule.validate_schedule(scheduled.reference,
            before="1999-01-01T00:00:00+00:00", _context=context)
    assert len(scheduled.calls) == 1


@pytest.mark.parametrize("mutation", ["raw-log", "client-mode", "source-member", "sidecar-body",
    "application-member", "original-campaign", "current-campaign", "original-traffic", "current-traffic",
    "current-host-launcher", "nested-admission-raw", "initial-provenance", "study-profile"])
def test_cached_schedule_dependencies_reopen_before_effects(scheduled, mutation):
    context = operations.OperationFacts()
    schedule.validate_schedule(scheduled.reference, _context=context)
    if mutation == "raw-log":
        (scheduled.runtimes[1] / "raw-operation.stderr").write_bytes(b"unreported error\n")
    elif mutation == "client-mode":
        (scheduled.runtimes[1] / "client").chmod(0o444)
    elif mutation == "source-member":
        _write(scheduled.sources[1] / "unreported.py", b"extra source\n")
    elif mutation == "sidecar-body":
        (scheduled.sidecars / "site.json").write_bytes(b"changed qualified response\n")
    elif mutation == "application-member":
        _write(scheduled.executions[1] / "config/workloads/site-application-response-evidence/extra.json", {})
    elif mutation == "current-host-launcher":
        scheduled.current.host_launcher.write_bytes(b"changed current launcher\n")
    elif mutation == "nested-admission-raw":
        scheduled.nested_raw.write_bytes(b"changed authenticated admission dependency\n")
    elif mutation == "initial-provenance":
        scheduled.initial_provenance.write_bytes(b"changed original admission provenance\n")
    elif mutation == "study-profile":
        (scheduled.executions[1] / ordinary.STUDY_PROFILE_FILE).write_bytes(b"changed fixed study profile\n")
    elif mutation.endswith("campaign"):
        index = 0 if mutation.startswith("original") else 1
        (scheduled.executions[index] / "config/campaigns/fixture-formal.yml").write_bytes(b"changed fixed campaign\n")
    else:
        index = 0 if mutation.startswith("original") else 1
        relative, _ = ordinary.TRAFFIC_FILES["buflo_parameters_sha256"]
        (scheduled.executions[index] / relative).write_bytes(b"changed fixed parameters\n")
    effects = []
    with pytest.raises(ValueError, match="operation dependency"):
        context.check()
        effects.append("must not reach an effect")
    assert effects == [] and len(scheduled.calls) == 1


@pytest.mark.parametrize("mutation", ["clean-source", "execution-source", "result-body", "result-member",
    "campaign", "workload", "application-body", "application-member", "qualification-body",
    "qualification-git-member", "result-git-member", "external-recipe", "external-helper", "canary-traffic"])
def test_cached_readiness_reopens_external_canary_source_and_result(scheduled, monkeypatch, mutation):
    validated = []
    def validate(*args, **kwargs):
        validated.append((args, kwargs))
        return {"fixture": "closed canary"}
    monkeypatch.setattr(evidence, "validate_canary", validate)
    context = operations.OperationFacts()
    for _ in range(2):
        schedule.validate_ready_canary(scheduled.canary, scheduled.reference,
            mode="undefended", before="2000-01-01T00:02:00+00:00", _context=context)
    context.check()
    assert len(validated) == 1
    if mutation == "clean-source":
        (scheduled.canary_source / "src/measurement.py").write_bytes(b"changed retained canary source\n")
    elif mutation == "execution-source":
        (scheduled.canary_execution / "src/measurement.py").write_bytes(b"changed canary execution source\n")
    elif mutation == "result-body":
        (scheduled.canary_result / "experiment.json").write_bytes(b"changed canary result\n")
    elif mutation == "result-member":
        _write(scheduled.canary_result / "unreported.json", {"changed": True})
    elif mutation == "campaign":
        scheduled.canary_campaign.write_bytes(b"changed original canary campaign\n")
    elif mutation == "workload":
        scheduled.canary_workload.write_bytes(b"changed original canary graph\n")
    elif mutation == "application-body":
        (scheduled.canary_application / "raw.json").write_bytes(b"changed original canary response bytes\n")
    elif mutation == "application-member":
        _write(scheduled.canary_application / "unreported.json", {})
    elif mutation == "qualification-body":
        (scheduled.canary_qualification / "canary-site.json").write_bytes(b"changed original qualification\n")
    elif mutation == "qualification-git-member":
        _write(scheduled.canary_qualification / ".git/unreported", b"data member cannot hide as Git metadata\n")
    elif mutation == "result-git-member":
        _write(scheduled.canary_result / ".git/unreported", b"result member cannot hide as Git metadata\n")
    elif mutation == "external-recipe":
        scheduled.canary_recipe.write_bytes(b"changed original installed deep recipe\n")
    elif mutation == "external-helper":
        scheduled.canary_helper.write_bytes(b"changed original installed deep helper\n")
    else:
        relative, _ = ordinary.TRAFFIC_FILES["buflo_parameters_sha256"]
        (scheduled.canary_execution / relative).write_bytes(b"changed original canary traffic settings\n")
    with pytest.raises(ValueError, match="operation dependency"):
        context.check()
    assert len(scheduled.calls) == 1


@pytest.mark.parametrize("added", ["application", "qualification"])
def test_baseline_canary_optional_roots_bind_absence_and_reject_later_addition(scheduled, added):
    shutil.rmtree(scheduled.canary_application)
    shutil.rmtree(scheduled.canary_qualification)
    runtime = {key: scheduled.base.serializable()[key] for key in ordinary.RUNTIME_KEYS}
    context = operations.OperationFacts()
    calls = []
    def validate(*args, **kwargs):
        calls.append((args, kwargs))
        return {"fixture": "original undefended canary requires no qualification"}
    for _ in range(2):
        context.validate_canary(scheduled.canary, runtime, "undefended", validate)
    context.check()
    assert len(calls) == 1
    assert not scheduled.canary_application.exists() and not scheduled.canary_qualification.exists()
    destination = scheduled.canary_application if added == "application" else scheduled.canary_qualification
    _write(destination / "unreported.json", {"added_after_validation": True})
    with pytest.raises(ValueError, match="previously absent membership"):
        context.check()
    assert len(calls) == 1


def test_cached_equivalent_canary_reopens_external_original_execution_traffic(scheduled, tmp_path):
    original_execution = tmp_path / "external-original-canary-execution"
    for relative, _ in ordinary.TRAFFIC_FILES.values():
        _write(original_execution / relative, (ROOT / relative).read_bytes())
    runtime = {key: scheduled.base.serializable()[key] for key in ordinary.RUNTIME_KEYS}
    original = {**runtime, "execution_root": str(original_execution)}
    capsule = _write(scheduled.current.data_root / "external-canary-equivalence.json", {
        "original_runtime": original, "current_runtime": runtime})
    reference = {**scheduled.canary, "schema_version": 2, "source_equivalence": _ref(capsule)}
    context = operations.OperationFacts()
    calls = []
    def validate(*args, **kwargs):
        calls.append((args, kwargs))
        return {"fixture": "closed original and current canary runtime roles"}
    for _ in range(2):
        context.validate_canary(reference, runtime, "undefended", validate)
    context.check()
    assert len(calls) == 1
    assert original_execution not in (scheduled.base.execution_root, scheduled.canary_execution)
    relative, _ = ordinary.TRAFFIC_FILES["buflo_parameters_sha256"]
    (original_execution / relative).write_bytes(b"changed external original fixed traffic\n")
    with pytest.raises(ValueError, match="operation dependency"):
        context.check()
    assert len(calls) == 1


def test_nested_enrollment_references_keep_the_declared_admission_root(tmp_path):
    formal_root = tmp_path / "formal"
    admission_root = tmp_path / "admission"
    formal_root.mkdir()
    terminal = _write(admission_root / "attempts/site/terminal.json", {"engineering_fixture": True})
    relative = {"path": "attempts/site/terminal.json", "sha256": evidence._sha(terminal.read_bytes())}
    enrollment = _write(formal_root / "enrollment.json", ordinary.admission._bind(
        "qcsd-rapid-v6-immutable-enrollment-batch",
        {"admission_root": str(admission_root), "decisions": [{"terminal": relative}]}))
    context = operations.OperationFacts()
    context._references({"enrollment": _ref(enrollment)}, formal_root)
    context.check()
    terminal.write_bytes(b"changed original admission terminal\n")
    with pytest.raises(ValueError, match="operation dependency"):
        context.check()


def test_raw_observations_detect_same_size_changes_with_restored_mtime(tmp_path):
    path = _write(tmp_path / "closed-record", b"original")
    metadata = path.stat()
    context = operations.OperationFacts()
    assert context.watch_file(path) == b"original"
    path.write_bytes(b"tampered")
    os.utime(path, ns=(metadata.st_atime_ns, metadata.st_mtime_ns))
    assert path.stat().st_size == metadata.st_size
    assert path.stat().st_mtime_ns == metadata.st_mtime_ns
    with pytest.raises(ValueError, match="bytes or mode"):
        context.check()


@pytest.mark.parametrize("mutation", ["file-mode", "directory-mode", "added-file", "removed-file", "empty-directory", "git-data-member", "symlink"])
def test_complete_tree_membership_and_modes_are_bound(tmp_path, mutation):
    root = tmp_path / "frozen-tree"
    path = _write(root / "nested/module.py", b"unchanged\n")
    path.chmod(0o644)
    path.parent.chmod(0o755)
    context = operations.OperationFacts()
    context.watch_tree(root)
    if mutation == "file-mode":
        path.chmod(0o600)
    elif mutation == "directory-mode":
        path.parent.chmod(0o700)
    elif mutation == "added-file":
        _write(root / "extra.py", b"new member\n")
    elif mutation == "removed-file":
        path.unlink()
    elif mutation == "empty-directory":
        (root / "unreported-empty-directory").mkdir()
    elif mutation == "git-data-member":
        _write(root / ".git/unreported", b"immutable data member\n")
    else:
        path.unlink()
        path.symlink_to(_write(tmp_path / "foreign", b"unchanged\n"))
    with pytest.raises(ValueError, match="operation dependency"):
        context.check()


def test_returned_facts_cannot_rewrite_remembered_authority():
    context = operations.OperationFacts()
    original = {"names": ["retained"], "scientific_credit": False}
    context.remember(("validated", "capsule"), original)
    original["names"].append("changed original")
    returned = context.get(("validated", "capsule"))
    returned["names"].append("changed return")
    assert context.get(("validated", "capsule")) == {"names": ["retained"], "scientific_credit": False}
    assert not operations.OperationFacts().has(("validated", "capsule"))


def test_operation_scope_resets_after_exception_and_restores_nested_parent():
    parent, child = operations.OperationFacts(), operations.OperationFacts()
    assert operations.current_context() is None
    with parent.scope():
        assert operations.current_context() is parent
        with pytest.raises(RuntimeError, match="nested failure"):
            with child.scope():
                assert operations.current_context() is child
                raise RuntimeError("nested failure")
        assert operations.current_context() is parent
    assert operations.current_context() is None
    with pytest.raises(RuntimeError, match="outer failure"):
        with parent.scope():
            raise RuntimeError("outer failure")
    assert operations.current_context() is None


def test_installed_qualification_hook_uses_only_the_current_operation_scope(scheduled, monkeypatch):
    from qcsd_lab import rapid_runtime_epochs as epochs
    client_sha = evidence._sha(scheduled.base.client_binary.read_bytes())
    receipts = [_implementation(client_sha, successor=bool(index)) for index in range(2)]
    for index, (root, implementation) in enumerate(zip(scheduled.runtimes, receipts, strict=True)):
        inventory = _write(root / "source-inventory.json", {
            name: {"sha256": digest, "executable": False}
            for name, digest in implementation["source_files"].items()})
        canonical = _write(root / "canonical.json", {"verified_at": "2000-01-01T00:00:00+00:00",
            "source": implementation["source"], "installed_client_sha256": client_sha,
            "source_inventory_sha256": _ref(inventory)["sha256"],
            "checks": {"collection": {"qualification_implementation_sha256": implementation["sha256"]}}})
        scheduled.payload["current_canonical" if index else "original_canonical"] = _ref(canonical)
    _write(scheduled.capsule, scheduled.payload)
    scheduled.reference = _ref(scheduled.capsule)
    monkeypatch.setenv(epochs.COMPATIBILITY_ENV, str(scheduled.capsule))
    monkeypatch.setenv("QCSD_LAB_IMAGE_DIGEST", scheduled.runtime["collection_image_digest"])
    monkeypatch.delenv("QCSD_RAPID_CAPTURE_CONTROL_INSTALLATION", raising=False)
    context = operations.OperationFacts()
    schedule.validate_schedule(scheduled.reference, _context=context)
    with context.scope():
        epochs.validate_qualification_reuse(*receipts)
        epochs.validate_qualification_reuse(*receipts)
    assert len(scheduled.calls) == 1 and operations.current_context() is None
    epochs.validate_qualification_reuse(*receipts)
    epochs.validate_qualification_reuse(*receipts)
    assert len(scheduled.calls) == 3


@pytest.fixture
def qualified_graphs(tmp_path, monkeypatch):
    workload_id = "cloudflare-quiche-r3"
    before, after = tmp_path / "before", tmp_path / "current"
    workload = _write(before / "workloads" / (workload_id + ".json"),
        (ROOT / "config/workloads" / (workload_id + ".json")).read_bytes())
    _write(before / "workloads" / (workload_id + "-application-response-evidence") / "raw.json",
        {"engineering_fixture": "retained application response bytes"})
    implementation = _implementation("e" * 64)
    sidecars = before / "sets/fixture"
    _write(sidecars / (workload_id + ".json"),
        response_sidecar(workload, workload_id, implementation, "sha256:" + "a" * 64))
    manifest = qualification.build_named_qualification_set_manifest([workload_id],
        qualification_set="fixture", qualification_scope="response-only",
        workload_root=workload.parent, sidecar_root=sidecars,
        qualification_sidecar_schema_version=qualification.RESPONSE_ONLY_SIDECAR_V2_SCHEMA_VERSION,
        require_current_implementation=False)
    _write(sidecars / "_qualification-set.json", manifest)
    _write(before / "qualification.json", {"schema_version": 1, "qualification_sets": [{
        "qualification_set": "fixture", "manifest": "sets/fixture/_qualification-set.json",
        "sidecar_root": "sets/fixture", "prefix_spec_root": None}]})
    shutil.copytree(before, after)
    cohort = _write(tmp_path / "enrollment.json", {"engineering_fixture": "same retained enrollment"})
    sites = [{"workload_id": workload_id, "workload_sha256": _ref(workload)["sha256"]}]
    actual_validator = qualification.validate_named_qualification_set_manifest
    calls = []
    class CurrentImplementationRequired(RuntimeError):
        pass
    def validator(value, **arguments):
        calls.append(arguments["require_current_implementation"])
        if arguments["require_current_implementation"]:
            raise CurrentImplementationRequired("fresh current implementation must execute its validator")
        return actual_validator(value, **arguments)
    monkeypatch.setattr(qualification, "validate_named_qualification_set_manifest", validator)
    return SimpleNamespace(before=before, after=after, cohort=cohort, sites=sites,
        workload_id=workload_id, manifest=manifest, calls=calls, validator=validator,
        current_required=CurrentImplementationRequired)


def test_identical_qualified_graphs_validate_once_and_false_cannot_authorize_true(qualified_graphs):
    fixture = qualified_graphs
    context = operations.OperationFacts()
    values = [schedule._qualified_inputs(fixture.cohort, root / "qualification.json",
        root / "workloads", fixture.sites, _context=context) for root in (fixture.before, fixture.after)]
    assert values[0] == values[1] and fixture.calls == [False]
    with pytest.raises(fixture.current_required):
        context.validate_named_qualification(fixture.manifest, fixture.validator,
            workload_root=fixture.after / "workloads", sidecar_root=fixture.after / "sets/fixture",
            prefix_spec_root=None, expected_qualification_set="fixture",
            expected_workload_ids=[fixture.workload_id], expected_qualification_scope="response-only",
            require_current_implementation=True)
    assert fixture.calls == [False, True]
    context.check()


@pytest.mark.parametrize("mutation", ["source-label", "workload-body"])
def test_qualified_input_reuse_still_binds_source_labels_and_workload_bodies(qualified_graphs, mutation):
    fixture = qualified_graphs
    context = operations.OperationFacts()
    for root in (fixture.before, fixture.after):
        schedule._qualified_inputs(fixture.cohort, root / "qualification.json",
            root / "workloads", fixture.sites, _context=context)
    if mutation == "source-label":
        path = fixture.after / "sets/fixture" / (fixture.workload_id + ".json")
        value = json.loads(path.read_bytes())
        value["qualification_source"]["lab_commit"] = "f" * 40
        _write(path, value)
    else:
        path = fixture.after / "workloads" / (fixture.workload_id + ".json")
        path.write_bytes(path.read_bytes() + b"\n")
    with pytest.raises(ValueError, match="operation dependency"):
        context.check()
    assert fixture.calls == [False]


def test_cached_qualified_inputs_reject_another_expected_workload_sha(qualified_graphs):
    fixture = qualified_graphs
    context = operations.OperationFacts()
    arguments = (fixture.cohort, fixture.before / "qualification.json", fixture.before / "workloads")
    schedule._qualified_inputs(*arguments, fixture.sites, _context=context)
    schedule._qualified_inputs(*arguments, fixture.sites, _context=context)
    assert fixture.calls == [False]
    bad_sites = [{**fixture.sites[0], "workload_sha256": "0" * 64}]
    assert bad_sites != fixture.sites
    with pytest.raises(ValueError, match="SHA-256 differs"):
        schedule._qualified_inputs(*arguments, bad_sites, _context=context)
    # The unchanged named graph can still be reused; the separate expected
    # hash check must execute for this distinct plan expectation.
    assert fixture.calls == [False]
    context.check()


@pytest.fixture(scope="module")
def frozen_v4(tmp_path_factory):
    raw = (ROOT / "tests/fixtures/rapid_rolling_schedule_v4.py.zlib.b85.txt").read_bytes()
    assert hashlib.sha256(raw).hexdigest() == V4_FIXTURE_SHA256
    value = json.loads(raw)
    assert value["source_commit"] == "db473bccadaddb3be7b96366c155895a9bf160e3"
    assert value["source_path"] == schedule.MODULE_FILE and value["encoding"] == "zlib-base85"
    assert value["schema_version"] == 1 and value["artifact_type"] == "qcsd-immutable-source-fixture"
    source = zlib.decompress(base64.b85decode(value["encoded_source"]))
    assert len(source) == value["uncompressed_bytes"] == 51058
    assert hashlib.sha256(source).hexdigest() == value["sha256"] == V4_HELPER_SHA256
    path = tmp_path_factory.mktemp("immutable-v4-helper") / "retained.py"
    path.write_bytes(source)
    spec = importlib.util.spec_from_file_location("qcsd_lab._operation_retained_v4", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return source, module


@pytest.fixture(scope="module")
def historical_qualification_sources():
    # Scheduling parity describes the pre-amendment qualification science.
    # The prospective static role legitimately reaches new adapter authority;
    # it cannot become the science baseline of a historical V1--V4 test.
    raw = (ROOT / "tests/fixtures/rapid_pre_static_qualification_v1.sources.zlib.b85.txt").read_bytes()
    assert hashlib.sha256(raw).hexdigest() == "a6b60df738fc2c33770a5623b5ae5e45c40abbb195fd34d5dace632ea3b85186"
    value = json.loads(raw)
    assert value["source_commit"] == "0730fa6fd4ba383dbc08bfaf58a5306a893112b9"
    assert value["schema_version"] == 1 and value["artifact_type"] == "qcsd-immutable-source-fixture"
    expected = {"src/qcsd_lab/manifest.py": (50626, "91a18c74815a0e1ebf1765fecc8829f9aeaad0ecc26e6cb283de01c89202aee2"),
        "src/qcsd_lab/application_response_policy.py": (28435, "f8f0cf9d93ed2a60e03a03f4f478f33f3c129f022c484baf0bf3c86bd2a71992")}
    assert set(value["sources"]) == set(expected)
    result = {}
    for path, (size, digest) in expected.items():
        record = value["sources"][path]
        assert record["encoding"] == "zlib-base85"
        source = zlib.decompress(base64.b85decode(record["encoded_source"]))
        assert len(source) == record["uncompressed_bytes"] == size
        assert hashlib.sha256(source).hexdigest() == record["sha256"] == digest
        result[path] = source
    return result


@pytest.mark.parametrize("contract", [schedule.CONTRACT_V1, schedule.CONTRACT_V2,
    schedule.CONTRACT_V3, schedule.CONTRACT_V4])
def test_portable_v4_helper_preserves_all_historical_projection_results(source_bytes, frozen_v4, historical_qualification_sources, contract):
    source, retained = frozen_v4
    before = {**source_bytes, schedule.MODULE_FILE: source, **historical_qualification_sources}
    path = "src/qcsd_lab/rapid_formal_parallel.py"
    tree = ast.parse(before[path])
    function = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "_audit")
    function.body.insert(0, ast.parse("historical_control_probe = True").body[0])
    after = {**before, path: ast.unparse(tree).encode()}
    expected = retained.source_changes(before, after, client_sha256="a" * 64, contract=contract)
    assert schedule.source_changes(before, after, client_sha256="a" * 64, contract=contract) == expected


@pytest.mark.parametrize("edit", ["facts", "readiness", "gate"])
def test_v4_cannot_authorize_new_operation_facts_readiness_or_gate_edits(source_bytes, frozen_v4, historical_qualification_sources, edit):
    source, _ = frozen_v4
    before = {**source_bytes, schedule.MODULE_FILE: source, **historical_qualification_sources}
    before.pop(schedule.FACTS_FILE, None)
    if edit == "facts":
        after = {**before, schedule.FACTS_FILE: (ROOT / schedule.FACTS_FILE).read_bytes()}
    else:
        path, name = (("src/qcsd_lab/rapid_rolling_readiness.py", "readiness_mount_roots")
            if edit == "readiness" else ("src/qcsd_lab/rapid_parallel_capture.py", "gate"))
        tree = ast.parse(before[path])
        function = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == name)
        function.body.insert(0, ast.parse("prospective_control_probe = True").body[0])
        after = {**before, path: ast.unparse(tree).encode()}
    with pytest.raises(ValueError):
        schedule.source_changes(before, after, client_sha256="a" * 64, contract=schedule.CONTRACT_V4)


def test_change_while_acquiring_lock_rejects_before_image_or_lane_claim(formal_setup, monkeypatch):
    fixture = formal_setup
    external = _write(fixture.spec.data_root / "closed-external-response.json", {"retained": True})
    context = operations.OperationFacts()
    context.watch_file(external)
    @contextmanager
    def waited_lock(*args, **kwargs):
        external.write_bytes(b"changed while waiting for ownership\n")
        yield 7
    monkeypatch.setattr(ordinary, "capture_lock", waited_lock)
    output = fixture.spec.data_root / "must-not-claim-authority.json"
    with pytest.raises(ValueError, match="operation dependency"):
        formal.prepare_batch(fixture.spec_path, fixture.root,
            [fixture.lanes[0].campaign_name, fixture.lanes[8].campaign_name], output, _context=context)
    assert fixture.image_calls == [] and not output.exists()
    assert not (fixture.root / "lanes").exists()


def test_repeated_image_check_executes_the_actual_external_actuator(formal_setup):
    fixture = formal_setup
    before = len(fixture.image_calls)
    context = operations.OperationFacts()
    ordinary.check_bound_image(fixture.spec, fixture.root, _context=context)
    ordinary.check_bound_image(fixture.spec, fixture.root, _context=context)
    assert len(fixture.image_calls) == before + 2


def test_cached_immutable_facts_do_not_cache_live_dns_or_runtime_checks(formal_setup, monkeypatch):
    from qcsd_lab import class_acquisition, runtime_provenance
    batch = _prepare(formal_setup)
    dns_calls = []
    def resolve(origins):
        dns_calls.append(tuple(origins))
        address = "8.8.8.8" if len(dns_calls) == 1 else "1.1.1.1"
        return {origin: address for origin in origins}
    monkeypatch.setattr(class_acquisition, "public_origin_ip_pins", resolve)
    first = formal.resolve_dns(batch.path, 0)
    second = formal.resolve_dns(batch.path, 0)
    assert len(dns_calls) == 2
    assert first["hosts"] != second["hosts"]
    validate = runtime_provenance.validate_runtime_receipt
    runtime_calls = []
    def installed(**kwargs):
        runtime_calls.append(kwargs)
        return validate(**kwargs)
    monkeypatch.setattr(runtime_provenance, "validate_runtime_receipt", installed)
    context = operations.OperationFacts()
    formal.image_preflight(batch.path, batch.digest, _context=context)
    formal.image_preflight(batch.path, batch.digest, _context=context)
    assert len(runtime_calls) == 2


@pytest.mark.parametrize("mutation", [False, True])
def test_each_installed_gate_derives_fresh_and_rechecks_source_before_exec(scheduled, monkeypatch, mutation):
    """Isolate the formal runtime closure; retain the real installed gate."""
    root = scheduled.current.data_root
    second_campaign = _write(scheduled.current.campaign_dir / "second-formal.yml", b"second complete lane\n")
    value = {"artifact_type": formal.AUTHORITY_TYPE,
        "runtime": {"execution_root": str(scheduled.current.execution_root)},
        "campaigns": [_ref(scheduled.current.campaign_dir / "fixture-formal.yml"), _ref(second_campaign)]}
    authority = _write(root / "gate-authority.json", value)
    digest = evidence._sha(authority.read_bytes())
    intent = _write(root / "gate-intent.json", {"fixture": "closed formal intent"})
    facts = [(scheduled.current, root, intent, {}, {},
        SimpleNamespace(study_version=6, campaign_name=f"gate-{index}"), ()) for index in range(2)]
    contexts = []
    def audit(path, *, _context=None, **kwargs):
        assert path == authority and isinstance(_context, operations.OperationFacts)
        contexts.append(_context)
        # The authority and its nested prerequisites legitimately consume the
        # same capsule more than once within this one gate operation.
        schedule.validate_schedule(scheduled.reference, _context=_context)
        schedule.validate_schedule(scheduled.reference, _context=_context)
        return value, facts
    def environment(_value, _index, *, _context=None, **kwargs):
        assert _value == value and isinstance(_context, operations.OperationFacts)
        schedule.validate_schedule(scheduled.reference, _context=_context)
        if mutation:
            (scheduled.sources[1] / "src/module.py").write_bytes(b"changed during gate preparation\n")
        return {"QCSD_ENGINEERING_GATE_FIXTURE": str(_index)}
    monkeypatch.setattr(formal, "_audit", audit)
    monkeypatch.setattr(formal, "worker_environment", environment)
    monkeypatch.setenv("QCSD_LAB_UID", str(os.geteuid()))
    monkeypatch.setenv("QCSD_LAB_GID", str(os.getegid()))
    executions = []
    monkeypatch.setattr(parallel.os, "execv", lambda command, argv: executions.append((command, argv)))
    for index, (client, orchestrator) in enumerate(((2, 4), (7, 9))):
        gate = root / "gates" / f"lane-{index}"
        partition = _write(gate / "host-partition.json", {
            "measured_container_id": f"worker-{index}", "declared_workers": [
                {"id": "worker-0", "client_cpu": 2, "orchestrator_cpu": 4},
                {"id": "worker-1", "client_cpu": 7, "orchestrator_cpu": 9}]})
        campaign = "/lab/" + str(Path(value["campaigns"][index]["path"]).relative_to(scheduled.current.execution_root))
        _write(gate / "release.json", {"authority_sha256": digest, "campaign": campaign,
            "worker_id": f"worker-{index}", "host_partition_sha256": evidence._sha(partition.read_bytes())})
        monkeypatch.setenv("QCSD_CAPTURE_CLIENT_CPU", str(client))
        monkeypatch.setenv("QCSD_CAPTURE_ORCHESTRATOR_CPU", str(orchestrator))
        if mutation:
            with pytest.raises(ValueError, match="operation dependency"):
                parallel.gate(gate, digest, index, authority)
            assert executions == [] and len(scheduled.calls) == 1
            return
        parallel.gate(gate, digest, index, authority)
    assert len(executions) == 2 and len(scheduled.calls) == 2
    assert len({id(context) for context in contexts}) == 2
