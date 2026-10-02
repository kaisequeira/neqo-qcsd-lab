"""Engineering regressions for the prospective primary-body capture contract."""

from copy import deepcopy
import hashlib
import json
from types import SimpleNamespace

import pytest

from qcsd_lab import chaff_qualification, orchestrator
from qcsd_lab.application_response_policy import (
    VARIABLE_PRIMARY_DOCUMENT_BODY_POLICY,
    build_primary_document_identity_evidence,
)
from qcsd_lab.class_run_binding import resolve_class_sample_run_binding, validate_class_sample_run_binding
from qcsd_lab.manifest import canonical_bytes, runtime_manifest
from qcsd_lab.util import atomic_json, response_signature, sha256_file
from qcsd_lab.verification import _validate_policy_application_responses
from tests.test_class_run_binding import _fixture
from tests.test_primary_document_identity_policy import variable_workload


def test_admission_comparison_accepts_primary_variation_but_diagnoses_only_static_drift(tmp_path):
    manifest, runs = variable_workload()
    workload = SimpleNamespace(id="page", data=manifest)
    atomic_json(tmp_path / "neqo/run.json", runs[1])
    assert orchestrator._prepared_response_identity_failure(workload, tmp_path) is None
    runs[1]["responses"][1]["body_sha256"] = "f" * 64
    atomic_json(tmp_path / "neqo/run.json", runs[1])
    failure = orchestrator._prepared_response_identity_failure(workload, tmp_path)
    assert failure["details"][0]["differing_resource_ids"] == [1]
    assert "application resource 1" in failure["details"][0]["response_policy_validation_error"]


def test_comparison_rejects_invalid_primary_even_when_ignored_body_fields_match(tmp_path):
    manifest, runs = variable_workload()
    runs[1]["responses"][0]["complete"] = False
    atomic_json(tmp_path / "neqo/run.json", runs[1])
    failure = orchestrator._prepared_response_identity_failure(SimpleNamespace(id="page", data=manifest), tmp_path)
    assert failure is not None
    assert failure["details"][0]["response_policy_validation_error"]


def test_five_conditions_use_same_policy_and_keep_actual_signature_hashes(tmp_path, monkeypatch):
    manifest, runs = variable_workload()
    samples = []
    for index, (mode, runtime) in enumerate([
        ("undefended", "none"), ("front", "front"), ("tamaraw", "tamaraw"),
        ("buflo", "buflo"), ("cs-buflo", "cs_buflo"),
    ]):
        relative = f"samples/{mode}"
        atomic_json(tmp_path / relative / "neqo/run.json", runs[index % 3])
        samples.append({"state": "accepted", "baseline": index == 0, "path": relative,
                        "defense": mode, "runtime_kind": runtime,
                        "diagnostics": {"capture": {"valid": True}, "operationally_valid": True}})
    for name in ("validate_accepted_scheduler_runtime_receipt", "validate_accepted_observer_topology_receipt",
                 "validate_accepted_kernel_tx_evidence"):
        monkeypatch.setattr(orchestrator, name, lambda *_args: None)
    monkeypatch.setattr(orchestrator, "_schedule_realization_metrics", lambda *_args: {})
    monkeypatch.setattr(orchestrator, "fidelity_eligible", lambda *_args, **kw: kw["sample_eligible"])
    orchestrator._compare_group(tmp_path, {}, samples, SimpleNamespace(id="page", data=manifest))
    assert all(sample["eligible"] and sample["diagnostics"]["paired_baseline_response_match"] for sample in samples)
    actual = response_signature(tmp_path / samples[1]["path"])
    assert samples[1]["diagnostics"]["response_signature_sha256"] == hashlib.sha256(
        json.dumps(actual, sort_keys=True).encode()).hexdigest()
    assert samples[0]["diagnostics"]["response_signature_sha256"] != samples[1]["diagnostics"]["response_signature_sha256"]
    changed = deepcopy(runs[1])
    changed["responses"][1]["bytes"] += 1
    atomic_json(tmp_path / samples[1]["path"] / "neqo/run.json", changed)
    orchestrator._compare_group(tmp_path, {}, samples, SimpleNamespace(id="page", data=manifest))
    assert not samples[1]["eligible"]
    assert all(sample["eligible"] for sample in samples if sample is not samples[1])


def test_deep_response_reopening_allows_only_declared_primary_variation(tmp_path):
    manifest, runs = variable_workload()
    path = tmp_path / "inputs/page.json"
    atomic_json(path, manifest)
    atomic_json(tmp_path / "samples/one/neqo/run.json", runs[1])
    experiment = {"configuration": {"workloads": [{"id": "page", "manifest": "inputs/page.json",
                                                   "sha256": sha256_file(path)}]},
                  "samples": [{"state": "accepted", "workload_id": "page", "path": "samples/one"}]}
    _validate_policy_application_responses(tmp_path, experiment)
    runs[1]["responses"][1]["body_sha256"] = "f" * 64
    atomic_json(tmp_path / "samples/one/neqo/run.json", runs[1])
    with pytest.raises(ValueError, match="application resource 1"):
        _validate_policy_application_responses(tmp_path, experiment)


@pytest.mark.parametrize("mode,runtime,baseline", [
    ("undefended", "none", True), ("front", "front", False), ("tamaraw", "tamaraw", False),
    ("buflo", "buflo", False), ("cs-buflo", "cs_buflo", False),
])
def test_resolved_binding_preserves_full_runtime_projection_with_variable_primary(tmp_path, mode, runtime, baseline):
    root, config, sample, run = _fixture(tmp_path, mode, runtime, baseline)
    entry = config["workloads"][0]
    prepared_path = root / entry["manifest"]
    manifest = json.loads(prepared_path.read_bytes())
    manifest["resources"][0]["chaff_priority"] = False
    manifest["preparation"].update(application_response_policy="completed-terminal-http-errors-v1",
                                   primary_document_identity_policy=VARIABLE_PRIMARY_DOCUMENT_BODY_POLICY)
    run.update(application_response_policy="completed-terminal-http-errors-v1", terminal_evidence_render_errors=[])
    for row, resource in zip(run["responses"], manifest["resources"], strict=True):
        row.update(url=resource["url"], request_headers=resource["headers"], content_length=row["bytes"],
                   response_headers=[["content-type", "text/html; charset=utf-8"]])
    runs = [deepcopy(run) for _ in range(3)]
    for index, witness in enumerate(runs[1:], 1):
        primary = witness["responses"][0]
        primary.update(bytes=primary["bytes"] + index, content_length=primary["bytes"] + index,
                       body_sha256=str(index) * 64)
    manifest["preparation"]["primary_document_identity_evidence"] = build_primary_document_identity_evidence(
        manifest, runs, stability_run_sha256s=[str(index + 3) * 64 for index in range(3)])
    prepared_path.write_bytes(canonical_bytes(manifest))
    runtime_path = root / entry["runtime_manifest"]
    runtime_path.write_bytes(canonical_bytes(runtime_manifest(manifest)))
    entry.update(sha256=sha256_file(prepared_path), runtime_manifest_sha256=sha256_file(runtime_path))
    changed = runs[1]
    changed.update(workload_hash_sha256=entry["runtime_manifest_sha256"],
                   application_workload_source_hash_sha256=None if baseline else entry["sha256"])
    binding = resolve_class_sample_run_binding(root, config, sample)
    assert binding.primary_document_identity_policy == VARIABLE_PRIMARY_DOCUMENT_BODY_POLICY
    validate_class_sample_run_binding(changed, sample, binding)
    changed["responses"][1]["body_sha256"] = "f" * 64
    with pytest.raises(ValueError, match="application resource 1"):
        validate_class_sample_run_binding(changed, sample, binding)


def test_chaff_inventory_keeps_error_leaf_without_making_it_eligible(monkeypatch):
    manifest, _runs = variable_workload()
    expected = chaff_qualification._prepared_expected_responses(manifest)
    assert expected[1]["status"] == 401
    manifest["preparation"]["approved_origins"] = ["https://page.test", "https://cdn.test"]
    monkeypatch.setattr(chaff_qualification, "selected_navigation_root", lambda *_args: manifest["resources"][0])
    with pytest.raises(ValueError, match="no eligible identity-response candidate"):
        chaff_qualification.response_only_candidate_resources(manifest, "page")
    manifest["resources"].append({"id": 2, "url": "https://page.test/main.js", "type": "Script",
                                  "known_valid": True, "chaff_priority": True, "depends_on": [0],
                                  "headers": [["accept", "*/*"], ["accept-encoding", "gzip, deflate, br"],
                                              ["accept-language", "en-US,en;q=0.9"]]})
    manifest["preparation"]["coverage_admission"]["required_resources"].append(
        {"id": 2, "url": "https://page.test/main.js"})
    manifest["preparation"]["expected_responses"].append(
        {"resource_id": 2, "status": 200, "bytes": 1800, "body_sha256": "e" * 64})
    candidates = chaff_qualification.response_only_candidate_resources(manifest, "page")
    assert [resource["id"] for resource, _response in candidates] == [2]
