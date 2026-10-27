"""Offline explicit-donor controls; synthetic local contexts are not admission/H3 proof.

The original immutable-context and manifest readers run. Only Native process,
Docker/DNS/runtime leaves use the established offline adapter boundaries.
"""
from contextlib import nullcontext
from copy import deepcopy
import hashlib
import json
from pathlib import Path

import pytest

from qcsd_lab import tamaraw_fixed_configuration as tamaraw

from qcsd_lab import resource_study_cohorts as cohorts
from qcsd_lab import resource_study_inputs as inputs
from qcsd_lab import resource_study_native as native
from qcsd_lab import resource_study_runtime as runtime_adapter
from qcsd_lab import resource_study_selection as selection
from tests.test_resource_study_buflo_capped_chaff import install_sustained
from tests.test_resource_study_native import (
    HOST, URLS, executable, offline_durability, install_process_stub, runtime,
)


def put(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists(): path.chmod(0o644)
    path.write_bytes(raw); path.chmod(0o444)
    return hashlib.sha256(raw).hexdigest()


def local_context(root, host, urls, digest):
    """A genuine typed immutable input-context component; no live parent/SQL claim."""
    enc = inputs.canonical_json
    sha = lambda value: hashlib.sha256(enc(value)).hexdigest()
    assignment = {"subnet": "10.200.0.0/29", "client_ipv4": "10.200.0.2"}
    network = {"assignments": {host: assignment}, "predecessor_sha256": "e" * 64}
    selected = {"parent_root": str(root.parent / "component-parent"), "parent_study_sha256": "b" * 64}
    plan = {"class_selection": selected, "class_network": network, "source_sha256": "a" * 64}
    study_sha = put(root / "study.json", enc(plan))
    definition = {"urls": list(urls), "workload_sha256": digest, "acceptance": "component-only",
                  "network": {"mapping_sha256": sha(network), "assignment": assignment}}
    prior = {"record_type": cohorts.ADMISSION, "sequence": 0, "parent_study_sha256": "b" * 64,
             "class_transition": {"class_selection": selected, "class_network": network},
             "cells": [{"hostname": host, "mode": "buflo", "root": str(root.parent / "component-donor"),
                        "definition": definition, "definition_sha256": sha(definition)}]}
    context = {"record_type": cohorts.INPUT_CONTEXT_TYPE, "schema_version": 1,
               "root": str(root), "study_sha256": study_sha,
               "parent": {"root": selected["parent_root"], "study_sha256": "b" * 64},
               "predecessor": prior, "predecessor_sha256": sha(prior),
               "class_selection_sha256": sha(selected), "source_sha256": "a" * 64,
               "scientific_credit": False}
    put(root / cohorts.INPUT_CONTEXT, enc(context))


@pytest.fixture
def donor(tmp_path):
    urls = URLS[:20]
    value = native._manifest(HOST, urls, require_twenty=True)
    value["resources"][0]["type"] = "Document"
    for row in value["resources"]:
        row["data_length"] = row["content_length"] = 2_500 + row["id"]
    # Deliberately noncanonical whitespace detects parse/reserialize mistakes.
    raw = (json.dumps(value, indent=3) + "\n").encode()
    source = tmp_path / "donor-original-resources.json"; digest = put(source, raw)
    root = tmp_path / "new-cohort"; local_context(root, HOST, urls, digest)
    return root, source, digest, raw, value, urls


@pytest.mark.parametrize("cap", [None, 2_200])
def test_donor_manifest_keeps_exact_bytes_and_fresh_twenty_GET_and_chaff(donor, executable, monkeypatch, cap):
    root, source, digest, raw, value, urls = donor
    calls = install_process_stub(monkeypatch)
    sustained = install_sustained(monkeypatch, actual_sizes={1: 2_000})
    result = native.prepare_domain(HOST, urls, root / "prepared", client=executable,
        runtime=runtime(executable), frozen_application_manifest=source,
        frozen_application_manifest_sha256=digest, buflo_chaff_cap_bytes=cap)
    assert source.read_bytes() == (root / "prepared/resources.json").read_bytes() == raw
    assert result["workload_sha256"] == digest
    prepared = json.loads((root / "prepared/prepared-workload.json").read_bytes())
    assert prepared["resources"] == value["resources"]
    assert len(prepared["preparation"]["expected_responses"]) == 20
    assert {r["bytes"] for r in prepared["preparation"]["expected_responses"]} == {2_000}
    assert all(r["data_length"] != 2_000 for r in prepared["resources"])
    assert prepared["preparation"]["frozen_application_manifest"] == selection.frozen_application_manifest_declaration(digest)
    assert len([c for c in calls if c[1] == "run"]) == 21  # twenty probes + one full twenty GET.
    assert len([c for c in calls if c[1] == "qualify-chaff-response"]) == 3
    assert [identifier for identifier, _ in sustained] == ([] if cap is None else [1])
    if cap is not None:
        # Fresh 2000-byte bodies fit; every frozen 2500+ hint exceeds this cap.
        assert result["buflo_chaff_selection"]["cap_bytes"] == cap
        assert result["paths"]["buflo_chaff_manifest"] is not None
    assert result["mode_readiness"] == dict.fromkeys(native.MODES, True)
    assert result["scientific_credit"] is False


def test_failed_fresh_GET_cannot_borrow_donor_preparation_or_chaff(donor, executable, monkeypatch):
    root, source, digest, raw, _, urls = donor
    calls = install_process_stub(monkeypatch, rejected=(urls[0],))
    with pytest.raises(ValueError, match="did not yield20 actual complete"):
        native.prepare_domain(HOST, urls, root / "failed", client=executable,
            runtime=runtime(executable), frozen_application_manifest=source,
            frozen_application_manifest_sha256=digest)
    assert not any(c[1] == "qualify-chaff-response" for c in calls)
    assert source.read_bytes() == raw and not (root / "failed/enrollment.json").exists()


@pytest.mark.parametrize("case", ["wrong-sha", "wrong-host", "reordered", "changed-request", "half-pair"])
def test_invalid_donor_refuses_before_Native_operation_or_output(donor, executable, monkeypatch, case):
    root, source, digest, raw, value, urls = donor
    calls = install_process_stub(monkeypatch)
    host = HOST
    if case == "wrong-sha": digest = "f" * 64
    elif case == "wrong-host": host = "other.example.org"
    elif case == "reordered": urls = list(reversed(urls))
    elif case == "changed-request":
        value["resources"][1]["headers"][0][1] = "text/html"
        digest = put(source, inputs.canonical_json(value))
    else: digest = None
    with pytest.raises(ValueError):
        native.prepare_domain(host, urls, root / "refused", client=executable,
            runtime=runtime(executable), frozen_application_manifest=source,
            frozen_application_manifest_sha256=digest)
    assert not calls and not (root / "refused").exists()


def test_frozen_input_requires_same_host_current_context_workload(donor):
    root, source, digest, raw, _, urls = donor
    for host, claimed, selected in [("other.example.org", digest, urls),
                                   (HOST, "f" * 64, urls), (HOST, digest, list(reversed(urls)))]:
        with pytest.raises(ValueError): selection.freeze_application_manifest(root, host, source, claimed, selected)
    binding = selection.freeze_application_manifest(root, HOST, source, digest, urls)
    assert selection.read_frozen_application_manifest(root, HOST, urls, binding)[0] == raw
    assert source.read_bytes() == (root / binding["manifest_path"]).read_bytes() == raw
    assert binding["context_sha256"] == inputs.sha256_file(root / cohorts.INPUT_CONTEXT)


@pytest.mark.parametrize("case", ["missing-declaration", "wrong-context", "uninventoried", "rewritten-bytes", "changed-prepared"])
def test_frozen_preparation_proof_refuses_partial_or_changed_inputs(donor, case):
    root, source, digest, raw, value, urls = donor
    binding = selection.freeze_application_manifest(root, HOST, source, digest, urls)
    workload = root / "prepared/resources.json"; put(workload, raw)
    enrollment = {"hostname": HOST, "urls": urls, "frozen_application_manifest": binding,
        "workload_path": "prepared/resources.json", "workload_sha256": digest,
        "files": {binding["manifest_path"]: digest, cohorts.INPUT_CONTEXT: binding["context_sha256"]}}
    prepared = {"resources": deepcopy(value["resources"]), "preparation": {
        "frozen_application_manifest": selection.frozen_application_manifest_declaration(digest)}}
    assert selection._validate_frozen_application_manifest_proof(root, enrollment, prepared)
    if case == "missing-declaration": prepared["preparation"].clear()
    elif case == "wrong-context": binding["context_sha256"] = "f" * 64
    elif case == "uninventoried": enrollment["files"].pop(binding["manifest_path"])
    elif case == "rewritten-bytes": put(workload, inputs.canonical_json(value))
    else: prepared["resources"][1]["data_length"] += 1
    with pytest.raises(ValueError): selection._validate_frozen_application_manifest_proof(root, enrollment, prepared)


def test_runtime_passes_frozen_input_separately_and_keeps_four_field_job(donor, monkeypatch):
    root, source, digest, raw, value, urls = donor
    binding = selection.freeze_application_manifest(root, HOST, source, digest, urls)
    bound = {"collection_image_digest": "sha256:" + "a" * 64}; observed = []
    monkeypatch.setattr(runtime_adapter, "public_ipv4", lambda _host: {"selected_ipv4": "8.8.8.8"})
    monkeypatch.setattr(runtime_adapter, "docker_lock", nullcontext)
    monkeypatch.setattr(runtime_adapter, "_runtime_check", lambda current: None)
    def docker(*argv, **kwargs):
        assert argv[0] == "run" and kwargs["timeout"] > 0
        job = json.loads(Path(argv[argv.index("--job") + 1]).read_bytes()); observed.append((argv, job))
        assert set(job) == {"hostname", "urls", "output", "runtime"}
        assert argv[argv.index("--frozen-application-manifest") + 1] == str(root / binding["manifest_path"])
        assert argv[argv.index("--frozen-application-manifest-sha256") + 1] == digest
        base = Path(job["output"]); put(base / "resources.json", raw)
        prepared = {"resources": value["resources"], "preparation": {"runtime": bound,
            "frozen_application_manifest": selection.frozen_application_manifest_declaration(digest)}}
        put(base / "prepared-workload.json", inputs.canonical_json(prepared))
        files = {name: inputs.sha256_file(base / name) for name in ("resources.json", "prepared-workload.json")}
        return json.dumps({"hostname": HOST, "urls": urls, "runtime": bound,
            "workload_path": str(base / "resources.json"), "workload_sha256": digest,
            "paths": {"manifest": str(base / "resources.json"), "prepared_workload": str(base / "prepared-workload.json")},
            "files": files, "mode_policies": {"tamaraw": {tamaraw.FIELD: tamaraw.POLICY}},
            "mode_settings": {"tamaraw": {"configuration_sha256": tamaraw.configuration_sha256(selected_policy=tamaraw.POLICY),
                "resolved_configuration": tamaraw.resolved_configuration(selected_policy=tamaraw.POLICY)}},
            "scientific_credit": False})
    monkeypatch.setattr(runtime_adapter, "_docker", docker)
    result = runtime_adapter.PreparationRuntime(root, bound).prepare({"hostname": HOST, "urls": urls},
        root / "enrollment-attempt", frozen_application_manifest=binding)
    assert len(observed) == 1 and result["frozen_application_manifest"] == binding
    assert result["files"][binding["manifest_path"]] == digest
    assert result["files"][cohorts.INPUT_CONTEXT] == binding["context_sha256"]
    assert result["scientific_credit"] is False and source.read_bytes() == raw
