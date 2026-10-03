import hashlib
import json
from pathlib import Path
import shutil
from copy import deepcopy

import pytest

from qcsd_lab import prepare
from qcsd_lab.application_response_policy import (
    COMPLETED_TERMINAL_HTTP_ERRORS_POLICY as RESPONSE_POLICY,
    VARIABLE_PRIMARY_DOCUMENT_BODY_POLICY as PRIMARY_POLICY,
    validate_application_responses,
    validate_primary_document_identity_evidence,
)
from qcsd_lab.manifest import validate_manifest
from tests.test_prepare_application_response_policy import install_negative_preparation


def install_variable_preparation(monkeypatch, *, negative=False, alter_primary=None, alter_other=None):
    commands = install_negative_preparation(monkeypatch)
    existing_run = prepare.run

    def actual_stage(command, **options):
        result = existing_run(command, **options)
        if command[1] == "probe":
            if not negative:
                output = Path(command[command.index("--output") + 1])
                resolved = json.loads(output.read_bytes())
                resolved["resources"][1].update(known_valid=True, content_length=101, data_length=101)
                output.write_text(json.dumps(resolved))
                head_path = output.parent / "probe-output.probe-head/run.json"
                head = json.loads(head_path.read_bytes())
                head["completion_status"] = "complete"
                head["responses"][1].update(status=200, content_length=101, outcome="succeeded")
                head_path.write_text(json.dumps(head))
                # The real all-known-valid probe performs no GET fallback.
                shutil.rmtree(output.parent / "probe-output.probe-get")
        else:
            output = Path(command[command.index("--output-dir") + 1])
            index = int(output.name.rsplit("-", 1)[1])
            path = output / "run.json"
            run = json.loads(path.read_bytes())
            primary = run["responses"][0]
            primary.update(bytes=2000 + index, content_length=2000 + index,
                body_sha256=("a", "c", "d")[index] * 64,
                response_headers=[["content-type", "text/html; charset=utf-8"], ["date", str(index)]])
            if not negative:
                run["responses"][1].update(status=200, bytes=101, content_length=101, body_sha256="b" * 64)
            if alter_primary:
                alter_primary(index, primary)
            if alter_other:
                alter_other(index, run["responses"][1])
            path.write_text(json.dumps(run))
        return result

    monkeypatch.setattr(prepare, "run", actual_stage)
    return commands


def prepare_variable(tmp_path, *, workload_id="variable-page", policy=PRIMARY_POLICY):
    return prepare.prepare_workload(workload_id, "https://page.test/", ["https://page.test", "https://cdn.test"],
        output_root=tmp_path, stability_interval_seconds=0, require_complete_coverage=True,
        application_response_policy=RESPONSE_POLICY, primary_document_identity_policy=policy)


@pytest.mark.parametrize("negative", [False, True])
def test_actual_pipeline_retains_three_variable_primary_snapshots_and_full_graph(tmp_path, monkeypatch, negative):
    commands = install_variable_preparation(monkeypatch, negative=negative)
    prepared = prepare_variable(tmp_path)
    manifest = json.loads(prepared.path.read_bytes())
    validate_manifest(manifest)
    proof = validate_primary_document_identity_evidence(manifest)
    assert [row["id"] for row in manifest["resources"]] == [0, 1]
    assert manifest["resources"][0]["content_length"] == 2000
    assert manifest["resources"][0]["data_length"] == 100  # Actual probe size is retained.
    assert manifest["preparation"]["expected_responses"][0]["body_sha256"] == "a" * 64
    assert [row["bytes"] for row in proof["stability_primary_responses"]] == [2000, 2001, 2002]
    retained = prepared.application_response_evidence_path
    inventory = json.loads((retained / "inventory.json").read_bytes())
    assert inventory["schema_version"] == 2
    assert inventory["primary_document_identity_policy"] == PRIMARY_POLICY
    assert inventory["primary_document_identity_evidence"] == proof
    assert inventory["capture_source_before"] == inventory["capture_source_after"]
    assert inventory["started_at"] <= inventory["completed_at"]
    assert inventory["scientific_credit"] is False
    assert not Path(inventory["original_directory"]).exists()
    assert ("probe-output.probe-get/run.json" in inventory["files"]) is negative
    assert (inventory["policy_evidence"] is not None) is negative
    files = {path.relative_to(retained / "artifacts").as_posix(): path
             for path in (retained / "artifacts").rglob("*") if path.is_file()}
    assert set(files) == set(inventory["files"])
    for name, path in files.items():
        raw = path.read_bytes()
        assert inventory["files"][name] == {"sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw)}
    raw_signatures = []
    for index in range(3):
        run_path = files[f"stability-{index}/run.json"]
        assert hashlib.sha256(run_path.read_bytes()).hexdigest() == proof["stability_run_sha256s"][index]
        run = json.loads(run_path.read_bytes())
        raw_signatures.append(validate_application_responses(manifest, run)["response_signature"])
        assert f"stability-{index}.log.execution.json" in files
    assert len({repr(signature) for signature in raw_signatures}) == 3
    assert [command[1] for command in commands] == ["probe", "run", "run", "run"]


@pytest.mark.parametrize("change", ["empty", "partial", "length", "not-html"])
def test_invalid_variable_primary_stops_before_another_replay_and_retains_actual_failure(tmp_path, monkeypatch, change):
    def mutate(_index, row):
        if change == "empty":
            row.update(bytes=0, content_length=0, body_sha256=hashlib.sha256(b"").hexdigest())
        elif change == "partial":
            row["complete"] = False
        elif change == "length":
            row["content_length"] += 1
        else:
            row["response_headers"][0][1] = "application/json"

    commands = install_variable_preparation(monkeypatch, alter_primary=mutate)
    message = "concrete request headers" if change == "partial" else "primary Document replay is invalid"
    with pytest.raises(prepare.PreparationError, match=message):
        prepare_variable(tmp_path)
    assert len(commands) == 2
    retained = tmp_path / "variable-page-failure-evidence/artifacts"
    assert (retained / "stability-0/run.json").is_file()
    assert not (retained / "stability-1").exists()
    assert not (tmp_path / "variable-page.json").exists()


@pytest.mark.parametrize("negative", [False, True])
def test_variable_primary_nonprimary_body_drift_has_reopenable_typed_failure(tmp_path, monkeypatch, negative):
    def mutate(index, row):
        # Reproduce the observed Poki SDK response pattern: three successful
        # complete auxiliary bodies with different lengths and identities.
        row.update(bytes=(2672, 2713, 2702)[index], content_length=(2672, 2713, 2702)[index],
                   body_sha256=hashlib.sha256(f"sdk-response-{index}".encode()).hexdigest())

    commands = install_variable_preparation(monkeypatch, negative=negative, alter_other=mutate)
    with pytest.raises(prepare.ResponseStabilityPolicyError, match="resource IDs: 1") as raised:
        prepare_variable(tmp_path)
    error = raised.value
    assert type(error) is prepare.ResponseStabilityPolicyError
    assert error.capture_source == prepare.source_metadata()
    assert error.capture_started_at <= error.capture_completed_at
    proof = prepare.validate_preparation_policy_failure_evidence(error.evidence, source_url="https://page.test/")
    assert proof["schema_version"] == 3
    assert [row["id"] for row in proof["replay_manifest"]["resources"]] == [0, 1]
    assert proof["replay_manifest"]["resources"][1]["known_valid"] is (not negative)
    declaration = proof["primary_document_identity_manifest"]
    compared = prepare.response_stability_evidence(proof["response_runs"],
        primary_document_identity_policy=PRIMARY_POLICY, manifest=declaration)
    assert compared["stable_resource_ids"] == [0]
    # Ordinary successful admission/capture still rejects these exact runs.
    with pytest.raises(ValueError, match="prepared response identity"):
        validate_application_responses(declaration, proof["response_runs"][1])
    assert len(commands) == 4
    assert (tmp_path / "variable-page-failure-evidence/artifacts/stability-2/run.json").is_file()
    assert not (tmp_path / "variable-page.json").exists()


@pytest.mark.parametrize("change", ["hash", "url", "headers", "status", "outcome", "terminal-errors"])
def test_variable_primary_malformed_auxiliary_replay_remains_operational(tmp_path, monkeypatch, change):
    def mutate(index, row):
        if index != 1:
            return
        if change == "hash":
            row["body_sha256"] = "not-a-body-hash"
        elif change == "url":
            row["url"] = "https://different.test/app.js"
        elif change == "headers":
            row["request_headers"].append(["x-mutated", "request"])
        elif change == "status":
            row["status"] = 201
        elif change == "outcome":
            row["outcome"] = "endpoint_closed"

    commands = install_variable_preparation(monkeypatch, alter_other=mutate)
    if change == "terminal-errors":
        ordinary = prepare.run
        def actual_stage(command, **options):
            result = ordinary(command, **options)
            if command[1] == "run":
                path = Path(command[command.index("--output-dir") + 1]) / "run.json"
                value = json.loads(path.read_bytes())
                value["terminal_evidence_render_errors"] = ["malformed terminal output"]
                path.write_text(json.dumps(value))
            return result
        monkeypatch.setattr(prepare, "run", actual_stage)
    with pytest.raises(prepare.PreparationError) as raised:
        prepare_variable(tmp_path)
    assert type(raised.value) is (prepare.PreparationError if change == "outcome" else prepare.RecoverablePreparationError)
    assert not hasattr(raised.value, "capture_started_at")
    assert not (tmp_path / "variable-page.json").exists()
    # Malformed identities and incomplete outcomes abort at their first raw run.
    assert len(commands) == (3 if change in {"hash", "outcome"} else 4)


@pytest.mark.parametrize("change", ["primary-only", "missing-run", "changed-declaration", "malformed-ledger"])
def test_variable_primary_typed_drift_proof_rejects_resealed_invalid_authority(tmp_path, monkeypatch, change):
    def mutate(index, row):
        row.update(bytes=2672 + index, content_length=2672 + index, body_sha256=f"{index + 10:064x}")
    install_variable_preparation(monkeypatch, alter_other=mutate)
    with pytest.raises(prepare.ResponseStabilityPolicyError) as raised:
        prepare_variable(tmp_path)
    proof = deepcopy(raised.value.evidence)
    if change == "missing-run":
        del proof["artifacts"]["stability-2/run.json"]
    elif change == "changed-declaration":
        proof["primary_document_identity_manifest"]["preparation"]["max_response_bytes"] += 1
    else:
        from tests.test_prepare import _replace_failure_artifact
        if change == "primary-only":
            original = proof["response_runs"][0]["responses"][1]
            for run in proof["response_runs"]:
                run["responses"][1] = deepcopy(original)
        else:
            proof["response_runs"][1]["responses"].pop()
        for index, run in enumerate(proof["response_runs"]):
            _replace_failure_artifact(proof, f"stability-{index}/run.json", json.dumps(run).encode())
        if change == "primary-only":
            declaration = proof["primary_document_identity_manifest"]
            declaration["preparation"]["primary_document_identity_evidence"]["stability_run_sha256s"] = [
                proof["artifacts"][f"stability-{index}/run.json"]["sha256"] for index in range(3)]
    with pytest.raises(ValueError):
        prepare.validate_preparation_policy_failure_evidence(proof)


def test_default_primary_identity_still_rejects_primary_drift(tmp_path, monkeypatch):
    install_variable_preparation(monkeypatch)
    with pytest.raises(prepare.ResponseStabilityPolicyError, match="resource IDs: 0"):
        prepare_variable(tmp_path, policy=None)
    assert not (tmp_path / "variable-page.json").exists()


def test_variable_sidecar_is_create_only_and_does_not_overwrite_old_bytes(tmp_path, monkeypatch):
    install_variable_preparation(monkeypatch)
    old = tmp_path / "variable-page-application-response-evidence"
    old.mkdir()
    (old / "old.json").write_bytes(b"immutable old proof")
    with pytest.raises(FileExistsError):
        prepare_variable(tmp_path)
    assert (old / "old.json").read_bytes() == b"immutable old proof"
    assert (tmp_path / "variable-page-failure-evidence/artifacts/stability-2/run.json").is_file()
    assert not (tmp_path / "variable-page.json").exists()


def test_optional_get_cannot_hide_a_broken_link(tmp_path, monkeypatch):
    directory = tmp_path / "original"
    directory.mkdir()
    get = directory / "probe-output.probe-get/run.json"
    get.parent.mkdir()
    get.symlink_to(tmp_path / "missing-run.json")
    monkeypatch.setattr(prepare, "_failure_capture_source", lambda: {})
    with pytest.raises(prepare.PreparationError, match="probe-output.probe-get/run.json"):
        # Other raw files need not exist for this check: inclusion rather than
        # omission is observable directly in the first retained-file reads.
        for relative in ("probe-input.json", "probe-output.json", "probe.log.execution.json",
                         "probe-output.probe-head/run.json"):
            path = directory / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("{}")
        prepare._retain_application_response_evidence(directory, tmp_path / "sidecar", workload_id="linked",
            capture_source={}, started_at="2026-10-03T00:00:00+00:00", stability_runs=3,
            policy_evidence=None, primary_document_identity_evidence={})
