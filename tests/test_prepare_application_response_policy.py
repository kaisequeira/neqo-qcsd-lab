from copy import deepcopy
import hashlib
import json
from pathlib import Path
import subprocess
import time

import pytest

from qcsd_lab import prepare
from qcsd_lab.application_response_policy import COMPLETED_TERMINAL_HTTP_ERRORS_POLICY as POLICY
from qcsd_lab.application_response_policy import validate_application_response_policy_evidence
from qcsd_lab.manifest import validate_manifest
from tests.test_prepare import discovered, install_fake_preparation


def install_negative_preparation(monkeypatch, *, alter_probe=None, alter_stability=None):
    commands = install_fake_preparation(monkeypatch)
    ordinary_run = prepare.run

    def actual_stage(command, **options):
        result = ordinary_run(command, **options)
        if command[1] == "probe":
            source = json.loads(Path(command[command.index("--input-manifest") + 1]).read_bytes())
            output = Path(command[command.index("--output") + 1])
            resolved = json.loads(output.read_bytes())
            resolved["resources"][1].update(known_valid=False, content_length=157, data_length=157)
            output.write_text(json.dumps(resolved))
            parent = output.parent
            now = time.time_ns()
            provenance = {"neqo_version": "0.1.0", "neqo_base_commit": "base",
                          "published_qcsd_commit": "published", "migration_commit": "migration"}
            for stage, resources in (("head", source["resources"]), ("get", [source["resources"][1]])):
                location = parent / f"probe-output.probe-{stage}"
                location.mkdir()
                origins = sorted({prepare.origin(row["url"]) for row in resources})
                rows = [{"resource_id": row["id"], "url": row["url"], "request_headers": row["headers"],
                         "status": 401 if row["id"] == 1 else 200,
                         "bytes": 157 if stage == "get" else 0,
                         "content_length": 157 if row["id"] == 1 else 100,
                         "body_sha256": "b" * 64 if stage == "get" else hashlib.sha256(b"").hexdigest(),
                         "complete": True, "outcome": "failed" if row["id"] == 1 else "succeeded"}
                        for row in resources]
                run = {**provenance, "method": "HEAD" if stage == "head" else "GET",
                       "request_policy": "as-defined", "seed": 0, "completion_status": "partial",
                       "error": None, "error_class": None, "terminal_evidence_render_errors": [],
                       "application_response_policy": "http-2xx-only-v1",
                       "workload_hash_sha256": prepare._probe_runtime_manifest_hash(resources),
                       "application_workload_source_hash_sha256": None, "chaff_manifest_hash_sha256": None,
                       "defense_parameters": None, "max_response_bytes": 0 if stage == "head" else int(command[command.index("--max-bytes") + 1]),
                       "resolved_configuration": {"defense": {"kind": "none"}},
                       "started_unix_ns": now, "ended_unix_ns": now, "time_anchor_unix_ns": now,
                       "endpoints": [{"id": index, "origin": origin + "/", "negotiated_protocol": "h3"}
                                     for index, origin in enumerate(origins)], "responses": rows}
                if alter_probe:
                    alter_probe(stage, run)
                (location / "run.json").write_text(json.dumps(run))
        else:
            output = Path(command[command.index("--output-dir") + 1])
            run = json.loads((output / "run.json").read_bytes())
            run["application_response_policy"] = POLICY
            run["terminal_evidence_render_errors"] = []
            run["responses"][1].update(status=401, bytes=157, body_sha256="b" * 64)
            if alter_stability:
                alter_stability(int(output.name.rsplit("-", 1)[1]), run)
            (output / "run.json").write_text(json.dumps(run))
        return result

    monkeypatch.setattr(prepare, "run", actual_stage)
    return commands


def test_actual_preparation_pipeline_keeps_proven_401_leaf_and_all_resource_ids(tmp_path, monkeypatch):
    commands = install_negative_preparation(monkeypatch)
    prepared = prepare.prepare_workload("policy-page", "https://page.test/", ["https://page.test", "https://cdn.test"],
        output_root=tmp_path, stability_interval_seconds=0, require_complete_coverage=True,
        application_response_policy=POLICY)
    manifest = json.loads(prepared.path.read_bytes())
    validate_manifest(manifest)
    proof = validate_application_response_policy_evidence(manifest)
    assert [row["id"] for row in manifest["resources"]] == [0, 1]
    assert manifest["resources"][1]["known_valid"] is False
    assert manifest["preparation"]["expected_responses"][1] == {
        "resource_id": 1, "status": 401, "bytes": 157, "body_sha256": "b" * 64}
    assert proof["get_responses"][0]["outcome"] == "failed"
    assert proof["get_endpoints"] == [{"id": 0, "origin": "https://cdn.test/", "negotiated_protocol": "h3"}]
    assert len(proof["stability_responses"]) == 3
    assert "--application-response-policy" not in commands[0]
    assert all(command[command.index("--application-response-policy") + 1] == POLICY for command in commands[1:])
    retained = prepared.application_response_evidence_path
    assert retained == tmp_path / "policy-page-application-response-evidence"
    inventory = json.loads((retained / "inventory.json").read_bytes())
    assert inventory["scientific_credit"] is False
    assert inventory["policy_evidence"] == proof
    assert inventory["capture_source_before"] == inventory["capture_source_after"]
    assert not Path(inventory["original_directory"]).exists()
    actual_files = {path.relative_to(retained / "artifacts").as_posix(): path
                    for path in (retained / "artifacts").rglob("*") if path.is_file()}
    assert set(actual_files) == set(inventory["files"])
    assert not any(path.endswith((".csv", ".log")) for path in actual_files)
    for relative, path in actual_files.items():
        raw = path.read_bytes()
        assert inventory["files"][relative] == {"sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw)}
    assert hashlib.sha256(actual_files["probe-output.probe-get/run.json"].read_bytes()).hexdigest() == proof["get_run_sha256"]
    assert [hashlib.sha256(actual_files[f"stability-{index}/run.json"].read_bytes()).hexdigest()
            for index in range(3)] == proof["stability_run_sha256s"]
    reopened = prepare._terminal_http_error_probe_records(
        discovered(), json.loads(actual_files["probe-output.json"].read_bytes()), retained / "artifacts",
        execution_directory=Path(inventory["original_directory"]),
    )
    assert reopened[1]["status"] == 401
    assert reopened[1]["outcome"] == "failed"


def test_response_proof_retention_is_create_only_and_failure_keeps_raw_ledgers(tmp_path, monkeypatch):
    install_negative_preparation(monkeypatch)
    existing = tmp_path / "collision-application-response-evidence"
    existing.mkdir()
    marker = existing / "old-proof.json"
    marker.write_bytes(b"old immutable evidence")
    with pytest.raises(FileExistsError):
        prepare.prepare_workload("collision", "https://page.test/", ["https://page.test", "https://cdn.test"],
            output_root=tmp_path, stability_interval_seconds=0, require_complete_coverage=True,
            application_response_policy=POLICY)
    assert marker.read_bytes() == b"old immutable evidence"
    assert not (tmp_path / "collision.json").exists()
    assert (tmp_path / "collision-failure-evidence/artifacts/probe-output.probe-get/run.json").is_file()
    assert (tmp_path / "collision-failure-evidence/artifacts/stability-2/run.json").is_file()


def test_legacy_success_cleans_temporary_proof_and_returns_no_evidence_path(tmp_path, monkeypatch):
    install_fake_preparation(monkeypatch)
    prepared = prepare.prepare_workload("legacy-cleanup", "https://page.test/", ["https://page.test", "https://cdn.test"],
        output_root=tmp_path, stability_interval_seconds=0, require_complete_coverage=True)
    assert prepared.application_response_evidence_path is None
    assert sorted(path.name for path in tmp_path.iterdir()) == ["legacy-cleanup.json"]


def test_incomplete_native_replay_stops_before_repeat_and_retains_actual_failure(tmp_path, monkeypatch):
    def mutate(_index, run):
        run["completion_status"] = "partial"
        run["responses"][1].update(status=None, complete=False, outcome="request_error")

    commands = install_negative_preparation(monkeypatch, alter_stability=mutate)
    with pytest.raises(prepare.RecoverablePreparationError, match="1 incomplete responses.*request_error"):
        prepare.prepare_workload(
            "partial-replay", "https://page.test/", ["https://page.test", "https://cdn.test"],
            output_root=tmp_path, stability_interval_seconds=0, require_complete_coverage=True,
            application_response_policy=POLICY,
        )
    assert len(commands) == 2  # One probe and one failed replay, no later replay.
    assert not (tmp_path / "partial-replay.json").exists()
    retained = tmp_path / "partial-replay-failure-evidence/artifacts"
    actual = json.loads((retained / "stability-0/run.json").read_bytes())
    assert actual["responses"][1]["outcome"] == "request_error"
    assert not (retained / "stability-1").exists()
    assert not (retained / "stability-2").exists()


@pytest.mark.parametrize("change", ["incomplete", "wrong-url", "h2", "reset", "wrong-hash", "truncated-body", "bool-length", "string-length"])
def test_opt_in_probe_resolution_requires_actual_retained_complete_http_error(tmp_path, monkeypatch, change):
    def mutate(stage, run):
        if stage != "get":
            return
        if change == "incomplete":
            run["responses"][0]["complete"] = False
        elif change == "wrong-url":
            run["responses"][0]["url"] = "https://different.test/"
        elif change == "h2":
            run["endpoints"][0]["negotiated_protocol"] = "h2"
        elif change == "reset":
            run["responses"][0]["outcome"] = "reset"
        elif change == "truncated-body":
            run["responses"][0]["content_length"] = 158
        elif change == "bool-length":
            run["responses"][0]["content_length"] = True
        elif change == "string-length":
            run["responses"][0]["content_length"] = "157"
        else:
            run["workload_hash_sha256"] = "f" * 64
    install_negative_preparation(monkeypatch, alter_probe=mutate)
    with pytest.raises(prepare.PreparationError, match="terminal HTTP error preflight evidence is invalid"):
        prepare.prepare_workload("invalid-proof", "https://page.test/", ["https://page.test", "https://cdn.test"],
            output_root=tmp_path, stability_interval_seconds=0, require_complete_coverage=True,
            application_response_policy=POLICY)
    assert not (tmp_path / "invalid-proof.json").exists()
    assert (tmp_path / "invalid-proof-failure-evidence/artifacts/probe-output.probe-get/run.json").exists()


def test_policy_does_not_allow_false_probe_manifest_without_actual_get(tmp_path):
    discovery = discovered()
    resolved = {"resources": deepcopy(discovery.resources)}
    resolved["resources"][0].update(known_valid=True, content_length=100)
    with pytest.raises(prepare.PreparationError, match="actual retained probe directory"):
        prepare.resolve_probe_output(discovery, resolved, require_complete_coverage=True,
                                     application_response_policy=POLICY)


@pytest.mark.parametrize("change", ["wrong-policy", "response-drift", "probe-stability-drift"])
def test_stability_policy_and_exact_error_identity_remain_required_and_retained(tmp_path, monkeypatch, change):
    def mutate(index, run):
        if change == "wrong-policy":
            run.pop("application_response_policy")
        elif change == "response-drift" and index == 1:
            run["responses"][1]["body_sha256"] = "f" * 64
        elif change == "probe-stability-drift":
            run["responses"][1]["body_sha256"] = "f" * 64
    install_negative_preparation(monkeypatch, alter_stability=mutate)
    with pytest.raises(prepare.PreparationError):
        prepare.prepare_workload("drifting-proof", "https://page.test/", ["https://page.test", "https://cdn.test"],
            output_root=tmp_path, stability_interval_seconds=0, require_complete_coverage=True,
            application_response_policy=POLICY)
    assert not (tmp_path / "drifting-proof.json").exists()
    assert (tmp_path / "drifting-proof-failure-evidence/artifacts/stability-2/run.json").exists()


@pytest.mark.parametrize("policy", [False, "unknown", {}])
def test_prepare_rejects_malformed_policy_before_any_live_call(tmp_path, monkeypatch, policy):
    monkeypatch.setattr(prepare, "discover_page", lambda *_a, **_k: pytest.fail("live discovery must not run"))
    with pytest.raises(ValueError, match="unknown or malformed"):
        prepare.prepare_workload("bad-policy", "https://page.test/", ["https://page.test"],
                                output_root=tmp_path, application_response_policy=policy)
    assert not tmp_path.joinpath("bad-policy.json").exists()


@pytest.mark.parametrize("policy", [None, False, "unknown", {}])
def test_manifest_rejects_explicit_malformed_prepared_policy(policy):
    from tests.test_manifest import prepared_manifest
    manifest = prepared_manifest()
    manifest["preparation"]["application_response_policy"] = policy
    with pytest.raises(ValueError, match="application response policy"):
        validate_manifest(manifest)


@pytest.mark.parametrize("policy", ["http-2xx-only-v1", POLICY])
def test_manifest_accepts_registered_2xx_policy_without_negative_evidence(policy):
    from tests.test_manifest import prepared_manifest
    manifest = prepared_manifest()
    for row in manifest["resources"]:
        row["known_valid"] = True
    manifest["preparation"]["application_response_policy"] = policy
    validate_manifest(manifest)
