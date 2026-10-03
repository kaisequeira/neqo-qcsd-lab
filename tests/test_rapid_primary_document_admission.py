"""Prospective authority and retained raw proof for primary-document variation."""

from copy import deepcopy
from dataclasses import asdict
from datetime import UTC, datetime
import json
from pathlib import Path
import time
from types import SimpleNamespace

import pytest

from qcsd_lab import class_acquisition, prepare
from qcsd_lab import rapid_selection_amendment as amendment
from qcsd_lab import rapid_site_admission as admission
from qcsd_lab.discovery_evidence import evidence_sha256
from tests.test_rapid_site_admission import Backend, _amended_context, _auto_page, _root_logs, context
from tests.test_prepare import discovered
from tests.test_prepare_application_response_policy import install_negative_preparation

APPLICATION_POLICY = "completed-terminal-http-errors-v1"
PRIMARY_POLICY = "variable-primary-document-body-v1"


def test_revision6_preserves_all_five_published_parents_and_16000_target():
    for revision in range(1, 6):
        receipt = amendment.build_selection_amendment(
            published_at_utc=getattr(amendment, f"FROZEN_V{revision}_AMENDMENT_PUBLICATION_UTC"),
            revision=revision,
        )
        assert amendment.selection_amendment_sha256(receipt) == getattr(amendment, f"FROZEN_V{revision}_AMENDMENT_SHA256")
        assert "primary_document_identity_policy" not in receipt["payload"]
    receipt = amendment.build_selection_amendment(
        published_at_utc=datetime.now(UTC).isoformat().replace("+00:00", "Z"), revision=6)
    value = amendment.validate_selection_amendment(receipt)
    assert value["parent_selection_amendment_sha256"] == amendment.FROZEN_V5_AMENDMENT_SHA256
    assert value["primary_document_identity_policy"] == PRIMARY_POLICY
    assert value["application_response_policy"] == APPLICATION_POLICY
    assert value["cohort_contracts"][-1]["formal_sample_target"] == 50 * 5 * 64


@pytest.mark.parametrize("change", ["policy", "other-resources", "graph", "primary-status"])
def test_resealed_primary_waiver_cannot_expand_the_registered_scope(change):
    receipt = amendment.build_selection_amendment(
        published_at_utc=datetime.now(UTC).isoformat().replace("+00:00", "Z"), revision=6)
    value = deepcopy(receipt["payload"])
    if change == "policy":
        value["primary_document_identity_policy"] = "any-resource-may-change"
    elif change == "graph":
        value["admitted_resource_graph"] = "pruned"
    else:
        key = "other_resources" if change == "other-resources" else "unchanged_identity"
        value["primary_document_identity_acceptance"][key] = "waived"
    with pytest.raises(ValueError, match="fixed contract"):
        amendment.validate_selection_amendment(admission.profile._bind(
            value, amendment.SELECTION_AMENDMENT_RECEIPT_TYPE, schema_version=5))


def test_existing_backend_forwards_primary_policy_without_changing_old_kwargs(tmp_path, monkeypatch):
    calls = []
    class ReachedProducer(Exception):
        pass
    def producer(*args, **kwargs):
        calls.append(kwargs)
        raise ReachedProducer
    monkeypatch.setattr(class_acquisition, "prepare_workload", producer)
    backend = class_acquisition.ExistingAcquisitionBackend()
    for index, (application, primary) in enumerate(((None, None), (APPLICATION_POLICY, None), (APPLICATION_POLICY, PRIMARY_POLICY))):
        with pytest.raises(ReachedProducer):
            backend.prepare("fixture", "https://page.test/", ["https://page.test"], tmp_path / str(index),
                origin_ip_pins={"https://page.test": "1.1.1.1"}, application_response_policy=application,
                primary_document_identity_policy=primary)
    assert "primary_document_identity_policy" not in calls[0] and "primary_document_identity_policy" not in calls[1]
    assert calls[2]["primary_document_identity_policy"] == PRIMARY_POLICY
    assert all(call["stability_runs"] == 3 and call["require_complete_coverage"] is True for call in calls)
    with pytest.raises(ValueError, match="requires"):
        backend.prepare("fixture", "https://page.test/", ["https://page.test"], tmp_path / "invalid",
            origin_ip_pins={"https://page.test": "1.1.1.1"}, primary_document_identity_policy=PRIMARY_POLICY)
    assert len(calls) == 3


def test_revision6_live_boundary_receives_policy_and_preserves_failed_attempt(context, tmp_path):
    amended = _amended_context(context, tmp_path, revision=6)
    candidate, navigation, h3, screen = _auto_page(amended, tmp_path)
    class FailedBackend(Backend):
        def prepare(self, *args, application_response_policy=None, primary_document_identity_policy=None, **kwargs):
            assert application_response_policy == APPLICATION_POLICY
            assert primary_document_identity_policy == PRIMARY_POLICY
            raise RuntimeError("actual failed backend operation under prospectively fixed primary rule")
    failure = admission.prepare_site(amended, candidate_id=candidate["candidate_id"], navigation=navigation,
        page_h3=h3, automated_screen=screen, backend=FailedBackend(amended))
    facts = admission.unsuccessful_attempt_failure_facts(failure, amended, candidate["candidate_id"])
    assert len(facts["implementation_hashes"]) == 19
    assert facts["scientific_credit"] is False and facts["site_credit"] == 0


def _prepared_variable_workload(context, tmp_path, monkeypatch, *, negative=True, capacity=True,
                                amended=None, source_url="https://page.test/", workload_id="variable-page",
                                output_root=None, alter_stability=None, preparation_policies=None,
                                identity_chaff_headers=False):
    amended = amended or _amended_context(context, tmp_path, revision=6)
    def vary(index, run):
        row = run["responses"][0]
        row.update(bytes=100 + index, body_sha256=f"{index + 1:064x}", content_length=100 + index,
                   response_headers=[["content-type", "text/html"], ["content-length", str(100 + index)]])
        if not negative:
            run["responses"][1].update(status=200)
        if capacity:
            run["responses"][2].update(bytes=1200, body_sha256="c" * 64, content_length=1200)
        if alter_stability is not None:
            alter_stability(index, run)
    install_negative_preparation(monkeypatch, alter_stability=vary)
    discovery = discovered()
    if source_url != discovery.source_url:
        def rebind(value):
            if isinstance(value, str):
                return value.replace("https://page.test", source_url.rstrip("/"))
            if isinstance(value, list):
                return [rebind(item) for item in value]
            if isinstance(value, dict):
                return {rebind(key): rebind(item) for key, item in value.items()}
            return value
        discovery = type(discovery)(**rebind(asdict(discovery)))
    if capacity:
        resource = deepcopy(discovery.resources[1])
        resource.update(id=2, url=source_url.rstrip("/") + "/static.js")
        if identity_chaff_headers:
            resource["headers"].extend([["accept-encoding", "gzip"], ["accept-language", "en-US"]])
            resource["headers"].sort()
        discovery.resources.append(resource)
        audit = discovery.discovery_event_audit
        events = deepcopy(audit["events"][3:6])
        for sequence, event in enumerate(events, 7):
            event.update(sequence=sequence, network_id="network-2")
            if "url" in event:
                event["url"] = resource["url"]
            if event["kind"] == "network-request":
                event.update(occurrence_id="request-00000002", mapping={"kind": "resource", "resource_id": 2})
                if identity_chaff_headers:
                    event["safe_request_headers"] = deepcopy(resource["headers"])
            elif event["kind"] == "fetch-request":
                event.update(fetch_id="fetch-2", network_occurrence_id="request-00000002")
            else:
                event["network_occurrence_ids"] = ["request-00000002"]
        audit["events"].extend(events)
        audit["summary"].update(event_count=9, network_request_count=3, fetch_request_count=3,
            terminal_event_count=3, resource_occurrence_count=3)
        discovery.observed_request_count = 3
    discovery.discovery_event_audit_sha256 = evidence_sha256(discovery.discovery_event_audit)
    monkeypatch.setattr(prepare, "discover_page", lambda *_args, **_kwargs: discovery)
    monkeypatch.setattr(prepare, "source_metadata", lambda: dict(amended.expected_runtime_source))
    ordinary = prepare.run
    provenance = {"neqo_base_commit": "4" * 40, "published_qcsd_commit": "5" * 40, "migration_commit": "6" * 40}
    def retained_native(command, **options):
        result = ordinary(command, **options)
        if command[1] == "run":
            output = Path(command[command.index("--output-dir") + 1]) / "run.json"
            raw = admission._load(output.read_bytes())
            now = time.time_ns()
            raw.update(**provenance, started_unix_ns=now, ended_unix_ns=now, time_anchor_unix_ns=now,
                workload_hash_sha256=admission._sha(Path(command[command.index("--workload") + 1]).read_bytes()))
            output.write_bytes(admission._json(raw))
        else:
            output = Path(command[command.index("--output") + 1])
            if capacity:
                resolved = admission._load(output.read_bytes())
                resolved["resources"][2].update(content_length=1200, data_length=1200)
                output.write_bytes(admission._json(resolved))
            if not negative:
                resolved = admission._load(output.read_bytes())
                resolved["resources"][1]["known_valid"] = True
                output.write_bytes(admission._json(resolved))
            for stage in ("head", "get"):
                path = output.parent / f"probe-output.probe-{stage}" / "run.json"
                raw = admission._load(path.read_bytes())
                raw.update(provenance)
                if capacity and stage == "head":
                    raw["responses"][2]["content_length"] = 1200
                if not negative:
                    raw["completion_status"] = "complete"
                    for row in raw["responses"]:
                        row.update(status=200, outcome="succeeded")
                path.write_bytes(admission._json(raw))
        return result
    monkeypatch.setattr(prepare, "run", retained_native)
    result = prepare.prepare_workload(workload_id, source_url, [source_url.rstrip("/"), "https://cdn.test"],
        output_root=output_root or amended.root / "workloads", stability_interval_seconds=0, require_complete_coverage=True,
        application_response_policy=APPLICATION_POLICY, primary_document_identity_policy=PRIMARY_POLICY,
        **(preparation_policies or {}))
    manifest = admission._load(result.path.read_bytes())
    graph = result.path.parent / "full-graph.json"
    graph.write_bytes(admission._json(admission._full_graph(manifest)))
    return amended, result, graph


@pytest.mark.parametrize("malformed", [False, True])
def test_revision6_observed_nonprimary_response_drift_advances_but_malformed_replay_blocks(
    context, tmp_path, monkeypatch, malformed,
):
    amended = _amended_context(context, tmp_path, revision=6)
    candidate, navigation, h3, screen = _auto_page(amended, tmp_path)
    captured = {}

    def drift(index, run):
        row = run["responses"][2]
        size = (2672, 2713, 2702)[index]
        row.update(bytes=size, content_length=size, body_sha256=f"{index + 20:064x}")
        if malformed and index == 1:
            row["body_sha256"] = "invalid-runner-body-hash"

    class ProducingBackend(Backend):
        def discover(self, url, approved):
            result = super().discover(url, approved)
            origins = sorted([url.rstrip("/"), "https://cdn.test"])
            result.observed_origins = result.approved_origins = result.expandable_origins = origins
            result.origin_ip_pins = {value: "1.1.1.1" for value in origins}
            return result

        def prepare(self, workload_id, url, approved, output_root, **kwargs):
            assert kwargs["application_response_policy"] == APPLICATION_POLICY
            assert kwargs["primary_document_identity_policy"] == PRIMARY_POLICY
            try:
                return _prepared_variable_workload(context, tmp_path, monkeypatch,
                    amended=amended, source_url=url, workload_id=workload_id, output_root=output_root,
                    alter_stability=drift)
            except prepare.PreparationError as error:
                captured["error"] = error
                captured["diagnostics"] = output_root / f"{workload_id}-failure-evidence"
                raise

    arguments = dict(candidate_id=candidate["candidate_id"], navigation=navigation,
                     page_h3=h3, automated_screen=screen, backend=ProducingBackend(amended))
    if malformed:
        with pytest.raises(prepare.RecoverablePreparationError):
            admission.prepare_site(amended, **arguments)
        assert type(captured["error"]) is prepare.RecoverablePreparationError
        assert not any(amended.root.rglob("attempt-failure.json"))
        status = admission.acquisition_status(amended)
        assert status["next_candidate"] == candidate
        assert status["attempts"][candidate["candidate_id"]][0]["state"] == "retryable-operational-error"
    else:
        proof = admission.prepare_site(amended, **arguments)
        error = captured["error"]
        assert type(error) is prepare.ResponseStabilityPolicyError
        assert error.capture_source == dict(amended.expected_runtime_source)
        assert error.capture_started_at <= error.capture_completed_at
        reopened = prepare.validate_preparation_policy_failure_evidence(error.evidence)
        assert reopened["schema_version"] == 3
        assert [row["id"] for row in reopened["replay_manifest"]["resources"]] == [0, 1, 2]
        compared = prepare.response_stability_evidence(reopened["response_runs"],
            primary_document_identity_policy=PRIMARY_POLICY,
            manifest=reopened["primary_document_identity_manifest"])
        assert compared["stable_resource_ids"] == [0, 1]
        facts = admission.unsuccessful_attempt_failure_facts(proof, amended, candidate["candidate_id"])
        assert facts["raw_failure"]["exception"]["exception_type"] == "ResponseStabilityPolicyError"
        assert facts["scientific_credit"] is False and facts["site_credit"] == 0
        terminal = admission.produce_site_terminal(amended, candidate_id=candidate["candidate_id"],
            root_surveys=_root_logs(context, tmp_path), attempt_failure=proof, automated_screen=screen)
        assert admission.verify_site_terminal(terminal, amended)["outcome"] == "unsuccessful-live-attempt-screen-deferred"
        status = admission.acquisition_status(amended)
        assert status["next_candidate"] == amended.candidates[1]
        assert status["terminal_count"] == 1
    assert status["admitted_site_count"] == status["formal_accepted_trace_count"] == 0
    retained = captured["diagnostics"] / "artifacts"
    run_count = 2 if malformed else 3
    assert all((retained / f"stability-{index}/run.json").is_file() for index in range(run_count))
    assert (retained / "stability-2/run.json").is_file() is (not malformed)
    assert not any(amended.root.rglob("preparation.json"))


@pytest.mark.parametrize("negative", [True, False])
def test_revision6_reopens_three_complete_raw_graphs_and_first_actual_primary_snapshot(context, tmp_path, monkeypatch, negative):
    amended, result, graph = _prepared_variable_workload(context, tmp_path, monkeypatch, negative=negative)
    facts = admission.verify_prepared_workload(result.path, graph, amended, selected_page_url="https://page.test/")
    assert facts["primary_document_identity_policy"] == PRIMARY_POLICY
    assert facts["terminal_http_error_resource_ids"] == ([1] if negative else [])
    manifest = admission._load(result.path.read_bytes())
    assert manifest["preparation"]["expected_responses"][0]["bytes"] == 100
    assert manifest["preparation"]["expected_responses"][0]["body_sha256"] == f"{1:064x}"
    assert [row["id"] for row in manifest["resources"]] == [0, 1, 2]
    assert manifest["preparation"]["expected_responses"][2]["bytes"] == 1200
    inventory = admission._load((result.application_response_evidence_path / "inventory.json").read_bytes())
    assert inventory["schema_version"] == 2 and len(inventory["files"]) == 12
    assert [row["bytes"] for row in inventory["primary_document_identity_evidence"]["stability_primary_responses"]] == [100, 101, 102]
    assert facts["application_response_evidence_sha256"] == admission._sha(
        (result.application_response_evidence_path / "inventory.json").read_bytes())
    with pytest.raises(ValueError, match="identity policy"):
        class_acquisition.validate_class_study_preparation(manifest, workload_id="variable-page",
            application_response_policy=APPLICATION_POLICY)


def test_revision6_rejects_complete_graph_without_stable_same_origin_padding_capacity(context, tmp_path, monkeypatch):
    amended, result, graph = _prepared_variable_workload(context, tmp_path, monkeypatch, capacity=False)
    manifest = admission._load(result.path.read_bytes())
    assert [row["id"] for row in manifest["resources"]] == [0, 1]
    assert result.application_response_evidence_path.is_dir()
    with pytest.raises(ValueError, match="no stable same-origin auxiliary response.*1200 bytes.*potential padding capacity"):
        admission.verify_prepared_workload(result.path, graph, amended, selected_page_url="https://page.test/")
    assert not amended.proof_cache["prepared"]
    assert admission._load(result.path.read_bytes()) == manifest


@pytest.mark.parametrize("invalid_proof", [False, True])
def test_revision6_observed_complete_preparation_capacity_failure_can_seal_and_advance_but_invalid_proof_blocks(
    context, tmp_path, monkeypatch, invalid_proof,
):
    amended = _amended_context(context, tmp_path, revision=6)
    candidate, navigation, h3, screen = _auto_page(amended, tmp_path)
    roots = _root_logs(context, tmp_path)
    retained = {}

    class ProducingBackend(Backend):
        def discover(self, url, approved):
            result = super().discover(url, approved)
            origins = sorted([url.rstrip("/"), "https://cdn.test"])
            result.observed_origins = result.approved_origins = result.expandable_origins = origins
            result.origin_ip_pins = {value: "1.1.1.1" for value in origins}
            return result

        def prepare(self, workload_id, url, approved, output_root, **kwargs):
            assert kwargs["application_response_policy"] == APPLICATION_POLICY
            assert kwargs["primary_document_identity_policy"] == PRIMARY_POLICY
            _, result, _ = _prepared_variable_workload(context, tmp_path, monkeypatch,
                amended=amended, source_url=url, workload_id=workload_id, output_root=output_root,
                capacity=False)
            retained["workload"] = result.path
            retained["evidence"] = result.application_response_evidence_path
            if invalid_proof:
                inventory_path = result.application_response_evidence_path / "inventory.json"
                inventory = admission._load(inventory_path.read_bytes())
                inventory["capture_source_after"]["lab_commit"] = "f" * 40
                inventory_path.write_bytes(admission._json(inventory))
            return SimpleNamespace(prepared=result)

    arguments = dict(candidate_id=candidate["candidate_id"], navigation=navigation,
                     page_h3=h3, automated_screen=screen, backend=ProducingBackend(amended))
    if invalid_proof:
        with pytest.raises(ValueError, match="runtime"):
            admission.prepare_site(amended, **arguments)
        assert not any(amended.root.rglob("attempt-failure.json"))
        status = admission.acquisition_status(amended)
        assert status["next_candidate"] == candidate
        assert status["attempts"][candidate["candidate_id"]][0]["state"] == "retryable-operational-error"
    else:
        proof = admission.prepare_site(amended, **arguments)
        facts = admission.unsuccessful_attempt_failure_facts(proof, amended, candidate["candidate_id"])
        assert facts["raw_failure"]["exception"]["exception_type"] == "InsufficientPaddingCapacityError"
        assert facts["raw_failure"]["exception"]["exception_module"] == "qcsd_lab.rapid_site_admission"
        assert facts["scientific_credit"] is False and facts["site_credit"] == 0
        terminal = admission.produce_site_terminal(amended, candidate_id=candidate["candidate_id"],
            root_surveys=roots, attempt_failure=proof, automated_screen=screen)
        assert admission.verify_site_terminal(terminal, amended)["outcome"] == "unsuccessful-live-attempt-screen-deferred"
        status = admission.acquisition_status(amended)
        assert status["next_candidate"] == amended.candidates[1]
        assert status["terminal_count"] == 1 and status["admitted_site_count"] == 0
        assert status["formal_accepted_trace_count"] == 0
    manifest = admission._load(retained["workload"].read_bytes())
    assert len(manifest["resources"]) == 2 and retained["evidence"].is_dir()
    assert not any(amended.root.rglob("preparation.json"))


@pytest.mark.parametrize("change", ["other-body", "primary-status", "incomplete-primary", "source", "missing-run"])
def test_revision6_cached_reopening_rejects_tampered_or_resealed_raw_witnesses(context, tmp_path, monkeypatch, change):
    amended, result, graph = _prepared_variable_workload(context, tmp_path, monkeypatch)
    admission.verify_prepared_workload(result.path, graph, amended, selected_page_url="https://page.test/")
    sidecar = result.application_response_evidence_path
    inventory_path = sidecar / "inventory.json"
    inventory = admission._load(inventory_path.read_bytes())
    name = "stability-1/run.json"
    path = sidecar / "artifacts" / name
    if change == "source":
        inventory["capture_source_after"]["lab_commit"] = "f" * 40
    elif change == "missing-run":
        path.unlink()
    else:
        raw = admission._load(path.read_bytes())
        if change == "other-body":
            raw["responses"][1]["body_sha256"] = "f" * 64
        elif change == "primary-status":
            raw["responses"][0]["status"] = 201
        else:
            raw["responses"][0]["complete"] = False
        content = admission._json(raw)
        path.write_bytes(content)
        inventory["files"][name] = {"sha256": admission._sha(content), "size": len(content)}
    inventory_path.write_bytes(admission._json(inventory))
    with pytest.raises(ValueError):
        admission.verify_prepared_workload(result.path, graph, amended, selected_page_url="https://page.test/")
