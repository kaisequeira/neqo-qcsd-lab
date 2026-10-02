from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path
import time

import pytest

from qcsd_lab import class_acquisition, rapid_attempt_failure_evidence as observer
from qcsd_lab import prepare
from qcsd_lab import rapid_selection_amendment as amendment
from qcsd_lab import rapid_site_admission as admission
from qcsd_lab.application_response_policy import TERMINAL_HTTP_ERROR_POLICY as POLICY
from tests.test_class_acquisition import _prepared_manifest
from tests.test_rapid_site_admission import (
    Backend, _amended_context, _auto_page, _root_logs, context,
)
from tests.test_prepare_application_response_policy import install_negative_preparation


def test_prospective_leaf_policy_keeps_published_parents_and_16000_target():
    for revision, stamp, digest in (
        (1, amendment.FROZEN_V1_AMENDMENT_PUBLICATION_UTC, amendment.FROZEN_V1_AMENDMENT_SHA256),
        (2, amendment.FROZEN_V2_AMENDMENT_PUBLICATION_UTC, amendment.FROZEN_V2_AMENDMENT_SHA256),
        (3, amendment.FROZEN_V3_AMENDMENT_PUBLICATION_UTC, amendment.FROZEN_V3_AMENDMENT_SHA256),
        (4, amendment.FROZEN_V4_AMENDMENT_PUBLICATION_UTC, amendment.FROZEN_V4_AMENDMENT_SHA256),
    ):
        receipt = amendment.build_selection_amendment(published_at_utc=stamp, revision=revision)
        assert amendment.selection_amendment_sha256(receipt) == digest
        assert "application_response_policy" not in receipt["payload"]
    receipt = amendment.build_selection_amendment(
        published_at_utc=datetime.now(UTC).isoformat().replace("+00:00", "Z"), revision=5)
    payload = amendment.validate_selection_amendment(receipt)
    assert payload["parent_selection_amendment_sha256"] == amendment.FROZEN_V4_AMENDMENT_SHA256
    assert payload["application_response_policy"] == POLICY
    assert payload["formal_modes"] == ["undefended", "front", "tamaraw", "buflo", "cs-buflo"]
    assert payload["cohort_contracts"][-1]["class_count"] == 50
    assert payload["cohort_contracts"][-1]["formal_sample_target"] == 50 * 5 * 64 == 16000


@pytest.mark.parametrize("change", ["policy", "leaf", "primary", "graph", "stability", "chaff", "parent", "boolean-revision"])
def test_resealed_policy_weakening_has_no_prospective_authority(change):
    receipt = amendment.build_selection_amendment(
        published_at_utc=datetime.now(UTC).isoformat().replace("+00:00", "Z"), revision=5)
    payload = deepcopy(receipt["payload"])
    if change == "policy":
        payload["application_response_policy"] = "accept-any-response"
    elif change == "parent":
        payload["parent_selection_amendment_sha256"] = "a" * 64
    elif change == "boolean-revision":
        payload["revision"] = True
    else:
        key = {"leaf": "allowed_errors", "primary": "primary_document", "graph": "full_resource_graph",
               "stability": "stability", "chaff": "chaff"}[change]
        payload["application_response_acceptance"][key] = "waived"
    with pytest.raises(ValueError, match="fixed contract"):
        amendment.validate_selection_amendment(admission.profile._bind(
            payload, amendment.SELECTION_AMENDMENT_RECEIPT_TYPE, schema_version=5))


def test_revision5_requires_direct_helper_in_both_execution_groups(context, tmp_path):
    amended = _amended_context(context, tmp_path, revision=5)
    assert amended.application_response_policy == POLICY
    assert len(amended.mounted_module_hashes["preparation"]) == 8
    assert len(amended.mounted_module_hashes[admission.ATTEMPT_GROUP]) == 19
    helper = admission.APPLICATION_RESPONSE_POLICY_MODULE
    assert amended.mounted_module_hashes["preparation"][helper] == amended.mounted_module_hashes[admission.ATTEMPT_GROUP][helper]
    assert helper not in observer.implementation_sources()
    assert helper in observer.implementation_sources(application_response_policy=True)
    receipt = admission._unpack((amended.root / "provenance.json").read_bytes(), admission.PROVENANCE_TYPE)
    del receipt["module_sources"][admission.ATTEMPT_GROUP][helper]
    (amended.root / "provenance.json").write_bytes(admission._json(admission._bind(admission.PROVENANCE_TYPE, receipt)))
    with pytest.raises(ValueError, match="attempt implementation inventory"):
        admission.load_admission_context(amended.root)


def test_existing_backend_forwards_opt_in_without_changing_legacy_arguments(tmp_path, monkeypatch):
    calls = []
    class ReachedPreparer(Exception):
        pass
    def prepare(*args, **kwargs):
        calls.append(kwargs)
        raise ReachedPreparer
    monkeypatch.setattr(class_acquisition, "prepare_workload", prepare)
    backend = class_acquisition.ExistingAcquisitionBackend()
    for index, policy in enumerate((None, POLICY)):
        with pytest.raises(ReachedPreparer):
            backend.prepare("fixture", "https://page.test/", ["https://page.test"], tmp_path / str(index),
                            origin_ip_pins={"https://page.test": "1.1.1.1"}, application_response_policy=policy)
    assert "application_response_policy" not in calls[0]
    assert calls[1]["application_response_policy"] == POLICY
    assert all(call["require_complete_coverage"] is True and call["stability_runs"] == 3 for call in calls)


@pytest.mark.parametrize("policy", [None, "unknown", False])
def test_policy_manifest_requires_matching_prospective_authority(context, policy):
    manifest = _prepared_manifest("https://page.test/", ["https://cdn.test", "https://page.test"],
                                  source_override=dict(context.expected_runtime_source))
    for resource in manifest["resources"]:
        resource["known_valid"] = True
    manifest["preparation"]["application_response_policy"] = POLICY
    with pytest.raises(ValueError, match="policy|authority"):
        class_acquisition.validate_class_study_preparation(manifest, workload_id="fixture", application_response_policy=policy)
    class_acquisition.validate_class_study_preparation(manifest, workload_id="fixture", application_response_policy=POLICY)


def test_revision5_real_admission_dispatch_preserves_full_graph_and_explicit_policy(context, tmp_path):
    amended = _amended_context(context, tmp_path, revision=5)
    candidate, navigation, h3, screen = _auto_page(amended, tmp_path)
    class PolicyBackend(Backend):
        def prepare(self, *args, application_response_policy=None, **kwargs):
            assert application_response_policy == POLICY
            result = super().prepare(*args, **kwargs)
            manifest = admission._load(result.prepared.path.read_bytes())
            for resource in manifest["resources"]:
                resource["known_valid"] = True
            manifest["preparation"]["application_response_policy"] = application_response_policy
            result.prepared.path.write_bytes(admission._json(manifest))
            return result
    preparation = admission.prepare_site(amended, candidate_id=candidate["candidate_id"],
        navigation=navigation, page_h3=h3, automated_screen=screen, backend=PolicyBackend(amended))
    facts, _, _ = admission._preparation_facts(preparation, amended, candidate["candidate_id"])
    assert facts["application_response_policy"] == POLICY
    assert facts["terminal_http_error_resource_ids"] == []
    assert facts["cross_origin_resource_count"] == 1
    roots = _root_logs(amended, tmp_path)
    terminal = admission.produce_site_terminal(amended, candidate_id=candidate["candidate_id"],
        root_surveys=roots, preparation=preparation, automated_screen=screen)
    assert admission.verify_site_terminal(terminal, amended)["outcome"] == "admitted"
    assert admission.acquisition_status(amended)["formal_accepted_trace_count"] == 0


def test_revision5_unsuccessful_live_call_retains_19_sources_and_cannot_reopen_as_legacy(context, tmp_path):
    amended = _amended_context(context, tmp_path, revision=5)
    candidate, navigation, h3, screen = _auto_page(amended, tmp_path)
    class FailedBackend(Backend):
        def prepare(self, *args, application_response_policy=None, **kwargs):
            assert application_response_policy == POLICY
            raise RuntimeError("actual unsuccessful backend call")
    proof = admission.prepare_site(amended, candidate_id=candidate["candidate_id"],
        navigation=navigation, page_h3=h3, automated_screen=screen, backend=FailedBackend(amended))
    facts = admission.unsuccessful_attempt_failure_facts(proof, amended, candidate["candidate_id"])
    assert facts["actual_attempt_count"] == 1 and facts["site_credit"] == 0
    assert len(facts["implementation_hashes"]) == 19
    assert admission.APPLICATION_RESPONSE_POLICY_MODULE in facts["implementation_hashes"]
    raw = proof.with_name("attempt-observation.json")
    legacy = {key: value for key, value in facts["implementation_hashes"].items()
              if key != admission.APPLICATION_RESPONSE_POLICY_MODULE}
    with pytest.raises(ValueError, match="independent frozen"):
        observer.verify_attempt_failure(raw, execution_binding=amended.execution_binding,
            expected_implementation_hashes=legacy, not_before_utc=amended.attempt_not_before_utc,
            expected_action=facts["action"])


def _negative_workload(context, tmp_path, monkeypatch):
    amended = _amended_context(context, tmp_path, revision=5)
    install_negative_preparation(monkeypatch)
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
            parent = Path(command[command.index("--output") + 1]).parent
            for stage in ("head", "get"):
                path = parent / f"probe-output.probe-{stage}" / "run.json"
                value = admission._load(path.read_bytes())
                value.update(provenance)
                path.write_bytes(admission._json(value))
        return result
    monkeypatch.setattr(prepare, "run", retained_native)
    prepared = prepare.prepare_workload("negative-workload", "https://page.test/",
        ["https://cdn.test", "https://page.test"], output_root=amended.root / "workloads",
        stability_interval_seconds=0, require_complete_coverage=True, application_response_policy=POLICY)
    manifest = admission._load(prepared.path.read_bytes())
    graph = prepared.path.parent / "full-graph.json"
    graph.write_bytes(admission._json(admission._full_graph(manifest)))
    return amended, prepared, graph


def test_independent_admission_reopens_actual_401_get_and_three_full_graph_runs(context, tmp_path, monkeypatch):
    amended, prepared, graph = _negative_workload(context, tmp_path, monkeypatch)
    facts = admission.verify_prepared_workload(prepared.path, graph, amended, selected_page_url="https://page.test/")
    assert facts["application_response_policy"] == POLICY
    assert facts["terminal_http_error_resource_ids"] == [1]
    assert facts["application_response_evidence_sha256"] == admission._sha(
        (prepared.application_response_evidence_path / "inventory.json").read_bytes())
    assert facts["cross_origin_resource_count"] == 1
    manifest = admission._load(prepared.path.read_bytes())
    assert manifest["resources"][1]["known_valid"] is False
    assert manifest["preparation"]["expected_responses"][1]["status"] == 401
    assert manifest["preparation"]["application_response_policy_evidence"]["get_responses"][0]["outcome"] == "failed"


@pytest.mark.parametrize("change", ["raw-after-cache", "missing", "source", "stale", "child-policy", "stale-run", "declared-length"])
def test_independent_admission_rejects_changed_or_resealed_raw_policy_evidence(context, tmp_path, monkeypatch, change):
    amended, prepared, graph = _negative_workload(context, tmp_path, monkeypatch)
    admission.verify_prepared_workload(prepared.path, graph, amended, selected_page_url="https://page.test/")
    sidecar = prepared.application_response_evidence_path
    inventory_path = sidecar / "inventory.json"
    inventory = admission._load(inventory_path.read_bytes())
    if change == "source":
        inventory["capture_source_after"]["lab_commit"] = "f" * 40
    elif change == "stale":
        inventory["started_at"] = inventory["completed_at"] = "2026-10-01T00:00:00Z"
    elif change == "missing":
        (sidecar / "artifacts/stability-2/run.json").unlink()
    else:
        name = ("stability-1.log.execution.json" if change == "child-policy" else "stability-1/run.json")
        path = sidecar / "artifacts" / name
        value = admission._load(path.read_bytes())
        if change == "child-policy":
            value["command"][value["command"].index("--application-response-policy") + 1] = "http-2xx-only-v1"
        elif change == "stale-run":
            value["started_unix_ns"] = value["ended_unix_ns"] = value["time_anchor_unix_ns"] = 1
        elif change == "declared-length":
            value["responses"][1]["content_length"] = 156
        else:
            value["responses"][1]["body_sha256"] = "f" * 64
        raw = admission._json(value)
        path.write_bytes(raw)
        if change != "raw-after-cache":
            inventory["files"][name] = {"sha256": admission._sha(raw), "size": len(raw)}
    inventory_path.write_bytes(admission._json(inventory))
    with pytest.raises(ValueError):
        admission.verify_prepared_workload(prepared.path, graph, amended, selected_page_url="https://page.test/")
