"""V11 is sealed prospectively and independently reopened with the full graph."""
from copy import deepcopy
from datetime import UTC, datetime
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from qcsd_lab import capture_acceptance_policy as policy, class_acquisition, prepare
from qcsd_lab import rapid_selection_amendment as amendment, rapid_site_admission as admission
from tools import rapid_acquire, rapid_acquisition_control as control
from tests.test_rapid_primary_document_admission import _prepared_variable_workload
from tests.test_rapid_site_admission import Backend, _amended_context, _auto_page, _root_logs, context

ROOT = Path(__file__).resolve().parents[1]


def test_v11_declaration_retains_exact_v10_parent_and_16000_grid():
    value = amendment.build_selection_amendment(published_at_utc=datetime.now(UTC).isoformat().replace("+00:00", "Z"), revision=11)
    payload = amendment.validate_selection_amendment(value)
    assert payload[policy.FRONT_FIELD] == policy.FRONT_POLICY
    assert payload[policy.TAMARAW_FIELD] == policy.TAMARAW_POLICY
    assert payload[policy.FIELD] == policy.ACK_START_POLICY
    assert payload["parent_selection_amendment_sha256"] == amendment.FROZEN_V10_AMENDMENT_SHA256
    assert payload["formal_modes"] == ["undefended", "front", "tamaraw", "buflo", "cs-buflo"]
    assert payload["cohort_contracts"][-1]["formal_sample_target"] == 16000
    for revision in range(1, 11):
        path = ROOT / f"config/curated-sources/crux73-tranco600-rapid-v5-selection-v{revision}.json"
        raw = path.read_bytes(); historical = json.loads(raw)
        assert amendment.selection_amendment_sha256(historical) == admission._sha(raw)
        assert policy.FRONT_FIELD not in amendment.validate_selection_amendment(historical)


@pytest.mark.parametrize("mutation", ["policy", "parent", "ratio", "reason", "incoming", "tamaraw", "buflo"])
def test_v11_resealed_contract_substitution_is_rejected(mutation):
    value = amendment.build_selection_amendment(published_at_utc=datetime.now(UTC).isoformat().replace("+00:00", "Z"), revision=11)
    payload = deepcopy(value["payload"])
    if mutation == "policy": payload[policy.FRONT_FIELD] = None
    elif mutation == "parent": payload["parent_selection_amendment_sha256"] = "a" * 64
    elif mutation == "ratio": payload["front_capture_acceptance"]["outgoing_omission_ratio_denominator"] = 99
    elif mutation == "reason": payload["front_capture_acceptance"]["outgoing_omission_reason"] = "PacingLimited"
    elif mutation == "incoming": payload["front_capture_acceptance"]["incoming_physical_proof"] = "incoming-misses-allowed"
    elif mutation == "tamaraw": payload[policy.TAMARAW_FIELD] = None
    else: payload[policy.FIELD] = policy.POLICY
    with pytest.raises(ValueError, match="fixed contract"):
        amendment.validate_selection_amendment(admission.profile._bind(payload, amendment.SELECTION_AMENDMENT_RECEIPT_TYPE, schema_version=5))


def test_v11_cannot_predate_its_v10_parent():
    with pytest.raises(ValueError, match="before"):
        amendment.build_selection_amendment(published_at_utc="2026-10-03T10:28:07Z", revision=11)


def test_parent_construction_memo_has_bounded_work_and_no_shared_mutation(monkeypatch):
    original = amendment._memoized_amendment_payload
    calls = []
    def counted(published, parent, *, revision=1, _memo):
        calls.append((published, parent, revision))
        return original(published, parent, revision=revision, _memo=_memo)
    monkeypatch.setattr(amendment, "_memoized_amendment_payload", counted)
    raw = (ROOT / "config/curated-sources/crux73-tranco600-rapid-v5-selection-v11.json").read_bytes()
    fixed = json.loads(raw)
    built = amendment.build_selection_amendment(published_at_utc=fixed["payload"]["published_at_utc"], revision=11)
    assert admission._json(built) == raw
    assert len(set(calls)) == 11 and len(calls) <= 1 + sum(range(1, 12))
    built["payload"]["formal_modes"].clear()
    built["payload"]["automated_site_screen_policy"]["domain_safety_policy"]["denied_substrings"].clear()
    calls.clear()
    assert admission._json(amendment.build_selection_amendment(
        published_at_utc=fixed["payload"]["published_at_utc"], revision=11)) == raw
    assert len(set(calls)) == 11
    altered = deepcopy(fixed["payload"])
    altered["front_capture_acceptance"]["outgoing_omission_ratio_denominator"] = 99
    resealed = admission.profile._bind(altered, amendment.SELECTION_AMENDMENT_RECEIPT_TYPE, schema_version=5)
    with pytest.raises(ValueError, match="fixed contract"):
        amendment.validate_selection_amendment(resealed)


@pytest.mark.parametrize("mutation", ["parent-hash", "loaded-policy"])
def test_parent_memo_never_caches_live_contract_drift_across_requests(monkeypatch, mutation):
    fixed = json.loads((ROOT / "config/curated-sources/crux73-tranco600-rapid-v5-selection-v11.json").read_bytes())
    amendment.validate_selection_amendment(fixed)
    if mutation == "parent-hash":
        monkeypatch.setattr(amendment, "FROZEN_V10_AMENDMENT_SHA256", "f" * 64)
    else:
        changed = deepcopy(admission.profile.DOMAIN_SAFETY_POLICY)
        changed["denied_substrings"].append("changed-after-construction")
        monkeypatch.setattr(admission.profile, "DOMAIN_SAFETY_POLICY", changed)
    with pytest.raises(ValueError, match="declaration no longer verifies"):
        amendment.validate_selection_amendment(fixed)


def test_v11_context_inventory_registry_and_observer_reject_unbound_front_before_live_call(context, tmp_path):
    current = _amended_context(context, tmp_path, revision=11)
    assert current.front_capture_policy == policy.FRONT_POLICY
    assert current.tamaraw_capture_policy == policy.TAMARAW_POLICY
    assert len(current.mounted_module_hashes["preparation"]) == 10
    assert len(current.mounted_module_hashes[admission.ATTEMPT_GROUP]) == 21
    assert control.registry_record_type(current) == "private-frozen-v11-front-congestion-omission-policy-ordered-root-log-registry-v11"
    backend = Backend(current)
    observed = admission.ObservedLiveBackend(backend, current, current.candidates[0]["candidate_id"], tmp_path / "uncreated", {})
    with pytest.raises(ValueError, match="FRONT capture policy"):
        observed.prepare("fixture", "https://page.test/", ["https://page.test"], tmp_path / "workloads",
            origin_ip_pins={"https://page.test": "1.1.1.1"}, application_response_policy=current.application_response_policy,
            primary_document_identity_policy=current.primary_document_identity_policy,
            qualified_chaff_origin_policy=current.qualified_chaff_origin_policy,
            buflo_incoming_credit_release_policy=current.buflo_incoming_credit_release_policy,
            tamaraw_capture_policy=current.tamaraw_capture_policy)
    assert backend.calls == [] and not (tmp_path / "uncreated").exists()


@pytest.mark.parametrize("mutation", ["unknown", "coverage", "primary", "response", "chaff"])
def test_front_preparation_rejects_unbound_policy_before_discovery(tmp_path, monkeypatch, mutation):
    monkeypatch.setattr(prepare, "discover_page", lambda *_a, **_k: pytest.fail("unexpected live discovery"))
    kwargs = {policy.FRONT_FIELD: policy.FRONT_POLICY, "require_complete_coverage": True,
        "application_response_policy": "completed-terminal-http-errors-v1",
        "primary_document_identity_policy": "variable-primary-document-body-v1",
        "qualified_chaff_origin_policy": "prepared-approved-origins-v1"}
    key = {"unknown": policy.FRONT_FIELD, "coverage": "require_complete_coverage", "primary": "primary_document_identity_policy",
        "response": "application_response_policy", "chaff": "qualified_chaff_origin_policy"}[mutation]
    kwargs[key] = False if mutation == "coverage" else None if mutation in {"primary", "response", "chaff"} else "unknown"
    with pytest.raises(ValueError):
        prepare.prepare_workload("unbound-front", "https://page.test/", ["https://page.test"], output_root=tmp_path, **kwargs)
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize("declared", [False, True])
def test_existing_backend_forwards_front_only_when_registered(tmp_path, monkeypatch, declared):
    class ReachedPreparation(Exception): pass
    captured = []
    def reached(*_args, **kwargs):
        captured.append(kwargs); raise ReachedPreparation
    monkeypatch.setattr(class_acquisition, "prepare_workload", reached)
    kwargs = {policy.FRONT_FIELD: policy.FRONT_POLICY,
        "application_response_policy": "completed-terminal-http-errors-v1",
        "primary_document_identity_policy": "variable-primary-document-body-v1",
        "qualified_chaff_origin_policy": "prepared-approved-origins-v1"} if declared else {}
    with pytest.raises(ReachedPreparation):
        class_acquisition.ExistingAcquisitionBackend().prepare("fixture", "https://page.test/", ["https://page.test"],
            tmp_path / "workloads", origin_ip_pins={"https://page.test": "1.1.1.1"}, **kwargs)
    assert (policy.FRONT_FIELD in captured[0]) is declared


def test_v11_actual_prepare_terminal_reopens_three_raw_replays_and_all_graph_resources(context, tmp_path, monkeypatch):
    current = _amended_context(context, tmp_path, revision=11)
    candidate, navigation, h3, screen = _auto_page(current, tmp_path)
    original_seal = prepare.write_frozen_manifest
    sealed = []
    def seal(path, manifest, **kwargs):
        assert not path.exists() and manifest["preparation"][policy.FRONT_FIELD] == policy.FRONT_POLICY
        sealed.append(deepcopy(manifest)); return original_seal(path, manifest, **kwargs)
    monkeypatch.setattr(prepare, "write_frozen_manifest", seal)
    class ProducingBackend(Backend):
        def discover(self, url, approved):
            result = super().discover(url, approved)
            origins = sorted([url.rstrip("/"), "https://cdn.test"])
            result.observed_origins = result.approved_origins = result.expandable_origins = origins
            result.origin_ip_pins = {origin: "1.1.1.1" for origin in origins}
            result.origin_ip_pins[url.rstrip("/")] = "8.8.8.8"
            return result
        def prepare(self, workload_id, url, approved, output_root, **kwargs):
            assert kwargs[policy.FRONT_FIELD] == policy.FRONT_POLICY and kwargs[policy.TAMARAW_FIELD] == policy.TAMARAW_POLICY and kwargs[policy.FIELD] == policy.ACK_START_POLICY
            _, prepared, _ = _prepared_variable_workload(context, tmp_path, monkeypatch, amended=current,
                source_url=url, workload_id=workload_id, output_root=output_root, identity_chaff_headers=True,
                preparation_policies={key: kwargs[key] for key in ("qualified_chaff_origin_policy", policy.FIELD, policy.TAMARAW_FIELD, policy.FRONT_FIELD)})
            manifest = admission._load(prepared.path.read_bytes()); primary = manifest["preparation"]["expected_responses"][0]
            return SimpleNamespace(prepared=prepared, final_url=url, status=primary["status"], content_type="text/html",
                body_bytes=primary["bytes"], body_sha256=primary["body_sha256"], chromium_version=manifest["preparation"]["chromium_version"])
    receipt = admission.prepare_site(current, candidate_id=candidate["candidate_id"], navigation=navigation, page_h3=h3,
        automated_screen=screen, backend=ProducingBackend(current))
    facts, _, _ = admission._preparation_facts(receipt, current, candidate["candidate_id"])
    assert facts[policy.FRONT_FIELD] == policy.FRONT_POLICY and facts[policy.TAMARAW_FIELD] == policy.TAMARAW_POLICY and len(sealed) == 1
    raw = admission._unpack(receipt.read_bytes(), admission.PREPARATION_TYPE)
    workload = admission._child(current.root, raw["prepared_workload"])
    manifest = admission._load(workload.read_bytes())
    assert [row["id"] for row in manifest["resources"]] == [0, 1, 2]
    terminal = admission.produce_site_terminal(current, candidate_id=candidate["candidate_id"], root_surveys=_root_logs(current, tmp_path),
        preparation=receipt, automated_screen=screen)
    reopened = admission.verify_site_terminal(terminal, current)
    assert reopened["outcome"] == "admitted" and reopened["admission"][policy.FRONT_FIELD] == policy.FRONT_POLICY
    assert admission.acquisition_status(current)["formal_accepted_trace_count"] == 0
    legacy = deepcopy(manifest); legacy["preparation"].pop(policy.FRONT_FIELD)
    with pytest.raises(ValueError, match="FRONT capture policy"):
        class_acquisition.validate_class_study_preparation(legacy, workload_id=workload.stem,
            application_response_policy=current.application_response_policy, primary_document_identity_policy=current.primary_document_identity_policy,
            qualified_chaff_origin_policy=current.qualified_chaff_origin_policy,
            buflo_incoming_credit_release_policy=current.buflo_incoming_credit_release_policy, tamaraw_capture_policy=current.tamaraw_capture_policy, front_capture_policy=current.front_capture_policy)
    with pytest.raises(ValueError, match="FRONT capture policy"):
        class_acquisition.validate_class_study_preparation(manifest, workload_id=workload.stem,
            application_response_policy=current.application_response_policy, primary_document_identity_policy=current.primary_document_identity_policy,
            qualified_chaff_origin_policy=current.qualified_chaff_origin_policy, buflo_incoming_credit_release_policy=current.buflo_incoming_credit_release_policy, tamaraw_capture_policy=current.tamaraw_capture_policy)
    manifest["preparation"][policy.FRONT_FIELD] = "unknown"
    workload.write_bytes(admission._json(manifest))
    with pytest.raises(ValueError, match="FRONT capture policy"):
        admission.verify_prepared_workload(workload, admission._child(current.root, raw["full_resource_graph"]), current,
            selected_page_url=f"https://{candidate['domain']}/")


def test_v11_failed_navigation_official_observer_keeps_zero_credit_coordinator(context, tmp_path, monkeypatch):
    current = _amended_context(context, tmp_path, revision=11); candidate = current.candidates[0]
    roots = _root_logs(current, tmp_path)
    def fail(_self, _domain): raise RuntimeError("actual test navigation failure under v11")
    monkeypatch.setattr(admission.ExistingAcquisitionBackend, "discover_navigation", fail)
    proof = rapid_acquire._page_action(current, candidate["candidate_id"], SimpleNamespace(command="navigate"))
    failure = admission.unsuccessful_attempt_failure_facts(proof, current, candidate["candidate_id"])
    assert len(failure["implementation_hashes"]) == 21
    registry = {"root_surveys": {"curated": [admission.import_evidence(current.root, path) for path in roots], "fallback": []}}
    assert control.plan_action(admission, current, registry, admission.acquisition_status(current), 1)["action"] == "seal"
    terminal = admission.produce_site_terminal(current, candidate_id=candidate["candidate_id"], root_surveys=roots, attempt_failure=proof)
    assert admission.verify_site_terminal(terminal, current)["admission"] is None
