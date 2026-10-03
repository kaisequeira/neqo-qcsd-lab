"""V9 binds the prospective startup policy before immutable preparation publication."""
from copy import deepcopy
from datetime import UTC, datetime
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from qcsd_lab import capture_acceptance_policy as policy
from qcsd_lab import rapid_attempt_failure_evidence as observer
from qcsd_lab import rapid_selection_amendment as amendment
from qcsd_lab import rapid_site_admission as admission
from tools import rapid_acquire, rapid_acquisition_control as control
from tests.test_rapid_primary_document_admission import _prepared_variable_workload
from tests.test_rapid_site_admission import Backend, _amended_context, _auto_page, _root_logs, context

ROOT = Path(__file__).resolve().parents[1]


def test_published_v9_reopens_exact_v8_and_preserves_older_receipts():
    for revision in range(1, 10):
        raw = (ROOT / f"config/curated-sources/crux73-tranco600-rapid-v5-selection-v{revision}.json").read_bytes()
        receipt = json.loads(raw)
        assert amendment.selection_amendment_sha256(receipt) == admission._sha(raw)
        payload = amendment.validate_selection_amendment(receipt)
        if revision < 8: assert policy.FIELD not in payload
        elif revision == 8: assert payload[policy.FIELD] == policy.POLICY
        else:
            assert payload["parent_selection_amendment_sha256"] == amendment.FROZEN_V8_AMENDMENT_SHA256
            assert payload[policy.FIELD] == policy.ACK_START_POLICY
            assert payload["formal_modes"] == ["undefended", "front", "tamaraw", "buflo", "cs-buflo"]
            assert payload["cohort_contracts"][-1]["formal_sample_target"] == 16_000
            assert payload["capture_authority"] == "none-requires-separate-live-capture-readiness"


def test_v9_cannot_predate_its_exact_published_v8_parent():
    with pytest.raises(ValueError, match="before"):
        amendment.build_selection_amendment(published_at_utc="2026-10-03T06:59:58Z", revision=9)


@pytest.mark.parametrize("mutation", ["policy", "parent", "incoming-clock", "outgoing-deadline", "graph", "null"])
def test_resealed_v9_changes_cannot_gain_startup_authority(mutation):
    value = amendment.build_selection_amendment(
        published_at_utc=datetime.now(UTC).isoformat().replace("+00:00", "Z"), revision=9)
    payload = deepcopy(value["payload"])
    if mutation == "policy": payload[policy.FIELD] = policy.POLICY
    elif mutation == "parent": payload["parent_selection_amendment_sha256"] = "a" * 64
    elif mutation == "incoming-clock": payload["buflo_incoming_credit_release_acceptance"]["incoming_clock"] = "unshaped-bootstrap"
    elif mutation == "outgoing-deadline": payload["buflo_incoming_credit_release_acceptance"]["outgoing_deadline_window_us"] = 10_000
    elif mutation == "graph": payload["admitted_resource_graph"] = "primary-only"
    else: payload[policy.FIELD] = None
    with pytest.raises(ValueError, match="fixed contract"):
        amendment.validate_selection_amendment(admission.profile._bind(payload, amendment.SELECTION_AMENDMENT_RECEIPT_TYPE, schema_version=5))


def test_v9_context_reuses_exact_v8_inventory_sets_and_distinct_registry(context, tmp_path):
    current = _amended_context(context, tmp_path, revision=9)
    assert current.buflo_incoming_credit_release_policy == policy.ACK_START_POLICY
    assert len(current.mounted_module_hashes["preparation"]) == 10
    assert len(current.mounted_module_hashes[admission.ATTEMPT_GROUP]) == 21
    assert control.registry_record_type(current) == "private-frozen-v9-buflo-ack-start-policy-ordered-root-log-registry-v9"
    for factory in (admission.preparation_implementation_sources, observer.implementation_sources):
        actual = factory(application_response_policy=True, qualified_chaff_origin_policy=True,
            buflo_incoming_credit_release_policy=True)
        assert admission.CAPTURE_ACCEPTANCE_POLICY_MODULE in actual
    with pytest.raises(ValueError, match="exact revision"):
        control.registry_record_type(SimpleNamespace(selection_amendment_revision=9,
            qualified_chaff_origin_policy="prepared-approved-origins-v1", buflo_incoming_credit_release_policy=policy.POLICY))
    backend = Backend(current)
    observed = admission.ObservedLiveBackend(backend, current, current.candidates[0]["candidate_id"],
        tmp_path / "not-created", {})
    with pytest.raises(ValueError, match="policy"):
        observed.prepare("fixture", "https://page.test/", ["https://page.test"], tmp_path / "workloads",
            origin_ip_pins={"https://page.test": "1.1.1.1"},
            application_response_policy=current.application_response_policy,
            primary_document_identity_policy=current.primary_document_identity_policy,
            qualified_chaff_origin_policy=current.qualified_chaff_origin_policy,
            buflo_incoming_credit_release_policy=policy.POLICY)
    assert backend.calls == [] and not (tmp_path / "not-created").exists()


def test_v9_actual_preparation_dispatch_seals_new_policy_before_full_raw_graph(context, tmp_path, monkeypatch):
    current = _amended_context(context, tmp_path, revision=9)
    candidate, navigation, h3, screen = _auto_page(current, tmp_path)
    class ProducingBackend(Backend):
        def discover(self, url, approved):
            result = super().discover(url, approved)
            origins = sorted([url.rstrip("/"), "https://cdn.test"])
            result.observed_origins = result.approved_origins = result.expandable_origins = origins
            result.origin_ip_pins = {value: "1.1.1.1" for value in origins}
            result.origin_ip_pins[url.rstrip("/")] = "8.8.8.8"
            return result

        def prepare(self, workload_id, url, approved, output_root, **kwargs):
            assert kwargs[policy.FIELD] == policy.ACK_START_POLICY
            _, prepared, _ = _prepared_variable_workload(context, tmp_path, monkeypatch,
                amended=current, source_url=url, workload_id=workload_id, output_root=output_root,
                identity_chaff_headers=True,
                preparation_policies={key: kwargs[key] for key in ("qualified_chaff_origin_policy", policy.FIELD)})
            manifest = admission._load(prepared.path.read_bytes())
            assert manifest["preparation"][policy.FIELD] == policy.ACK_START_POLICY
            primary = manifest["preparation"]["expected_responses"][0]
            return SimpleNamespace(prepared=prepared, final_url=url, status=primary["status"], content_type="text/html",
                body_bytes=primary["bytes"], body_sha256=primary["body_sha256"],
                chromium_version=manifest["preparation"]["chromium_version"])

    receipt = admission.prepare_site(current, candidate_id=candidate["candidate_id"], navigation=navigation,
        page_h3=h3, automated_screen=screen, backend=ProducingBackend(current))
    facts, _, _ = admission._preparation_facts(receipt, current, candidate["candidate_id"])
    assert facts[policy.FIELD] == policy.ACK_START_POLICY
    raw = admission._unpack(receipt.read_bytes(), admission.PREPARATION_TYPE)
    workload = admission._child(current.root, raw["prepared_workload"])
    manifest = admission._load(workload.read_bytes())
    assert [row["id"] for row in manifest["resources"]] == [0, 1, 2]
    terminal = admission.produce_site_terminal(current, candidate_id=candidate["candidate_id"],
        root_surveys=_root_logs(current, tmp_path), preparation=receipt, automated_screen=screen)
    reopened = admission.verify_site_terminal(terminal, current)
    assert reopened["outcome"] == "admitted" and reopened["admission"][policy.FIELD] == policy.ACK_START_POLICY
    assert admission.acquisition_status(current)["formal_accepted_trace_count"] == 0
    manifest["preparation"][policy.FIELD] = policy.POLICY
    workload.write_bytes(admission._json(manifest))
    with pytest.raises(ValueError, match="policy"):
        admission.verify_prepared_workload(workload, admission._child(current.root, raw["full_resource_graph"]),
            current, selected_page_url=f"https://{candidate['domain']}/")


def test_v9_failed_navigation_uses_official_observer_and_zero_credit_plan(context, tmp_path, monkeypatch):
    current = _amended_context(context, tmp_path, revision=9)
    candidate = current.candidates[0]
    roots = _root_logs(current, tmp_path)
    def fail(_self, _domain):
        raise RuntimeError("actual test backend navigation failure under v9")
    monkeypatch.setattr(admission.ExistingAcquisitionBackend, "discover_navigation", fail)
    proof = rapid_acquire._page_action(current, candidate["candidate_id"], SimpleNamespace(command="navigate"))
    failure = admission.unsuccessful_attempt_failure_facts(proof, current, candidate["candidate_id"])
    assert len(failure["implementation_hashes"]) == 21
    registry = {"root_surveys": {"curated": [admission.import_evidence(current.root, p) for p in roots], "fallback": []}}
    plan = control.plan_action(admission, current, registry, admission.acquisition_status(current), 1)
    assert plan["action"] == "seal" and plan["live"] is False
    terminal = admission.produce_site_terminal(current, candidate_id=candidate["candidate_id"], root_surveys=roots,
        attempt_failure=proof)
    assert admission.verify_site_terminal(terminal, current)["admission"] is None
    assert admission.acquisition_status(current)["formal_accepted_trace_count"] == 0
