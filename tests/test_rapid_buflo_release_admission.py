"""Prospective v8 admission seals the declared tolerance before capture authority."""

from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime, timedelta
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from qcsd_lab import capture_acceptance_policy as acceptance
from qcsd_lab import rapid_attempt_failure_evidence as observer
from qcsd_lab import rapid_selection_amendment as amendment
from qcsd_lab import rapid_site_admission as admission
from tools import rapid_acquire, rapid_acquisition_control as control
from tests.test_rapid_primary_document_admission import _prepared_variable_workload
from tests.test_rapid_site_admission import Backend, _amended_context, _auto_page, _root_logs, context

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("source_factory", [admission.preparation_implementation_sources, observer.implementation_sources])
def test_v8_source_inventory_cannot_omit_its_required_v7_origin_policy(source_factory):
    with pytest.raises(ValueError, match="source inventory"):
        source_factory(application_response_policy=True, buflo_incoming_credit_release_policy=True)
    older = source_factory(application_response_policy=True, qualified_chaff_origin_policy=True)
    newer = source_factory(application_response_policy=True, qualified_chaff_origin_policy=True,
        buflo_incoming_credit_release_policy=True)
    assert set(newer) - set(older) == {admission.CAPTURE_ACCEPTANCE_POLICY_MODULE}


def test_v8_reopens_exact_seven_published_parents_and_preserves_fixed_grid():
    for revision in range(1, 8):
        raw = (ROOT / f"config/curated-sources/crux73-tranco600-rapid-v5-selection-v{revision}.json").read_bytes()
        value = json.loads(raw)
        assert amendment.selection_amendment_sha256(value) == admission._sha(raw)
        assert acceptance.FIELD not in amendment.validate_selection_amendment(value)
    value = amendment.build_selection_amendment(
        published_at_utc=datetime.now(UTC).isoformat().replace("+00:00", "Z"), revision=8)
    payload = amendment.validate_selection_amendment(value)
    assert payload["parent_selection_amendment_sha256"] == amendment.FROZEN_V7_AMENDMENT_SHA256
    assert payload[acceptance.FIELD] == acceptance.POLICY
    assert payload["formal_modes"] == ["undefended", "front", "tamaraw", "buflo", "cs-buflo"]
    assert payload["cohort_contracts"][-1]["formal_sample_target"] == 50 * 5 * 64
    assert payload["capture_authority"] == "none-requires-separate-live-capture-readiness"


@pytest.mark.parametrize("change", ["policy", "null", "missing", "window", "float-window", "outgoing", "parent", "graph"])
def test_resealed_v8_policy_changes_do_not_gain_authority(change):
    value = amendment.build_selection_amendment(
        published_at_utc=datetime.now(UTC).isoformat().replace("+00:00", "Z"), revision=8)
    payload = deepcopy(value["payload"])
    if change == "missing":
        del payload[acceptance.FIELD]
    elif change in {"policy", "null"}:
        payload[acceptance.FIELD] = None if change == "null" else "relax-all-deadlines"
    elif change == "parent":
        payload["parent_selection_amendment_sha256"] = "a" * 64
    elif change == "graph":
        payload["admitted_resource_graph"] = "pruned"
    else:
        key = "incoming_release_window_us" if change in {"window", "float-window"} else "outgoing_deadline_window_us"
        payload["buflo_incoming_credit_release_acceptance"][key] = 10000.0 if change == "float-window" else 20000
    with pytest.raises(ValueError, match="fixed contract"):
        amendment.validate_selection_amendment(admission.profile._bind(
            payload, amendment.SELECTION_AMENDMENT_RECEIPT_TYPE, schema_version=5))


@pytest.mark.parametrize("stamp", ["2026-10-03T03:22:45Z", "future"])
def test_v8_cannot_precede_parent_or_be_published_in_future(stamp):
    if stamp == "future":
        stamp = (datetime.now(UTC) + timedelta(days=1)).isoformat().replace("+00:00", "Z")
    with pytest.raises(ValueError, match="before|future"):
        amendment.build_selection_amendment(published_at_utc=stamp, revision=8)


@pytest.mark.parametrize("group", ["preparation", admission.ATTEMPT_GROUP])
def test_v8_requires_exact_independent_policy_helper_inventory(context, tmp_path, group):
    amended = _amended_context(context, tmp_path, revision=8)
    assert len(amended.mounted_module_hashes["preparation"]) == 10
    assert len(amended.mounted_module_hashes[admission.ATTEMPT_GROUP]) == 21
    assert amended.buflo_incoming_credit_release_policy == acceptance.POLICY
    path = amended.root / "provenance.json"
    payload = admission._unpack(path.read_bytes(), admission.PROVENANCE_TYPE)
    del payload["module_sources"][group][admission.CAPTURE_ACCEPTANCE_POLICY_MODULE]
    path.write_bytes(admission._json(admission._bind(admission.PROVENANCE_TYPE, payload)))
    with pytest.raises(ValueError, match="implementation inventory"):
        admission.load_admission_context(amended.root)


def test_v8_actual_preparation_dispatch_reopens_full_raw_graph_and_seals_policy(context, tmp_path, monkeypatch):
    amended = _amended_context(context, tmp_path, revision=8)
    candidate, navigation, h3, screen = _auto_page(amended, tmp_path)
    class ProducingBackend(Backend):
        def discover(self, url, approved):
            result = super().discover(url, approved)
            origins = sorted([url.rstrip("/"), "https://cdn.test"])
            result.observed_origins = result.approved_origins = result.expandable_origins = origins
            result.origin_ip_pins = {value: "1.1.1.1" for value in origins}
            result.origin_ip_pins[url.rstrip("/")] = "8.8.8.8"
            return result

        def prepare(self, workload_id, url, approved, output_root, **kwargs):
            assert kwargs[acceptance.FIELD] == acceptance.POLICY
            assert kwargs["qualified_chaff_origin_policy"] == "prepared-approved-origins-v1"
            _, prepared, _ = _prepared_variable_workload(context, tmp_path, monkeypatch,
                amended=amended, source_url=url, workload_id=workload_id, output_root=output_root,
                identity_chaff_headers=True,
                preparation_policies={key: kwargs[key] for key in (
                    "qualified_chaff_origin_policy", acceptance.FIELD)})
            manifest = admission._load(prepared.path.read_bytes())
            primary = manifest["preparation"]["expected_responses"][0]
            return SimpleNamespace(prepared=prepared, final_url=url, status=primary["status"],
                content_type="text/html", body_bytes=primary["bytes"], body_sha256=primary["body_sha256"],
                chromium_version=manifest["preparation"]["chromium_version"])

    receipt = admission.prepare_site(amended, candidate_id=candidate["candidate_id"], navigation=navigation,
        page_h3=h3, automated_screen=screen, backend=ProducingBackend(amended))
    facts, _, _ = admission._preparation_facts(receipt, amended, candidate["candidate_id"])
    assert facts[acceptance.FIELD] == acceptance.POLICY
    assert facts["terminal_http_error_resource_ids"] == [1]
    raw = admission._unpack(receipt.read_bytes(), admission.PREPARATION_TYPE)
    workload = admission._child(amended.root, raw["prepared_workload"])
    manifest = admission._load(workload.read_bytes())
    assert [row["id"] for row in manifest["resources"]] == [0, 1, 2]
    inventory = admission._load((workload.parent / f"{workload.stem}-application-response-evidence/inventory.json").read_bytes())
    assert all(f"stability-{index}/run.json" in inventory["files"] for index in range(3))
    assert inventory["schema_version"] == 2
    assert acceptance.FIELD not in inventory  # Exact immutable workload and invocation supply this authority.
    terminal = admission.produce_site_terminal(amended, candidate_id=candidate["candidate_id"],
        root_surveys=_root_logs(amended, tmp_path), preparation=receipt, automated_screen=screen)
    reopened = admission.verify_site_terminal(terminal, amended)
    assert reopened["outcome"] == "admitted" and reopened["admission"][acceptance.FIELD] == acceptance.POLICY
    assert admission.acquisition_status(amended)["formal_accepted_trace_count"] == 0
    # Cache keys reopen all bytes; removing even the declared policy cannot reuse the passing result.
    del manifest["preparation"][acceptance.FIELD]
    workload.write_bytes(admission._json(manifest))
    with pytest.raises(ValueError, match="policy"):
        admission.verify_prepared_workload(workload, admission._child(amended.root, raw["full_resource_graph"]),
            amended, selected_page_url=f"https://{candidate['domain']}/")


def test_v8_failed_navigation_uses_official_observer_then_coordinator_zero_credit_seal(context, tmp_path, monkeypatch):
    amended = _amended_context(context, tmp_path, revision=8)
    candidate = amended.candidates[0]
    roots = _root_logs(amended, tmp_path)
    def fail(_self, _domain):
        raise RuntimeError("actual test backend navigation failure under v8")
    monkeypatch.setattr(admission.ExistingAcquisitionBackend, "discover_navigation", fail)
    proof = rapid_acquire._page_action(amended, candidate["candidate_id"], SimpleNamespace(command="navigate"))
    failure = admission.unsuccessful_attempt_failure_facts(proof, amended, candidate["candidate_id"])
    assert len(failure["implementation_hashes"]) == 21
    registry = {"root_surveys": {"curated": [admission.import_evidence(amended.root, p) for p in roots], "fallback": []}}
    plan = control.plan_action(admission, amended, registry, admission.acquisition_status(amended), 1)
    assert plan["action"] == "seal" and plan["live"] is False
    terminal = admission.produce_site_terminal(amended, candidate_id=candidate["candidate_id"],
        root_surveys=roots, attempt_failure=proof)
    facts = admission.verify_site_terminal(terminal, amended)
    assert facts["admission"] is None and facts["outcome"] == "unsuccessful-live-attempt-screen-deferred"
    assert admission.acquisition_status(amended)["next_candidate"] == amended.candidates[1]
    # The extra helper source is authority: the retained v8 attempt cannot reopen against v7's 20-module set.
    older = {key: value for key, value in failure["implementation_hashes"].items()
             if key != admission.CAPTURE_ACCEPTANCE_POLICY_MODULE}
    with pytest.raises(ValueError, match="independent frozen"):
        observer.verify_attempt_failure(proof.with_name("attempt-observation.json"),
            execution_binding=amended.execution_binding, expected_implementation_hashes=older,
            not_before_utc=amended.attempt_not_before_utc, expected_action=failure["action"])


def test_v8_registry_is_distinct_and_binds_the_explicit_policy(context, tmp_path):
    amended = _amended_context(context, tmp_path, revision=8)
    value = {"schema_version": 1, "record_type": control.REGISTRY_RECORD_TYPES[8],
        "created_at": control.now(), "provenance_sha256": amended.provenance_sha256,
        "selection_amendment_sha256": amended.selection_amendment_sha256, "previous_registry": None,
        "root_surveys": {"curated": [], "fallback": []}, "scientific_credit": False, "docker_executed": False}
    path = tmp_path / "registry-v8.json"; path.write_bytes(admission._json(value))
    assert control.load_registry(admission, amended, path, control.digest(path.read_bytes())) == value
    value["record_type"] = control.REGISTRY_RECORD_TYPES[7]
    path.write_bytes(admission._json(value))
    with pytest.raises(ValueError, match="frozen context"):
        control.load_registry(admission, amended, path, control.digest(path.read_bytes()))
    with pytest.raises(ValueError, match="exact revision"):
        control.registry_record_type(SimpleNamespace(selection_amendment_revision=8,
            qualified_chaff_origin_policy="prepared-approved-origins-v1", buflo_incoming_credit_release_policy=None))


def test_v8_bootstrap_reopens_policy_helper_and_mismatch_blocks_before_backend_call(context, tmp_path):
    amended = _amended_context(context, tmp_path, revision=8)
    image = amended.execution_binding["admission_image_digest"]
    argv = ["docker", "run", "--name", "checked", "-e", f"QCSD_LAB_IMAGE_DIGEST={image}",
        "-e", "QCSD_LAB_ROOT=/runtime", "-v", f"{ROOT}:/runtime:ro",
        "-v", f"{amended.root}:/evidence:rw", "--entrypoint", "python3", image,
        "/runtime/tools/rapid_acquire.py"]
    assert control.verify_bootstrap(admission, amended, ROOT, argv) == ("/evidence", 3)
    hashes = deepcopy(amended.mounted_module_hashes)
    hashes["preparation"][admission.CAPTURE_ACCEPTANCE_POLICY_MODULE] = "0" * 64
    with pytest.raises(ValueError, match="bound input changed"):
        control.verify_bootstrap(admission, replace(amended, mounted_module_hashes=hashes), ROOT, argv)
    backend = Backend(amended)
    observed = admission.ObservedLiveBackend(backend, amended, amended.candidates[0]["candidate_id"],
        tmp_path / "not-created", {})
    for value in (None, "unknown", False):
        with pytest.raises(ValueError, match="policy"):
            observed.prepare("fixture", "https://page.test/", ["https://page.test"], tmp_path / "workloads",
                origin_ip_pins={"https://page.test": "1.1.1.1"},
                application_response_policy=amended.application_response_policy,
                primary_document_identity_policy=amended.primary_document_identity_policy,
                qualified_chaff_origin_policy=amended.qualified_chaff_origin_policy,
                buflo_incoming_credit_release_policy=value)
    assert backend.calls == []
    assert not (tmp_path / "not-created").exists()
