from __future__ import annotations

import copy
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from qcsd_lab import cdp_targets, rapid_collector_failure_evidence as evidence
from qcsd_lab import rapid_page_evidence as page, rapid_study_profile as profile

ROOT = Path(__file__).parents[1]
PROFILE = json.loads((ROOT / "config/curated-sources/crux73-tranco600-rapid-v5.profile.json").read_bytes())
SOURCE = (ROOT / "config/curated-sources/crux-73-v1.raw.json").read_bytes()
CATALOGUE = (ROOT / "config/class-study/v1/classifier-multiorigin100-v1-candidates.json").read_bytes()


def _raise_actual_handler_error():
    router = SimpleNamespace(_track_root_srcdoc_lifecycle=True, _root_source=object(), _aborting=False,
                             _root_frame_id="root-frame", _page_frame_parents={}, _page_frame_pending_swap_removals=set(),
                             _seen_page_frame_ids=set(), _srcdoc_ineligible_frame_ids=set(), _srcdoc_candidates={})
    cdp_targets.RecursiveCdpTargetRouter._handle_root_page_lifecycle(
        router, "Page.frameDetached", {"frameId": "unknown-frame", "reason": "remove"},
    )


def actual_collector_error(*, primary=False):
    if primary:
        from tests.test_discover import (
            _PassiveClock, _PassiveRouter, _PassivePage, _SanitizedEventProjection,
            _successful_egress_guard, _NoServiceWorkerContext, _wait_for_passive_render,
        )
        clock = _PassiveClock()
        audit = _SanitizedEventProjection(clock_ns=clock.nanoseconds)
        router = _PassiveRouter()
        router.active_request_identities = ((cdp_targets.CdpTargetSource((), "page", "page"), "never-finishes"),)
        try:
            _wait_for_passive_render(_PassivePage(clock), router, audit, _successful_egress_guard(),
                                    _NoServiceWorkerContext(), navigation_started_ms=0, load_event_ms=0)
        except evidence.acquisition_errors.PassiveRenderPolicyError:
            try:
                _raise_actual_handler_error()
            except cdp_targets.CdpTargetIntegrityError as error:
                return error
    else:
        try:
            _raise_actual_handler_error()
        except cdp_targets.CdpTargetIntegrityError as error:
            return error
    raise AssertionError("actual source CDP handler did not fail")


def collector_failure_fixture(
    tmp_path, monkeypatch, *, action_kind="catalogue-boundary-navigation", selection_amendment_sha256="e" * 64,
    not_before_utc=None, candidate_id=None, primary=False,
):
    """Reusable real producer/reopening fixture for amendment and admission tests."""
    candidates = profile.validate_v5_profile_receipt(PROFILE, SOURCE, CATALOGUE)
    candidate = candidates[0] if candidate_id is None else next(row for row in candidates if row["candidate_id"] == candidate_id)
    source_manifest = {"image_digest": None, "lab_commit": "1" * 40, "lab_dirty": False, "lab_patch_sha256": page._EMPTY_SHA,
                       "neqo_commit": "2" * 40, "neqo_dirty": False, "neqo_patch_sha256": page._EMPTY_SHA,
                       "neqo_pinned_commit": "2" * 40}
    source_path = tmp_path / "image-source.json"
    source_path.write_bytes(page._json(source_manifest))
    client = tmp_path / "frozen-client"
    client.write_bytes(b"actual independently frozen client fixture bytes\n")
    binding = {"source_manifest_sha256": page._sha(source_path.read_bytes()), "admission_image_digest": "sha256:" + "d" * 64}
    monkeypatch.setenv("QCSD_LAB_SOURCE_METADATA", str(source_path))
    monkeypatch.setenv("QCSD_LAB_IMAGE_DIGEST", binding["admission_image_digest"])
    monkeypatch.setenv("QCSD_NEQO_CLIENT", str(client))
    barrier = not_before_utc or datetime.now(UTC) - timedelta(seconds=1)
    hashes = evidence.implementation_hashes()
    runtime = evidence.begin_collector_action(binding, hashes, barrier)
    attempt = tmp_path / "attempt-001"
    attempt.mkdir()
    (attempt / "inputs.json").write_bytes(b"actual retained outer inputs\n")
    started = datetime.now(UTC).isoformat()
    error = actual_collector_error(primary=primary)
    action = {"kind": action_kind, "url": f"https://{candidate['domain']}/",
              "scope": "catalogue-root-and-optional-link-navigation" if action_kind == "catalogue-boundary-navigation"
                       else "exact-selected-page-complete-resource-graph-preparation",
              "selected_page_ordinal": None if action_kind == "catalogue-boundary-navigation" else 0}
    common = {"profile_receipt": PROFILE, "source_bytes": SOURCE, "catalogue_bytes": CATALOGUE,
              "candidate_id": candidate["candidate_id"], "execution_binding": binding,
              "selection_amendment_sha256": selection_amendment_sha256,
              "expected_implementation_hashes": hashes, "not_before_utc": barrier}
    path = attempt / "collector-observation.json"
    produce = {**common, "error": error, "runtime": runtime, "started_at": started, "action": action, "attempt_root": attempt}
    evidence.retain_collector_failure(path, **produce)
    verify = {**common, "expected_action": action}
    facts = evidence.verify_collector_failure(path, **verify)
    return {"facts": facts, "verify": verify, "produce": produce, "candidate": candidate, "path": path,
            "source_manifest": source_manifest, "source_path": source_path, "binding": binding, "barrier": barrier,
            "error": error, "attempt": attempt, "client": client}


@pytest.mark.parametrize("action_kind", ["catalogue-boundary-navigation", "complete-graph-preparation"])
def test_actual_handler_proof_reopens_closed_sources_client_and_zero_credit(tmp_path, monkeypatch, action_kind):
    value = collector_failure_fixture(tmp_path, monkeypatch, action_kind=action_kind)
    facts = value["facts"]
    assert facts["raw_failure"]["exception_type"] == "CdpTargetIntegrityError"
    assert facts["raw_failure"]["raise_site"]["function"] == "_handle_root_page_lifecycle"
    assert facts["raw_failure"]["raise_site"]["source_sha256"] == facts["implementation_hashes"]["qcsd_lab.cdp_targets"]
    assert facts["implementation_hashes"]["neqo-qcsd-client"] == page._sha(value["client"].read_bytes())
    assert facts["event_parameters"] == "unavailable-not-reconstructed"
    assert facts["whole_domain_ineligible"] is False and facts["retryable"] is True
    assert facts["formal_accepted_trace_count"] == facts["site_credit"] == 0
    assert facts["actual_attempt_count"] == 1
    assert "inputs.json" in facts["attempt_inventory"]
    (value["attempt"] / "collector-failure.json").write_bytes(b"later independently checked outer wrapper\n")
    assert evidence.verify_collector_failure(value["path"], **value["verify"]) == facts
    with pytest.raises(ValueError, match="create-only"):
        evidence.retain_collector_failure(value["path"], **value["produce"])


def test_actual_primary_passive_render_exception_and_traceback_survive_cleanup_error(tmp_path, monkeypatch):
    value = collector_failure_fixture(tmp_path, monkeypatch, primary=True)
    raw = value["facts"]["raw_failure"]
    assert raw["exception"]["context"]["exception_type"] == "PassiveRenderPolicyError"
    assert raw["exception"]["context"]["attributes"]["evidence"]["render_observation"]["cutoff_ms"] == 30_000
    assert "PassiveRenderPolicyError" in raw["traceback_text"] and "_wait_for_passive_render" in raw["traceback_text"]


@pytest.mark.parametrize("mutation", ["binary", "traceback", "existing-attempt", "extra-file", "source", "stale"])
def test_independent_reopening_rejects_raw_source_inventory_and_freshness_changes(tmp_path, monkeypatch, mutation):
    value = collector_failure_fixture(tmp_path, monkeypatch)
    payload = page._open(value["path"], evidence.COLLECTOR_FAILURE_RECEIPT_TYPE)[0]
    if mutation == "stale":
        verify = {**value["verify"], "not_before_utc": datetime.now(UTC) + timedelta(seconds=1)}
    else:
        verify = value["verify"]
        target = {"binary": payload["artifacts"]["sources"]["neqo-qcsd-client"]["path"],
                  "traceback": payload["artifacts"]["traceback"]["path"], "existing-attempt": "inputs.json",
                  "source": payload["artifacts"]["sources"]["qcsd_lab.cdp_targets"]["path"], "extra-file": "unregistered.txt"}[mutation]
        path = value["attempt"] / target
        path.write_bytes((path.read_bytes() if path.exists() else b"") + b"changed\n")
    with pytest.raises(ValueError):
        evidence.verify_collector_failure(value["path"], **verify)


@pytest.mark.parametrize("mutation", ["site_credit", "attempt_bool", "class", "domain", "image"])
def test_resealed_facts_cannot_gain_authority_or_change_the_exact_failure(tmp_path, monkeypatch, mutation):
    value = collector_failure_fixture(tmp_path, monkeypatch)
    facts = copy.deepcopy(value["facts"])
    if mutation == "site_credit":
        facts["site_credit"] = 1
    elif mutation == "attempt_bool":
        facts["actual_attempt_count"] = True
    elif mutation == "class":
        facts["raw_failure"]["exception_type"] = "RuntimeError"
    elif mutation == "domain":
        facts["candidate"]["domain"] = "unrelated.example"
    else:
        facts["runtime_source"]["image_digest"] = "sha256:" + "f" * 64
    with pytest.raises(ValueError):
        evidence.validate_collector_failure_facts(facts, candidate=value["candidate"], execution_binding=value["binding"],
                                                   selection_amendment_sha256="e" * 64, not_before_utc=value["barrier"],
                                                   expected_action=value["verify"]["expected_action"])


def test_generic_wrapped_unraised_subclass_and_global_setup_errors_never_qualify():
    assert evidence.is_collector_failure(actual_collector_error())
    assert not evidence.is_collector_failure(cdp_targets.CdpTargetIntegrityError("matching words"))
    assert not evidence.is_collector_failure(RuntimeError("root Page frame detachment identity is invalid"))
    class Subclass(cdp_targets.CdpTargetIntegrityError):
        pass
    try:
        raise Subclass("typed subclass")
    except Subclass as error:
        assert not evidence.is_collector_failure(error)
    router = SimpleNamespace(_failure=None, _secondary_integrity_failures=[], _secondary_integrity_saturated=False)
    cdp_targets.RecursiveCdpTargetRouter._record_failure(router, RuntimeError("global transport failed"))
    try:
        raise router._failure
    except cdp_targets.CdpTargetIntegrityError as error:
        assert not evidence.is_collector_failure(error)


def test_resealed_raw_message_cannot_contradict_the_source_raise_or_traceback(tmp_path, monkeypatch):
    value = collector_failure_fixture(tmp_path, monkeypatch)
    payload = page._open(value["path"], evidence.COLLECTOR_FAILURE_RECEIPT_TYPE)[0]
    reference = payload["artifacts"]["exception"]
    raw_path = value["attempt"] / reference["path"]
    error = page._loads(raw_path.read_bytes())
    error["message"] = "invented collector observation"
    raw_path.write_bytes(page._json(error))
    reference["sha256"] = page._sha(raw_path.read_bytes())
    payload["attempt_inventory"][reference["path"]] = {"sha256": reference["sha256"], "size": raw_path.stat().st_size}
    receipt = {"schema_version": 1, "receipt_type": evidence.COLLECTOR_FAILURE_RECEIPT_TYPE,
               "payload": payload, "payload_sha256": page._sha(page._json(payload))}
    value["path"].write_bytes(page._json(receipt))
    with pytest.raises(ValueError, match="literal raise|actual traceback"):
        evidence.verify_collector_failure(value["path"], **value["verify"])
