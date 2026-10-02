from __future__ import annotations

import copy
import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from qcsd_lab import browser_egress
from qcsd_lab import rapid_browser_policy_evidence as policy
from qcsd_lab import rapid_selection_amendment as amendment
from qcsd_lab import rapid_study_profile as rapid
from qcsd_lab.class_acquisition import ExistingAcquisitionBackend

ROOT = Path(__file__).resolve().parents[1]
PROFILE_PATH = ROOT / "config/curated-sources/crux73-tranco600-rapid-v5.profile.json"
SOURCE_PATH = ROOT / "config/curated-sources/crux-73-v1.raw.json"
CATALOGUE_PATH = ROOT / "config/class-study/v1/classifier-multiorigin100-v1-candidates.json"
SOURCE = SOURCE_PATH.read_bytes()
CATALOGUE = CATALOGUE_PATH.read_bytes()
PROFILE = json.loads(PROFILE_PATH.read_bytes())


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _receipt(*, revision: int = 1) -> dict:
    published = datetime.now(UTC) - timedelta(seconds=1)
    return amendment.build_selection_amendment(
        published_at_utc=published.isoformat().replace("+00:00", "Z"),
        revision=revision,
    )


def _terminal(candidate: dict, binding: dict) -> dict:
    root = f"https://{candidate['domain']}/"
    result = {
        "candidate_id": candidate["candidate_id"], "domain": candidate["domain"],
        "source_kind": candidate["source_kind"], "execution_binding": binding,
        "outcome": "admitted",
        "root_screen": {
            "policy": rapid.V5_TRIAGE_POLICY["root_screen_policy"], "url": root,
            "outcome": "known-valid", "detail": "known-valid",
            "receipt_sha256": "e" * 64, "controls_passed": True,
        },
        "site_safety_review": {
            "policy": rapid.SITE_SAFETY_REVIEW_POLICY["policy"],
            "decision": "approved-public-page", "reason": None,
            "receipt_sha256": "f" * 64,
        },
        "selected_page_h3_proof": {
            "policy": rapid.V5_SELECTED_PAGE_H3_POLICY, "url": root,
            "selected_page_ordinal": 0, "navigation_receipt_sha256": "9" * 64,
            "outcome": "known-valid", "receipt_sha256": "a" * 64,
            "controls_passed": True,
        },
        "admission": {
            "selected_page_url": root, "prepared_workload_sha256": "b" * 64,
            "cross_origin_resource_count": 1, "full_resource_graph_sha256": "1" * 64,
            "h3_proof_sha256": "a" * 64,
        },
    }
    unsafe = rapid.unsafe_catalogue_domain_reason(candidate["domain"])
    if unsafe is not None:
        result.update(outcome="screen-deferred", root_screen=None,
                      site_safety_review=None, selected_page_h3_proof=None, admission=None)
        result["triage"] = {
            "policy": rapid.V5_TRIAGE_POLICY["policy"],
            "reason": "automatic-safety-exclusion", "safety_reason": unsafe,
        }
    return result


@pytest.fixture
def context(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict:
    receipt = _receipt()
    source = {
        "image_digest": None, "lab_commit": "1" * 40, "lab_dirty": False,
        "lab_patch_sha256": _sha(b""), "neqo_commit": "2" * 40,
        "neqo_dirty": False, "neqo_patch_sha256": _sha(b""),
        "neqo_pinned_commit": "2" * 40,
    }
    manifest = tmp_path / "source.json"
    manifest.write_bytes(json.dumps(source).encode())
    binding = {
        "source_manifest_sha256": _sha(manifest.read_bytes()),
        "admission_image_digest": "sha256:" + "d" * 64,
    }
    monkeypatch.setenv("QCSD_LAB_SOURCE_METADATA", str(manifest))
    monkeypatch.setenv("QCSD_LAB_IMAGE_DIGEST", binding["admission_image_digest"])
    candidates = rapid.validate_v5_profile_receipt(PROFILE, SOURCE, CATALOGUE)
    candidate = candidates[0]

    def navigation(domain: str):
        guard = browser_egress.NonReplayableEgressGuard()
        guard.mark_context_guards_installed()
        guard.bind_root_page(object())
        guard.record(api="WebSocket", mechanism="playwright-websocket-route",
                     url=f"wss://{domain}/socket")
        guard.raise_if_failed()
        raise AssertionError("real egress guard did not fail")

    failure_path = tmp_path / "fresh-policy-failure.json"
    proof_args = {
        "candidate_id": candidate["candidate_id"], "execution_binding": binding,
        "policy_amendment_sha256": amendment.selection_amendment_sha256(receipt),
        "expected_implementation_hashes": policy.implementation_hashes(),
        "not_before_utc": amendment.selection_amendment_not_before_utc(receipt),
    }
    policy.produce_navigation_policy_observation(
        output=failure_path, backend=ExistingAcquisitionBackend(navigation=navigation),
        profile=PROFILE_PATH, source=SOURCE_PATH, catalogue=CATALOGUE_PATH,
        **proof_args,
    )
    records, digests = {}, []
    admitted = 0
    for index, item in enumerate(candidates):
        digest = f"{index + 1:064x}"
        facts = _terminal(item, binding)
        if index == 0:
            facts.update(outcome="screen-deferred", admission=None,
                         site_safety_review=None, selected_page_h3_proof=None)
            facts["triage"] = {
                "policy": amendment.BROWSER_POLICY_DEFERRAL_POLICY,
                "reason": amendment.BROWSER_POLICY_DEFERRAL_REASON, "safety_reason": None,
            }
        elif facts["outcome"] == "admitted":
            admitted += 1
        records[digest] = facts
        digests.append(digest)
        if admitted == 50:
            break

    def verify(digest: str) -> dict:
        facts = copy.deepcopy(records[digest])
        if digest == digests[0]:
            facts["browser_policy_failure"] = policy.verify_browser_policy_failure(
                failure_path, profile_receipt=PROFILE, source_bytes=SOURCE,
                catalogue_bytes=CATALOGUE, **proof_args,
            )
        return facts

    return {"amendment": receipt, "binding": binding, "candidates": candidates,
            "digests": digests, "records": records, "verify": verify,
            "failure": failure_path, "proof_args": proof_args}


def _build(context: dict, **kwargs) -> dict:
    options = {
        "generation": "final-50", "terminal_sha256s": context["digests"],
        "execution_binding": context["binding"], "deep_verify_terminal": context["verify"],
        **kwargs,
    }
    return amendment.build_amended_cohort_receipt(
        PROFILE, SOURCE, CATALOGUE, selection_amendment=context["amendment"],
        **options,
    )


def test_amendment_keeps_fixed_16000_and_zero_credit_shakedown():
    receipt = _receipt()
    payload = amendment.validate_selection_amendment(receipt)
    assert payload["parent_profile_sha256"] == rapid.FROZEN_V5_PROFILE_SHA256
    contracts = {item["generation"]: item for item in payload["cohort_contracts"]}
    assert contracts["final-50"]["class_count"] == 50
    assert contracts["final-50"]["planned_visit_count"] == 50 * 5 * 64 == 16_000
    assert contracts["launch-10"]["class_count"] == 10
    assert contracts["launch-10"]["planned_visit_count"] == 50
    assert contracts["launch-10"]["formal_sample_target"] == 0
    assert payload["capture_authority"] == "none-requires-separate-live-capture-readiness"
    assert _sha(rapid._canonical_json(receipt)) == amendment.selection_amendment_sha256(receipt)
    assert _sha(PROFILE_PATH.read_bytes()) == rapid.FROZEN_V5_PROFILE_SHA256


@pytest.mark.parametrize("change", ["parent", "modes", "count", "guard", "freshness"])
def test_rehashed_amendment_contract_changes_are_rejected(change: str):
    receipt = _receipt()
    payload = copy.deepcopy(receipt["payload"])
    if change == "parent":
        payload["parent_profile_sha256"] = "0" * 64
    elif change == "modes":
        payload["formal_modes"].pop()
    elif change == "count":
        payload["cohort_contracts"][1]["class_count"] = 5
    elif change == "guard":
        payload["non_replayable_egress_guard"] = "disabled"
    else:
        payload["freshness_policy"]["old_failed_attempts"] = "promote-old-failures"
    with pytest.raises(ValueError, match="prospective fixed contract"):
        amendment.validate_selection_amendment(rapid._bind(
            payload, amendment.SELECTION_AMENDMENT_RECEIPT_TYPE, schema_version=5,
        ))


@pytest.mark.parametrize("published", ["2026-10-02T12:58:16Z", "2099-01-01T00:00:00Z", "2026-10-02T13:00:00", "2026-10-02T13:00:00+00:00"])
def test_publication_requires_real_canonical_prospective_barrier(published: str):
    with pytest.raises(ValueError, match="publication"):
        amendment.build_selection_amendment(published_at_utc=published)


def test_new_policy_deferral_reopens_receipt_and_preserves_fifty_admitted(context: dict):
    cohort = _build(context)
    payload = cohort["payload"]
    assert cohort["receipt_type"] == amendment.AMENDED_COHORT_RECEIPT_TYPE
    assert payload["planned_visit_count"] == payload["formal_sample_target"] == 16_000
    assert len(payload["selected_candidate_ids"]) == 50
    assert context["candidates"][0]["candidate_id"] not in payload["selected_candidate_ids"]
    first = payload["terminal_decisions"][0]
    assert first["outcome"] == "screen-deferred"
    assert first["admission"] is first["selected_page_h3_proof"] is None
    assert first["browser_policy_failure"]["scientific_credit"] is False
    assert first["browser_policy_failure"]["failure_page_attribution"] == "unavailable"
    selected = amendment.validate_amended_cohort_receipt(
        cohort, PROFILE, SOURCE, CATALOGUE,
        selection_amendment=context["amendment"], execution_binding=context["binding"],
        deep_verify_terminal=context["verify"],
    )
    assert selected == tuple(payload["selected_candidate_ids"])
    with pytest.raises(ValueError):
        rapid.validate_v5_cohort_receipt(
            cohort, PROFILE, SOURCE, CATALOGUE, execution_binding=context["binding"],
            deep_verify_terminal=context["verify"],
        )


def test_old_policy_attempt_does_not_gain_later_publication_authority(context: dict):
    later = amendment.build_selection_amendment(
        published_at_utc=datetime.now(UTC).isoformat().replace("+00:00", "Z"),
    )
    old_facts = context["verify"](context["digests"][0])
    old_facts["browser_policy_failure"]["policy_amendment_sha256"] = amendment.selection_amendment_sha256(later)
    context["amendment"] = later
    context["verify"] = lambda digest: (old_facts if digest == context["digests"][0]
                                         else copy.deepcopy(context["records"][digest]))
    with pytest.raises(ValueError, match="stale"):
        _build(context)


def test_launch_cohort_is_still_ten_sites_fifty_visits_zero_credit(context: dict, tmp_path: Path):
    prefix, admitted = [], 0
    for digest in context["digests"]:
        prefix.append(digest)
        admitted += context["records"][digest]["outcome"] == "admitted"
        if admitted == 10:
            break
    cohort = _build(context, generation="launch-10", terminal_sha256s=prefix)
    assert len(cohort["payload"]["selected_candidate_ids"]) == 10
    assert cohort["payload"]["planned_visit_count"] == 50
    assert cohort["payload"]["formal_sample_target"] == 0
    assert cohort["payload"]["sample_credit_policy"] == "zero-credit-diagnostic"
    output = tmp_path / "launch-amended-cohort.json"
    amendment.write_receipt_create_only(output, cohort)
    reopened = json.loads(output.read_bytes())
    assert amendment.validate_amended_cohort_receipt(
        reopened, PROFILE, SOURCE, CATALOGUE, selection_amendment=context["amendment"],
        execution_binding=context["binding"], deep_verify_terminal=context["verify"],
    ) == tuple(cohort["payload"]["selected_candidate_ids"])


@pytest.mark.parametrize("change", ["candidate", "image", "source", "module", "error", "credit", "page", "root", "review", "triage", "admission"])
def test_policy_deferral_cannot_hide_wrong_identity_or_promote_credit(context: dict, change: str):
    first = context["verify"](context["digests"][0])
    failure = first["browser_policy_failure"]
    if change == "candidate":
        failure["candidate"] = context["candidates"][1]
    elif change == "image":
        failure["execution_binding"]["admission_image_digest"] = "sha256:" + "0" * 64
    elif change == "source":
        failure["runtime_source"]["neqo_pinned_commit"] = "0" * 40
    elif change == "module":
        failure["implementation_hashes"].clear()
    elif change == "error":
        failure["raw_failure"]["exception_type"] = "TimeoutError"
    elif change == "credit":
        failure["scientific_credit"] = True
    elif change == "page":
        failure["failure_page_attribution"] = "root"
    elif change == "root":
        first["root_screen"]["outcome"] = "known-invalid"
        first["root_screen"]["detail"] = "known-invalid"
    elif change == "review":
        first["site_safety_review"] = _terminal(context["candidates"][0], context["binding"])["site_safety_review"]
    elif change == "triage":
        first["triage"]["safety_reason"] = "unsafe"
    else:
        first["admission"] = _terminal(context["candidates"][0], context["binding"])["admission"]
    context["verify"] = lambda digest: (first if digest == context["digests"][0]
                                         else copy.deepcopy(context["records"][digest]))
    with pytest.raises(ValueError):
        _build(context)


def test_failure_receipt_is_reopened_instead_of_trusting_cached_facts(context: dict):
    context["failure"].write_bytes(context["failure"].read_bytes() + b"tamper")
    with pytest.raises(ValueError):
        _build(context)


def test_original_leaf_order_and_full_graph_validation_are_retained(context: dict):
    context["records"][context["digests"][1]]["admission"]["cross_origin_resource_count"] = 0
    with pytest.raises(ValueError, match="multi-origin proof"):
        _build(context)
    context["records"][context["digests"][1]]["admission"]["cross_origin_resource_count"] = 1
    context["digests"][1], context["digests"][2] = context["digests"][2], context["digests"][1]
    with pytest.raises(ValueError, match="candidate order"):
        _build(context)


def test_rehashed_cohort_cannot_shrink_target_or_omit_amendment(context: dict):
    cohort = _build(context)
    for change in ("formal_sample_target", "selection_amendment_sha256"):
        payload = copy.deepcopy(cohort["payload"])
        if change == "formal_sample_target":
            payload[change] = 8_000
        else:
            del payload[change]
        changed = rapid._bind(payload, amendment.AMENDED_COHORT_RECEIPT_TYPE, schema_version=5)
        with pytest.raises(ValueError, match="deep-verified ordered selection"):
            amendment.validate_amended_cohort_receipt(
                changed, PROFILE, SOURCE, CATALOGUE,
                selection_amendment=context["amendment"], execution_binding=context["binding"],
                deep_verify_terminal=context["verify"],
            )


def test_selection_amendment_publication_is_create_only(tmp_path: Path):
    path = tmp_path / "amendment.json"
    receipt = _receipt()
    amendment.write_receipt_create_only(path, receipt)
    original = path.read_bytes()
    with pytest.raises(FileExistsError):
        amendment.write_receipt_create_only(path, receipt)
    assert path.read_bytes() == original


@pytest.fixture
def context_v2(context: dict) -> dict:
    result = dict(context)
    result["amendment"] = _receipt(revision=2)
    records, digests, admitted = {}, [], 0
    for index, candidate in enumerate(result["candidates"]):
        digest = f"{index + 1:064x}"
        facts = _terminal(candidate, result["binding"])
        facts["automated_site_screen"] = None
        if facts["outcome"] == "admitted":
            proof = facts["selected_page_h3_proof"]
            facts["site_safety_review"] = None
            facts["automated_site_screen"] = {
                "policy": amendment.AUTOMATED_SITE_SCREEN_POLICY,
                "policy_sha256": amendment.automated_screen_policy_sha256(),
                "decision": amendment.AUTOMATED_SITE_SCREEN_DECISION,
                "selected_page_url": proof["url"],
                "selected_page_ordinal": proof["selected_page_ordinal"],
                "navigation_receipt_sha256": proof["navigation_receipt_sha256"],
                "selected_page_h3_receipt_sha256": proof["receipt_sha256"],
                "receipt_sha256": f"{index + 100:064x}",
                "execution_binding": result["binding"],
                "selection_amendment_sha256": amendment.selection_amendment_sha256(result["amendment"]),
                "screened_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                "scientific_credit": False,
            }
            admitted += 1
        records[digest] = facts
        digests.append(digest)
        if admitted == 50:
            break
    result.update(records=records, digests=digests,
                  verify=lambda digest: copy.deepcopy(records[digest]))
    return result


def test_v2_contract_rederives_frozen_v1_and_records_narrow_automatic_rules():
    old_path = ROOT / "config/curated-sources/crux73-tranco600-rapid-v5-selection-v1.json"
    old = json.loads(old_path.read_bytes())
    assert amendment.selection_amendment_revision(old) == 1
    assert amendment.selection_amendment_sha256(old) == amendment.FROZEN_V1_AMENDMENT_SHA256
    assert amendment.build_selection_amendment(
        published_at_utc=old["payload"]["published_at_utc"],
    ) == old
    value = _receipt(revision=2)
    payload = amendment.validate_selection_amendment(value)
    assert amendment.selection_amendment_revision(value) == 2
    assert payload["parent_selection_amendment_sha256"] == amendment.FROZEN_V1_AMENDMENT_SHA256
    assert payload["parent_profile_sha256"] == rapid.FROZEN_V5_PROFILE_SHA256
    assert payload["selection_policy"] != old["payload"]["selection_policy"]
    assert payload["automated_screen_policy_sha256"] == _sha(amendment.automated_screen_policy_bytes())
    assert payload["automated_site_screen_policy"]["named_human_review"] == "not-required"
    assert payload["automated_site_screen_policy"]["content_classification_claimed"] is False
    assert payload["cohort_contracts"] == old["payload"]["cohort_contracts"]
    assert "may-reopen-unchanged" in payload["freshness_policy"]["supporting_navigation_and_exact_page_h3"]
    rules = amendment.automated_screen_policy_payload()
    rules["domain_safety_policy"]["denied_substrings"].clear()
    assert amendment.automated_screen_policy_payload()["domain_safety_policy"]["denied_substrings"]


@pytest.mark.parametrize("change", ["rules", "rules-sha", "parent-v1", "exception", "action", "freshness", "named-review"])
def test_v2_rehashed_rule_or_typed_failure_contract_changes_fail(change: str):
    payload = copy.deepcopy(_receipt(revision=2)["payload"])
    if change == "rules":
        payload["automated_site_screen_policy"]["domain_safety_policy"]["denied_substrings"].clear()
    elif change == "rules-sha":
        payload["automated_screen_policy_sha256"] = "0" * 64
    elif change == "parent-v1":
        payload["parent_selection_amendment_sha256"] = "0" * 64
    elif change == "exception":
        payload["page_policy_deferral"]["navigation_action"]["exception_types"].append("RuntimeError")
    elif change == "action":
        payload["page_policy_deferral"]["preparation_action"]["required_proof"] = "none"
    elif change == "freshness":
        payload["freshness_policy"]["new_automated_screen_and_page_policy_failure"] = "any-time"
    else:
        payload["automated_site_screen_policy"]["named_human_review"] = "required"
    with pytest.raises(ValueError, match="prospective fixed contract"):
        amendment.validate_selection_amendment(rapid._bind(
            payload, amendment.SELECTION_AMENDMENT_RECEIPT_TYPE, schema_version=5,
        ))


@pytest.mark.parametrize("revision", [0, 4, True, "2"])
def test_unknown_or_loosely_typed_amendment_revision_fails(revision):
    with pytest.raises(ValueError, match="revision"):
        amendment.build_selection_amendment(
            published_at_utc=datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            revision=revision,
        )


def test_v2_cannot_predate_its_frozen_v1_parent():
    with pytest.raises(ValueError, match="before its v1 parent"):
        amendment.build_selection_amendment(published_at_utc="2026-10-02T14:00:00Z", revision=2)


def test_v3_rederives_actual_v2_parent_and_preserves_all_acceptance_rules():
    for revision, published, digest in (
        (1, amendment.FROZEN_V1_AMENDMENT_PUBLICATION_UTC, amendment.FROZEN_V1_AMENDMENT_SHA256),
        (2, amendment.FROZEN_V2_AMENDMENT_PUBLICATION_UTC, amendment.FROZEN_V2_AMENDMENT_SHA256),
    ):
        receipt = amendment.build_selection_amendment(published_at_utc=published, revision=revision)
        raw = rapid._canonical_json(receipt)
        assert _sha(raw) == digest
        assert raw == (ROOT / f"config/curated-sources/crux73-tranco600-rapid-v5-selection-v{revision}.json").read_bytes()
    parent = json.loads((ROOT / "config/curated-sources/crux73-tranco600-rapid-v5-selection-v2.json").read_bytes())["payload"]
    receipt = _receipt(revision=3)
    payload = amendment.validate_selection_amendment(receipt)
    assert amendment.selection_amendment_revision(receipt) == 3
    assert payload["parent_selection_amendment_sha256"] == amendment.FROZEN_V2_AMENDMENT_SHA256
    assert payload["selection_policy"] == amendment.AMENDED_V3_SELECTION_POLICY
    for key in ("admission_policy", "admitted_resource_graph", "formal_modes", "cohort_contracts",
                "automated_site_screen_policy", "automated_screen_policy_sha256",
                "non_replayable_egress_guard", "candidate_order_policy"):
        assert payload[key] == parent[key]
    for branch in ("browser_policy_deferral", "page_policy_deferral"):
        assert {key: value for key, value in payload[branch].items() if key != "required_root_screen"} == {
            key: value for key, value in parent[branch].items() if key != "required_root_screen"
        }
        assert payload[branch]["required_root_screen"] == amendment.V3_BROWSER_ROOT_REQUIREMENT
    assert payload["browser_root_progression"]["allowed_outcome_details"] == [
        ["known-valid", "known-valid"], ["ambiguous", "response-known-invalid"],
    ]
    disposition = payload["operational_collector_deferral"]
    assert disposition["exception_type"] == "CdpTargetIntegrityError"
    assert disposition["exception_module"] == "qcsd_lab.cdp_targets"
    assert type(disposition["actual_attempt_count"]) is int and disposition["actual_attempt_count"] == 1
    assert disposition["retryable"] is True and disposition["whole_domain_ineligible"] is False
    assert disposition["site_credit"] == disposition["formal_accepted_trace_count"] == 0
    assert "no-v3-relabel" in payload["freshness_policy"]["v2_failed_attempts"]


def test_v3_cannot_predate_actual_v2_parent():
    with pytest.raises(ValueError, match="before its v2 parent"):
        amendment.build_selection_amendment(published_at_utc="2026-10-02T15:19:12Z", revision=3)


@pytest.mark.parametrize("revision,outcome,detail,controls,allowed", [
    (1, "known-valid", "known-valid", True, True),
    (2, "ambiguous", "response-known-invalid", True, False),
    (3, "ambiguous", "response-known-invalid", True, True),
    (3, "ambiguous", "response-known-invalid", False, False),
    (3, "ambiguous", "dns-name-not-found", True, False),
    (3, "ambiguous", "peer-close-336", True, False),
    (3, "timeout", "timeout", True, False),
    (3, "peer-tls-handshake-failure", "peer-close-296", True, False),
])
def test_v3_root_progression_retains_completed_response_ambiguity_without_promoting_it(revision, outcome, detail, controls, allowed):
    root = {"outcome": outcome, "detail": detail, "controls_passed": controls}
    original = copy.deepcopy(root)
    assert amendment.root_screen_allows_browser_progression(root, revision=revision) is allowed
    assert root == original


@pytest.mark.parametrize("change", ["parent", "exception", "module", "attempts", "boolean-count", "boolean-credit", "scientific", "retryable", "domain-verdict", "action", "freshness", "acceptance", "root-progression"])
def test_v3_rehashed_deferral_and_acceptance_changes_are_rejected(change):
    payload = copy.deepcopy(_receipt(revision=3)["payload"])
    disposition = payload["operational_collector_deferral"]
    if change == "parent":
        payload["parent_selection_amendment_sha256"] = amendment.FROZEN_V1_AMENDMENT_SHA256
    elif change == "exception":
        disposition["exception_type"] = "RuntimeError"
    elif change == "module":
        disposition["exception_module"] = "operator_supplied"
    elif change == "attempts":
        disposition["actual_attempt_count"] = 2
    elif change == "boolean-count":
        disposition["actual_attempt_count"] = True
    elif change == "boolean-credit":
        disposition["site_credit"] = False
    elif change == "scientific":
        disposition["scientific_credit"] = True
    elif change == "retryable":
        disposition["retryable"] = False
    elif change == "domain-verdict":
        disposition["whole_domain_ineligible"] = True
    elif change == "action":
        disposition["preparation_action"]["required_proof"] = "none"
    elif change == "freshness":
        payload["freshness_policy"]["new_operational_collector_failure"] = "old-attempts-allowed"
    elif change == "root-progression":
        payload["browser_root_progression"]["allowed_outcome_details"].append(["ambiguous", "dns-name-not-found"])
    else:
        payload["admitted_resource_graph"] = "trim-unavailable-resources"
    resealed = rapid._bind(payload, amendment.SELECTION_AMENDMENT_RECEIPT_TYPE, schema_version=5)
    with pytest.raises(ValueError, match="prospective fixed contract"):
        amendment.validate_selection_amendment(resealed)


@pytest.fixture
def context_v3(context_v2):
    result = dict(context_v2)
    result["amendment"] = _receipt(revision=3)
    result["records"] = copy.deepcopy(context_v2["records"])
    result["digests"] = list(context_v2["digests"])
    digest = amendment.selection_amendment_sha256(result["amendment"])
    now = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    for facts in result["records"].values():
        if facts["automated_site_screen"] is not None:
            facts["automated_site_screen"].update(selection_amendment_sha256=digest, screened_at=now)
    result["verify"] = lambda sha: copy.deepcopy(result["records"][sha])
    return result


def test_v3_normal_admissions_still_require_exact_fifty_and_full_graph(context_v3):
    cohort = _build(context_v3)
    assert cohort["payload"]["selection_policy"] == amendment.AMENDED_V3_SELECTION_POLICY
    assert len(cohort["payload"]["selected_candidate_ids"]) == 50
    assert cohort["payload"]["formal_sample_target"] == 16_000
    assert all("operational_collector_failure" not in row for row in cohort["payload"]["terminal_decisions"])
    first = context_v3["records"][context_v3["digests"][0]]
    first["admission"]["cross_origin_resource_count"] = 0
    with pytest.raises(ValueError, match="multi-origin proof"):
        _build(context_v3)


def test_v3_actual_cohort_opens_existing_capture_planner_binding(context_v3, tmp_path):
    from dataclasses import replace
    from qcsd_lab import rapid_capture_plan as plan

    cohort = _build(context_v3)
    cohort_path = tmp_path / "v3-cohort.json"
    policy_path = tmp_path / "v3-selection.json"
    cohort_path.write_bytes(rapid._canonical_json(cohort))
    policy_path.write_bytes(rapid._canonical_json(context_v3["amendment"]))
    bindings = plan.FrozenBindings(
        PROFILE_PATH, rapid.FROZEN_V5_PROFILE_SHA256, cohort_path, _sha(cohort_path.read_bytes()), 5,
        policy_path, _sha(policy_path.read_bytes()),
    )
    plan._check_bindings(bindings)
    assert bindings.digests()["selection_amendment_sha256"] == amendment.selection_amendment_sha256(context_v3["amendment"])
    wrong = _receipt(revision=2)
    wrong_path = tmp_path / "wrong-selection.json"
    wrong_path.write_bytes(rapid._canonical_json(wrong))
    with pytest.raises(ValueError, match="identities differ"):
        plan._check_bindings(replace(
            bindings, selection_amendment_receipt=wrong_path,
            selection_amendment_sha256=_sha(wrong_path.read_bytes()),
        ))


def _collector_deferral(context, tmp_path, monkeypatch, *, preparation):
    from qcsd_lab import rapid_collector_failure_evidence as collector
    from tests.test_rapid_collector_failure_evidence import collector_failure_fixture

    first = context["records"][context["digests"][0]]
    page = first["selected_page_h3_proof"]
    automatic = copy.deepcopy(first["automated_site_screen"])
    proof = collector_failure_fixture(
        tmp_path, monkeypatch,
        action_kind="complete-graph-preparation" if preparation else "catalogue-boundary-navigation",
        selection_amendment_sha256=amendment.selection_amendment_sha256(context["amendment"]),
        not_before_utc=amendment.selection_amendment_not_before_utc(context["amendment"]),
        candidate_id=context["candidates"][0]["candidate_id"], primary=preparation,
    )
    context["binding"] = proof["binding"]
    for facts in context["records"].values():
        facts["execution_binding"] = proof["binding"]
        if facts["automated_site_screen"] is not None:
            facts["automated_site_screen"]["execution_binding"] = proof["binding"]
    automatic["execution_binding"] = proof["binding"]
    support = {
        "navigation_receipt_sha256": page["navigation_receipt_sha256"] if preparation else None,
        "selected_page_h3_receipt_sha256": page["receipt_sha256"] if preparation else None,
        "automated_site_screen_receipt_sha256": automatic["receipt_sha256"] if preparation else None,
    }
    failure = {**proof["facts"], **support}
    first.update(outcome=amendment.OPERATIONAL_COLLECTOR_DEFERRAL_REASON, admission=None,
                 operational_collector_failure=failure,
                 triage={"policy": amendment.OPERATIONAL_COLLECTOR_DEFERRAL_POLICY,
                         "reason": amendment.OPERATIONAL_COLLECTOR_DEFERRAL_REASON, "safety_reason": None})
    if not preparation:
        first.update(selected_page_h3_proof=None, automated_site_screen=None)
    # Continue the immutable order to replace the deferred candidate's lost
    # admission; a collector limitation never reduces the target to 49 sites.
    for index in range(len(context["digests"]), len(context["candidates"])):
        candidate = context["candidates"][index]
        facts = _terminal(candidate, context["binding"])
        facts["automated_site_screen"] = None
        if facts["outcome"] == "admitted":
            facts["site_safety_review"] = None
            facts["automated_site_screen"] = {
                **automatic, "selected_page_url": facts["selected_page_h3_proof"]["url"],
                "receipt_sha256": f"{index + 100:064x}",
            }
        digest = f"{index + 1:064x}"
        context["records"][digest] = facts
        context["digests"].append(digest)
        if facts["outcome"] == "admitted":
            break

    def reopen(digest):
        facts = copy.deepcopy(context["records"][digest])
        if digest == context["digests"][0]:
            actual = collector.verify_collector_failure(proof["path"], **proof["verify"])
            retained = facts["operational_collector_failure"]
            if {key: value for key, value in retained.items() if key not in support} != actual:
                raise ValueError("terminal collector facts differ from independently reopened raw proof")
        return facts

    context["verify"] = reopen
    return proof, failure


@pytest.mark.parametrize("preparation", [False, True])
def test_v3_actual_collector_deferral_reopens_proof_and_preserves_fifty(context_v3, tmp_path, monkeypatch, preparation):
    proof, failure = _collector_deferral(context_v3, tmp_path, monkeypatch, preparation=preparation)
    cohort = _build(context_v3)
    first = cohort["payload"]["terminal_decisions"][0]
    assert first["operational_collector_failure"] == failure
    assert first["admission"] is None
    assert first["outcome"] == amendment.OPERATIONAL_COLLECTOR_DEFERRAL_REASON
    assert failure["retryable"] is True and failure["whole_domain_ineligible"] is False
    assert failure["scientific_credit"] is False
    assert failure["site_credit"] == failure["formal_accepted_trace_count"] == 0
    assert (first["selected_page_h3_proof"] is not None) == preparation
    assert (first["automated_site_screen"] is not None) == preparation
    assert len(cohort["payload"]["selected_candidate_ids"]) == 50
    assert cohort["payload"]["formal_sample_target"] == 16_000
    assert context_v3["candidates"][0]["candidate_id"] not in cohort["payload"]["selected_candidate_ids"]
    assert amendment.validate_amended_cohort_receipt(
        cohort, PROFILE, SOURCE, CATALOGUE, selection_amendment=context_v3["amendment"],
        execution_binding=context_v3["binding"], deep_verify_terminal=context_v3["verify"],
    ) == tuple(cohort["payload"]["selected_candidate_ids"])
    if not preparation:
        count, prefix = 0, []
        for digest in context_v3["digests"]:
            prefix.append(digest)
            count += context_v3["records"][digest]["outcome"] == "admitted"
            if count == 10:
                break
        shakedown = _build(context_v3, generation="launch-10", terminal_sha256s=prefix)
        assert len(shakedown["payload"]["selected_candidate_ids"]) == 10
        assert shakedown["payload"]["planned_visit_count"] == 50
        assert shakedown["payload"]["formal_sample_target"] == 0
    (proof["attempt"] / "inputs.json").write_bytes(b"changed retained attempt bytes\n")
    with pytest.raises(ValueError):
        _build(context_v3)


@pytest.mark.parametrize("preparation", [False, True])
def test_v3_actual_collector_deferral_accepts_only_controlled_response_ambiguity(context_v3, tmp_path, monkeypatch, preparation):
    _collector_deferral(context_v3, tmp_path, monkeypatch, preparation=preparation)
    root = context_v3["records"][context_v3["digests"][0]]["root_screen"]
    root.update(outcome="ambiguous", detail="response-known-invalid")
    cohort = _build(context_v3)
    retained = cohort["payload"]["terminal_decisions"][0]["root_screen"]
    assert retained["outcome"] == "ambiguous" and retained["detail"] == "response-known-invalid"
    root.update(detail="dns-name-not-found")
    with pytest.raises(ValueError, match="controlled screening context"):
        _build(context_v3)


@pytest.mark.parametrize("change", ["v2-authority", "missing-page", "missing-auto", "navigation-hash",
                                     "wrong-root", "human-verdict", "mixed-failure", "attempt-count", "credit"])
def test_v3_collector_branch_rejects_unproved_context_or_promoted_facts(context_v3, tmp_path, monkeypatch, change):
    _, failure = _collector_deferral(context_v3, tmp_path, monkeypatch, preparation=True)
    first = context_v3["records"][context_v3["digests"][0]]
    if change == "v2-authority":
        context_v3["amendment"] = _receipt(revision=2)
    elif change == "missing-page":
        first["selected_page_h3_proof"] = None
    elif change == "missing-auto":
        first["automated_site_screen"] = None
    elif change == "navigation-hash":
        failure["navigation_receipt_sha256"] = "0" * 64
    elif change == "wrong-root":
        first["root_screen"].update(outcome="ambiguous", detail="dns-name-not-found")
    elif change == "human-verdict":
        first["site_safety_review"] = _terminal(context_v3["candidates"][0], context_v3["binding"])["site_safety_review"]
    elif change == "mixed-failure":
        first["page_policy_failure"] = {}
    elif change == "attempt-count":
        failure["actual_attempt_count"] = 2
    else:
        failure["site_credit"] = 1
    with pytest.raises(ValueError):
        _build(context_v3)


def test_v2_fifty_site_admission_uses_automatic_proof_without_human_fact(context_v2: dict):
    cohort = _build(context_v2)
    assert cohort["payload"]["selection_policy"] == amendment.AMENDED_V2_SELECTION_POLICY
    assert cohort["payload"]["formal_sample_target"] == 16_000
    assert len(cohort["payload"]["selected_candidate_ids"]) == 50
    assert all(decision["site_safety_review"] is None for decision in cohort["payload"]["terminal_decisions"])
    assert all(decision["automated_site_screen"] is not None for decision in cohort["payload"]["terminal_decisions"]
               if decision["outcome"] == "admitted")
    assert amendment.validate_amended_cohort_receipt(
        cohort, PROFILE, SOURCE, CATALOGUE, selection_amendment=context_v2["amendment"],
        execution_binding=context_v2["binding"], deep_verify_terminal=context_v2["verify"],
    ) == tuple(cohort["payload"]["selected_candidate_ids"])


@pytest.mark.parametrize("change", ["missing", "policy-sha", "candidate-url", "ordinal", "nav-sha", "h3-sha", "binding", "amendment", "old", "credit", "cross-origin", "resource-graph"])
def test_v2_automatic_rule_page_binding_and_complete_graph_remain_required(context_v2: dict, change: str):
    first = context_v2["records"][context_v2["digests"][0]]
    screen = first["automated_site_screen"]
    if change == "missing":
        first["automated_site_screen"] = None
    elif change == "policy-sha":
        screen["policy_sha256"] = "0" * 64
    elif change == "candidate-url":
        screen["selected_page_url"] = "https://outside.example/"
    elif change == "ordinal":
        screen["selected_page_ordinal"] = 1
    elif change == "nav-sha":
        screen["navigation_receipt_sha256"] = "0" * 64
    elif change == "h3-sha":
        screen["selected_page_h3_receipt_sha256"] = "0" * 64
    elif change == "binding":
        screen["execution_binding"] = {**context_v2["binding"], "source_manifest_sha256": "0" * 64}
    elif change == "amendment":
        screen["selection_amendment_sha256"] = "0" * 64
    elif change == "old":
        screen["screened_at"] = amendment.PARENT_PROFILE_PUBLICATION_UTC
    elif change == "credit":
        screen["scientific_credit"] = True
    elif change == "cross-origin":
        first["admission"]["cross_origin_resource_count"] = 0
    else:
        first["admission"]["full_resource_graph_sha256"] = ""
    with pytest.raises(ValueError):
        _build(context_v2)


def test_v1_cannot_gain_automatic_screen_authority(context_v2: dict):
    context_v2["amendment"] = _receipt()
    with pytest.raises(ValueError, match="invalid facts"):
        _build(context_v2)


def _typed_page_failure(context: dict, *, preparation: bool) -> dict:
    from qcsd_lab import rapid_site_admission as admission
    from qcsd_lab.util import source_metadata
    from tests.test_prepare import _actual_render_failure_evidence

    first = context["records"][context["digests"][0]]
    candidate = context["candidates"][0]
    proof = first["selected_page_h3_proof"]
    automatic = first["automated_site_screen"]
    now = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    failure = {
        "page_policy_failure_receipt_sha256": "4" * 64,
        "policy": amendment.PAGE_POLICY_DEFERRAL_POLICY,
        "profile_sha256": rapid.FROZEN_V5_PROFILE_SHA256,
        "selection_amendment_sha256": amendment.selection_amendment_sha256(context["amendment"]),
        "candidate": candidate, "execution_binding": context["binding"],
        "runtime_source": source_metadata(),
        "implementation_hashes": {
            "preparation": admission.preparation_implementation_hashes(),
            "browser_policy": policy.implementation_hashes(),
        },
        "started_at": now, "completed_at": now,
        "action": {
            "kind": "complete-graph-preparation" if preparation else "catalogue-boundary-navigation",
            "url": proof["url"] if preparation else f"https://{candidate['domain']}/",
            "scope": ("exact-selected-page-complete-resource-graph-preparation" if preparation
                      else "catalogue-root-and-optional-link-navigation"),
            "selected_page_ordinal": proof["selected_page_ordinal"] if preparation else None,
        },
        "failure_page_attribution": "exact-selected-page" if preparation else "unavailable",
        "raw_failure": {
            "exception_type": "PassiveRenderPolicyError", "message": "passive render reached its bounded hard cap",
            "evidence": _actual_render_failure_evidence(),
            "capture_source": None, "capture_started_at": None, "capture_completed_at": None,
        },
        "navigation_receipt_sha256": proof["navigation_receipt_sha256"] if preparation else None,
        "selected_page_h3_receipt_sha256": proof["receipt_sha256"] if preparation else None,
        "automated_site_screen_receipt_sha256": automatic["receipt_sha256"] if preparation else None,
        "scientific_credit": False,
    }
    first.update(outcome=amendment.PAGE_POLICY_DEFERRAL_REASON, admission=None)
    if not preparation:
        first.update(selected_page_h3_proof=None, automated_site_screen=None)
    first["triage"] = {
        "policy": amendment.PAGE_POLICY_DEFERRAL_POLICY,
        "reason": amendment.PAGE_POLICY_DEFERRAL_REASON, "safety_reason": None,
    }
    first["page_policy_failure"] = failure
    # This early candidate earns no admission. Continue in the unchanged order
    # until there are still exactly fifty admitted sites in the test prefix.
    template = copy.deepcopy(automatic)
    for index in range(len(context["digests"]), len(context["candidates"])):
        row = context["candidates"][index]
        facts = _terminal(row, context["binding"])
        facts["automated_site_screen"] = None
        if facts["outcome"] == "admitted":
            facts["site_safety_review"] = None
            facts["automated_site_screen"] = {
                **template, "selected_page_url": facts["selected_page_h3_proof"]["url"],
                "receipt_sha256": f"{index + 100:064x}", "screened_at": now,
            }
        digest = f"{index + 1:064x}"
        context["records"][digest] = facts
        context["digests"].append(digest)
        if facts["outcome"] == "admitted":
            break
    return failure


def test_v3_inherited_browser_branch_reopens_exact_guard_proof_on_controlled_response_ambiguity(context_v3, tmp_path):
    _typed_page_failure(context_v3, preparation=False)
    first = context_v3["records"][context_v3["digests"][0]]
    del first["page_policy_failure"]
    first.update(outcome="screen-deferred", triage={
        "policy": amendment.BROWSER_POLICY_DEFERRAL_POLICY,
        "reason": amendment.BROWSER_POLICY_DEFERRAL_REASON, "safety_reason": None,
    })
    first["root_screen"].update(outcome="ambiguous", detail="response-known-invalid")

    def navigation(domain):
        guard = browser_egress.NonReplayableEgressGuard()
        guard.mark_context_guards_installed()
        guard.bind_root_page(object())
        guard.record(api="WebSocket", mechanism="playwright-websocket-route", url=f"wss://{domain}/socket")
        guard.raise_if_failed()

    proof_args = {
        "candidate_id": context_v3["candidates"][0]["candidate_id"],
        "execution_binding": context_v3["binding"],
        "policy_amendment_sha256": amendment.selection_amendment_sha256(context_v3["amendment"]),
        "expected_implementation_hashes": policy.implementation_hashes(),
        "not_before_utc": amendment.selection_amendment_not_before_utc(context_v3["amendment"]),
    }
    path = tmp_path / "v3-navigation-policy-failure.json"
    policy.produce_navigation_policy_observation(
        output=path, backend=ExistingAcquisitionBackend(navigation=navigation),
        profile=PROFILE_PATH, source=SOURCE_PATH, catalogue=CATALOGUE_PATH, **proof_args,
    )

    def reopen(digest):
        facts = copy.deepcopy(context_v3["records"][digest])
        if digest == context_v3["digests"][0]:
            facts["browser_policy_failure"] = policy.verify_browser_policy_failure(
                path, profile_receipt=PROFILE, source_bytes=SOURCE, catalogue_bytes=CATALOGUE, **proof_args,
            )
        return facts

    context_v3["verify"] = reopen
    cohort = _build(context_v3)
    assert cohort["payload"]["terminal_decisions"][0]["root_screen"]["outcome"] == "ambiguous"
    first["root_screen"].update(detail="dns-name-not-found")
    with pytest.raises(ValueError, match="browser-policy deferral"):
        _build(context_v3)


@pytest.mark.parametrize("preparation", [False, True])
def test_v3_inherited_page_branch_keeps_exact_page_requirements_on_response_ambiguity(context_v3, preparation):
    _typed_page_failure(context_v3, preparation=preparation)
    root = context_v3["records"][context_v3["digests"][0]]["root_screen"]
    root.update(outcome="ambiguous", detail="response-known-invalid")
    cohort = _build(context_v3)
    first = cohort["payload"]["terminal_decisions"][0]
    assert first["root_screen"]["outcome"] == "ambiguous"
    assert (first["selected_page_h3_proof"] is not None) == preparation
    assert (first["automated_site_screen"] is not None) == preparation
    root.update(detail="peer-close-336")
    with pytest.raises(ValueError, match="controlled screening context"):
        _build(context_v3)


@pytest.mark.parametrize("preparation", [False, True])
def test_v2_typed_page_failure_is_zero_credit_and_does_not_reduce_fifty(context_v2: dict, preparation: bool):
    failure = _typed_page_failure(context_v2, preparation=preparation)
    cohort = _build(context_v2)
    assert len(cohort["payload"]["selected_candidate_ids"]) == 50
    assert cohort["payload"]["formal_sample_target"] == 16_000
    first = cohort["payload"]["terminal_decisions"][0]
    assert first["outcome"] == amendment.PAGE_POLICY_DEFERRAL_REASON
    assert first["admission"] is None
    assert first["page_policy_failure"] == failure
    assert first["page_policy_failure"]["scientific_credit"] is False
    assert (first["selected_page_h3_proof"] is not None) == preparation
    assert (first["automated_site_screen"] is not None) == preparation
    assert context_v2["candidates"][0]["candidate_id"] not in cohort["payload"]["selected_candidate_ids"]


@pytest.mark.parametrize("change", ["runtime-error", "cdp-error", "old", "candidate", "image", "scope", "attribution", "raw-contract", "raw-observation", "modules", "credit", "missing-page", "missing-auto", "nav-proof-hash"])
def test_v2_page_deferral_rejects_operational_error_and_unproved_bindings(context_v2: dict, change: str):
    preparation = change in {"missing-page", "missing-auto", "nav-proof-hash"}
    failure = _typed_page_failure(context_v2, preparation=preparation)
    first = context_v2["records"][context_v2["digests"][0]]
    if change == "runtime-error":
        failure["raw_failure"]["exception_type"] = "RuntimeError"
    elif change == "cdp-error":
        failure["raw_failure"]["exception_type"] = "InvalidInterceptionId"
    elif change == "old":
        failure["started_at"] = amendment.FROZEN_V1_AMENDMENT_PUBLICATION_UTC
    elif change == "candidate":
        failure["candidate"] = context_v2["candidates"][1]
    elif change == "image":
        failure["runtime_source"]["image_digest"] = "sha256:" + "0" * 64
    elif change == "scope":
        failure["action"]["scope"] = "whole-domain-rejection"
    elif change == "attribution":
        failure["failure_page_attribution"] = "exact-selected-page"
    elif change == "raw-contract":
        failure["raw_failure"]["evidence"]["passive_render_contract"]["hard_cap_after_load_ms"] = 10
    elif change == "raw-observation":
        failure["raw_failure"]["evidence"]["render_observation"]["cutoff_reason"] = "quiescent"
    elif change == "modules":
        failure["implementation_hashes"]["preparation"].clear()
    elif change == "credit":
        failure["scientific_credit"] = True
    elif change == "missing-page":
        first["selected_page_h3_proof"] = None
    elif change == "missing-auto":
        first["automated_site_screen"] = None
    else:
        failure["navigation_receipt_sha256"] = "0" * 64
    with pytest.raises(ValueError):
        _build(context_v2)
