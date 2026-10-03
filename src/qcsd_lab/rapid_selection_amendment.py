"""Prospective selection amendments beside the unchanged frozen v5 study.

V1 records fresh typed browser-navigation deferrals. V2 adds an explicit
automatic URL/domain screen and narrow typed navigation/preparation deferrals.
V3 adds a bounded, explicitly operational collector limitation disposition.
Deferrals give no admission or trace credit and make no whole-domain claim.
Complete admitted graphs, controlled page H3 proof and the 16,000-visit grid
remain required; the original v1 declaration stays independently verifiable.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import rapid_study_profile as profile
from .util import durable_create

SELECTION_AMENDMENT_RECEIPT_TYPE = "qcsd-rapid-v5-selection-amendment"
AMENDED_COHORT_RECEIPT_TYPE = "qcsd-rapid-v5-amended-class-cohort"
AMENDED_SELECTION_POLICY = "first-N-admitted-with-prospective-browser-policy-screen-deferrals-v1"
AMENDED_V2_SELECTION_POLICY = "first-N-automatic-public-url-screened-with-typed-page-policy-deferrals-v2"
AMENDED_V2_ADMISSION_POLICY = "root-and-exact-page-h3-automatic-public-url-screen-complete-live-graph-and-cross-origin-v2"
AMENDED_V3_SELECTION_POLICY = "first-N-automatic-public-url-screened-with-bounded-operational-collector-deferrals-v3"
AMENDED_V4_SELECTION_POLICY = "first-N-admitted-with-source-bound-unsuccessful-live-attempt-deferrals-v4"
AMENDED_V5_ADMISSION_POLICY = "root-and-exact-page-h3-complete-live-graph-with-completed-terminal-http-errors-v5"
AMENDED_V6_ADMISSION_POLICY = "root-and-exact-page-h3-complete-live-graph-with-variable-primary-document-body-v6"
AMENDED_V7_ADMISSION_POLICY = "root-and-exact-page-h3-complete-live-graph-with-approved-origin-auxiliary-chaff-v7"
AMENDED_V8_ADMISSION_POLICY = "root-and-exact-page-h3-complete-live-graph-with-bound-buflo-incoming-release-policy-v8"
VARIABLE_PRIMARY_DOCUMENT_POLICY = "variable-primary-document-body-v1"
ATTEMPT_FAILURE_DEFERRAL_POLICY = "prospective-unsuccessful-live-attempt-deferral-v4"
ATTEMPT_FAILURE_DEFERRAL_REASON = "unsuccessful-live-attempt-screen-deferred"
BROWSER_POLICY_DEFERRAL_POLICY = "prospective-nonreplayable-browser-navigation-deferral-v1"
BROWSER_POLICY_DEFERRAL_REASON = "browser-navigation-policy-deferred"
PAGE_POLICY_DEFERRAL_POLICY = "prospective-typed-page-policy-screen-deferral-v2"
PAGE_POLICY_DEFERRAL_REASON = "page-policy-screen-deferred"
OPERATIONAL_COLLECTOR_DEFERRAL_POLICY = "prospective-bounded-operational-collector-screen-deferral-v3"
OPERATIONAL_COLLECTOR_DEFERRAL_REASON = "operational-collector-screen-deferred"
V3_BROWSER_ROOT_REQUIREMENT = "known-valid-or-completed-response-known-invalid-with-passing-controls"
PARENT_PROFILE_PUBLICATION_UTC = "2026-10-02T12:58:17Z"
FROZEN_V1_AMENDMENT_PUBLICATION_UTC = "2026-10-02T14:30:27.785695Z"
FROZEN_V1_AMENDMENT_SHA256 = "ffc91c4a4fafe39ae9ec3875c982d8a5537fcaae6a253ee58e33c7f492bc8486"
FROZEN_V2_AMENDMENT_PUBLICATION_UTC = "2026-10-02T15:19:12.576895Z"
FROZEN_V2_AMENDMENT_SHA256 = "32cd9eb8440c86f204919bde64a5f27cdcf1efcf28e7becf127d8e3798266457"
FROZEN_V3_AMENDMENT_PUBLICATION_UTC = "2026-10-02T17:00:14.866744Z"
FROZEN_V3_AMENDMENT_SHA256 = "e175fa86345946999af391ec3a98115abd2b84c4cfffdce075dab10b09e3ad3e"
FROZEN_V4_AMENDMENT_PUBLICATION_UTC = "2026-10-02T18:13:34.038260Z"
FROZEN_V4_AMENDMENT_SHA256 = "0808c27b60b229de938bd8a3ae26aca615455c3c4978130b4792041787420a28"
FROZEN_V5_AMENDMENT_PUBLICATION_UTC = "2026-10-02T21:06:26.442961Z"
FROZEN_V5_AMENDMENT_SHA256 = "45c0e5cbdb7b5388c72d9e23de63748d085c9f027c03c06b74b2809f06a3334f"
FROZEN_V6_AMENDMENT_PUBLICATION_UTC = "2026-10-02T22:01:23.089910Z"
FROZEN_V6_AMENDMENT_SHA256 = "7017fe41d41b64673abd75a7f3e0a3fc083450fff9b3264b6abd33e1ad5c7045"
FROZEN_V7_AMENDMENT_PUBLICATION_UTC = "2026-10-03T03:22:45.926573Z"
FROZEN_V7_AMENDMENT_SHA256 = "5a155267592b48fbd58f479ab38641540cb8ae7ae9fef7afd929af8d9cfc498f"
AUTOMATED_SITE_SCREEN_POLICY = "frozen-public-url-and-domain-screen-v1"
AUTOMATED_SITE_SCREEN_DECISION = "automatic-policy-pass"


def automated_screen_policy_payload() -> dict[str, Any]:
    """Declare the narrow URL/domain rules; this is no content classifier."""
    return {
        "policy": AUTOMATED_SITE_SCREEN_POLICY,
        "decision": AUTOMATED_SITE_SCREEN_DECISION,
        "domain_safety_policy": deepcopy(profile.DOMAIN_SAFETY_POLICY),
        "selected_page_url_policy": "canonical-query-free-html-https-default-port-exact-candidate-or-subdomain-v1",
        "selected_page_choice": "independently-rederived-navigation-ordinal-zero-through-four",
        "selected_page_h3": "separate-passing-control-known-valid-exact-url-receipt",
        "named_human_review": "not-required",
        "content_classification_claimed": False,
        "scientific_credit": False,
    }


def automated_screen_policy_bytes() -> bytes:
    return profile._canonical_json(automated_screen_policy_payload())


def automated_screen_policy_sha256() -> str:
    return profile._sha(automated_screen_policy_bytes())


def _utc(value: Any) -> datetime:
    if not isinstance(value, str):
        raise ValueError("selection amendment publication must be a UTC timestamp")
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("selection amendment publication must be a UTC timestamp") from error
    if result.tzinfo is None or result.utcoffset() != UTC.utcoffset(result):
        raise ValueError("selection amendment publication must use UTC")
    if value != result.isoformat().replace("+00:00", "Z"):
        raise ValueError("selection amendment publication must use canonical UTC")
    return result


def _amendment_payload(
    published_at_utc: str, parent_profile_sha256: str, *, revision: int = 1,
) -> dict[str, Any]:
    if type(revision) is not int or revision not in (1, 2, 3, 4, 5, 6, 7, 8):
        raise ValueError("selection amendment revision is unregistered")
    published = _utc(published_at_utc)
    if published < _utc(PARENT_PROFILE_PUBLICATION_UTC) or published > datetime.now(UTC):
        raise ValueError("selection amendment publication is before its parent or in the future")
    if parent_profile_sha256 != profile.FROZEN_V5_PROFILE_SHA256:
        raise ValueError("selection amendment parent is not the frozen v5 profile")
    result = {
        "amendment_id": "crux73-tranco600-rapid-v5-selection-v1",
        "parent_profile_sha256": parent_profile_sha256,
        "parent_selection_policy": profile.V5_SELECTION_POLICY,
        "published_at_utc": published_at_utc,
        "selection_policy": AMENDED_SELECTION_POLICY,
        "browser_policy_deferral": {
            "policy": BROWSER_POLICY_DEFERRAL_POLICY,
            "triage_reason": BROWSER_POLICY_DEFERRAL_REASON,
            "exception_type": "NonReplayableEgressPolicyError",
            "action_kind": "catalogue-boundary-navigation",
            "action_scope": "catalogue-root-and-optional-link-navigation",
            "failure_page_attribution": "unavailable",
            "required_root_screen": "known-valid-with-passing-controls",
            "human_review": "none-at-this-navigation-screen-branch",
            "outcome": "screen-deferred",
            "scientific_credit": False,
            "scope": "candidate-navigation-screen-only-not-whole-domain-ineligibility",
            "required_proof": "independently-reopened-exact-candidate-image-source-module-and-raw-guard-evidence",
        },
        "freshness_policy": {
            "parent_profile_not_before_utc": PARENT_PROFILE_PUBLICATION_UTC,
            "supporting_root_observations": "may-reopen-unchanged-parent-v5-profile-source-image-and-module-bound-observations",
            "new_typed_browser_policy_failure": "started-at-or-after-published-at-utc",
            "old_failed_attempts": "preserved-zero-credit-no-promotion-relabel-or-retroactive-terminal-authority",
        },
        "candidate_order_policy": profile.ORDER_POLICY,
        "admission_policy": profile.V5_ADMISSION_POLICY,
        "admitted_resource_graph": "unchanged-complete-live-resource-graph-with-cross-origin-proof",
        "non_replayable_egress_guard": "unchanged-fail-closed-no-api-suppression-or-transport-waiver",
        "formal_modes": list(profile.FORMAL_MODES),
        "cohort_contracts": [
            {"generation": generation, **contract}
            for generation, contract in profile.V5_COHORT_CONTRACTS.items()
        ],
        "capture_authority": "none-requires-separate-live-capture-readiness",
    }
    if revision >= 2:
        if published < _utc(FROZEN_V1_AMENDMENT_PUBLICATION_UTC):
            raise ValueError("selection amendment v2 publication is before its v1 parent")
        # Reconstruct the frozen v1 envelope independently. A change to its
        # declaration cannot silently become a differently interpreted parent.
        parent = profile._bind(
            _amendment_payload(FROZEN_V1_AMENDMENT_PUBLICATION_UTC, parent_profile_sha256),
            SELECTION_AMENDMENT_RECEIPT_TYPE, schema_version=5,
        )
        parent_sha = profile._sha(profile._canonical_json(parent))
        if parent_sha != FROZEN_V1_AMENDMENT_SHA256:
            raise ValueError("frozen v1 selection amendment declaration no longer verifies")
        result.update({
            "amendment_id": "crux73-tranco600-rapid-v5-selection-v2",
            "revision": 2,
            "parent_selection_amendment_sha256": parent_sha,
            "selection_policy": AMENDED_V2_SELECTION_POLICY,
            "parent_admission_policy": profile.V5_ADMISSION_POLICY,
            "admission_policy": AMENDED_V2_ADMISSION_POLICY,
            "automated_site_screen_policy": automated_screen_policy_payload(),
            "automated_screen_policy_sha256": automated_screen_policy_sha256(),
            "page_policy_deferral": {
                "policy": PAGE_POLICY_DEFERRAL_POLICY,
                "triage_reason": PAGE_POLICY_DEFERRAL_REASON,
                "outcome": PAGE_POLICY_DEFERRAL_REASON,
                "scientific_credit": False,
                "scope": "candidate-action-screen-only-not-whole-domain-ineligibility",
                "required_root_screen": "known-valid-with-passing-controls",
                "navigation_action": {
                    "kind": "catalogue-boundary-navigation",
                    "scope": "catalogue-root-and-optional-link-navigation",
                    "failure_page_attribution": "unavailable",
                    "exception_types": ["PassiveRenderPolicyError"],
                    "selected_page_h3_and_automated_screen": "absent-before-page-selection",
                },
                "preparation_action": {
                    "kind": "complete-graph-preparation",
                    "exception_types": [
                        "PassiveRenderPolicyError", "FullGraphH3PolicyError",
                        "ResponseStabilityPolicyError",
                    ],
                    "required_proof": "exact-navigation-selected-page-h3-and-automated-screen",
                },
                "required_failure_proof": "independently-reopened-exact-candidate-image-source-modules-and-raw-typed-stage-evidence",
                "new_failure_freshness": "started-at-or-after-published-at-utc",
                "other_errors": "operational-no-policy-screen-terminal-authority",
            },
        })
        result["freshness_policy"] = {
            **result["freshness_policy"],
            "supporting_navigation_and_exact_page_h3": "may-reopen-unchanged-parent-v5-profile-source-image-and-independent-module-bound-observations",
            "new_automated_screen_and_page_policy_failure": "at-or-after-published-at-utc",
            "v1_browser_failure_receipts": "retain-v1-only-authority-no-v2-relabel-or-promotion",
        }
    if revision >= 3:
        if published < _utc(FROZEN_V2_AMENDMENT_PUBLICATION_UTC):
            raise ValueError("selection amendment v3 publication is before its v2 parent")
        parent = profile._bind(
            _amendment_payload(FROZEN_V2_AMENDMENT_PUBLICATION_UTC, parent_profile_sha256, revision=2),
            SELECTION_AMENDMENT_RECEIPT_TYPE, schema_version=5,
        )
        parent_sha = profile._sha(profile._canonical_json(parent))
        if parent_sha != FROZEN_V2_AMENDMENT_SHA256:
            raise ValueError("frozen v2 selection amendment declaration no longer verifies")
        result.update({
            "amendment_id": "crux73-tranco600-rapid-v5-selection-v3",
            "revision": 3,
            "parent_selection_amendment_sha256": parent_sha,
            "parent_selection_policy": AMENDED_V2_SELECTION_POLICY,
            "selection_policy": AMENDED_V3_SELECTION_POLICY,
            "parent_admission_policy": AMENDED_V2_ADMISSION_POLICY,
            "browser_root_progression": {
                "policy": "controlled-known-valid-or-completed-response-known-invalid-ambiguity-v3",
                "controls_passed": True,
                "allowed_outcome_details": [
                    ["known-valid", "known-valid"], ["ambiguous", "response-known-invalid"],
                ],
                "response_ambiguity": "completed-root-response-only-not-known-valid-or-site-admission",
                "other_root_failures": "retain-separate-bounded-root-screen-disposition",
                "exact_selected_page_h3_and_complete_graph_acceptance": "unchanged-required",
            },
            "operational_collector_deferral": {
                "policy": OPERATIONAL_COLLECTOR_DEFERRAL_POLICY,
                "triage_reason": OPERATIONAL_COLLECTOR_DEFERRAL_REASON,
                "outcome": OPERATIONAL_COLLECTOR_DEFERRAL_REASON,
                "exception_type": "CdpTargetIntegrityError",
                "exception_module": "qcsd_lab.cdp_targets",
                "proof_policy": "prospective-exact-cdp-event-collector-limitation-v1",
                "actual_attempt_count": 1,
                "required_root_screen": V3_BROWSER_ROOT_REQUIREMENT,
                "navigation_action": {
                    "kind": "catalogue-boundary-navigation",
                    "scope": "catalogue-root-and-optional-link-navigation",
                    "selected_page_h3_and_automated_screen": "absent-before-page-selection",
                },
                "preparation_action": {
                    "kind": "complete-graph-preparation",
                    "scope": "exact-selected-page-complete-resource-graph-preparation",
                    "required_proof": "exact-navigation-selected-page-h3-and-automated-screen",
                },
                "required_failure_proof": "independently-reopened-exact-candidate-runtime-source-modules-actual-class-traceback-action-and-closed-attempt-inventory",
                "failure_scope": "collector-limitation",
                "event_parameters": "unavailable-not-reconstructed",
                "retryable": True,
                "whole_domain_ineligible": False,
                "scientific_credit": False,
                "site_credit": 0,
                "formal_accepted_trace_count": 0,
                "new_failure_freshness": "started-at-or-after-published-at-utc",
                "other_errors": "blocking-operational-no-terminal-authority",
                "acceptance_policy": "unchanged-v2-complete-live-graph-and-cross-origin",
            },
        })
        result["browser_policy_deferral"]["required_root_screen"] = V3_BROWSER_ROOT_REQUIREMENT
        result["page_policy_deferral"]["required_root_screen"] = V3_BROWSER_ROOT_REQUIREMENT
        result["freshness_policy"] = {
            **result["freshness_policy"],
            "new_operational_collector_failure": "started-at-or-after-published-at-utc",
            "v2_failed_attempts": "retain-v2-only-authority-no-v3-relabel-or-promotion",
        }
    if revision >= 4:
        if published < _utc(FROZEN_V3_AMENDMENT_PUBLICATION_UTC):
            raise ValueError("selection amendment v4 publication is before its v3 parent")
        parent = profile._bind(_amendment_payload(
            FROZEN_V3_AMENDMENT_PUBLICATION_UTC, parent_profile_sha256, revision=3,
        ), SELECTION_AMENDMENT_RECEIPT_TYPE, schema_version=5)
        parent_sha = profile._sha(profile._canonical_json(parent))
        if parent_sha != FROZEN_V3_AMENDMENT_SHA256:
            raise ValueError("frozen v3 selection amendment declaration no longer verifies")
        result.update({
            "amendment_id": "crux73-tranco600-rapid-v5-selection-v4", "revision": 4,
            "parent_selection_amendment_sha256": parent_sha,
            "parent_selection_policy": AMENDED_V3_SELECTION_POLICY,
            "selection_policy": AMENDED_V4_SELECTION_POLICY,
            "unsuccessful_live_attempt_deferral": {
                "policy": ATTEMPT_FAILURE_DEFERRAL_POLICY,
                "outcome": ATTEMPT_FAILURE_DEFERRAL_REASON,
                "required_root_screen": V3_BROWSER_ROOT_REQUIREMENT,
                "actions": ["catalogue-boundary-navigation", "selected-page-h3-probe", "complete-graph-preparation"],
                "boundary": "actual-live-backend-call-after-independent-source-runtime-and-input-preflight",
                "failed_operation_evidence": "actual-exception-and-closed-retained-attempt-inventory-not-message-derived-site-classification",
                "controlled_negative_page_probe": "independently-reopened-before-and-after-known-valid-controls-and-exact-page-raw-probe",
                "blocking_failures": "input-schema-source-runtime-configuration-preflight-post-call-verification-and-failed-controls",
                "actual_attempt_count": 1, "retryable": True, "whole_domain_ineligible": False,
                "scientific_credit": False, "site_credit": 0, "formal_accepted_trace_count": 0,
                "admission_policy": "unchanged-complete-live-graph-and-cross-origin-exact-page-h3",
            },
        })
        result["freshness_policy"] = {**result["freshness_policy"],
            "new_unsuccessful_live_attempt": "started-at-or-after-published-at-utc",
            "v3_failed_attempts": "retain-v3-only-authority-no-v4-relabel-or-promotion"}
    if revision >= 5:
        from .application_response_policy import TERMINAL_HTTP_ERROR_POLICY
        if published < _utc(FROZEN_V4_AMENDMENT_PUBLICATION_UTC):
            raise ValueError("selection amendment v5 publication is before its v4 parent")
        parent = profile._bind(_amendment_payload(
            FROZEN_V4_AMENDMENT_PUBLICATION_UTC, parent_profile_sha256, revision=4,
        ), SELECTION_AMENDMENT_RECEIPT_TYPE, schema_version=5)
        parent_sha = profile._sha(profile._canonical_json(parent))
        if parent_sha != FROZEN_V4_AMENDMENT_SHA256:
            raise ValueError("frozen v4 selection amendment declaration no longer verifies")
        result.update({
            "amendment_id": "crux73-tranco600-rapid-v5-selection-v5", "revision": 5,
            "parent_selection_amendment_sha256": parent_sha,
            "parent_selection_policy": AMENDED_V4_SELECTION_POLICY,
            "parent_admission_policy": AMENDED_V2_ADMISSION_POLICY,
            "admission_policy": AMENDED_V5_ADMISSION_POLICY,
            "application_response_policy": TERMINAL_HTTP_ERROR_POLICY,
            "application_response_acceptance": {
                "full_resource_graph": "unchanged-no-resource-or-origin-pruning",
                "allowed_errors": "complete-4xx-or-5xx-non-primary-terminal-leaves-only",
                "error_qualification": "known-valid-false-and-not-chaff",
                "dependency_parents": "must-remain-known-valid-2xx",
                "primary_document": "known-valid-complete-2xx-html-with-exact-page-proof",
                "transport": "actual-negotiated-http3-and-complete-response-required",
                "response_identity": "retain-exact-status-body-bytes-hash-and-headers",
                "stability": "three-fresh-complete-full-graph-policy-matching-replays",
                "required_proof": "independently-reopened-original-get-and-stability-policy-evidence",
                "chaff": "unchanged-qualified-known-valid-2xx-only",
            },
        })
        result["freshness_policy"] = {**result["freshness_policy"],
            "new_policy_preparation": "started-at-or-after-published-at-utc",
            "v4_failed_attempts": "retain-v4-only-authority-no-v5-relabel-or-promotion"}
    if revision >= 6:
        if published < _utc(FROZEN_V5_AMENDMENT_PUBLICATION_UTC):
            raise ValueError("selection amendment v6 publication is before its v5 parent")
        parent = profile._bind(_amendment_payload(
            FROZEN_V5_AMENDMENT_PUBLICATION_UTC, parent_profile_sha256, revision=5,
        ), SELECTION_AMENDMENT_RECEIPT_TYPE, schema_version=5)
        parent_sha = profile._sha(profile._canonical_json(parent))
        if parent_sha != FROZEN_V5_AMENDMENT_SHA256:
            raise ValueError("frozen v5 selection amendment declaration no longer verifies")
        result.update({
            "amendment_id": "crux73-tranco600-rapid-v5-selection-v6", "revision": 6,
            "parent_selection_amendment_sha256": parent_sha,
            "parent_admission_policy": AMENDED_V5_ADMISSION_POLICY,
            "admission_policy": AMENDED_V6_ADMISSION_POLICY,
            "primary_document_identity_policy": VARIABLE_PRIMARY_DOCUMENT_POLICY,
            "primary_document_identity_acceptance": {
                "resource": "unique-known-valid-primary-document-zero-only",
                "body_variation": "actual-complete-body-byte-count-and-sha256-may-vary",
                "unchanged_identity": "exact-url-prepared-2xx-status-request-headers-and-full-graph",
                "expected_primary_response": "retain-first-actual-native-response-status-bytes-and-sha256",
                "other_resources": "exact-prepared-status-body-byte-count-and-sha256",
                "required_proof": "three-fresh-complete-source-bound-full-graph-raw-replays-independently-reopened",
                "chaff": "unchanged-qualified-known-valid-2xx-exact-response-only",
                "scientific_scope": "fixed-public-page-resource-graph-with-variable-primary-document-body",
            },
        })
        result["freshness_policy"] = {**result["freshness_policy"],
            "new_primary_identity_preparation": "started-at-or-after-published-at-utc",
            "v5_failed_attempts": "retain-v5-only-authority-no-v6-relabel-or-promotion"}
    if revision >= 7:
        from .application_response_policy import APPROVED_ORIGINS_CHAFF_POLICY
        if published < _utc(FROZEN_V6_AMENDMENT_PUBLICATION_UTC):
            raise ValueError("selection amendment v7 publication is before its v6 parent")
        parent = profile._bind(_amendment_payload(
            FROZEN_V6_AMENDMENT_PUBLICATION_UTC, parent_profile_sha256, revision=6,
        ), SELECTION_AMENDMENT_RECEIPT_TYPE, schema_version=5)
        parent_sha = profile._sha(profile._canonical_json(parent))
        if parent_sha != FROZEN_V6_AMENDMENT_SHA256:
            raise ValueError("frozen v6 selection amendment declaration no longer verifies")
        result.update({
            "amendment_id": "crux73-tranco600-rapid-v5-selection-v7", "revision": 7,
            "parent_selection_amendment_sha256": parent_sha,
            "parent_admission_policy": AMENDED_V6_ADMISSION_POLICY,
            "admission_policy": AMENDED_V7_ADMISSION_POLICY,
            "qualified_chaff_origin_policy": APPROVED_ORIGINS_CHAFF_POLICY,
            "qualified_chaff_origin_acceptance": {
                "origins": "exact-preparation-approved-origins-only",
                "resource": "known-valid-2xx-non-primary-resource-with-prepared-body-at-least-1200-bytes",
                "primary_document": "resource-zero-excluded-from-padding",
                "candidate_order": "prepared-body-bytes-descending-then-resource-id-then-url",
                "identity": "separate-fresh-sustained-identity-response-qualification-required",
                "full_resource_graph": "unchanged-no-resource-or-origin-pruning",
                "scientific_credit": False,
            },
        })
        result["freshness_policy"] = {**result["freshness_policy"],
            "new_approved_origin_chaff_preparation": "started-at-or-after-published-at-utc",
            "v6_failed_attempts": "retain-v6-only-authority-no-v7-relabel-or-promotion"}
    if revision == 8:
        from .capture_acceptance_policy import POLICY as BUFLO_POLICY
        if published < _utc(FROZEN_V7_AMENDMENT_PUBLICATION_UTC):
            raise ValueError("selection amendment v8 publication is before its v7 parent")
        parent = profile._bind(_amendment_payload(
            FROZEN_V7_AMENDMENT_PUBLICATION_UTC, parent_profile_sha256, revision=7,
        ), SELECTION_AMENDMENT_RECEIPT_TYPE, schema_version=5)
        parent_sha = profile._sha(profile._canonical_json(parent))
        if parent_sha != FROZEN_V7_AMENDMENT_SHA256:
            raise ValueError("frozen v7 selection amendment declaration no longer verifies")
        result.update({
            "amendment_id": "crux73-tranco600-rapid-v5-selection-v8", "revision": 8,
            "parent_selection_amendment_sha256": parent_sha,
            "parent_admission_policy": AMENDED_V7_ADMISSION_POLICY,
            "admission_policy": AMENDED_V8_ADMISSION_POLICY,
            "buflo_incoming_credit_release_policy": BUFLO_POLICY,
            "buflo_incoming_credit_release_acceptance": {
                "binding": "explicit-preparation-opt-in-before-workload-hash-and-admission-seal",
                "native_marker": "bound-preparation-v1-exact-policy-period-cell-and-window",
                "incoming_release_window_us": 10000,
                "period_us": 20000,
                "cell_bytes": 1200,
                "outgoing_deadline_window_us": 5000,
                "traffic_settings": "unchanged-fixed-1200-byte-cells-at-20000-microsecond-period",
                "other_modes": "unchanged-no-buflo-marker-or-release-window-authority",
                "full_resource_graph": "unchanged-no-resource-or-origin-pruning",
                "capture_authority": "none-requires-separate-live-capture-readiness-and-deep-verification",
                "scientific_credit": False,
            },
        })
        result["freshness_policy"] = {**result["freshness_policy"],
            "new_buflo_release_policy_preparation": "started-at-or-after-published-at-utc",
            "v7_failed_attempts_and_admissions": "retain-v7-only-authority-no-v8-relabel-promotion-or-post-admission-manifest-change"}
    return result


def build_selection_amendment(
    *, published_at_utc: str,
    parent_profile_sha256: str = profile.FROZEN_V5_PROFILE_SHA256,
    revision: int = 1,
) -> dict[str, Any]:
    return profile._bind(
        _amendment_payload(published_at_utc, parent_profile_sha256, revision=revision),
        SELECTION_AMENDMENT_RECEIPT_TYPE, schema_version=5,
    )


def validate_selection_amendment(
    value: Mapping[str, Any], *,
    parent_profile_sha256: str = profile.FROZEN_V5_PROFILE_SHA256,
) -> dict[str, Any]:
    payload = profile._unpack(value, SELECTION_AMENDMENT_RECEIPT_TYPE, schema_version=5)
    ids = {
        "crux73-tranco600-rapid-v5-selection-v1": 1,
        "crux73-tranco600-rapid-v5-selection-v2": 2,
        "crux73-tranco600-rapid-v5-selection-v3": 3,
        "crux73-tranco600-rapid-v5-selection-v4": 4,
        "crux73-tranco600-rapid-v5-selection-v5": 5,
        "crux73-tranco600-rapid-v5-selection-v6": 6,
        "crux73-tranco600-rapid-v5-selection-v7": 7,
        "crux73-tranco600-rapid-v5-selection-v8": 8,
    }
    amendment_id = payload.get("amendment_id")
    revision = ids.get(amendment_id) if isinstance(amendment_id, str) else None
    expected = _amendment_payload(
        payload.get("published_at_utc"), parent_profile_sha256, revision=revision,
    )
    if payload != expected or (revision >= 3 and profile._canonical_json(payload) != profile._canonical_json(expected)):
        raise ValueError("selection amendment differs from its prospective fixed contract")
    return payload


def selection_amendment_revision(value: Mapping[str, Any]) -> int:
    return validate_selection_amendment(value).get("revision", 1)


def selection_amendment_not_before_utc(value: Mapping[str, Any]) -> datetime:
    return _utc(validate_selection_amendment(value)["published_at_utc"])


def selection_amendment_sha256(value: Mapping[str, Any]) -> str:
    validate_selection_amendment(value)
    return profile._sha(profile._canonical_json(value))


def root_screen_allows_browser_progression(root: Mapping[str, Any] | None, *, revision: int) -> bool:
    """Apply the narrow root rule after independent v5 root validation.

    A completed response ambiguity can proceed to an exact page test only in
    v3/v4. It gains neither known-valid status nor admission from this predicate.
    """
    if root is None or root.get("controls_passed") is not True:
        return False
    identity = (root.get("outcome"), root.get("detail"))
    return identity == ("known-valid", "known-valid") or (
        type(revision) is int and revision in {3, 4, 5, 6, 7, 8}
        and identity == ("ambiguous", "response-known-invalid")
    )


def write_receipt_create_only(path: Path, receipt: Mapping[str, Any]) -> Path:
    """Publish a new amendment/cohort envelope once without widening v5."""
    if not isinstance(receipt, Mapping) or receipt.get("receipt_type") not in {
        SELECTION_AMENDMENT_RECEIPT_TYPE, AMENDED_COHORT_RECEIPT_TYPE,
    }:
        raise ValueError("only selection amendment and amended cohort receipts may be published")
    profile._unpack(receipt, receipt["receipt_type"], schema_version=5)
    if receipt["receipt_type"] == SELECTION_AMENDMENT_RECEIPT_TYPE:
        validate_selection_amendment(receipt)
    durable_create(path, profile._canonical_json(receipt))
    return path


def _browser_deferral(
    facts: Mapping[str, Any], candidate: Mapping[str, Any], binding: Mapping[str, str],
    selection_amendment: Mapping[str, Any], screen: Mapping[str, Any] | None,
    review: Mapping[str, Any] | None,
) -> dict[str, Any]:
    if (
        facts["outcome"] != "screen-deferred" or facts["admission"] is not None
        or facts["selected_page_h3_proof"] is not None
        or not root_screen_allows_browser_progression(
            screen, revision=selection_amendment_revision(selection_amendment),
        )
        or profile.unsafe_catalogue_domain_reason(candidate["domain"]) is not None
        or review is not None
        or facts["triage"] != {
            "policy": BROWSER_POLICY_DEFERRAL_POLICY,
            "reason": BROWSER_POLICY_DEFERRAL_REASON, "safety_reason": None,
        }
    ):
        raise ValueError("browser-policy deferral cannot admit or scientifically reject a site")
    from .rapid_browser_policy_evidence import validate_browser_policy_failure_facts

    failure = validate_browser_policy_failure_facts(
        facts["browser_policy_failure"], candidate=candidate,
        execution_binding=binding,
        policy_amendment_sha256=selection_amendment_sha256(selection_amendment),
        not_before_utc=selection_amendment_not_before_utc(selection_amendment),
    )
    return dict(failure)


def _automated_screen(
    value: Any, candidate: Mapping[str, Any], page_proof: Mapping[str, Any] | None,
    binding: Mapping[str, str], selection_amendment: Mapping[str, Any],
) -> dict[str, Any] | None:
    if value is None:
        return None
    if page_proof is None:
        raise ValueError("automated site screen lacks its exact selected-page H3 proof")
    from .rapid_site_admission import validate_automated_site_screen_facts

    screen = validate_automated_site_screen_facts(
        value, candidate=candidate, selected_page_url=page_proof["url"],
        execution_binding=binding,
        selection_amendment_sha256=selection_amendment_sha256(selection_amendment),
        not_before_utc=selection_amendment_not_before_utc(selection_amendment),
    )
    if (
        screen["policy"] != AUTOMATED_SITE_SCREEN_POLICY
        or screen["decision"] != AUTOMATED_SITE_SCREEN_DECISION
        or screen["policy_sha256"] != automated_screen_policy_sha256()
        or screen["selected_page_url"] != page_proof["url"]
        or screen["selected_page_ordinal"] != page_proof["selected_page_ordinal"]
        or screen["navigation_receipt_sha256"] != page_proof["navigation_receipt_sha256"]
        or screen["selected_page_h3_receipt_sha256"] != page_proof["receipt_sha256"]
    ):
        raise ValueError("automated site screen differs from its declared rules or exact page proof")
    return dict(screen)


def _page_policy_deferral(
    facts: Mapping[str, Any], candidate: Mapping[str, Any], binding: Mapping[str, str],
    selection_amendment: Mapping[str, Any], root: Mapping[str, Any] | None,
    page_proof: Mapping[str, Any] | None, automated_screen: Mapping[str, Any] | None,
    review: Mapping[str, Any] | None,
) -> dict[str, Any]:
    if (
        facts["outcome"] != PAGE_POLICY_DEFERRAL_REASON or facts["admission"] is not None
        or not root_screen_allows_browser_progression(
            root, revision=selection_amendment_revision(selection_amendment),
        ) or review is not None
        or profile.unsafe_catalogue_domain_reason(candidate["domain"]) is not None
        or facts["triage"] != {
            "policy": PAGE_POLICY_DEFERRAL_POLICY,
            "reason": PAGE_POLICY_DEFERRAL_REASON, "safety_reason": None,
        }
    ):
        raise ValueError("typed page-policy deferral lacks its controlled screening context")
    from .rapid_site_admission import validate_page_policy_failure_facts

    failure = validate_page_policy_failure_facts(
        facts["page_policy_failure"], candidate=candidate, execution_binding=binding,
        selection_amendment_sha256=selection_amendment_sha256(selection_amendment),
        not_before_utc=selection_amendment_not_before_utc(selection_amendment),
        selected_page_h3_proof=page_proof, automated_site_screen=automated_screen,
    )
    action = failure["action"]["kind"]
    if action == "catalogue-boundary-navigation":
        if page_proof is not None or automated_screen is not None:
            raise ValueError("navigation policy deferral cannot carry later preparation proofs")
    elif action == "complete-graph-preparation":
        if page_proof is None or automated_screen is None:
            raise ValueError("preparation policy deferral lacks exact page and automated screen proofs")
    else:
        raise ValueError("page-policy deferral action is unregistered")
    return dict(failure)


def _operational_collector_deferral(
    facts: Mapping[str, Any], candidate: Mapping[str, Any], binding: Mapping[str, str],
    selection_amendment: Mapping[str, Any], root: Mapping[str, Any] | None,
    page_proof: Mapping[str, Any] | None, automated_screen: Mapping[str, Any] | None,
    review: Mapping[str, Any] | None,
) -> dict[str, Any]:
    if (
        facts["outcome"] != OPERATIONAL_COLLECTOR_DEFERRAL_REASON
        or facts["admission"] is not None or review is not None
        or not root_screen_allows_browser_progression(
            root, revision=selection_amendment_revision(selection_amendment),
        )
        or profile.unsafe_catalogue_domain_reason(candidate["domain"]) is not None
        or facts["triage"] != {
            "policy": OPERATIONAL_COLLECTOR_DEFERRAL_POLICY,
            "reason": OPERATIONAL_COLLECTOR_DEFERRAL_REASON, "safety_reason": None,
        }
    ):
        raise ValueError("operational collector deferral lacks its controlled screening context")
    from .rapid_site_admission import validate_operational_collector_failure_facts

    failure = validate_operational_collector_failure_facts(
        facts["operational_collector_failure"], candidate=candidate,
        execution_binding=binding,
        selection_amendment_sha256=selection_amendment_sha256(selection_amendment),
        not_before_utc=selection_amendment_not_before_utc(selection_amendment),
        selected_page_h3_proof=page_proof, automated_site_screen=automated_screen,
    )
    if (
        failure["failure_scope"] != "collector-limitation"
        or failure["event_parameters"] != "unavailable-not-reconstructed"
        or failure["retryable"] is not True
        or failure["whole_domain_ineligible"] is not False
        or failure["scientific_credit"] is not False
        or any(type(failure[key]) is not int or failure[key] != 0
               for key in ("site_credit", "formal_accepted_trace_count"))
        or type(failure["actual_attempt_count"]) is not int
        or failure["actual_attempt_count"] != 1
    ):
        raise ValueError("collector deferral must retain one actual retryable zero-credit limitation")
    action = failure["action"]["kind"]
    if action == "catalogue-boundary-navigation":
        if page_proof is not None or automated_screen is not None:
            raise ValueError("navigation collector deferral cannot carry later preparation proofs")
    elif action == "complete-graph-preparation":
        if page_proof is None or automated_screen is None:
            raise ValueError("preparation collector deferral lacks exact page and automated screen proofs")
    else:
        raise ValueError("operational collector deferral action is unregistered")
    return dict(failure)


def _unsuccessful_attempt_deferral(
    facts: Mapping[str, Any], candidate: Mapping[str, Any], binding: Mapping[str, str],
    selection_amendment: Mapping[str, Any], root: Mapping[str, Any] | None,
    page_proof: Mapping[str, Any] | None, automated_screen: Mapping[str, Any] | None,
    review: Mapping[str, Any] | None,
) -> dict[str, Any]:
    if (facts["outcome"] != ATTEMPT_FAILURE_DEFERRAL_REASON or facts["admission"] is not None
        or review is not None or not root_screen_allows_browser_progression(root, revision=4)
        or facts["triage"] != {"policy": ATTEMPT_FAILURE_DEFERRAL_POLICY,
            "reason": ATTEMPT_FAILURE_DEFERRAL_REASON, "safety_reason": None}):
        raise ValueError("unsuccessful attempt deferral lacks its independent controlled context")
    from .rapid_site_admission import validate_unsuccessful_attempt_failure_facts
    failure = validate_unsuccessful_attempt_failure_facts(
        facts["unsuccessful_attempt_failure"], candidate=candidate, execution_binding=binding,
        selection_amendment_sha256=selection_amendment_sha256(selection_amendment),
        not_before_utc=selection_amendment_not_before_utc(selection_amendment),
        selected_page_h3_proof=page_proof, automated_site_screen=automated_screen)
    from .rapid_attempt_failure_evidence import APPLICATION_RESPONSE_POLICY_MODULE, CHAFF_QUALIFICATION_MODULE
    has_policy_source = APPLICATION_RESPONSE_POLICY_MODULE in failure["implementation_hashes"]
    if has_policy_source != (selection_amendment_revision(selection_amendment) >= 5):
        raise ValueError("unsuccessful attempt source inventory differs from its prospective application policy")
    if (CHAFF_QUALIFICATION_MODULE in failure["implementation_hashes"]) != (selection_amendment_revision(selection_amendment) >= 7):
        raise ValueError("unsuccessful attempt source inventory differs from its prospective qualified chaff origin policy")
    if ("qcsd_lab.capture_acceptance_policy" in failure["implementation_hashes"]) != (selection_amendment_revision(selection_amendment) == 8):
        raise ValueError("unsuccessful attempt source inventory differs from its prospective BufLO release policy")
    if failure["action"]["kind"] == "complete-graph-preparation":
        if page_proof is None or automated_screen is None:
            raise ValueError("unsuccessful preparation lacks its exact page and automatic screen")
    elif page_proof is not None or automated_screen is not None:
        raise ValueError("unsuccessful navigation/probe cannot claim later preparation inputs")
    return failure


def build_amended_cohort_receipt(
    profile_receipt: Mapping[str, Any], source_bytes: bytes, catalogue_bytes: bytes, *,
    selection_amendment: Mapping[str, Any], generation: str,
    terminal_sha256s: Sequence[str], execution_binding: Mapping[str, Any],
    deep_verify_terminal: Callable[[str], Mapping[str, Any]],
) -> dict[str, Any]:
    payload = _selection_payload(
        profile_receipt, source_bytes, catalogue_bytes, generation, terminal_sha256s,
        execution_binding, deep_verify_terminal, selection_amendment,
    )
    return profile._bind(payload, AMENDED_COHORT_RECEIPT_TYPE, schema_version=5)


def validate_amended_cohort_receipt(
    value: Mapping[str, Any], profile_receipt: Mapping[str, Any],
    source_bytes: bytes, catalogue_bytes: bytes, *,
    selection_amendment: Mapping[str, Any], execution_binding: Mapping[str, Any],
    deep_verify_terminal: Callable[[str], Mapping[str, Any]],
) -> tuple[str, ...]:
    payload = profile._unpack(value, AMENDED_COHORT_RECEIPT_TYPE, schema_version=5)
    terminals = payload.get("terminal_decisions")
    if not isinstance(terminals, list):
        raise ValueError("amended cohort terminal decisions are invalid")
    digests = [
        item.get("terminal_receipt_sha256") if isinstance(item, Mapping) else None
        for item in terminals
    ]
    expected = _selection_payload(
        profile_receipt, source_bytes, catalogue_bytes, payload.get("generation"), digests,
        execution_binding, deep_verify_terminal, selection_amendment,
    )
    if (payload != expected or selection_amendment_revision(selection_amendment) == 8
        and profile._canonical_json(payload) != profile._canonical_json(expected)):
        raise ValueError("amended cohort differs from deep-verified ordered selection")
    return tuple(expected["selected_candidate_ids"])



def _selection_payload(
    profile_receipt: Mapping[str, Any],
    source_bytes: bytes,
    catalogue_bytes: bytes,
    generation: str,
    terminal_sha256s: Sequence[str],
    execution_binding: Mapping[str, Any],
    deep_verify_terminal: Callable[[str], Mapping[str, Any]],
    selection_amendment: Mapping[str, Any],
) -> dict[str, Any]:
    """Select first-N sites only after exact-page H3 and complete-graph proof."""

    candidates = profile.validate_v5_profile_receipt(
        profile_receipt, source_bytes, catalogue_bytes
    )
    amendment_payload = validate_selection_amendment(
        selection_amendment,
        parent_profile_sha256=profile._sha(profile._canonical_json(profile_receipt)),
    )
    revision = amendment_payload.get("revision", 1)
    binding = profile._execution_binding(execution_binding)
    if not isinstance(generation, str) or generation not in profile.V5_COHORT_CONTRACTS:
        raise ValueError("v5 rapid-study cohort generation is unregistered")
    if not isinstance(terminal_sha256s, Sequence) or isinstance(
        terminal_sha256s, (str, bytes)
    ):
        raise ValueError("v5 rapid-study terminal SHA-256s must be ordered")
    if not callable(deep_verify_terminal):
        raise ValueError("v5 rapid-study requires independent terminal verification")
    contract = profile.V5_COHORT_CONTRACTS[generation]
    if len(terminal_sha256s) > len(candidates):
        raise ValueError("v5 rapid-study terminal prefix exceeds candidate list")
    decisions: list[dict[str, Any]] = []
    selected: list[dict[str, Any]] = []
    seen: set[str] = set()
    for candidate, digest in zip(candidates, terminal_sha256s, strict=False):
        if not isinstance(digest, str) or profile._SHA_RE.fullmatch(digest) is None or digest in seen:
            raise ValueError("v5 rapid-study terminal digest is invalid or repeated")
        seen.add(digest)
        facts = deep_verify_terminal(digest)
        fields = {
            "candidate_id", "domain", "source_kind", "outcome", "admission",
            "execution_binding", "root_screen", "site_safety_review",
            "selected_page_h3_proof",
        }
        if revision >= 2:
            fields |= {"automated_site_screen"}
        allowed_fields = (
            fields, fields | {"triage"}, fields | {"triage", "browser_policy_failure"},
        )
        if revision >= 2:
            allowed_fields += (fields | {"triage", "page_policy_failure"},)
        if revision >= 3:
            allowed_fields += (fields | {"triage", "operational_collector_failure"},)
        if revision >= 4:
            allowed_fields += (fields | {"triage", "unsuccessful_attempt_failure"},)
        if not isinstance(facts, Mapping) or set(facts) not in allowed_fields:
            raise ValueError("v5 terminal verifier returned invalid facts")
        if profile._execution_binding(facts["execution_binding"]) != binding:
            raise ValueError("v5 terminal belongs to another source or image")
        if any(
            facts[key] != candidate[key] for key in ("candidate_id", "domain", "source_kind")
        ):
            raise ValueError("v5 terminal differs from frozen candidate order")
        screen = (
            profile._validated_v5_root_screen(facts["root_screen"], candidate)
            if facts["root_screen"] is not None else None
        )
        review = (
            profile._validated_site_safety_review(facts["site_safety_review"])
            if facts["site_safety_review"] is not None else None
        )
        page_proof = (
            profile._validated_v5_selected_page_h3_proof(
                facts["selected_page_h3_proof"], candidate
            )
            if facts["selected_page_h3_proof"] is not None else None
        )
        outcome, admission = facts["outcome"], facts["admission"]
        triage = facts.get("triage")
        browser_failure = None
        page_failure = None
        collector_failure = None
        attempt_failure = None
        automatic_screen = (
            _automated_screen(
                facts["automated_site_screen"], candidate, page_proof, binding,
                selection_amendment,
            ) if revision >= 2 else None
        )
        if revision >= 4 and "unsuccessful_attempt_failure" in facts:
            attempt_failure = _unsuccessful_attempt_deferral(
                facts, candidate, binding, selection_amendment, screen, page_proof,
                automatic_screen, review)
        elif "browser_policy_failure" in facts:
            if automatic_screen is not None:
                raise ValueError("browser navigation deferral cannot carry a later automated page screen")
            browser_failure = _browser_deferral(
                facts, candidate, binding, selection_amendment, screen, review,
            )
        elif revision >= 2 and "page_policy_failure" in facts:
            page_failure = _page_policy_deferral(
                facts, candidate, binding, selection_amendment, screen, page_proof,
                automatic_screen, review,
            )
        elif revision >= 3 and "operational_collector_failure" in facts:
            collector_failure = _operational_collector_deferral(
                facts, candidate, binding, selection_amendment, screen, page_proof,
                automatic_screen, review,
            )
        elif outcome == "admitted":
            admission_fields = {
                "selected_page_url", "prepared_workload_sha256",
                "cross_origin_resource_count", "full_resource_graph_sha256",
                "h3_proof_sha256",
            }
            if revision >= 5:
                admission_fields |= {"application_response_policy", "terminal_http_error_resource_ids",
                                     "application_response_evidence_sha256"}
            if revision >= 6:
                admission_fields |= {"primary_document_identity_policy"}
            if revision >= 7:
                admission_fields |= {"qualified_chaff_origin_policy"}
            if revision == 8:
                admission_fields |= {"buflo_incoming_credit_release_policy"}
            if "triage" in facts or not isinstance(admission, Mapping) or set(admission) != admission_fields:
                raise ValueError("v5 admitted site lacks exact page and complete graph proof")
            if revision >= 5:
                error_ids = admission["terminal_http_error_resource_ids"]
                if (admission["application_response_policy"] != amendment_payload["application_response_policy"]
                    or not isinstance(error_ids, list)
                    or any(type(identifier) is not int or identifier <= 0 for identifier in error_ids)
                    or error_ids != sorted(set(error_ids))):
                    raise ValueError("admitted application response policy differs from its prospective contract")
                proof_sha = admission["application_response_evidence_sha256"]
                requires_raw_proof = bool(error_ids) or revision >= 6
                if (requires_raw_proof and (not isinstance(proof_sha, str) or profile._SHA_RE.fullmatch(proof_sha) is None)
                    or not requires_raw_proof and proof_sha is not None):
                    raise ValueError("admitted application response errors lack their independently reopened raw proof")
            if revision >= 6 and admission["primary_document_identity_policy"] != amendment_payload["primary_document_identity_policy"]:
                raise ValueError("admitted primary document identity policy differs from its prospective contract")
            if revision >= 7 and admission["qualified_chaff_origin_policy"] != amendment_payload["qualified_chaff_origin_policy"]:
                raise ValueError("admitted qualified chaff origin policy differs from its prospective contract")
            if revision == 8 and admission["buflo_incoming_credit_release_policy"] != amendment_payload["buflo_incoming_credit_release_policy"]:
                raise ValueError("admitted BufLO release policy differs from its prospective contract")
            if profile.unsafe_catalogue_domain_reason(candidate["domain"]) is not None:
                raise ValueError("v5 automatically unsafe site cannot be admitted")
            if screen is None or page_proof is None:
                raise ValueError("v5 admitted site lacks controlled root and selected-page screens")
            if page_proof["receipt_sha256"] == screen["receipt_sha256"]:
                raise ValueError("v5 selected-page H3 proof must be separately controlled")
            if revision == 1 and (
                review is None or review["decision"] != profile.SITE_SAFETY_REVIEW_POLICY["admission_decision"]
            ):
                raise ValueError("v5 admitted site lacks approved human safety review")
            if revision >= 2 and (
                automatic_screen is None
                or (review is not None and review["decision"] != profile.SITE_SAFETY_REVIEW_POLICY["admission_decision"])
            ):
                raise ValueError("v2 admitted site lacks its independent automatic public URL screen")
            if (
                admission["selected_page_url"] != page_proof["url"]
                or admission["h3_proof_sha256"] != page_proof["receipt_sha256"]
                or type(admission["cross_origin_resource_count"]) is not int
                or admission["cross_origin_resource_count"] < 1
                or any(
                    not isinstance(admission[key], str)
                    or profile._SHA_RE.fullmatch(admission[key]) is None
                    for key in ("prepared_workload_sha256", "full_resource_graph_sha256")
                )
            ):
                raise ValueError("v5 admission differs from selected-page or multi-origin proof")
            selected.append(candidate)
        elif outcome == "ineligible":
            if (
                admission is not None or "triage" in facts or screen is None
                or page_proof is None
                or (revision == 1 and (
                    review is None or review["decision"] != profile.SITE_SAFETY_REVIEW_POLICY["admission_decision"]
                ))
                or (revision >= 2 and (
                    automatic_screen is None
                    or (review is not None and review["decision"] != profile.SITE_SAFETY_REVIEW_POLICY["admission_decision"])
                ))
            ):
                raise ValueError("v5 ineligible site lacks full screened page decision")
        elif outcome == "screen-deferred":
            if admission is not None or page_proof is not None or "triage" not in facts:
                raise ValueError("v5 screen-deferred site cannot carry admission proof")
            triage = profile._validated_v5_triage(triage, candidate, screen, review)
        else:
            raise ValueError("v5 operational errors are not scientific site terminals")
        decisions.append({
            "candidate_id": candidate["candidate_id"],
            "domain": candidate["domain"],
            "source_kind": candidate["source_kind"],
            "terminal_receipt_sha256": digest,
            "outcome": outcome,
            "admission": dict(admission) if admission is not None else None,
            "root_screen": screen,
            "site_safety_review": review,
            "selected_page_h3_proof": page_proof,
            **({"triage": triage} if outcome in {
                "screen-deferred", PAGE_POLICY_DEFERRAL_REASON,
                OPERATIONAL_COLLECTOR_DEFERRAL_REASON,
                ATTEMPT_FAILURE_DEFERRAL_REASON,
            } else {}),
            **({"browser_policy_failure": browser_failure} if browser_failure is not None else {}),
            **({"automated_site_screen": automatic_screen} if revision >= 2 else {}),
            **({"page_policy_failure": page_failure} if page_failure is not None else {}),
            **({"operational_collector_failure": collector_failure} if collector_failure is not None else {}),
            **({"unsuccessful_attempt_failure": attempt_failure} if attempt_failure is not None else {}),
        })
        if len(selected) == contract["class_count"] and len(decisions) != len(terminal_sha256s):
            raise ValueError("v5 terminal prefix continues past the first N admitted sites")
    if len(selected) != contract["class_count"]:
        raise ValueError("v5 cohort is incomplete: not enough deep-verified sites")
    return {
        "study_id": contract["study_id"],
        "generation": generation,
        "cohort_role": contract["role"],
        "profile_receipt_sha256": profile._sha(profile._canonical_json(profile_receipt)),
        "source_sha256": profile.SOURCE_SHA256,
        "fallback_catalogue_sha256": profile.FALLBACK_CATALOGUE_SHA256,
        "execution_binding": binding,
        "selection_policy": amendment_payload["selection_policy"],
        "selection_amendment_sha256": selection_amendment_sha256(selection_amendment),
        **({"application_response_policy": amendment_payload["application_response_policy"]} if revision >= 5 else {}),
        **({"primary_document_identity_policy": amendment_payload["primary_document_identity_policy"]} if revision >= 6 else {}),
        **({"qualified_chaff_origin_policy": amendment_payload["qualified_chaff_origin_policy"]} if revision >= 7 else {}),
        **({"buflo_incoming_credit_release_policy": amendment_payload["buflo_incoming_credit_release_policy"]} if revision == 8 else {}),
        **({"automated_screen_policy_sha256": automated_screen_policy_sha256()} if revision >= 2 else {}),
        "terminal_decisions": decisions,
        "selected_candidate_ids": [candidate["candidate_id"] for candidate in selected],
        "selected_candidates": [
            {
                key: candidate[key] for key in (
                    "candidate_id", "domain", "source_kind", "source_candidate_id",
                    "source_sha256", "source_position", "tranco_rank", "tranco_stratum",
                )
            }
            for candidate in selected
        ],
        "formal_modes": list(profile.FORMAL_MODES),
        "visits_per_class_mode": contract["visits_per_class_mode"],
        "planned_visit_count": contract["planned_visit_count"],
        "formal_sample_target": contract["formal_sample_target"],
        "sample_credit_policy": (
            "zero-credit-diagnostic" if contract["role"] == "shakedown"
            else "formal-only-after-separate-readiness-and-deep-verification"
        ),
        "capture_authority": "none-requires-separate-live-capture-readiness",
    }
