"""Resumable, provenance-bound acquisition for the 100-class study.

The runner deliberately performs only work whose probe window is currently due.
Network operations are behind :class:`AcquisitionBackend`, which makes the
state machine independently testable while allowing the production adapter to
reuse ``discover_page`` and ``prepare_workload``.
"""

from __future__ import annotations

import ipaddress
import os
import re
import socket
import time
from collections.abc import Callable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Lock
from typing import Any, Protocol
from urllib.parse import urlsplit

from .acquisition_errors import (
    RecoverableAcquisitionError,
    TerminalAcquisitionPolicyError,
)
from .browser_egress import (
    NON_REPLAYABLE_EGRESS_CONTRACT,
    NonReplayableEgressGuard,
    install_context_egress_guards,
    launch_production_browser,
    validate_non_replayable_egress_failure_evidence,
    validate_non_replayable_egress_success_summary,
)
from .acquisition_timing import (
    ACTION_TIMING_CONTRACT,
    BASELINE_SCHEDULING_CONTRACT,  # noqa: F401 - retained for historical verifier callers
    GLOBAL_LIVE_PAGE_CAP,
    MAX_CANDIDATES_PER_ACTION,
    MINIMUM_BASELINE_SPACING_MS,
    TERMINAL_RELEASE_BASELINE_SCHEDULING_CONTRACT,
    BaselineReservation,
    baseline_is_safe,
    baseline_is_safe_with_releases,
    earliest_safe_baseline,
    earliest_safe_baseline_with_releases,
    validate_baseline_schedule,
    validate_baseline_schedule_with_releases,
)
from .acquisition_selection import ACQUISITION_SELECTION_POLICY, derive_acquisition_selection
from .cdp_targets import (
    CDP_TARGET_INSTRUMENTATION_POLICY,
    NORMAL_SHUTDOWN_DISPOSAL_POLICY,
    NORMAL_SHUTDOWN_DISPOSAL_SUMMARY_SCHEMA_VERSION,
    SRCDOC_PSEUDO_DOCUMENT_POLICY,
    SRCDOC_PSEUDO_DOCUMENT_SUMMARY_SCHEMA_VERSION,
    BrowserSharedWorkerGuard,
    CdpTargetIntegrityError,
    CdpTargetSource,
    RecursiveCdpTargetRouter,
    validate_bootstrap_prearm_summary,
    validate_egress_prearm_summary,
    validate_normal_shutdown_disposal_summary,
    validate_srcdoc_pseudo_document_summary,
)
from .class_catalogue import (
    HTML_MEDIA_TYPES,
    STABILITY_PROBE_WINDOWS,
    DiscoveredLink,
    PageCandidate,
    StabilityObservation,
    derive_stability_decision,
    load_candidate_catalogue_receipt,
    select_page_candidates,
    validate_page_candidate,
)
from .class_study import bind_receipt, canonical_json_bytes, validate_hash_bound_receipt
from .discover import (
    DiscoveryResult,
    _abort_rejected_render,
    discover_page,
    origin,
)
from .discovery_evidence import (
    DISCOVERY_EVENT_AUDIT_SCHEMA_VERSION,
    PASSIVE_RENDER_CONTRACT,
    PASSIVE_RENDER_CONTRACT_SHA256,
    REQUEST_STAGE_OBSERVATION_POLICY,
    RENDER_OBSERVATION_SCHEMA_VERSION,
    evidence_sha256,
    validate_render_observation,
)
from .manifest import (
    project_stable_response_lengths,
    runtime_manifest,
    validate_research_preparation,
)
from .playwright_driver import (
    expected_browser_tool_identity,
    playwright_driver_session,
    validate_default_playwright_driver_once,
)
from .prepare import PreparedWorkload, prepare_workload
from .util import (
    ATOMIC_TEMP_MARKER,
    atomic_json,
    durable_create,
    fsync_directory,
    load_json,
    sha256_bytes,
    sha256_file,
    source_metadata,
)

SCHEMA_VERSION = 9
HISTORICAL_SCHEMA_VERSIONS = frozenset({1, 2, 3, 4, 5, 6, 7, 8})
SUPPORTED_SCHEMA_VERSIONS = HISTORICAL_SCHEMA_VERSIONS | {SCHEMA_VERSION}
PROVENANCE_TYPE = "qcsd-class-study-acquisition-provenance"
TERMINAL_TYPE = "qcsd-class-study-acquisition-terminal"
CHECKPOINT_SCHEMA_VERSION = 3
TERMINAL_SCHEMA_VERSION = 4
COMPLETION_TYPE = "qcsd-class-study-acquisition-completion"
SELECTION_TYPE = "qcsd-class-study-acquisition-selection"
COMPLETION_SCHEMA_VERSION = 4
CHECKPOINT_TYPE = "qcsd-class-study-acquisition-checkpoint"
ACTIVE_BATCH_SCHEMA_VERSION = 1
DOCUMENT_RESPONSE_RECEIPT_TYPE = "qcsd-class-study-document-response"
DOCUMENT_RESPONSE_SCHEMA_VERSION = 2
SCHEMA_SIX_CHECKPOINT_SCHEMA_VERSION = 2
SCHEMA_SIX_TERMINAL_SCHEMA_VERSION = 3
SCHEMA_SIX_COMPLETION_SCHEMA_VERSION = 3
SCHEMA_SIX_DOCUMENT_RESPONSE_SCHEMA_VERSION = 1
_MODERN_CHECKPOINT_SCHEMA_VERSIONS = frozenset({4, 5, 6, 7, 8, SCHEMA_VERSION})
_FIXED_PROVENANCE_SCHEMA_VERSIONS = frozenset({5, 6, 7, 8, SCHEMA_VERSION})
_POLICY_EVIDENCE_SCHEMA_VERSIONS = frozenset({5, 6, 7, 8, SCHEMA_VERSION})
_SELECTION_SCHEMA_VERSIONS = frozenset({6, 7, 8, SCHEMA_VERSION})
_INSTRUMENTATION_EVIDENCE_SCHEMA_VERSIONS = frozenset(
    {2, 3, 4, 5, 6, 7, 8, SCHEMA_VERSION}
)
_RENDER_EVIDENCE_SCHEMA_VERSIONS = frozenset({3, 4, 5, 6, 7, 8, SCHEMA_VERSION})
_TERMINAL_STATE_SCHEMA_VERSIONS = frozenset({2, 3, 4, 5, 6, 7, 8, SCHEMA_VERSION})
_DURATION_LIMIT_SCHEMA_VERSIONS = frozenset({3, 4, 5, 6, 7, 8, SCHEMA_VERSION})
MAX_ORIGIN_PASSES = 8
MAX_APPROVED_ORIGINS = 32
MAX_OBSERVED_AUDIT_ORIGINS = 512
MAX_PROBE_ATTEMPTS = 3
MAX_ACQUISITION_BACKEND_TIMEOUT_MS = 60_000
MAX_PASSIVE_RENDER_AFTER_LOAD_MS = int(PASSIVE_RENDER_CONTRACT["hard_cap_after_load_ms"])
PENDING_BASELINE_GUARD_MS = MINIMUM_BASELINE_SPACING_MS
TERMINAL_KINDS = frozenset(
    {
        "eligible",
        "stable-page-unavailable",
        "pre-probe-rejection",
        "probe-window-missed",
    }
)
NAVIGATION_REJECTION_KINDS = frozenset(
    {
        "captcha-or-challenge",
        "navigation-returned-no-response",
        "navigation-time-budget-exhausted",
        "non-html-primary-response",
        "playwright-navigation-failure",
        "redirect-has-query-fragment-or-userinfo",
        "redirect-outside-candidate-boundary",
    }
)
SCHEMA_ONE_OBSERVATION_FIELDS = frozenset(
    {
        "probe_id",
        "observed_at",
        "elapsed_ms",
        "final_url",
        "status",
        "content_type",
        "body_bytes",
        "body_sha256",
        "resource_graph_sha256",
        "prepared_workload_sha256",
        "runner_provenance_sha256",
        "approved_origins",
        "discovery_observed_origins",
        "discovery_expandable_origins",
        "discovery_origin_ip_pins",
        "chromium_version",
        "neqo_provenance",
        "prepared_path",
        "probe_completed_at",
    }
)
CURRENT_OBSERVATION_FIELDS = frozenset(
    {
        *StabilityObservation.__dataclass_fields__,
        "runner_provenance_sha256",
        "approved_origins",
        "discovery_observed_origins",
        "discovery_expandable_origins",
        "discovery_origin_ip_pins",
        "preparation_origin_ip_pins",
        "discovery_instrumentation_policy",
        "render_observation",
        "chromium_version",
        "neqo_provenance",
        "prepared_path",
        "probe_completed_at",
    }
)


class TerminalProbePolicyError(TerminalAcquisitionPolicyError):
    """A deterministic safety, policy, or finite-cap probe rejection."""


def validate_class_study_preparation(manifest: dict[str, Any], *, workload_id: str) -> None:
    """Require the class study's bounded complete-coverage preparation contract."""

    candidate_preparation = manifest.get("preparation")
    candidate_exclusions = (
        candidate_preparation.get("exclusions", [])
        if isinstance(candidate_preparation, Mapping)
        else []
    )
    unapproved_get_exclusions = [
        item
        for item in candidate_exclusions
        if isinstance(item, Mapping) and item.get("reason") == "origin not approved"
    ]
    if unapproved_get_exclusions:
        raise ValueError(
            f"class-study workload {workload_id!r} complete coverage cannot contain "
            "unapproved-origin HTTPS GET exclusions: "
            + ", ".join(
                sorted(str(item.get("url", "<malformed>")) for item in unapproved_get_exclusions)
            )
        )
    validate_research_preparation(manifest, workload_id=workload_id)
    preparation = manifest["preparation"]
    if "coverage_admission" not in preparation:
        raise ValueError(
            f"class-study workload {workload_id!r} requires a complete-coverage "
            "admission binding every approved origin and rendered resource"
        )
    coverage = preparation["coverage_admission"]
    audit = preparation.get("discovery_event_audit")
    if (
        not isinstance(coverage, Mapping)
        or type(coverage.get("schema_version")) is not int
        or coverage.get("schema_version") != 3
        or coverage.get("origin_ip_pins_sha256")
        != evidence_sha256(preparation.get("origin_ip_pins"))
        or preparation.get("request_header_transformation")
        != "browser-safe-input-to-neqo-stability-frozen-runtime-v1"
        or coverage.get("browser_request_headers_sha256")
        != evidence_sha256(preparation.get("browser_request_headers"))
        or preparation.get("passive_render_contract") != PASSIVE_RENDER_CONTRACT
        or preparation.get("passive_render_contract_sha256") != PASSIVE_RENDER_CONTRACT_SHA256
        or preparation.get("settle_ms") != PASSIVE_RENDER_CONTRACT["minimum_after_load_ms"]
        or not isinstance(audit, Mapping)
        or type(audit.get("schema_version")) is not int
        or audit.get("schema_version") != DISCOVERY_EVENT_AUDIT_SCHEMA_VERSION
        or audit.get("instrumentation_policy") != CDP_TARGET_INSTRUMENTATION_POLICY
    ):
        raise ValueError(
            f"class-study workload {workload_id!r} requires bounded-render "
            "discovery-evidence and origin-pin coverage schema three"
        )
    approved_origins = preparation["approved_origins"]
    observed_origins = preparation["observed_origins"]
    if len(approved_origins) > MAX_APPROVED_ORIGINS:
        raise ValueError(
            f"class-study workload {workload_id!r} exceeds the "
            f"{MAX_APPROVED_ORIGINS}-origin admission cap"
        )
    if len(observed_origins) > MAX_OBSERVED_AUDIT_ORIGINS:
        raise TerminalProbePolicyError(
            f"class-study workload {workload_id!r} exceeds the "
            f"{MAX_OBSERVED_AUDIT_ORIGINS}-origin audit cap"
        )


class MissedProbeWindow(ValueError):
    """A valid acquisition checkpoint whose next mandatory window expired."""


class InternalAcquisitionError(RuntimeError):
    """A durable fail-closed acquisition fault requiring source intervention."""


def _exception_reason(error: BaseException) -> str:
    try:
        message = str(error) or "exception carried no message"
    except BaseException:  # noqa: BLE001 - formatting must not defeat durable checkpointing
        message = "exception string conversion failed"
    return f"{type(error).__name__}: {message}"


def _internal_error_record(
    *,
    stage: str,
    attempt: int,
    recorded_at: datetime,
    error: BaseException,
    reason: str,
    page_ordinal: int | None = None,
    probe_id: str | None = None,
) -> dict[str, Any]:
    prefix = f"{type(error).__name__}: "
    if not reason.startswith(prefix) or not reason.removeprefix(prefix):
        raise AssertionError("internal acquisition reason lost its exception identity")
    return {
        "schema_version": 1,
        "stage": stage,
        "attempt": attempt,
        "page_ordinal": page_ordinal,
        "probe_id": probe_id,
        "exception_type": type(error).__name__,
        "message": reason.removeprefix(prefix),
        "recorded_at": _format_time(recorded_at),
    }


DOMAIN_SAFETY_POLICY = {
    "policy": "frozen-domain-safety-deny-v2",
    # Deterministic pre-browser safety policy, not a content classifier.  It
    # covers explicit-content and gambling labels present in the pinned input,
    # plus unambiguous abuse labels.  Rejections stay visible in attrition.
    "denied_substrings": [
        "adult",
        "bet",
        "casino",
        "escort",
        "gambl",
        "hentai",
        "malware",
        "phishing",
        "porn",
        "sex",
        "xxx",
    ],
    "denied_exact_domains": [
        "deep-nudes.com",
        "ebonyfacial.net",
        "greenxh.live",
        "hanime.tv",
        "joyclub.de",
        "mygirls.me",
        "xvideos.tube",
        "xnxx.com",
    ],
}

NAVIGATION_IMPLEMENTATION = "playwright-public-cdp-recursive-catalogue-boundary-egress-guard-v5"
REGISTRABLE_DOMAIN_POLICY = "exact-frozen-tranco-candidate-domain"
ELIGIBILITY_INPUTS = ["page-safety", "three-window-technical-stability"]
PROHIBITED_INPUTS = ["classifier", "defence", "latency", "bandwidth", "privacy"]
ORIGIN_POLICY = {
    "max_passes": MAX_ORIGIN_PASSES,
    "max_navigation_redirect_passes": MAX_ORIGIN_PASSES,
    "max_origins": MAX_APPROVED_ORIGINS,
    "max_observed_audit_origins": MAX_OBSERVED_AUDIT_ORIGINS,
    "max_navigation_attempts": MAX_PROBE_ATTEMPTS,
    "max_probe_attempts_per_window": MAX_PROBE_ATTEMPTS,
    "navigation_seed_scope": "page-specific-in-boundary-https-get-origins",
    "resource_graph_scope": "iteratively-converged-public-https-get-request-instances",
    "request_instance_identity": (
        "observation-order-resource-id-with-preceding-initiator-and-redirect-edges"
    ),
    "dns": "all-answers-global-and-browser-host-resolver-pinned",
    "neqo": "QCSD_PUBLIC_ORIGIN_ONLY-resolve-once-connect-exact-address",
}
SCHEMA_FIVE_PROVENANCE_FIELDS = frozenset(
    {
        "study_id",
        "acquisition_schema_version",
        "candidate_catalogue_sha256",
        "candidate_catalogue_payload_sha256",
        "candidate_count",
        "foundation_attestation",
        "started_at",
        "image_digest",
        "source",
        "browser_tool",
        "navigation_implementation",
        "cdp_target_instrumentation_policy",
        "non_replayable_egress_contract",
        "passive_render_contract",
        "passive_render_contract_sha256",
        "browser_navigation_timeout_ms",
        "passive_render_hard_cap_after_load_ms",
        "acquisition_action_timing_contract",
        "baseline_scheduling_contract",
        "registrable_domain_policy",
        "domain_safety_policy",
        "domain_safety_policy_sha256",
        "origin_policy",
        "eligibility_inputs",
        "prohibited_inputs",
    }
)
CURRENT_PROVENANCE_FIELDS = (SCHEMA_FIVE_PROVENANCE_FIELDS - {"foundation_attestation"}) | {
    "acquisition_authority",
    "acquisition_selection_policy",
}
_FIXED_PROVENANCE_FIELDS = frozenset(
    {
        "browser_tool",
        "navigation_implementation",
        "cdp_target_instrumentation_policy",
        "non_replayable_egress_contract",
        "passive_render_contract",
        "passive_render_contract_sha256",
        "browser_navigation_timeout_ms",
        "passive_render_hard_cap_after_load_ms",
        "acquisition_action_timing_contract",
        "baseline_scheduling_contract",
        "registrable_domain_policy",
        "domain_safety_policy",
        "domain_safety_policy_sha256",
        "origin_policy",
        "eligibility_inputs",
        "prohibited_inputs",
    }
)
# Historical contracts are literals recovered from the clean source that first
# emitted each schema, plus the immutable schema-six acquisition receipts.  Do
# not derive them from current imports: several policies changed without an
# acquisition-schema bump.
_SCHEMA_THREE_FOUR_CDP_TARGET_INSTRUMENTATION_POLICY = (
    "playwright-1.52-public-cdp-recursive-non-flat-paused-debugger-targets-v3"
)
_SCHEMA_THREE_FOUR_RENDER_OBSERVATION_SCHEMA_VERSION = 1
_SCHEMA_THREE_FOUR_DISCOVERY_EVENT_AUDIT_SCHEMA_VERSION = 2
_SCHEMA_THREE_FOUR_PASSIVE_RENDER_CONTRACT: dict[str, Any] = {
    "schema_version": 1,
    "policy": "bounded-passive-render-quiescence-v1",
    "viewport": {"width": 1365, "height": 768, "deviceScaleFactor": 1},
    "cache": "disabled",
    "service_workers": "bypassed-and-registration-blocked",
    "interaction": "none",
    "minimum_after_load_ms": 10_000,
    "quiet_window_ms": 3_000,
    "quiet_window_begins": "after-minimum-or-last-relevant-event-whichever-is-later",
    "hard_cap_after_load_ms": 30_000,
    "poll_interval_ms": 100,
    "active_request_scope": "all-network-request-occurrences",
    "relevant_events": [
        "network-request",
        "fetch-request",
        "network-terminal",
        "target-attached",
        "target-detached",
        "target-destroyed",
        "target-info-changed",
    ],
    "hard_cap_policy": "typed-candidate-rejection",
}
_SCHEMA_THREE_FOUR_PASSIVE_RENDER_CONTRACT_SHA256 = (
    "690d1715642ae553f7329bb13f2458f3089545a4483460874abd7d546faa192d"
)
_SCHEMA_FIVE_CDP_TARGET_INSTRUMENTATION_POLICY_V10 = (
    "playwright-1.57-filtered-public-cdp-guarded-shared-worker-tab-and-egress-v10"
)
_SCHEMA_FIVE_CDP_TARGET_INSTRUMENTATION_POLICY_V12 = (
    "playwright-1.57-filtered-public-cdp-guarded-shared-worker-tab-and-egress-v12"
)
_SCHEMA_FIVE_CDP_TARGET_INSTRUMENTATION_POLICY_V13 = (
    "playwright-1.57-filtered-public-cdp-guarded-shared-worker-tab-and-egress-v13"
)
_SCHEMA_FIVE_CDP_TARGET_INSTRUMENTATION_POLICY_V14 = (
    "playwright-1.57-filtered-public-cdp-guarded-shared-worker-tab-and-egress-v14"
)
_SCHEMA_FIVE_CDP_TARGET_INSTRUMENTATION_POLICY = _SCHEMA_FIVE_CDP_TARGET_INSTRUMENTATION_POLICY_V10
_SCHEMA_FIVE_FIXED_PROVENANCE_SHA256_BY_INSTRUMENTATION_POLICY = {
    _SCHEMA_FIVE_CDP_TARGET_INSTRUMENTATION_POLICY_V10: (
        "8c79b0093409f359b78a4bb5abd526ab6446ef872da56981471939e5cfd23820"
    ),
    _SCHEMA_FIVE_CDP_TARGET_INSTRUMENTATION_POLICY_V12: (
        "9f73fb7b93e64e8a14783d957818ab24945abbc034e3ebfb2fa066d96deed5aa"
    ),
    _SCHEMA_FIVE_CDP_TARGET_INSTRUMENTATION_POLICY_V13: (
        "c3fee8c6ccfa41028c74a3d0c06042812dfe71eabe07843457787032d6c74e02"
    ),
    _SCHEMA_FIVE_CDP_TARGET_INSTRUMENTATION_POLICY_V14: (
        "7f87a9b49211f96a9169d80066cca5c1813fe4583bb6f60cf9b247853514eed1"
    ),
}
_SCHEMA_FIVE_FIXED_PROVENANCE_SHA256 = (
    _SCHEMA_FIVE_FIXED_PROVENANCE_SHA256_BY_INSTRUMENTATION_POLICY[
        _SCHEMA_FIVE_CDP_TARGET_INSTRUMENTATION_POLICY
    ]
)
_SCHEMA_FIVE_SOURCE_LAB_COMMITS_BY_INSTRUMENTATION_POLICY = {
    _SCHEMA_FIVE_CDP_TARGET_INSTRUMENTATION_POLICY_V10: (
        "a20382c658857ca0362fcf877559c8e3320ac376",
        "e719219b42826126fdc7771c2dec0463d425a83d",
        "69a14ebe48f78d08a8b36d3e573955ec64f00ff9",
        "d7ff286e8606eb7802ccfc9bc48e540eeef0be79",
        "24d1972f1550cf9db5102d7ad2585b638e21df87",
        "9d53e08f95c5130c60aadbef8a99273a44d117b5",
        "c55b08aa06fbb4ac16e3655d6d3911109d853730",
        "2d96c924e653aa45ffef5964ff216ba6307cbb0c",
        "d2ff0f6bc439675ab016c94770015456890020ae",
        "81dd702affed4066322faa21ff27f3c7b842ed6b",
        "18d4ab3144e04f0a012ffcba54d349b4046c4336",
        "9a6a45c9d3adfa1b5d5dacd6c51b08440c07bde6",
        "d73ee3f67d9c001e5d4abcad64d6f9497ee73ef9",
        "93f7cfc0d5feb0b286e00056c32f2b7364f62c25",
    ),
    _SCHEMA_FIVE_CDP_TARGET_INSTRUMENTATION_POLICY_V12: (
        "01547462b212ac946aa4a47936e0fd99e2b09c78",
        "a0ed21ebe264dd7d4b8ea838ef456071df75564a",
        "9c85da3abac680cc787dd65c38ebd72ead026e7d",
        "fbb2112bc437ef36007c9db510120125cd64a48b",
        "03b0953235e45dcbd71cfcad63b3342924f9c3b8",
        "3b8c78895400c4b4eb8c5cba399d08226a002458",
        "2bab7a2c0a0d06e82e0f55102a3c1b7e552ef86f",
        "bee5b1a4bada4a461ac7f0a5c2d22c3f5aa14cdc",
        "15e478dc7bf8a52740d773de4fad4877140bc4a4",
        "60909195e3138957b8fdd12d70dedbf4eeb03224",
        "6da10dcb52e5856ce580759453925d20550fd683",
        "8223740fff4d8f928e912822935cad6d0b8e8426",
        "e57c6229a47524c0b23cb5047a75e9ff6fe2632e",
        "8ae6610bf4999af70d9327c874a3783ebabf9f7b",
    ),
    _SCHEMA_FIVE_CDP_TARGET_INSTRUMENTATION_POLICY_V13: (
        "3229a2996e7ec2c148886d431fe95b28ada703fa",
        "045fb99654ef77b93ba7ba3c64d57fcc07b904b9",
        "b466cd63e8f17835a75e10e97718cf4aae8b304e",
        "8e1a11d5071c58bfbd96633ee2e01629f19ec1c0",
        "ea4cf2b65b4a3fd650c0497beda600ea235db456",
    ),
    _SCHEMA_FIVE_CDP_TARGET_INSTRUMENTATION_POLICY_V14: (
        "46eb8172a4fba42a07e7e4da3a40c444ee48259d",
        "083612c02c07cd633ecd76b5df6df691f9d7ecf8",
        "7ad66e1a512574d3e660ec9ce06e50db7d089c5b",
        "4db93077025fcc16eeab427aef0880bff69abb5c",
        "44142d2e14917e03b26ffa9f819d1768c716087a",
    ),
}
_SCHEMA_SIX_CDP_TARGET_INSTRUMENTATION_POLICY_V14 = (
    "playwright-1.57-filtered-public-cdp-guarded-shared-worker-tab-and-egress-v14"
)
_SCHEMA_SIX_CDP_TARGET_INSTRUMENTATION_POLICY_V15 = (
    "playwright-1.57-filtered-public-cdp-guarded-shared-worker-tab-and-egress-v15"
)
_SCHEMA_SIX_CDP_TARGET_INSTRUMENTATION_POLICY = (
    "playwright-1.57-filtered-public-cdp-guarded-shared-worker-tab-and-egress-v16"
)
_SCHEMA_SIX_FIXED_PROVENANCE_SHA256_BY_INSTRUMENTATION_POLICY = {
    _SCHEMA_SIX_CDP_TARGET_INSTRUMENTATION_POLICY_V14: (
        "96ab7c6958bd99a3662745a17c3f8f2548b786c385af4b9af36ca2b58610acae"
    ),
    _SCHEMA_SIX_CDP_TARGET_INSTRUMENTATION_POLICY_V15: (
        "c90b21d46b3dd1081a7734f0d765eb85bbbffc31266af1e5d0a5da45dfc4d04c"
    ),
    _SCHEMA_SIX_CDP_TARGET_INSTRUMENTATION_POLICY: (
        "c709214c3e4bad8310cae0b0b23deff3144ed52639c2ab3aeccb2bad4d25e36d"
    ),
}
_SCHEMA_SIX_FIXED_PROVENANCE_SHA256 = _SCHEMA_SIX_FIXED_PROVENANCE_SHA256_BY_INSTRUMENTATION_POLICY[
    _SCHEMA_SIX_CDP_TARGET_INSTRUMENTATION_POLICY
]
_SCHEMA_SIX_RENDER_OBSERVATION_SCHEMA_VERSION = 3
_SCHEMA_SIX_DISCOVERY_EVENT_AUDIT_SCHEMA_VERSION = 4
_SCHEMA_SIX_PASSIVE_RENDER_CONTRACT: dict[str, Any] = {
    "schema_version": 3,
    "policy": "bounded-passive-render-quiescence-v3",
    "viewport": {"width": 1365, "height": 768, "deviceScaleFactor": 1},
    "cache": "disabled",
    "service_workers": "bypassed-and-registration-blocked",
    "interaction": "none",
    "minimum_after_load_ms": 10_000,
    "quiet_window_ms": 3_000,
    "quiet_window_begins": "after-minimum-or-last-relevant-event-whichever-is-later",
    "hard_cap_after_load_ms": 30_000,
    "poll_interval_ms": 100,
    "active_request_scope": "all-instrumented-urlloader-request-occurrences",
    "non_replayable_egress_policy": "blocked-non-urlloader-egress-v1",
    "non_replayable_egress_boundary": {
        "page_frame_websocket": "playwright-route-before-page",
        "paused_target_constructor_shim": True,
        "cdp_network_events": "post-construction-tripwire-only",
        "packet_level_completeness_claimed": False,
    },
    "quiescence_requires": [
        "no-active-network-request-occurrences",
        "recursive-target-router-shutdown-ready",
        "no-pending-shared-worker-bootstrap-prearm",
        "all-observed-target-egress-shims-prearmed",
        "zero-non-replayable-egress-attempts",
        "zero-browser-context-service-workers",
    ],
    "relevant_events": [
        "network-request",
        "fetch-request",
        "network-terminal",
        "target-attached",
        "target-detached",
        "target-destroyed",
        "target-info-changed",
        "non-replayable-egress-attempt",
    ],
    "hard_cap_policy": "typed-candidate-rejection",
}
_SCHEMA_SIX_PASSIVE_RENDER_CONTRACT_SHA256 = (
    "8679865eb1125ff78d614e06b89432a0c73b62326d6042f216a3320480a74ec9"
)
_SCHEMA_SEVEN_CDP_TARGET_INSTRUMENTATION_POLICY = (
    "playwright-1.57-filtered-public-cdp-guarded-shared-worker-tab-and-egress-v19"
)
_SCHEMA_SEVEN_FIXED_PROVENANCE_SHA256 = (
    "6534b4ff87066c1717f32018638aa8e67e7e0ab792dde271dbc7717d42401fb9"
)
_SCHEMA_SEVEN_RENDER_OBSERVATION_SCHEMA_VERSION = 4
_SCHEMA_SEVEN_DISCOVERY_EVENT_AUDIT_SCHEMA_VERSION = 5
_SCHEMA_SEVEN_PASSIVE_RENDER_CONTRACT: dict[str, Any] = {
    "schema_version": 4,
    "policy": "bounded-passive-render-quiescence-v4",
    "viewport": {"width": 1365, "height": 768, "deviceScaleFactor": 1},
    "cache": "disabled",
    "service_workers": "bypassed-and-registration-blocked",
    "interaction": "none",
    "minimum_after_load_ms": 10_000,
    "quiet_window_ms": 3_000,
    "quiet_window_begins": "after-minimum-or-last-relevant-event-whichever-is-later",
    "hard_cap_after_load_ms": 30_000,
    "poll_interval_ms": 100,
    "active_request_scope": "all-instrumented-urlloader-request-occurrences",
    "non_replayable_egress_policy": "blocked-non-urlloader-egress-v1",
    "non_replayable_egress_boundary": {
        "page_frame_websocket": "playwright-route-before-page",
        "paused_target_constructor_shim": True,
        "cdp_network_events": "post-construction-tripwire-only",
        "packet_level_completeness_claimed": False,
    },
    "quiescence_requires": [
        "no-active-network-request-occurrences",
        "recursive-target-router-shutdown-ready",
        "no-pending-shared-worker-bootstrap-prearm",
        "all-observed-target-egress-shims-prearmed",
        "terminal-root-srcdoc-loader-bound-orphan-abort-or-33-byte-finish-lifecycle",
        "zero-non-replayable-egress-attempts",
        "zero-browser-context-service-workers",
    ],
    "relevant_events": [
        "network-request",
        "fetch-request",
        "network-terminal",
        "target-attached",
        "target-detached",
        "target-destroyed",
        "target-info-changed",
        "browser-internal-document",
        "non-replayable-egress-attempt",
    ],
    "hard_cap_policy": "typed-candidate-rejection",
}
_SCHEMA_SEVEN_PASSIVE_RENDER_CONTRACT_SHA256 = (
    "6a63003feeb667799414bfdd9d24b473b0a43a29853932f55a992c46b8e9bd4e"
)
_SCHEMA_EIGHT_CDP_TARGET_INSTRUMENTATION_POLICY = (
    "playwright-1.57-filtered-public-cdp-guarded-shared-worker-tab-and-egress-v20"
)
_SCHEMA_EIGHT_FIXED_PROVENANCE_SHA256 = (
    "32841a18afb288885aeb55f42e5c734cfbbc4de0725f1b1fd40644bdb4b78046"
)
_SCHEMA_EIGHT_RENDER_OBSERVATION_SCHEMA_VERSION = 4
_SCHEMA_EIGHT_DISCOVERY_EVENT_AUDIT_SCHEMA_VERSION = 7
_SCHEMA_EIGHT_REQUEST_STAGE_OBSERVATION_POLICY = (
    "chromium-143-fetch-primary-or-failed-cors-preflight-v1"
)
_SCHEMA_EIGHT_NORMAL_SHUTDOWN_DISPOSAL_SUMMARY_SCHEMA_VERSION = 2
_SCHEMA_EIGHT_NORMAL_SHUTDOWN_DISPOSAL_POLICY = (
    "chromium-143-post-quiescence-context-disposal-v1"
)
_HISTORICAL_ACQUISITION_EVIDENCE_CONTRACTS: dict[int, tuple[Mapping[str, Any], ...]] = {
    # Schema one predates CDP instrumentation and document/render evidence.
    1: (
        {
            "instrumentation_policy": None,
            "passive_render_contract": None,
            "passive_render_contract_sha256": None,
            "render_observation_schema_version": None,
            "discovery_event_audit_schema_version": None,
            "document_response_schema_version": None,
            "fixed_provenance_sha256": None,
            "source_lab_commits": ("3ea8490ac8fd1c2b31b0ed828a11ae72d17d79c2",),
        },
    ),
    # No schema-two producer survives.  The schema-three reader at bbc0be9
    # nevertheless declares policy-v3 observations and schema-one document
    # response namespaces for schema two, but no render/audit contract.
    2: (
        {
            "instrumentation_policy": (_SCHEMA_THREE_FOUR_CDP_TARGET_INSTRUMENTATION_POLICY),
            "passive_render_contract": None,
            "passive_render_contract_sha256": None,
            "render_observation_schema_version": None,
            "discovery_event_audit_schema_version": None,
            "document_response_schema_version": 1,
            "fixed_provenance_sha256": None,
            "source_lab_commits": (),
        },
    ),
    3: (
        {
            "instrumentation_policy": (_SCHEMA_THREE_FOUR_CDP_TARGET_INSTRUMENTATION_POLICY),
            "passive_render_contract": _SCHEMA_THREE_FOUR_PASSIVE_RENDER_CONTRACT,
            "passive_render_contract_sha256": (_SCHEMA_THREE_FOUR_PASSIVE_RENDER_CONTRACT_SHA256),
            "render_observation_schema_version": (
                _SCHEMA_THREE_FOUR_RENDER_OBSERVATION_SCHEMA_VERSION
            ),
            "discovery_event_audit_schema_version": (
                _SCHEMA_THREE_FOUR_DISCOVERY_EVENT_AUDIT_SCHEMA_VERSION
            ),
            "document_response_schema_version": 1,
            "fixed_provenance_sha256": None,
            "source_lab_commits": ("bbc0be968ec21fddf5431493cf54c38d369208f5",),
        },
    ),
    4: (
        {
            "instrumentation_policy": (_SCHEMA_THREE_FOUR_CDP_TARGET_INSTRUMENTATION_POLICY),
            "passive_render_contract": _SCHEMA_THREE_FOUR_PASSIVE_RENDER_CONTRACT,
            "passive_render_contract_sha256": (_SCHEMA_THREE_FOUR_PASSIVE_RENDER_CONTRACT_SHA256),
            "render_observation_schema_version": (
                _SCHEMA_THREE_FOUR_RENDER_OBSERVATION_SCHEMA_VERSION
            ),
            "discovery_event_audit_schema_version": (
                _SCHEMA_THREE_FOUR_DISCOVERY_EVENT_AUDIT_SCHEMA_VERSION
            ),
            "document_response_schema_version": 1,
            "fixed_provenance_sha256": None,
            "source_lab_commits": (
                "84d6a19d155f54cee2bb1539abb6ff7797ac26ac",
                "a420d3240b43d92ee0fb1b063ab3c550bd4fbe6f",
            ),
        },
    ),
    5: tuple(
        {
            "instrumentation_policy": instrumentation_policy,
            "passive_render_contract": _SCHEMA_SIX_PASSIVE_RENDER_CONTRACT,
            "passive_render_contract_sha256": (_SCHEMA_SIX_PASSIVE_RENDER_CONTRACT_SHA256),
            "render_observation_schema_version": (_SCHEMA_SIX_RENDER_OBSERVATION_SCHEMA_VERSION),
            "discovery_event_audit_schema_version": (
                _SCHEMA_SIX_DISCOVERY_EVENT_AUDIT_SCHEMA_VERSION
            ),
            "document_response_schema_version": 1,
            "fixed_provenance_sha256": fixed_provenance_sha256,
            "source_lab_commits": source_lab_commits,
        }
        for instrumentation_policy, fixed_provenance_sha256, source_lab_commits in (
            (
                policy,
                _SCHEMA_FIVE_FIXED_PROVENANCE_SHA256_BY_INSTRUMENTATION_POLICY[policy],
                _SCHEMA_FIVE_SOURCE_LAB_COMMITS_BY_INSTRUMENTATION_POLICY[policy],
            )
            for policy in (
                _SCHEMA_FIVE_CDP_TARGET_INSTRUMENTATION_POLICY_V10,
                _SCHEMA_FIVE_CDP_TARGET_INSTRUMENTATION_POLICY_V12,
                _SCHEMA_FIVE_CDP_TARGET_INSTRUMENTATION_POLICY_V13,
                _SCHEMA_FIVE_CDP_TARGET_INSTRUMENTATION_POLICY_V14,
            )
        )
    ),
    6: tuple(
        {
            "instrumentation_policy": instrumentation_policy,
            "passive_render_contract": _SCHEMA_SIX_PASSIVE_RENDER_CONTRACT,
            "passive_render_contract_sha256": (_SCHEMA_SIX_PASSIVE_RENDER_CONTRACT_SHA256),
            "render_observation_schema_version": (_SCHEMA_SIX_RENDER_OBSERVATION_SCHEMA_VERSION),
            "discovery_event_audit_schema_version": (
                _SCHEMA_SIX_DISCOVERY_EVENT_AUDIT_SCHEMA_VERSION
            ),
            "document_response_schema_version": 1,
            "fixed_provenance_sha256": fixed_provenance_sha256,
            "source_lab_commits": (source_lab_commit,),
        }
        for instrumentation_policy, fixed_provenance_sha256, source_lab_commit in (
            (
                _SCHEMA_SIX_CDP_TARGET_INSTRUMENTATION_POLICY_V14,
                _SCHEMA_SIX_FIXED_PROVENANCE_SHA256_BY_INSTRUMENTATION_POLICY[
                    _SCHEMA_SIX_CDP_TARGET_INSTRUMENTATION_POLICY_V14
                ],
                "8eaf1daa4113cbe261c0c79d7a3404c9fd8b3eda",
            ),
            (
                _SCHEMA_SIX_CDP_TARGET_INSTRUMENTATION_POLICY_V15,
                _SCHEMA_SIX_FIXED_PROVENANCE_SHA256_BY_INSTRUMENTATION_POLICY[
                    _SCHEMA_SIX_CDP_TARGET_INSTRUMENTATION_POLICY_V15
                ],
                "9aed576a13659a51b0c25c6f81bf9115ebb8e149",
            ),
            (
                _SCHEMA_SIX_CDP_TARGET_INSTRUMENTATION_POLICY,
                _SCHEMA_SIX_FIXED_PROVENANCE_SHA256,
                "6957614b83e67cced5fd262fe97814824d21c8f9",
            ),
        )
    ),
    7: (
        {
            "instrumentation_policy": (_SCHEMA_SEVEN_CDP_TARGET_INSTRUMENTATION_POLICY),
            "passive_render_contract": _SCHEMA_SEVEN_PASSIVE_RENDER_CONTRACT,
            "passive_render_contract_sha256": (
                _SCHEMA_SEVEN_PASSIVE_RENDER_CONTRACT_SHA256
            ),
            "render_observation_schema_version": (
                _SCHEMA_SEVEN_RENDER_OBSERVATION_SCHEMA_VERSION
            ),
            "discovery_event_audit_schema_version": (
                _SCHEMA_SEVEN_DISCOVERY_EVENT_AUDIT_SCHEMA_VERSION
            ),
            "document_response_schema_version": 2,
            "fixed_provenance_sha256": _SCHEMA_SEVEN_FIXED_PROVENANCE_SHA256,
            "source_lab_commits": (
                "af6839fd9e4d389d04b1cfab5a6caa0299c5df0e",
                "679e1490774e3238c3693e780f1361078d6f7cd7",
            ),
        },
    ),
    8: (
        {
            "instrumentation_policy": (_SCHEMA_EIGHT_CDP_TARGET_INSTRUMENTATION_POLICY),
            "passive_render_contract": _SCHEMA_SEVEN_PASSIVE_RENDER_CONTRACT,
            "passive_render_contract_sha256": (
                _SCHEMA_SEVEN_PASSIVE_RENDER_CONTRACT_SHA256
            ),
            "render_observation_schema_version": (
                _SCHEMA_EIGHT_RENDER_OBSERVATION_SCHEMA_VERSION
            ),
            "discovery_event_audit_schema_version": (
                _SCHEMA_EIGHT_DISCOVERY_EVENT_AUDIT_SCHEMA_VERSION
            ),
            "document_response_schema_version": 2,
            "fixed_provenance_sha256": _SCHEMA_EIGHT_FIXED_PROVENANCE_SHA256,
            "source_lab_commits": (
                "8975d543e051b378b30df4b1c45e1b1a4349cc37",
            ),
        },
    ),
}
_SOURCE_FIELDS = frozenset(
    {
        "image_digest",
        "lab_commit",
        "lab_dirty",
        "lab_patch_sha256",
        "neqo_commit",
        "neqo_pinned_commit",
        "neqo_dirty",
        "neqo_patch_sha256",
    }
)
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
_IMAGE_DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}\Z")
_COMMIT_PATTERN = re.compile(r"[0-9a-f]{40}\Z")
_EMPTY_SHA256 = sha256_bytes(b"")


def _matches_json_contract(value: object, expected: object) -> bool:
    """Compare JSON values without Python's ``bool``/``int`` equality alias."""

    try:
        return canonical_json_bytes(value) == canonical_json_bytes(expected)
    except (TypeError, ValueError):
        return False


def _checkpoint_schema_for(acquisition_schema_version: int) -> int:
    if acquisition_schema_version in {7, 8, SCHEMA_VERSION}:
        return CHECKPOINT_SCHEMA_VERSION
    if acquisition_schema_version in {4, 5, 6}:
        return SCHEMA_SIX_CHECKPOINT_SCHEMA_VERSION
    raise ValueError("acquisition schema has no versioned checkpoint contract")


def _terminal_schema_for(acquisition_schema_version: int) -> int:
    if acquisition_schema_version in {7, 8, SCHEMA_VERSION}:
        return TERMINAL_SCHEMA_VERSION
    if acquisition_schema_version in {4, 5, 6}:
        return SCHEMA_SIX_TERMINAL_SCHEMA_VERSION
    if acquisition_schema_version in {2, 3}:
        return 2
    raise ValueError("acquisition schema has no versioned terminal contract")


def _completion_schema_for(acquisition_schema_version: int) -> int:
    if acquisition_schema_version in {7, 8, SCHEMA_VERSION}:
        return COMPLETION_SCHEMA_VERSION
    if acquisition_schema_version == 6:
        return SCHEMA_SIX_COMPLETION_SCHEMA_VERSION
    if acquisition_schema_version in {4, 5}:
        return 2
    raise ValueError("acquisition schema has no versioned completion contract")


def _historical_evidence_contract_for(
    acquisition_schema_version: int,
    *,
    instrumentation_policy: object = None,
) -> Mapping[str, Any]:
    variants = _HISTORICAL_ACQUISITION_EVIDENCE_CONTRACTS.get(acquisition_schema_version)
    if variants is None:
        raise ValueError("acquisition evidence schema is unsupported")
    if instrumentation_policy is None:
        if len(variants) != 1:
            raise ValueError(
                "historical acquisition evidence contract is ambiguous without its "
                "instrumentation policy"
            )
        return variants[0]
    matches = [
        contract
        for contract in variants
        if contract["instrumentation_policy"] == instrumentation_policy
    ]
    if len(matches) != 1:
        raise ValueError("historical acquisition instrumentation policy does not match its schema")
    return matches[0]


def _shared_historical_contract_value(
    acquisition_schema_version: int,
    field: str,
) -> object:
    variants = _HISTORICAL_ACQUISITION_EVIDENCE_CONTRACTS.get(acquisition_schema_version)
    if variants is None:
        raise ValueError("acquisition evidence schema is unsupported")
    encoded = {canonical_json_bytes(contract[field]) for contract in variants}
    if len(encoded) != 1:
        raise ValueError(f"historical acquisition {field} is ambiguous")
    return variants[0][field]


def _document_response_schema_for(
    acquisition_schema_version: int,
    *,
    instrumentation_policy: object = None,
) -> int:
    if acquisition_schema_version == SCHEMA_VERSION:
        return DOCUMENT_RESPONSE_SCHEMA_VERSION
    if acquisition_schema_version in HISTORICAL_SCHEMA_VERSIONS:
        if instrumentation_policy is None:
            value = _shared_historical_contract_value(
                acquisition_schema_version,
                "document_response_schema_version",
            )
        else:
            value = _historical_evidence_contract_for(
                acquisition_schema_version,
                instrumentation_policy=instrumentation_policy,
            )["document_response_schema_version"]
        if type(value) is int:
            return value
        raise ValueError("acquisition schema has no document-response contract")
    raise ValueError("acquisition schema has no document-response contract")


def _instrumentation_policy_for(
    acquisition_schema_version: int,
    *,
    recorded_policy: object = None,
) -> str:
    if acquisition_schema_version == SCHEMA_VERSION:
        if recorded_policy is not None and recorded_policy != CDP_TARGET_INSTRUMENTATION_POLICY:
            raise ValueError("current acquisition instrumentation policy is invalid")
        return CDP_TARGET_INSTRUMENTATION_POLICY
    if acquisition_schema_version in HISTORICAL_SCHEMA_VERSIONS:
        contract = _historical_evidence_contract_for(
            acquisition_schema_version,
            instrumentation_policy=recorded_policy,
        )
        value = contract["instrumentation_policy"]
        if isinstance(value, str):
            return value
        raise ValueError("acquisition schema has no instrumentation contract")
    raise ValueError("acquisition instrumentation schema is unsupported")


def _passive_render_contract_for(acquisition_schema_version: int) -> Mapping[str, Any]:
    if acquisition_schema_version == SCHEMA_VERSION:
        return PASSIVE_RENDER_CONTRACT
    if acquisition_schema_version in HISTORICAL_SCHEMA_VERSIONS:
        value = _shared_historical_contract_value(
            acquisition_schema_version,
            "passive_render_contract",
        )
        if isinstance(value, Mapping):
            return value
        raise ValueError("acquisition schema has no passive-render contract")
    raise ValueError("acquisition render schema is unsupported")


def _passive_render_contract_sha256_for(acquisition_schema_version: int) -> str:
    if acquisition_schema_version == SCHEMA_VERSION:
        return PASSIVE_RENDER_CONTRACT_SHA256
    if acquisition_schema_version in HISTORICAL_SCHEMA_VERSIONS:
        value = _shared_historical_contract_value(
            acquisition_schema_version,
            "passive_render_contract_sha256",
        )
        if isinstance(value, str):
            return value
        raise ValueError("acquisition schema has no passive-render contract")
    raise ValueError("acquisition render schema is unsupported")


def _validate_schema_three_four_render_observation(
    value: object,
    *,
    allow_failure: bool = False,
) -> None:
    """Validate the render-observation v1 shape emitted by schemas three/four."""

    fields = {
        "schema_version",
        "clock",
        "navigation_started_ms",
        "load_event_ms",
        "last_relevant_event_ms",
        "quiet_started_ms",
        "cutoff_ms",
        "active_request_ids",
        "active_request_count",
        "cutoff_reason",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise ValueError("historical render observation fields differ from the contract")
    if (
        type(value["schema_version"]) is not int
        or value["schema_version"] != _SCHEMA_THREE_FOUR_RENDER_OBSERVATION_SCHEMA_VERSION
        or value["clock"] != "monotonic-relative-ms"
    ):
        raise ValueError("historical render observation schema or clock is invalid")
    timing_fields = (
        "navigation_started_ms",
        "load_event_ms",
        "last_relevant_event_ms",
        "quiet_started_ms",
        "cutoff_ms",
    )
    if any(type(value[field]) is not int or value[field] < 0 for field in timing_fields):
        raise ValueError("historical render observation timestamps are invalid")
    navigation = value["navigation_started_ms"]
    load = value["load_event_ms"]
    last = value["last_relevant_event_ms"]
    quiet = value["quiet_started_ms"]
    cutoff = value["cutoff_ms"]
    contract = _SCHEMA_THREE_FOUR_PASSIVE_RENDER_CONTRACT
    minimum_boundary = load + contract["minimum_after_load_ms"]
    if (
        not navigation <= load <= quiet <= cutoff
        or last > cutoff
        or quiet != max(minimum_boundary, last)
    ):
        raise ValueError("historical render observation monotonic ordering is invalid")
    active = value["active_request_ids"]
    if (
        not isinstance(active, list)
        or any(not isinstance(item, str) or not item for item in active)
        or active != sorted(set(active))
        or type(value["active_request_count"]) is not int
        or value["active_request_count"] != len(active)
    ):
        raise ValueError("historical render observation active-request ledger is invalid")
    elapsed = cutoff - load
    quiet_elapsed = cutoff - quiet
    reason = value["cutoff_reason"]
    if reason == "quiescent":
        if active or elapsed < contract["minimum_after_load_ms"]:
            raise ValueError("historical quiescent render cutoff is premature")
        if quiet_elapsed < contract["quiet_window_ms"]:
            raise ValueError("historical render cutoff lacks the required quiet interval")
        if elapsed > contract["hard_cap_after_load_ms"]:
            raise ValueError("historical quiescent render cutoff exceeds its hard cap")
    elif reason == "hard-cap-non-quiescent" and allow_failure:
        hard_cap = contract["hard_cap_after_load_ms"]
        poll = contract["poll_interval_ms"]
        if not hard_cap <= elapsed <= hard_cap + poll:
            raise ValueError("historical hard-cap rejection is outside its boundary")
        if not active and quiet_elapsed >= contract["quiet_window_ms"]:
            raise ValueError("historical hard-cap rejection was already quiescent")
    else:
        raise ValueError("historical render observation cutoff reason is invalid")


def _validate_schema_six_render_observation(
    value: object,
    *,
    allow_failure: bool = False,
) -> None:
    """Validate the exact render-observation v3 contract used by schemas five/six."""

    fields = {
        "schema_version",
        "clock",
        "navigation_started_ms",
        "load_event_ms",
        "last_relevant_event_ms",
        "quiet_started_ms",
        "cutoff_ms",
        "active_request_ids",
        "active_request_count",
        "router_shutdown_ready",
        "bootstrap_prearm_summary",
        "egress_prearm_summary",
        "non_replayable_egress_summary",
        "browser_context_service_worker_count",
        "cutoff_reason",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise ValueError("historical render observation fields differ from the contract")
    if (
        type(value["schema_version"]) is not int
        or value["schema_version"] != _SCHEMA_SIX_RENDER_OBSERVATION_SCHEMA_VERSION
        or value["clock"] != "monotonic-relative-ms"
    ):
        raise ValueError("historical render observation schema or clock is invalid")
    timing_fields = (
        "navigation_started_ms",
        "load_event_ms",
        "last_relevant_event_ms",
        "quiet_started_ms",
        "cutoff_ms",
    )
    if any(type(value[field]) is not int or value[field] < 0 for field in timing_fields):
        raise ValueError("historical render observation timestamps are invalid")
    navigation = value["navigation_started_ms"]
    load = value["load_event_ms"]
    last = value["last_relevant_event_ms"]
    quiet = value["quiet_started_ms"]
    cutoff = value["cutoff_ms"]
    minimum_boundary = load + _SCHEMA_SIX_PASSIVE_RENDER_CONTRACT["minimum_after_load_ms"]
    if (
        not navigation <= load <= quiet <= cutoff
        or last > cutoff
        or quiet != max(minimum_boundary, last)
    ):
        raise ValueError("historical render observation monotonic ordering is invalid")
    active = value["active_request_ids"]
    if (
        not isinstance(active, list)
        or any(not isinstance(item, str) or not item for item in active)
        or active != sorted(set(active))
        or value["active_request_count"] != len(active)
    ):
        raise ValueError("historical render observation active-request ledger is invalid")
    elapsed = cutoff - load
    quiet_elapsed = cutoff - quiet
    reason = value["cutoff_reason"]
    router_shutdown_ready = value["router_shutdown_ready"]
    if type(router_shutdown_ready) is not bool:
        raise ValueError("historical render observation router readiness is invalid")
    validate_bootstrap_prearm_summary(
        value["bootstrap_prearm_summary"],
        require_terminal=reason == "quiescent",
    )
    validate_egress_prearm_summary(
        value["egress_prearm_summary"],
        require_terminal=reason == "quiescent",
    )
    validate_non_replayable_egress_success_summary(value["non_replayable_egress_summary"])
    service_worker_count = value["browser_context_service_worker_count"]
    if type(service_worker_count) is not int or service_worker_count < 0:
        raise ValueError("historical render observation service-worker count is invalid")
    if reason == "quiescent":
        if (
            active
            or not router_shutdown_ready
            or service_worker_count != 0
            or elapsed < _SCHEMA_SIX_PASSIVE_RENDER_CONTRACT["minimum_after_load_ms"]
        ):
            raise ValueError("historical quiescent render cutoff is premature")
        if quiet_elapsed < _SCHEMA_SIX_PASSIVE_RENDER_CONTRACT["quiet_window_ms"]:
            raise ValueError("historical render cutoff lacks the required quiet interval")
        if elapsed >= _SCHEMA_SIX_PASSIVE_RENDER_CONTRACT["hard_cap_after_load_ms"]:
            raise ValueError("historical quiescent render cutoff exceeds its hard cap")
    elif reason == "hard-cap-non-quiescent" and allow_failure:
        if elapsed < _SCHEMA_SIX_PASSIVE_RENDER_CONTRACT["hard_cap_after_load_ms"]:
            raise ValueError("historical hard-cap rejection is outside its boundary")
    else:
        raise ValueError("historical render observation cutoff reason is invalid")


def _validate_versioned_render_observation(
    value: object,
    *,
    acquisition_schema_version: int,
    allow_failure: bool = False,
) -> None:
    if acquisition_schema_version in {7, 8, SCHEMA_VERSION}:
        validate_render_observation(value, allow_failure=allow_failure)
        return
    if acquisition_schema_version in {3, 4}:
        _validate_schema_three_four_render_observation(
            value,
            allow_failure=allow_failure,
        )
        return
    if acquisition_schema_version in {5, 6}:
        _validate_schema_six_render_observation(value, allow_failure=allow_failure)
        return
    raise ValueError("acquisition render schema is unsupported")


def _zero_internal_document_lifecycle_summary() -> dict[str, Any]:
    """Return the current exact terminal zero-event lifecycle receipt."""

    summary = {
        "schema_version": SRCDOC_PSEUDO_DOCUMENT_SUMMARY_SCHEMA_VERSION,
        "policy": SRCDOC_PSEUDO_DOCUMENT_POLICY,
        "enabled": True,
        "total": 0,
        "resolved": 0,
        "pending": 0,
        "aborted": 0,
        "open_candidates": 0,
        "network_history_saturated": False,
        "fetch_history_saturated": False,
        "candidate_limit_saturated": False,
        "terminal_outcome_counts": {
            "Network.loadingFailed": 0,
            "Network.loadingFinished": 0,
        },
        "diagnostics": [],
    }
    return validate_srcdoc_pseudo_document_summary(summary, require_terminal=True)


def _zero_normal_shutdown_disposal_summary() -> dict[str, Any]:
    """Return a compatibility-only terminal zero-request disposal receipt."""

    return validate_normal_shutdown_disposal_summary(
        {
            "schema_version": NORMAL_SHUTDOWN_DISPOSAL_SUMMARY_SCHEMA_VERSION,
            "policy": NORMAL_SHUTDOWN_DISPOSAL_POLICY,
            "started": True,
            "terminal": True,
            "network_total": 0,
            "fetch_total": 0,
            "matched_total": 0,
            "network_only_synthetic_total": 0,
            "fetch_only_context_disposal_total": 0,
            "pending_network_total": 0,
            "pending_fetch_total": 0,
            "terminal_outcomes": {
                "Network.loadingFinished": 0,
                "Network.loadingFailed": 0,
                "Network.redirectResponse": 0,
                "qcsd-shutdown": 0,
            },
        },
        require_terminal=True,
    )


def _upgrade_historical_normal_shutdown_disposal_summary(
    value: object,
) -> dict[str, Any]:
    """Translate the frozen schema-eight shutdown ledger without losing counts."""

    if (
        not isinstance(value, Mapping)
        or value.get("schema_version")
        != _SCHEMA_EIGHT_NORMAL_SHUTDOWN_DISPOSAL_SUMMARY_SCHEMA_VERSION
        or value.get("policy") != _SCHEMA_EIGHT_NORMAL_SHUTDOWN_DISPOSAL_POLICY
    ):
        raise ValueError("schema-eight shutdown disposal contract is invalid")
    historical = validate_normal_shutdown_disposal_summary(
        value,
        require_terminal=True,
        allow_historical=True,
    )
    upgraded = deepcopy(historical)
    upgraded["schema_version"] = NORMAL_SHUTDOWN_DISPOSAL_SUMMARY_SCHEMA_VERSION
    upgraded["policy"] = NORMAL_SHUTDOWN_DISPOSAL_POLICY
    upgraded["fetch_only_context_disposal_total"] = 0
    return validate_normal_shutdown_disposal_summary(
        upgraded,
        require_terminal=True,
    )


def _zero_bootstrap_prearm_summary() -> dict[str, Any]:
    worker = {
        "held": 0,
        "released": 0,
        "pending": 0,
        "released_after_setup_envelopes": 0,
        "owner_target_types": {
            "page": 0,
            "iframe": 0,
            "worker": 0,
            "shared_worker": 0,
        },
    }
    summary = {
        "schema_version": 1,
        "held_total": 0,
        "released_total": 0,
        "pending_total": 0,
        "release_before_setup_envelopes_total": 0,
        "by_worker_type": {
            "worker": deepcopy(worker),
            "shared_worker": deepcopy(worker),
        },
    }
    return validate_bootstrap_prearm_summary(summary, require_terminal=True)


def _zero_egress_prearm_summary() -> dict[str, Any]:
    summary = {
        "schema_version": 2,
        "policy": "blocked-non-urlloader-egress-v1",
        "target_total": 0,
        "installed_total": 0,
        "pending_total": 0,
        "popup_guard_required_total": 0,
        "popup_guard_installed_total": 0,
        "by_target_type": {
            target_type: {
                "target_count": 0,
                "installed_count": 0,
                "pending_count": 0,
                "protected_api_observations": 0,
                "unavailable_api_observations": 0,
                "popup_guard_required_count": 0,
                "popup_guard_installed_count": 0,
            }
            for target_type in ("page", "iframe", "worker", "shared_worker")
        },
    }
    return validate_egress_prearm_summary(summary, require_terminal=True)


def _zero_non_replayable_egress_summary() -> dict[str, Any]:
    guard = NonReplayableEgressGuard()
    guard.mark_context_guards_installed()
    guard.bind_root_page(object())
    return validate_non_replayable_egress_success_summary(guard.success_summary())


def _validate_versioned_class_study_preparation(
    manifest: dict[str, Any],
    *,
    workload_id: str,
    acquisition_schema_version: int,
    instrumentation_policy: object,
) -> None:
    """Deep-validate current evidence or an exact historical projection.

    The adapter checks the source-era discriminators and hashes before adding
    synthetic zero-valued fields that did not exist in that era.  Current
    validators can then replay the otherwise unchanged resource/audit graph.
    """

    if acquisition_schema_version == SCHEMA_VERSION:
        validate_class_study_preparation(manifest, workload_id=workload_id)
        return
    if acquisition_schema_version not in HISTORICAL_SCHEMA_VERSIONS:
        raise ValueError("acquisition preparation schema is unsupported")
    if acquisition_schema_version < 3:
        raise ValueError("acquisition schema has no bounded-render preparation contract")
    if not isinstance(manifest, dict):
        raise TypeError("historical class-study manifest is not an object")
    upgraded = deepcopy(manifest)
    preparation = upgraded.get("preparation")
    if not isinstance(preparation, dict):
        raise TypeError("historical class-study preparation is not an object")
    render_observation = preparation.get("render_observation")
    render_observation_sha256 = preparation.get("render_observation_sha256")
    audit = preparation.get("discovery_event_audit")
    audit_sha256 = preparation.get("discovery_event_audit_sha256")
    if not isinstance(audit, Mapping):
        raise ValueError("historical preparation discovery evidence does not verify")
    contract = _historical_evidence_contract_for(
        acquisition_schema_version,
        instrumentation_policy=instrumentation_policy,
    )
    passive_render_contract = contract["passive_render_contract"]
    passive_render_contract_sha256 = contract["passive_render_contract_sha256"]
    if (
        not _matches_json_contract(
            preparation.get("passive_render_contract"),
            passive_render_contract,
        )
        or preparation.get("passive_render_contract_sha256") != passive_render_contract_sha256
        or not isinstance(render_observation, Mapping)
        or not isinstance(render_observation_sha256, str)
        or evidence_sha256(render_observation) != render_observation_sha256
        or not isinstance(audit_sha256, str)
        or evidence_sha256(audit) != audit_sha256
    ):
        raise ValueError("historical preparation discovery evidence does not verify")
    _validate_versioned_render_observation(
        render_observation,
        acquisition_schema_version=acquisition_schema_version,
    )
    expected_audit_fields = {
        "schema_version",
        "instrumentation_policy",
        "passive_render_contract_sha256",
        "render_observation_sha256",
        "events",
        "summary",
    }
    if acquisition_schema_version == 8:
        expected_audit_fields.update(
            {
                "request_stage_observation_policy",
                "normal_shutdown_disposal_summary",
            }
        )
    events = audit.get("events")
    summary = audit.get("summary")
    if (
        set(audit) != expected_audit_fields
        or type(audit.get("schema_version")) is not int
        or audit["schema_version"] != contract["discovery_event_audit_schema_version"]
        or audit.get("instrumentation_policy") != contract["instrumentation_policy"]
        or audit.get("passive_render_contract_sha256") != passive_render_contract_sha256
        or audit.get("render_observation_sha256") != render_observation_sha256
        or (
            acquisition_schema_version == 8
            and audit.get("request_stage_observation_policy")
            != _SCHEMA_EIGHT_REQUEST_STAGE_OBSERVATION_POLICY
        )
        or not isinstance(events, list)
        or any(not isinstance(event, Mapping) for event in events)
        or (
            acquisition_schema_version < 7
            and any(event.get("kind") == "browser-internal-document" for event in events)
        )
        or not isinstance(summary, Mapping)
        or (
            acquisition_schema_version < 7
            and "browser_internal_document_count" in summary
        )
        or (
            acquisition_schema_version in {7, 8}
            and "browser_internal_document_count" not in summary
        )
    ):
        raise ValueError("historical discovery-event audit contract is invalid")
    if acquisition_schema_version == 8:
        _upgrade_historical_normal_shutdown_disposal_summary(
            audit.get("normal_shutdown_disposal_summary")
        )
    coverage = preparation.get("coverage_admission")
    if not isinstance(coverage, dict) or any(
        coverage.get(field) != expected
        for field, expected in {
            "passive_render_contract_sha256": passive_render_contract_sha256,
            "render_observation_sha256": render_observation_sha256,
            "discovery_event_audit_sha256": audit_sha256,
        }.items()
    ):
        raise ValueError("historical coverage-admission evidence does not verify")

    current_render = deepcopy(dict(render_observation))
    shifted_boundary_event_ms: tuple[int, int] | None = None
    if acquisition_schema_version in {3, 4}:
        current_render.update(
            router_shutdown_ready=True,
            bootstrap_prearm_summary=_zero_bootstrap_prearm_summary(),
            egress_prearm_summary=_zero_egress_prearm_summary(),
            non_replayable_egress_summary=_zero_non_replayable_egress_summary(),
            browser_context_service_worker_count=0,
        )
        # Render-observation v1 admitted a quiescent cutoff exactly at its
        # hard cap; v3 made the hard-cap boundary strict.  The source-era
        # observation has already been validated above, so nudge only the
        # synthetic current projection used to replay the unchanged audit.
        render_contract = _SCHEMA_THREE_FOUR_PASSIVE_RENDER_CONTRACT
        if (
            current_render["cutoff_reason"] == "quiescent"
            and current_render["cutoff_ms"] - current_render["load_event_ms"]
            == render_contract["hard_cap_after_load_ms"]
        ):
            current_render["cutoff_ms"] -= 1
            if (
                current_render["cutoff_ms"] - current_render["quiet_started_ms"]
                < render_contract["quiet_window_ms"]
            ):
                old_last = current_render["last_relevant_event_ms"]
                if (
                    current_render["quiet_started_ms"] != old_last
                    or old_last
                    <= current_render["load_event_ms"] + render_contract["minimum_after_load_ms"]
                ):
                    raise ValueError("historical render hard-cap boundary is inconsistent")
                current_render["last_relevant_event_ms"] = old_last - 1
                current_render["quiet_started_ms"] = old_last - 1
                shifted_boundary_event_ms = (old_last, old_last - 1)
    current_render["schema_version"] = RENDER_OBSERVATION_SCHEMA_VERSION
    if acquisition_schema_version < 7:
        current_render["internal_document_lifecycle_summary"] = (
            _zero_internal_document_lifecycle_summary()
        )
    current_render_sha256 = evidence_sha256(current_render)
    current_audit = deepcopy(dict(audit))
    if shifted_boundary_event_ms is not None:
        old_last, new_last = shifted_boundary_event_ms
        for event in current_audit["events"]:
            if type(event.get("monotonic_ms")) is int and event["monotonic_ms"] == old_last:
                event["monotonic_ms"] = new_last
    current_audit["schema_version"] = DISCOVERY_EVENT_AUDIT_SCHEMA_VERSION
    current_audit["instrumentation_policy"] = CDP_TARGET_INSTRUMENTATION_POLICY
    current_audit["request_stage_observation_policy"] = (
        REQUEST_STAGE_OBSERVATION_POLICY
    )
    current_audit["passive_render_contract_sha256"] = PASSIVE_RENDER_CONTRACT_SHA256
    current_audit["render_observation_sha256"] = current_render_sha256
    current_audit["normal_shutdown_disposal_summary"] = (
        _upgrade_historical_normal_shutdown_disposal_summary(
            audit["normal_shutdown_disposal_summary"]
        )
        if acquisition_schema_version == 8
        else _zero_normal_shutdown_disposal_summary()
    )
    current_audit["summary"] = dict(summary)
    if acquisition_schema_version < 7:
        current_audit["summary"]["browser_internal_document_count"] = 0
    if acquisition_schema_version < 8:
        current_audit["summary"]["blocked_preflight_dependent_count"] = 0
        for event in current_audit["events"]:
            if event.get("kind") == "network-request":
                event["initiator_type"] = "historical-unavailable"
                event["initiator_request_id"] = None
                event["response_observed"] = False
                event["interception_exception"] = None
            elif event.get("kind") == "network-terminal":
                event["failure"] = (
                    None
                    if event.get("outcome") == "finished"
                    else {
                        "error_text": "historical-unavailable",
                        "canceled": None,
                        "blocked_reason": None,
                        "cors_error_status_present": False,
                    }
                )
    current_audit_sha256 = evidence_sha256(current_audit)
    preparation["passive_render_contract"] = deepcopy(PASSIVE_RENDER_CONTRACT)
    preparation["passive_render_contract_sha256"] = PASSIVE_RENDER_CONTRACT_SHA256
    preparation["render_observation"] = current_render
    preparation["render_observation_sha256"] = current_render_sha256
    preparation["discovery_event_audit"] = current_audit
    preparation["discovery_event_audit_sha256"] = current_audit_sha256
    coverage["passive_render_contract_sha256"] = PASSIVE_RENDER_CONTRACT_SHA256
    coverage["render_observation_sha256"] = current_render_sha256
    coverage["discovery_event_audit_sha256"] = current_audit_sha256
    validate_class_study_preparation(upgraded, workload_id=workload_id)


@dataclass(frozen=True)
class NavigationRejection:
    url: str
    kind: str
    reason: str

    def as_dict(self) -> dict[str, str]:
        return {"url": self.url, "kind": self.kind, "reason": self.reason}


@dataclass(frozen=True)
class NavigationDiscovery:
    registrable_domain: str
    links: tuple[DiscoveredLink, ...]
    observed_origins: tuple[str, ...] = ()
    rejections: tuple[NavigationRejection, ...] = ()
    page_observed_origins: tuple[tuple[str, tuple[str, ...]], ...] = ()


@dataclass(frozen=True)
class PreparedProbe:
    observed_at: str
    final_url: str
    status: int
    content_type: str
    body_bytes: int
    body_sha256: str
    resource_graph_sha256: str
    prepared: PreparedWorkload
    chromium_version: str
    neqo_provenance: Mapping[str, str]
    passive_render_contract_sha256: str | None = None
    render_observation: Mapping[str, Any] | None = None
    render_observation_sha256: str | None = None
    discovery_event_audit_sha256: str | None = None
    preparation_origin_ip_pins: Mapping[str, str] | None = None
    document_response_chromium_version: str | None = None


@dataclass(frozen=True)
class BrowserDocumentResponse:
    """Content-minimised identity of the browser's primary document response."""

    final_url: str
    status: int
    content_type: str
    chromium_version: str


class AcquisitionBackend(Protocol):
    def discover_navigation(self, domain: str) -> NavigationDiscovery: ...

    def discover(self, url: str, approved_origins: Sequence[str]) -> DiscoveryResult: ...

    def prepare(
        self,
        workload_id: str,
        url: str,
        approved_origins: Sequence[str],
        output_root: Path,
        *,
        origin_ip_pins: Mapping[str, str] | None = None,
    ) -> PreparedProbe: ...


class ExistingAcquisitionBackend:
    """Production bridge to the existing browser and complete-coverage preparer.

    Navigation extraction remains injectable for deterministic state-machine
    tests.  Production uses the exact frozen catalogue-domain boundary.
    """

    def __init__(
        self,
        *,
        navigation: Callable[[str], NavigationDiscovery] | None = None,
        content_type_probe: Callable[
            [str, Sequence[str], int, Mapping[str, str] | None],
            str | BrowserDocumentResponse,
        ]
        | None = None,
        timeout_ms: int = 60_000,
    ) -> None:
        if type(timeout_ms) is not int or not 1 <= timeout_ms <= MAX_ACQUISITION_BACKEND_TIMEOUT_MS:
            raise ValueError("acquisition backend timeout must be in [1, 60000] ms")
        self._navigation = navigation
        self._content_type_probe = content_type_probe or browser_document_content_type
        self._timeout_ms = timeout_ms

    def discover_navigation(self, domain: str) -> NavigationDiscovery:
        if self._navigation is not None:
            return self._navigation(domain)
        return catalogue_boundary_navigation(domain, timeout_ms=self._timeout_ms)

    def discover(self, url: str, approved_origins: Sequence[str]) -> DiscoveryResult:
        pins = public_origin_ip_pins(approved_origins)
        return discover_page(
            url,
            allow_origins=list(approved_origins),
            timeout_ms=self._timeout_ms,
            origin_ip_pins=pins,
        )

    def prepare(
        self,
        workload_id: str,
        url: str,
        approved_origins: Sequence[str],
        output_root: Path,
        *,
        origin_ip_pins: Mapping[str, str] | None = None,
    ) -> PreparedProbe:
        if output_root.exists() or output_root.is_symlink():
            try:
                _regular_directory(output_root)
            except ValueError as error:
                raise TerminalProbePolicyError(
                    "prepared-probe output root is not an owned regular directory"
                ) from error
        else:
            _new_directory(output_root)
        pins = _validated_frozen_origin_ip_pins(
            approved_origins,
            origin_ip_pins
            if origin_ip_pins is not None
            else public_origin_ip_pins(approved_origins),
        )
        prepared = prepare_workload(
            workload_id,
            url,
            list(approved_origins),
            output_root=output_root,
            require_complete_coverage=True,
            # Research preparation has its own three-run live replay gate;
            # the outer t+30 s/t+24 h/t+72 h class probes are an additional
            # longitudinal stability boundary, not a replacement for it.
            stability_runs=3,
            stability_interval_seconds=0,
            origin_ip_pins=pins,
        )
        manifest = load_json(prepared.path)
        validate_class_study_preparation(manifest, workload_id=workload_id)
        preparation = manifest["preparation"]
        current_image = os.environ.get("QCSD_LAB_IMAGE_DIGEST", "native")
        current_source = dict(source_metadata())
        if current_image == "native" and current_source.get("image_digest") is None:
            current_source["image_digest"] = "native"
        if (
            preparation.get("prepare_image_digest") != current_image
            or preparation.get("lab_source") != current_source
        ):
            raise TerminalProbePolicyError(
                "prepared workload source/image differs from acquisition runtime"
            )
        expected = _prepared_primary_response(manifest)
        if (
            type(expected["status"]) is not int
            or type(expected["bytes"]) is not int
            or expected["bytes"] < 1
            or not isinstance(expected["body_sha256"], str)
            or len(expected["body_sha256"]) != 64
            or any(character not in "0123456789abcdef" for character in expected["body_sha256"])
        ):
            raise TerminalProbePolicyError("prepared primary response identity is invalid")
        document_response = self._content_type_probe(url, approved_origins, self._timeout_ms, pins)
        if isinstance(document_response, str):
            document_response = BrowserDocumentResponse(
                final_url=preparation["final_url"],
                status=expected["status"],
                content_type=_normalise_content_type(document_response),
                chromium_version=preparation["chromium_version"],
            )
        if (
            not isinstance(document_response, BrowserDocumentResponse)
            or document_response.final_url != preparation["final_url"]
            or document_response.status != expected["status"]
            or _normalise_content_type(document_response.content_type) not in HTML_MEDIA_TYPES
            or document_response.chromium_version != preparation["chromium_version"]
            or preparation.get("origin_ip_pins") != pins
        ):
            raise TerminalProbePolicyError(
                "browser document response differs from prepared primary response"
            )
        observed_at = datetime.now(UTC).isoformat().replace("+00:00", "Z")
        return PreparedProbe(
            observed_at=observed_at,
            final_url=document_response.final_url,
            status=document_response.status,
            content_type=_normalise_content_type(document_response.content_type),
            body_bytes=expected["bytes"],
            body_sha256=expected["body_sha256"],
            resource_graph_sha256=_prepared_replay_identity_sha256(manifest),
            prepared=prepared,
            chromium_version=preparation["chromium_version"],
            neqo_provenance={
                key: str(preparation[key])
                for key in (
                    "neqo_version",
                    "neqo_base_commit",
                    "published_qcsd_commit",
                    "migration_commit",
                )
            },
            passive_render_contract_sha256=preparation["passive_render_contract_sha256"],
            render_observation=preparation["render_observation"],
            render_observation_sha256=preparation["render_observation_sha256"],
            discovery_event_audit_sha256=preparation["discovery_event_audit_sha256"],
            preparation_origin_ip_pins=pins,
            document_response_chromium_version=(document_response.chromium_version),
        )


def _prepared_replay_identity_sha256(
    manifest: Mapping[str, Any],
    *,
    acquisition_schema_version: int = SCHEMA_VERSION,
) -> str:
    """Hash stable replay semantics while excluding run-specific evidence.

    A prepared manifest intentionally contains packet-capture qualification
    hashes and other provenance.  Those values prove one preparation run but
    are not expected to repeat 30 seconds, 24 hours, and 72 hours later.  Page
    stability instead binds the complete Neqo runtime graph plus every stable
    response identity and navigation/origin boundary.
    """

    preparation = manifest.get("preparation")
    if not isinstance(preparation, Mapping):
        raise ValueError("prepared replay identity requires preparation evidence")
    expected = preparation.get("expected_responses")
    approved = preparation.get("approved_origins")
    if not isinstance(expected, list) or not isinstance(approved, list):
        raise ValueError("prepared replay identity is incomplete")
    runtime = (
        runtime_manifest(dict(manifest))
        if acquisition_schema_version == SCHEMA_VERSION
        else {
            "resources": project_stable_response_lengths(
                deepcopy(list(manifest.get("resources", []))),
                deepcopy(expected),
            )
        }
    )
    identity = {
        "schema_version": 3,
        "source_url": preparation.get("source_url"),
        "final_url": preparation.get("final_url"),
        "approved_origins": approved,
        "origin_ip_pins": preparation.get("origin_ip_pins"),
        "browser_request_headers": preparation.get("browser_request_headers"),
        "request_header_transformation": preparation.get("request_header_transformation"),
        "expected_responses": expected,
        "passive_render_contract_sha256": preparation.get("passive_render_contract_sha256"),
        "runtime_manifest": runtime,
    }
    return sha256_bytes(canonical_json_bytes(identity))


def _prepared_primary_response(manifest: Mapping[str, Any]) -> Mapping[str, Any]:
    """Derive the final root-document response from its exact redirect chain."""

    preparation = manifest.get("preparation")
    resources = manifest.get("resources")
    if not isinstance(preparation, Mapping) or not isinstance(resources, list):
        raise TerminalProbePolicyError("prepared navigation primary graph is malformed")
    audit = preparation.get("discovery_event_audit")
    events = audit.get("events") if isinstance(audit, Mapping) else None
    if not isinstance(events, list):
        raise TerminalProbePolicyError("prepared navigation has no request audit")
    resource_events: dict[int, Mapping[str, Any]] = {}
    for event in events:
        mapping = event.get("mapping") if isinstance(event, Mapping) else None
        if (
            isinstance(mapping, Mapping)
            and mapping.get("kind") == "resource"
            and type(mapping.get("resource_id")) is int
        ):
            resource_id = mapping["resource_id"]
            if resource_id in resource_events:
                raise TerminalProbePolicyError("prepared navigation resource mapping is ambiguous")
            resource_events[resource_id] = event
    current = resource_events.get(0)
    if not isinstance(current, Mapping):
        raise TerminalProbePolicyError("prepared navigation has no root resource")
    source = current.get("source")
    if (
        current.get("resource_type") != "Document"
        or not isinstance(source, Mapping)
        or source.get("session_path") != []
        or source.get("target_type") != "page"
        or source.get("generation") != 0
    ):
        raise TerminalProbePolicyError("prepared navigation resource zero is not the root document")
    while True:
        successors = [
            event
            for event in resource_events.values()
            if event.get("redirected") is True
            and event.get("redirect_from_occurrence_id") == current.get("occurrence_id")
            and event.get("network_id") == current.get("network_id")
            and event.get("source") == source
        ]
        if not successors:
            break
        if len(successors) != 1:
            raise TerminalProbePolicyError("prepared root-document redirect chain is ambiguous")
        current = successors[0]
        if current.get("resource_type") != "Document":
            raise TerminalProbePolicyError(
                "prepared root-document redirect chain changed resource type"
            )
    mapping = current.get("mapping")
    resource_id = mapping.get("resource_id") if isinstance(mapping, Mapping) else None
    resource = next(
        (item for item in resources if isinstance(item, Mapping) and item.get("id") == resource_id),
        None,
    )
    if (
        not isinstance(resource, Mapping)
        or resource.get("type") != "Document"
        or resource.get("url") != preparation.get("final_url")
        or current.get("url") != preparation.get("final_url")
    ):
        raise TerminalProbePolicyError(
            "prepared root-document redirect chain does not reach the final URL"
        )
    expected_matches = [
        item
        for item in preparation.get("expected_responses", [])
        if isinstance(item, Mapping) and item.get("resource_id") == resource_id
    ]
    if len(expected_matches) != 1:
        raise TerminalProbePolicyError("prepared navigation has no unique final primary response")
    return expected_matches[0]


def _create_document_response_receipt(
    runner_root: Path,
    *,
    workload_id: str,
    requested_url: str,
    approved_origins: Sequence[str],
    origin_ip_pins: Mapping[str, str],
    probe_started_at: str,
    prepared: PreparedProbe,
    runner_provenance_sha256: str,
    runner_provenance: Mapping[str, Any],
) -> dict[str, str]:
    """Durably bind one browser document observation before checkpointing it."""

    frozen_pins = _validated_frozen_origin_ip_pins(approved_origins, origin_ip_pins)
    preparation_pins = prepared.preparation_origin_ip_pins or frozen_pins
    if dict(preparation_pins) != frozen_pins:
        raise TerminalProbePolicyError(
            "document response and preparation used different origin-IP pins"
        )
    content_type = _normalise_content_type(prepared.content_type)
    browser_version = prepared.document_response_chromium_version or prepared.chromium_version
    payload = {
        "document_response_schema_version": _document_response_schema_for(
            runner_provenance["acquisition_schema_version"],
            instrumentation_policy=runner_provenance.get("cdp_target_instrumentation_policy"),
        ),
        "workload_id": workload_id,
        "requested_url": requested_url,
        "final_url": prepared.final_url,
        "status": prepared.status,
        "content_type": content_type,
        "body_bytes": prepared.body_bytes,
        "body_sha256": prepared.body_sha256,
        "resource_graph_sha256": prepared.resource_graph_sha256,
        "prepared_workload_sha256": prepared.prepared.sha256,
        "probe_started_at": probe_started_at,
        "response_observed_at": prepared.observed_at,
        "approved_origins": list(approved_origins),
        "origin_ip_pins": frozen_pins,
        "origin_ip_pins_sha256": evidence_sha256(frozen_pins),
        "chromium_version": browser_version,
        "preparation_chromium_version": prepared.chromium_version,
        "neqo_provenance": dict(prepared.neqo_provenance),
        "cdp_target_instrumentation_policy": _instrumentation_policy_for(
            runner_provenance["acquisition_schema_version"],
            recorded_policy=runner_provenance.get("cdp_target_instrumentation_policy"),
        ),
        "browser_tool": runner_provenance["browser_tool"],
        "runner_provenance_sha256": runner_provenance_sha256,
        "image_digest": runner_provenance["image_digest"],
        "source": runner_provenance["source"],
    }
    receipt = bind_receipt(payload, receipt_type=DOCUMENT_RESPONSE_RECEIPT_TYPE)
    relative = f"document-response-receipts/{workload_id}.json"
    destination = runner_root / relative
    _create_json(destination, receipt)
    return {"path": relative, "sha256": sha256_file(destination)}


class _NavigationPinExpansion(Exception):
    """An allowed document redirect named origins absent from the frozen pass."""

    def __init__(self, origins: set[str]) -> None:
        self.origins = tuple(sorted(origins))
        super().__init__(", ".join(self.origins))


def catalogue_boundary_navigation(domain: str, *, timeout_ms: int = 60_000) -> NavigationDiscovery:
    """Extract candidates after bounded, public-IP-pinned redirect convergence."""

    if timeout_ms < 1:
        raise ValueError("navigation timeout must be positive")
    deadline = time.monotonic() + timeout_ms / 1_000
    if reason := unsafe_catalogue_domain_reason(domain):
        raise TerminalProbePolicyError(reason)
    try:
        from playwright.sync_api import Error as PlaywrightError
        from playwright.sync_api import sync_playwright
    except ImportError as error:
        raise RuntimeError("navigation discovery requires the discovery Docker image") from error

    navigation_pins = public_origin_ip_pins((f"https://{domain}",))

    for pass_index in range(MAX_ORIGIN_PASSES):
        if time.monotonic() >= deadline:
            raise RecoverableAcquisitionError(
                "navigation redirect convergence exhausted its total timeout"
            )
        try:
            return _catalogue_boundary_navigation_pass(
                domain,
                deadline=deadline,
                navigation_pins=navigation_pins,
                sync_playwright=sync_playwright,
                playwright_error=PlaywrightError,
            )
        except _NavigationPinExpansion as expansion:
            new_origins = set(expansion.origins) - set(navigation_pins)
            if not new_origins:
                raise RuntimeError(
                    "navigation redirect pin expansion made no progress"
                ) from expansion
            if len(navigation_pins) + len(new_origins) > MAX_APPROVED_ORIGINS:
                raise TerminalProbePolicyError(
                    "navigation redirect discovery exceeded its finite origin cap"
                ) from expansion
            if pass_index + 1 >= MAX_ORIGIN_PASSES:
                raise TerminalProbePolicyError(
                    "navigation redirect origins did not converge within the finite pass cap"
                ) from expansion
            existing_by_hostname = {
                urlsplit(value).hostname: address for value, address in navigation_pins.items()
            }
            reused: dict[str, str] = {}
            unresolved: list[str] = []
            for value in sorted(new_origins):
                hostname = urlsplit(value).hostname
                if hostname in existing_by_hostname:
                    reused[value] = existing_by_hostname[hostname]
                else:
                    unresolved.append(value)
            navigation_pins.update(reused)
            navigation_pins.update(public_origin_ip_pins(tuple(unresolved)))
            _validated_frozen_origin_ip_pins(tuple(sorted(navigation_pins)), navigation_pins)
    raise AssertionError("navigation redirect convergence loop terminated unexpectedly")


def _catalogue_boundary_navigation_pass(
    domain: str,
    *,
    deadline: float,
    navigation_pins: Mapping[str, str],
    sync_playwright: Any,
    playwright_error: type[Exception],
) -> NavigationDiscovery:
    """Run one browser pass against an immutable exact-origin DNS pin set."""

    registrable = domain
    observed_origins: set[str] = set()
    current_page_origins: set[str] = set()
    unpinned_document_origins: set[str] = set()
    rejected_document_urls: set[str] = set()
    page_observed_origins: list[tuple[str, tuple[str, ...]]] = []
    verified: list[DiscoveredLink] = []
    rejections: list[NavigationRejection] = []

    def remaining_timeout() -> int:
        return max(0, round((deadline - time.monotonic()) * 1_000))

    try:
        validate_default_playwright_driver_once()
        with playwright_driver_session(sync_playwright, exclusive=True) as playwright:
            browser, _browser_egress_projection = launch_production_browser(
                playwright,
                approved_origins=tuple(sorted(navigation_pins)),
                origin_ip_pins=navigation_pins,
            )
            graph_primary: BaseException | None = None
            try:
                context = browser.new_context(ignore_https_errors=False, service_workers="block")
                egress_guard = NonReplayableEgressGuard()
                install_context_egress_guards(context, egress_guard)
                unowned_document_urls: set[str] = set()
                page = context.new_page()
                egress_guard.bind_root_page(page)
                session = context.new_cdp_session(page)
                browser_session = browser.new_browser_cdp_session()
                frame_tree = session.send("Page.getFrameTree")
                frame = frame_tree.get("frameTree", {}).get("frame", {})
                root_frame_id = frame.get("id")
                if not isinstance(root_frame_id, str) or not root_frame_id:
                    raise RuntimeError("catalogue navigation could not identify its root frame")

                router: RecursiveCdpTargetRouter

                def protocol_event(
                    source: CdpTargetSource,
                    method: str,
                    event: Mapping[str, Any],
                ) -> None:
                    if method != "Fetch.requestPaused":
                        return
                    request_id = event.get("requestId")
                    request = event.get("request")
                    if (
                        not isinstance(request_id, str)
                        or not request_id
                        or not isinstance(request, Mapping)
                    ):
                        raise RuntimeError("catalogue navigation Fetch event is malformed")
                    request_url = str(request.get("url", ""))
                    method_name = str(request.get("method", ""))
                    frame_id = event.get("frameId")
                    resource_type = event.get("resourceType")
                    is_primary_navigation = (
                        resource_type == "Document" and frame_id == root_frame_id
                    )
                    command = "Fetch.failRequest"
                    parameters: dict[str, Any] = {
                        "requestId": request_id,
                        "errorReason": "BlockedByClient",
                    }
                    if not _navigation_request_allowed(method_name, request_url, domain):
                        if is_primary_navigation:
                            rejected_document_urls.add(request_url)
                    else:
                        request_origin = origin(request_url)
                        if request_origin is None:
                            if is_primary_navigation:
                                rejected_document_urls.add(request_url)
                        elif request_origin not in navigation_pins:
                            # Preserve multi-origin page/worker behaviour: every
                            # in-boundary HTTPS GET origin, not merely a primary
                            # redirect, triggers a frozen-pin retry.
                            unpinned_document_origins.add(request_origin)
                        else:
                            observed_origins.add(request_origin)
                            current_page_origins.add(request_origin)
                            command = "Fetch.continueRequest"
                            parameters = {"requestId": request_id}
                    router.send(
                        source,
                        command,
                        parameters,
                        label=f"catalogue-navigation-policy:{command}",
                    )

                router = RecursiveCdpTargetRouter(
                    session,
                    on_event=protocol_event,
                    root_frame_id=root_frame_id,
                    root_continue_error_type=playwright_error,
                    track_root_srcdoc_lifecycle=True,
                    on_non_replayable_egress=lambda source, api, mechanism, request_url: (
                        egress_guard.record(
                            source=source,
                            api=api,
                            mechanism=mechanism,
                            url=request_url,
                        )
                    ),
                )
                router.start()
                browser_guard = BrowserSharedWorkerGuard(browser_session, router)
                browser_guard.start()
                graph_closed = False
                homepage_budget = remaining_timeout()
                if homepage_budget < 1:
                    raise RecoverableAcquisitionError(
                        "navigation exhausted its total timeout before homepage"
                    )
                current_page_origins.clear()
                rejected_document_urls.clear()
                try:
                    homepage_response = page.goto(
                        f"https://{domain}/", wait_until="load", timeout=homepage_budget
                    )
                except playwright_error as error:
                    egress_guard.raise_if_failed()
                    router.raise_if_failed()
                    if unowned_document_urls:
                        raise TerminalProbePolicyError(
                            "document navigation ownership could not be established"
                        ) from error
                    if unpinned_document_origins:
                        raise _NavigationPinExpansion(unpinned_document_origins) from error
                    if rejected_document_urls:
                        raise TerminalProbePolicyError(
                            "canonical homepage document navigation left the allowed HTTPS "
                            "candidate-domain boundary: "
                            + ", ".join(sorted(rejected_document_urls))
                        ) from error
                    raise
                egress_guard.raise_if_failed()
                router.raise_if_failed()
                if unpinned_document_origins:
                    raise _NavigationPinExpansion(unpinned_document_origins)
                if rejected_document_urls:
                    raise TerminalProbePolicyError(
                        "canonical homepage document navigation left the allowed HTTPS "
                        "candidate-domain boundary: " + ", ".join(sorted(rejected_document_urls))
                    )
                if unowned_document_urls:
                    raise TerminalProbePolicyError(
                        "document navigation ownership could not be established"
                    )
                if homepage_response is None:
                    raise RecoverableAcquisitionError(
                        "canonical homepage navigation returned no response"
                    )
                homepage_type = _normalise_content_type(
                    str(homepage_response.headers.get("content-type", ""))
                )
                if homepage_type not in HTML_MEDIA_TYPES or not _navigation_request_allowed(
                    "GET", page.url, domain
                ):
                    raise TerminalProbePolicyError(
                        "canonical homepage did not resolve to an in-boundary HTML document"
                    )
                if challenge := browser_challenge_reason(page):
                    raise TerminalProbePolicyError(challenge)
                egress_guard.raise_if_failed()
                page_observed_origins.append(
                    (f"https://{domain}/", tuple(sorted(current_page_origins)))
                )
                hrefs = tuple(
                    str(value)
                    for value in page.locator("a[href]").evaluate_all(
                        "elements => elements.map(element => element.href)"
                    )
                )
                egress_guard.raise_if_failed()
                router.raise_if_failed()
                provisional = select_page_candidates(
                    domain,
                    registrable_domain=registrable,
                    discovered_links=tuple(
                        DiscoveredLink(url=url, content_type="text/html") for url in hrefs
                    ),
                )[1:]
                for candidate_index, candidate in enumerate(provisional):
                    link_budget = remaining_timeout()
                    if link_budget < 1:
                        rejections.extend(
                            NavigationRejection(
                                url=remaining.url,
                                kind="navigation-time-budget-exhausted",
                                reason="total navigation timeout expired before optional link",
                            )
                            for remaining in provisional[candidate_index:]
                        )
                        break
                    try:
                        current_page_origins.clear()
                        rejected_document_urls.clear()
                        unowned_document_urls.clear()
                        response = page.goto(
                            candidate.url,
                            wait_until="domcontentloaded",
                            timeout=link_budget,
                        )
                    except playwright_error as error:
                        egress_guard.raise_if_failed()
                        router.raise_if_failed()
                        if unpinned_document_origins:
                            raise _NavigationPinExpansion(unpinned_document_origins) from error
                        if rejected_document_urls:
                            rejections.append(
                                NavigationRejection(
                                    url=candidate.url,
                                    kind="redirect-outside-candidate-boundary",
                                    reason=(
                                        "optional link document navigation left the allowed "
                                        "HTTPS candidate-domain boundary: "
                                        + ", ".join(sorted(rejected_document_urls))
                                    ),
                                )
                            )
                            continue
                        # Link verification is optional; an unreachable or slow
                        # secondary page must not invalidate a valid homepage.
                        rejections.append(
                            NavigationRejection(
                                url=candidate.url,
                                kind="playwright-navigation-failure",
                                reason=str(error),
                            )
                        )
                        continue
                    egress_guard.raise_if_failed()
                    router.raise_if_failed()
                    if unpinned_document_origins:
                        raise _NavigationPinExpansion(unpinned_document_origins)
                    if rejected_document_urls:
                        rejections.append(
                            NavigationRejection(
                                url=candidate.url,
                                kind="redirect-outside-candidate-boundary",
                                reason=(
                                    "optional link document navigation left the allowed HTTPS "
                                    "candidate-domain boundary: "
                                    + ", ".join(sorted(rejected_document_urls))
                                ),
                            )
                        )
                        continue
                    if response is None:
                        rejections.append(
                            NavigationRejection(
                                url=candidate.url,
                                kind="navigation-returned-no-response",
                                reason="optional link navigation returned no response",
                            )
                        )
                        continue
                    policy_rejection = _navigation_link_policy_rejection(
                        final_url=page.url,
                        content_type=str(response.headers.get("content-type", "")),
                        boundary=domain,
                    )
                    if policy_rejection is not None:
                        kind, reason = policy_rejection
                        rejections.append(
                            NavigationRejection(
                                url=candidate.url,
                                kind=kind,
                                reason=reason,
                            )
                        )
                        continue
                    verified_link = _verified_navigation_link(
                        candidate,
                        final_url=page.url,
                        content_type=str(response.headers.get("content-type", "")),
                        boundary=domain,
                    )
                    if verified_link is not None:
                        if challenge := browser_challenge_reason(page):
                            rejections.append(
                                NavigationRejection(
                                    url=candidate.url,
                                    kind="captcha-or-challenge",
                                    reason=challenge,
                                )
                            )
                            continue
                        verified.append(verified_link)
                        page_observed_origins.append(
                            (candidate.url, tuple(sorted(current_page_origins)))
                        )
                egress_guard.raise_if_failed()
                if len(context.service_workers):
                    raise TerminalProbePolicyError(
                        "catalogue navigation observed a browser service worker"
                    )
                while not router.shutdown_ready:
                    egress_guard.raise_if_failed()
                    router.raise_if_failed()
                    wait_budget = remaining_timeout()
                    if wait_budget < 1:
                        raise RecoverableAcquisitionError(
                            "navigation target instrumentation did not quiesce"
                        )
                    page.wait_for_timeout(min(25, wait_budget))
                router.begin_shutdown()
                browser_guard.begin_shutdown()
                context.close()
                browser_guard.finish()
                router.finish()
                graph_closed = True
                _require_unexceptional_navigation_completion(
                    router.root_invalid_interception_summary
                )
                validate_srcdoc_pseudo_document_summary(
                    router.srcdoc_pseudo_document_summary,
                    require_terminal=True,
                )
            except BaseException as error:
                graph_primary = error
                raise
            finally:
                if "graph_closed" in locals() and not graph_closed:
                    cleanup_primary = graph_primary or RuntimeError(
                        "catalogue navigation graph disposal"
                    )
                    _abort_rejected_render(context, router, browser_guard, cleanup_primary)
                try:
                    browser.close()
                except Exception as error:
                    if graph_primary is None:
                        graph_primary = error
                        raise
                    graph_primary.add_note(
                        "catalogue navigation cleanup browser-close failed with "
                        f"{type(error).__name__}"
                    )
                finally:
                    if "egress_guard" in locals():
                        # Retained egress evidence is a scientific policy
                        # failure and must outrank a retryable Playwright or
                        # navigation-expansion exception.
                        egress_guard.raise_if_failed()
                    if "router" in locals():
                        # Likewise, retained protocol-integrity evidence is
                        # never demoted to a cleanup note.
                        router.raise_if_failed()
    except _NavigationPinExpansion:
        raise
    except RecoverableAcquisitionError as error:
        if unpinned_document_origins:
            raise _NavigationPinExpansion(unpinned_document_origins) from error
        raise
    except playwright_error as error:
        if unpinned_document_origins:
            raise _NavigationPinExpansion(unpinned_document_origins) from error
        raise RecoverableAcquisitionError(f"Playwright navigation failed: {error}") from error
    if unpinned_document_origins:
        # Some browser versions return a response after a request-stage abort;
        # the next pass is still mandatory before accepting that navigation.
        raise _NavigationPinExpansion(unpinned_document_origins)
    if len(observed_origins) > MAX_APPROVED_ORIGINS:
        raise TerminalProbePolicyError("navigation discovery exceeded its finite origin cap")
    return NavigationDiscovery(
        registrable,
        tuple(verified),
        tuple(sorted(observed_origins)),
        tuple(rejections),
        tuple(page_observed_origins),
    )


def _require_unexceptional_navigation_completion(
    summary: Mapping[str, Any],
) -> None:
    """Discard any pass that needed exceptional root-Fetch race recovery."""

    total = summary.get("total")
    resolved = summary.get("resolved")
    pending = summary.get("pending")
    aborted = summary.get("aborted")
    terminal_outcomes = summary.get("terminal_outcomes")
    if (
        type(total) is not int
        or type(resolved) is not int
        or type(pending) is not int
        or type(aborted) is not int
        or min(total, resolved, pending, aborted) < 0
        or pending != 0
        or aborted != 0
        or resolved != total
        or type(terminal_outcomes) is not dict
        or set(terminal_outcomes) != {"Network.loadingFinished"}
        or type(terminal_outcomes["Network.loadingFinished"]) is not int
        or terminal_outcomes["Network.loadingFinished"] != resolved
    ):
        raise CdpTargetIntegrityError(
            "catalogue navigation root Fetch recovery summary is non-terminal"
        )
    if total:
        # The existing attempt ledger persists this bounded, identifier-free
        # reason. A later attempt may succeed, but an accepted navigation can
        # never silently depend on the Chromium interception race.
        raise RecoverableAcquisitionError(
            "catalogue navigation discarded after "
            f"{total} correlated root Fetch continuation race(s)"
        )


def initialise_runner(
    root: Path,
    *,
    candidate_catalogue_path: Path,
    foundation_attestation: Path | None = None,
    acquisition_authority: Path | None = None,
    started_at: str,
    browser_tool: str,
) -> Path:
    """Create the immutable provenance and initial resumable checkpoint."""

    # ``browser_tool`` remains an input for command-line compatibility only.
    # The foundation is deep-validated immediately below; evidence is derived
    # from the exact pinned driver identity and never from caller-authored text.
    del browser_tool
    catalogue, candidates = load_candidate_catalogue_receipt(candidate_catalogue_path)
    started = _timestamp(started_at)
    if (foundation_attestation is None) == (acquisition_authority is None):
        raise ValueError("supply exactly one acquisition authority or foundation attestation")
    authority = _acquisition_authority_binding(
        acquisition_authority if acquisition_authority is not None else foundation_attestation
    )
    destination = _new_directory(root)
    (destination / "terminals").mkdir()
    (destination / "document-response-receipts").mkdir()
    (destination / "prepared-probes").mkdir()
    fsync_directory(destination)
    durable_create(destination / ".class-study-acquisition.lock", b"")
    provenance = bind_receipt(
        {
            "study_id": "classifier-multiorigin100-v1",
            "acquisition_schema_version": SCHEMA_VERSION,
            "candidate_catalogue_sha256": sha256_file(candidate_catalogue_path),
            "candidate_catalogue_payload_sha256": catalogue["payload_sha256"],
            "candidate_count": len(candidates),
            "acquisition_authority": authority,
            "started_at": _format_time(started),
            "image_digest": os.environ.get("QCSD_LAB_IMAGE_DIGEST", "native"),
            "source": source_metadata(),
            "browser_tool": expected_browser_tool_identity(),
            "navigation_implementation": NAVIGATION_IMPLEMENTATION,
            "cdp_target_instrumentation_policy": CDP_TARGET_INSTRUMENTATION_POLICY,
            "non_replayable_egress_contract": NON_REPLAYABLE_EGRESS_CONTRACT,
            "passive_render_contract": PASSIVE_RENDER_CONTRACT,
            "passive_render_contract_sha256": PASSIVE_RENDER_CONTRACT_SHA256,
            "browser_navigation_timeout_ms": MAX_ACQUISITION_BACKEND_TIMEOUT_MS,
            "passive_render_hard_cap_after_load_ms": (MAX_PASSIVE_RENDER_AFTER_LOAD_MS),
            "acquisition_action_timing_contract": ACTION_TIMING_CONTRACT,
            "baseline_scheduling_contract": TERMINAL_RELEASE_BASELINE_SCHEDULING_CONTRACT,
            "acquisition_selection_policy": ACQUISITION_SELECTION_POLICY,
            "registrable_domain_policy": REGISTRABLE_DOMAIN_POLICY,
            "domain_safety_policy": DOMAIN_SAFETY_POLICY,
            "domain_safety_policy_sha256": sha256_bytes(canonical_json_bytes(DOMAIN_SAFETY_POLICY)),
            "origin_policy": ORIGIN_POLICY,
            "eligibility_inputs": ELIGIBILITY_INPUTS,
            "prohibited_inputs": PROHIBITED_INPUTS,
        },
        receipt_type=PROVENANCE_TYPE,
    )
    _create_json(destination / "provenance.json", provenance)
    checkpoint = _checkpoint(
        provenance_sha256=sha256_file(destination / "provenance.json"),
        catalogue_sha256=sha256_file(candidate_catalogue_path),
        baseline_batches=(),
        active_batch=None,
        candidates={
            candidate.candidate_id: {"state": "pending", "pages": [], "terminal": None}
            for candidate in candidates
        },
    )
    atomic_json(destination / "checkpoint.json", checkpoint)
    return destination


def run_due_acquisition(
    root: Path,
    *,
    candidate_catalogue_path: Path,
    stability_root: Path,
    workload_root: Path,
    backend: AcquisitionBackend,
    now: datetime | None = None,
    clock: Callable[[], datetime] | None = None,
    sleeper: Callable[[float], None] | None = None,
    max_candidates: int = MAX_CANDIDATES_PER_ACTION,
) -> dict[str, Any]:
    """Process one bounded, compatible batch and return current progress."""

    if type(max_candidates) is not int or not 1 <= max_candidates <= MAX_CANDIDATES_PER_ACTION:
        raise ValueError(f"max_candidates must be in [1, {MAX_CANDIDATES_PER_ACTION}]")
    if now is not None and clock is not None:
        raise ValueError("supply now or clock, not both")
    clock_function = clock or (lambda: datetime.now(UTC))
    initial_time = now or clock_function()
    if initial_time.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    last_clock = initial_time.astimezone(UTC)
    wait_function = sleeper
    if wait_function is None:
        wait_function = getattr(clock, "sleep", None) if clock is not None else None
    if wait_function is None:
        wait_function = time.sleep

    clock_lock = Lock()

    def read_clock() -> datetime:
        nonlocal last_clock
        with clock_lock:
            value = last_clock if now is not None else clock_function()
            if not isinstance(value, datetime) or value.tzinfo is None:
                raise ValueError("acquisition clock must return a timezone-aware datetime")
            value = value.astimezone(UTC)
            if value < last_clock:
                raise ValueError("acquisition clock moved backwards during a bounded action")
            last_clock = value
            return value

    def wait_until(target: datetime) -> datetime:
        nonlocal last_clock
        if target.tzinfo is None:
            raise ValueError("acquisition wait target must be timezone-aware")
        target = target.astimezone(UTC)
        if now is not None:
            if target > last_clock:
                last_clock = target
            return last_clock
        while True:
            current_clock = read_clock()
            remaining = (target - current_clock).total_seconds()
            if remaining <= 0:
                return current_clock
            wait_function(min(remaining, 1.0))

    runner = _regular_directory(root)
    provenance_path = runner / "provenance.json"
    provenance = load_json(provenance_path)
    provenance_payload = validate_hash_bound_receipt(provenance, expected_type=PROVENANCE_TYPE)
    if provenance_payload.get("acquisition_schema_version") != SCHEMA_VERSION:
        raise ValueError("historical acquisition runners are verification-only")
    _validate_runner_runtime(provenance_payload)
    _catalogue, candidates = load_candidate_catalogue_receipt(candidate_catalogue_path)
    if provenance_payload["candidate_catalogue_sha256"] != sha256_file(candidate_catalogue_path):
        raise ValueError("runner provenance is bound to another catalogue")
    checkpoint_path = runner / "checkpoint.json"
    checkpoint, persisted_terminal_recoveries = _load_checkpoint(
        checkpoint_path,
        provenance_path,
        candidate_catalogue_path,
        maximum_recovery_candidates=max_candidates,
    )
    if persisted_terminal_recoveries:
        # Publishing an immutable terminal and binding it into the mutable
        # checkpoint are one logical action.  A resume that finishes that
        # transaction must not also start unrelated network work.
        return acquisition_status(
            runner,
            candidate_catalogue_path=candidate_catalogue_path,
            now=read_clock(),
        )
    payload = checkpoint["payload"]
    states = payload["candidates"]
    baseline_batches = list(payload["baseline_batches"])
    active_batch = payload["active_batch"]

    def save_checkpoint() -> None:
        _save_acquisition_checkpoint(
            checkpoint_path,
            provenance_path=provenance_path,
            catalogue_path=candidate_catalogue_path,
            baseline_batches=baseline_batches,
            active_batch=active_batch,
            candidates=states,
        )

    def publish_active(value: Mapping[str, Any]) -> None:
        nonlocal active_batch
        active_batch = dict(value)
        save_checkpoint()

    def clear_active() -> None:
        nonlocal active_batch
        active_batch = None

    if active_batch is not None:
        _recover_active_batch(states, active_batch, recovered_at=read_clock())
        active_batch = None
        save_checkpoint()
        return acquisition_status(
            runner,
            candidate_catalogue_path=candidate_catalogue_path,
            now=read_clock(),
        )

    terminal_payloads = _checkpoint_terminal_payloads(runner, states)
    selection, selection_blocked = _derive_checkpoint_selection(
        candidates, _catalogue, states, terminal_payloads
    )
    admission_ids = set(selection["admission_ids"]) if not selection_blocked else set()
    reservations = _baseline_batch_reservations(baseline_batches, states, terminal_payloads)

    def classify(
        current_time: datetime,
    ) -> tuple[list[Any], list[Any], list[Any], list[Any], list[Any]]:
        finalisable_values: list[Any] = []
        due_values: list[tuple[Any, list[dict[str, Any]], str]] = []
        missed_values: list[Any] = []
        ready_values: list[Any] = []
        pending_values: list[Any] = []
        for candidate in candidates:
            state = states[candidate.candidate_id]
            if state["terminal"] is not None:
                continue
            if state["state"] == "probing":
                if _probe_candidate_is_finalisable(state):
                    finalisable_values.append(candidate)
                    continue
                try:
                    pages = _due_pages(
                        state,
                        current_time,
                        candidate_id=candidate.candidate_id,
                    )
                except MissedProbeWindow:
                    missed_values.append(candidate)
                else:
                    if pages:
                        probe_ids = {
                            STABILITY_PROBE_WINDOWS[len(page["observations"])].probe_id
                            for page in pages
                        }
                        if len(probe_ids) != 1:
                            raise ValueError("one candidate has incompatible due probe windows")
                        due_values.append((candidate, pages, probe_ids.pop()))
            elif state["state"] == "baseline-ready":
                ready_values.append(candidate)
            elif state["state"] == "pending" and (
                candidate.candidate_id in admission_ids or state.get("navigation_attempts")
            ):
                pending_values.append(candidate)
        return (
            finalisable_values,
            due_values,
            missed_values,
            ready_values,
            pending_values,
        )

    baseline_plan: tuple[tuple[Any, ...], datetime] | None = None
    scheduling_rechecks = 0
    while True:
        current = read_clock()
        finalisable, due, missed, ready, pending = classify(current)
        if due or finalisable or missed:
            break
        if ready and baseline_is_safe_with_releases(current, reservations):
            selected_ready = _select_compatible_batch(
                [
                    (candidate, len(states[candidate.candidate_id]["pages"]), "t+30s")
                    for candidate in ready
                ],
                maximum=max_candidates,
            )
            actual_baseline = read_clock()
            if not baseline_is_safe_with_releases(actual_baseline, reservations):
                scheduling_rechecks += 1
                if scheduling_rechecks > MAX_CANDIDATES_PER_ACTION:
                    raise ValueError("clock repeatedly crossed a baseline scheduling boundary")
                continue
            baseline_plan = (selected_ready, actual_baseline)
        break

    if due:
        selected = _select_compatible_batch(
            [(candidate, len(pages), probe_id) for candidate, pages, probe_id in due],
            maximum=max_candidates,
        )
        selected_ids = {candidate.candidate_id for candidate in selected}
        selected_due = {
            candidate.candidate_id: pages
            for candidate, pages, _probe_id in due
            if candidate.candidate_id in selected_ids
        }
        _run_probe_batch(
            selected,
            initial_pages=selected_due,
            runner=runner,
            provenance_path=provenance_path,
            provenance_payload=provenance_payload,
            candidate_catalogue_path=candidate_catalogue_path,
            stability_root=stability_root,
            workload_root=workload_root,
            backend=backend,
            states=states,
            baseline_batches=baseline_batches,
            read_clock=read_clock,
            publish=publish_active,
            clear=clear_active,
            save_checkpoint=save_checkpoint,
            missed_reason="recoverable probe retries exceeded the latest admissible window",
        )
    elif finalisable:
        for candidate in finalisable[:max_candidates]:
            state = states[candidate.candidate_id]
            _terminalise_completed_probe_candidate(
                candidate,
                state,
                runner=runner,
                provenance_path=provenance_path,
                candidate_catalogue_path=candidate_catalogue_path,
                stability_root=stability_root,
                workload_root=workload_root,
                terminalised_at=_finalisable_probe_terminal_time(state),
                baseline_batch=_baseline_batch_for_candidate(
                    baseline_batches,
                    candidate_id=candidate.candidate_id,
                ),
            )
            if state["terminal"] is None:
                raise AssertionError("finalisable probe candidate did not terminalise")
        save_checkpoint()
    elif missed:
        selected = tuple(missed[:max_candidates])
        for candidate in selected:
            state = states[candidate.candidate_id]
            _record_pending_probe_interruptions(state, recovered_at=current)
            _terminalise(
                runner,
                state,
                candidate.candidate_id,
                "probe-window-missed",
                "host resumed after the latest admissible probe window",
                provenance_path,
                terminalised_at=current,
                baseline_batch=_baseline_batch_for_candidate(
                    baseline_batches, candidate_id=candidate.candidate_id
                ),
            )
        save_checkpoint()
    elif baseline_plan is not None:
        selected, baseline = baseline_plan
        baseline_batch = _new_baseline_batch(
            selected,
            states=states,
            baseline_started_at=baseline,
        )
        baseline_batches.append(baseline_batch)
        for candidate in selected:
            state = states[candidate.candidate_id]
            state["state"] = "probing"
            state["baseline_started_at"] = _format_time(baseline)
        save_checkpoint()
        current = wait_until(
            baseline + timedelta(milliseconds=STABILITY_PROBE_WINDOWS[0].earliest_ms)
        )
        initial_pages: dict[str, list[dict[str, Any]]] = {}
        missed_after_wait: list[Any] = []
        for candidate in selected:
            try:
                initial_pages[candidate.candidate_id] = _due_pages(
                    states[candidate.candidate_id],
                    current,
                    candidate_id=candidate.candidate_id,
                )
            except MissedProbeWindow:
                missed_after_wait.append(candidate)
        if missed_after_wait:
            for candidate in missed_after_wait:
                _terminalise(
                    runner,
                    states[candidate.candidate_id],
                    candidate.candidate_id,
                    "probe-window-missed",
                    "bounded action passed the latest admissible probe window",
                    provenance_path,
                    terminalised_at=current,
                    baseline_batch=baseline_batch,
                )
            save_checkpoint()
        remaining = tuple(
            candidate
            for candidate in selected
            if candidate.candidate_id not in {value.candidate_id for value in missed_after_wait}
        )
        if remaining:
            _run_probe_batch(
                remaining,
                initial_pages=initial_pages,
                runner=runner,
                provenance_path=provenance_path,
                provenance_payload=provenance_payload,
                candidate_catalogue_path=candidate_catalogue_path,
                stability_root=stability_root,
                workload_root=workload_root,
                backend=backend,
                states=states,
                baseline_batches=baseline_batches,
                read_clock=read_clock,
                publish=publish_active,
                clear=clear_active,
                save_checkpoint=save_checkpoint,
                missed_reason=("recoverable probe retries exceeded the latest admissible window"),
            )
    elif pending and not _pending_navigation_blocked(states, current):
        selected = _select_compatible_batch(
            [(candidate, 1, "navigation") for candidate in pending],
            maximum=max_candidates,
        )
        _run_navigation_batch(
            selected,
            runner=runner,
            provenance_path=provenance_path,
            backend=backend,
            states=states,
            read_clock=read_clock,
            publish=publish_active,
            clear=clear_active,
            save_checkpoint=save_checkpoint,
        )
    else:
        save_checkpoint()

    return acquisition_status(
        runner,
        candidate_catalogue_path=candidate_catalogue_path,
        now=read_clock(),
    )


def _select_compatible_batch(
    options: Sequence[tuple[Any, int, str]],
    *,
    maximum: int,
) -> tuple[Any, ...]:
    """Select an anchor and its first compatible catalogue-order partner."""

    if not options or type(maximum) is not int or not 1 <= maximum <= MAX_CANDIDATES_PER_ACTION:
        raise ValueError("candidate batch selection inputs are invalid")
    anchor, anchor_pages, anchor_key = options[0]
    if (
        type(anchor_pages) is not int
        or not 1 <= anchor_pages <= GLOBAL_LIVE_PAGE_CAP
        or not isinstance(anchor_key, str)
        or not anchor_key
    ):
        raise ValueError("candidate batch option is invalid")
    if maximum == 1:
        return (anchor,)
    for partner, partner_pages, partner_key in options[1:]:
        if (
            type(partner_pages) is not int
            or not 1 <= partner_pages <= GLOBAL_LIVE_PAGE_CAP
            or not isinstance(partner_key, str)
            or not partner_key
        ):
            raise ValueError("candidate batch option is invalid")
        if partner_key == anchor_key and anchor_pages + partner_pages <= GLOBAL_LIVE_PAGE_CAP:
            return anchor, partner
    return (anchor,)


def _batch_identifier(prefix: str, payload: Mapping[str, Any]) -> str:
    if prefix not in {"active", "baseline"}:
        raise ValueError("acquisition batch prefix is invalid")
    return f"{prefix}-{sha256_bytes(canonical_json_bytes(payload))}"


def _new_baseline_batch(
    candidates: Sequence[Any],
    *,
    states: Mapping[str, Any],
    baseline_started_at: datetime,
) -> dict[str, Any]:
    candidate_ids = [candidate.candidate_id for candidate in candidates]
    live_page_count = sum(len(states[candidate_id]["pages"]) for candidate_id in candidate_ids)
    if (
        not 1 <= len(candidate_ids) <= MAX_CANDIDATES_PER_ACTION
        or len(candidate_ids) != len(set(candidate_ids))
        or not 1 <= live_page_count <= GLOBAL_LIVE_PAGE_CAP
    ):
        raise ValueError("baseline acquisition batch inputs are invalid")
    body = {
        "baseline_started_at": _format_time(baseline_started_at),
        "candidate_ids": candidate_ids,
        "live_page_count": live_page_count,
    }
    return {"batch_id": _batch_identifier("baseline", body), **body}


def _new_active_batch(
    stage: str,
    *,
    published_at: datetime,
    attempts: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    if stage not in {"navigation", "probe"} or not attempts:
        raise ValueError("active acquisition batch inputs are invalid")
    values = [dict(attempt) for attempt in attempts]
    candidate_ids = list(dict.fromkeys(item["candidate_id"] for item in values))
    if (
        not 1 <= len(candidate_ids) <= MAX_CANDIDATES_PER_ACTION
        or not 1 <= len(values) <= GLOBAL_LIVE_PAGE_CAP
        or any(item.get("started_at") != _format_time(published_at) for item in values)
    ):
        raise ValueError("active acquisition batch inputs are invalid")
    body = {
        "active_batch_schema_version": ACTIVE_BATCH_SCHEMA_VERSION,
        "stage": stage,
        "published_at": _format_time(published_at),
        "candidate_ids": candidate_ids,
        "live_page_count": len(values),
        "attempts": values,
    }
    return {"batch_id": _batch_identifier("active", body), **body}


def _run_navigation_batch(
    candidates: Sequence[Any],
    *,
    runner: Path,
    provenance_path: Path,
    backend: AcquisitionBackend,
    states: Mapping[str, dict[str, Any]],
    read_clock: Callable[[], datetime],
    publish: Callable[[Mapping[str, Any]], None],
    clear: Callable[[], None],
    save_checkpoint: Callable[[], None],
) -> None:
    """Run at most two navigation attempts and merge only in catalogue order."""

    unresolved = list(candidates)
    while unresolved:
        runnable: list[Any] = []
        for candidate in unresolved:
            attempts = states[candidate.candidate_id].setdefault("navigation_attempts", [])
            if len(attempts) >= MAX_PROBE_ATTEMPTS:
                continue
            if not attempts or attempts[-1]["outcome"] in {
                "recoverable-failure",
                "interrupted",
            }:
                runnable.append(candidate)
        if not runnable:
            break
        published_at = read_clock()
        active_attempts: list[dict[str, Any]] = []
        for candidate in runnable:
            state = states[candidate.candidate_id]
            attempt = len(state["navigation_attempts"]) + 1
            started_at = _format_time(published_at)
            state["pending_navigation"] = {
                "attempt": attempt,
                "started_at": started_at,
            }
            active_attempts.append(
                {
                    "candidate_id": candidate.candidate_id,
                    "page_ordinal": None,
                    "probe_id": None,
                    "workload_id": None,
                    "attempt": attempt,
                    "started_at": started_at,
                }
            )
        publish(
            _new_active_batch(
                "navigation",
                published_at=published_at,
                attempts=active_attempts,
            )
        )

        def acquire(candidate: Any) -> dict[str, Any]:
            try:
                navigation = backend.discover_navigation(candidate.domain)
                pages = select_page_candidates(
                    candidate.domain,
                    registrable_domain=navigation.registrable_domain,
                    discovered_links=navigation.links,
                )
                origins_by_page = _navigation_origins_by_page(navigation, pages)
            except TerminalAcquisitionPolicyError as error:
                policy_evidence = (
                    validate_non_replayable_egress_failure_evidence(error.evidence)
                    if error.evidence is not None
                    else None
                )
                result: dict[str, Any] = {
                    "outcome": "terminal-policy-rejection",
                    "reason": str(error),
                    "policy_evidence": policy_evidence,
                }
            except RecoverableAcquisitionError as error:
                result = {
                    "outcome": "recoverable-failure",
                    "reason": str(error),
                    "policy_evidence": None,
                }
            except Exception as error:  # noqa: BLE001 - coordinator records every result
                result = {
                    "outcome": "internal-acquisition-error",
                    "reason": _exception_reason(error),
                    "policy_evidence": None,
                    "internal_exception": error,
                }
            else:
                result = {
                    "outcome": "completed",
                    "reason": None,
                    "policy_evidence": None,
                    "navigation": navigation,
                    "pages": pages,
                    "origins_by_page": origins_by_page,
                }
            result["completed_at"] = _format_time(read_clock())
            return result

        with ThreadPoolExecutor(max_workers=len(runnable)) as executor:
            outcomes = tuple(executor.map(acquire, runnable))

        internal_failures: list[tuple[Any, BaseException]] = []
        next_unresolved: list[Any] = []
        for candidate, outcome in zip(runnable, outcomes, strict=True):
            state = states[candidate.candidate_id]
            pending_attempt = state.pop("pending_navigation")
            state["navigation_attempts"].append(
                {
                    **pending_attempt,
                    "completed_at": outcome["completed_at"],
                    "outcome": outcome["outcome"],
                    "reason": outcome["reason"],
                    "policy_evidence": outcome["policy_evidence"],
                }
            )
            if outcome["outcome"] == "completed":
                navigation = outcome["navigation"]
                pages = outcome["pages"]
                origins_by_page = outcome["origins_by_page"]
                state.update(
                    {
                        "state": "baseline-ready",
                        "pages": [
                            {
                                "page": page.as_dict(),
                                "observations": [],
                                "probe_attempts": [],
                                "approved_origins": [],
                                "navigation_observed_origins": list(origins_by_page[page.url]),
                            }
                            for page in pages
                        ],
                        "navigation_observed_origins": list(navigation.observed_origins),
                        "navigation_rejections": [
                            rejection.as_dict() for rejection in navigation.rejections
                        ],
                    }
                )
            elif outcome["outcome"] == "recoverable-failure":
                next_unresolved.append(candidate)
            elif outcome["outcome"] == "internal-acquisition-error":
                error = outcome.get("internal_exception")
                if not isinstance(error, BaseException):
                    raise AssertionError("internal acquisition result lost its exception")
                state["internal_acquisition_error"] = _internal_error_record(
                    stage="navigation",
                    attempt=pending_attempt["attempt"],
                    recorded_at=_timestamp(outcome["completed_at"]),
                    error=error,
                    reason=outcome["reason"],
                )
                internal_failures.append((candidate, error))
        clear()
        save_checkpoint()
        if internal_failures:
            first_candidate, first_error = internal_failures[0]
            raise InternalAcquisitionError(
                "acquisition stopped after durable internal navigation failure for "
                f"{first_candidate.candidate_id}: {_exception_reason(first_error)}"
            ) from first_error
        unresolved = next_unresolved

    # The outcome checkpoint above is the recoverable pre-terminal state.
    for candidate in candidates:
        state = states[candidate.candidate_id]
        if state["state"] != "pending":
            continue
        attempts = state.get("navigation_attempts", [])
        if not attempts:
            raise AssertionError("navigation batch made no durable progress")
        final = attempts[-1]
        if final["outcome"] == "terminal-policy-rejection":
            reason = final["reason"]
        elif len(attempts) == MAX_PROBE_ATTEMPTS and final["outcome"] in {
            "interrupted",
            "recoverable-failure",
        }:
            reason = (
                f"recoverable navigation failures exhausted {MAX_PROBE_ATTEMPTS} "
                f"attempts: {final['reason']}"
            )
        else:
            raise AssertionError("navigation batch stopped before a terminal outcome")
        _terminalise(
            runner,
            state,
            candidate.candidate_id,
            "pre-probe-rejection",
            reason,
            provenance_path,
            terminalised_at=_timestamp(final["completed_at"]),
            baseline_batch=None,
        )
    save_checkpoint()


def _run_probe_batch(
    candidates: Sequence[Any],
    *,
    initial_pages: Mapping[str, Sequence[dict[str, Any]]],
    runner: Path,
    provenance_path: Path,
    provenance_payload: Mapping[str, Any],
    candidate_catalogue_path: Path,
    stability_root: Path,
    workload_root: Path,
    backend: AcquisitionBackend,
    states: Mapping[str, dict[str, Any]],
    baseline_batches: Sequence[Mapping[str, Any]],
    read_clock: Callable[[], datetime],
    publish: Callable[[Mapping[str, Any]], None],
    clear: Callable[[], None],
    save_checkpoint: Callable[[], None],
    missed_reason: str,
) -> None:
    """Run a deterministic, globally capped page batch and merge its results."""

    retries = {
        candidate.candidate_id: list(initial_pages[candidate.candidate_id])
        for candidate in candidates
    }
    missed: set[str] = set()
    missed_before_launch: set[str] = set()
    terminal_clocks = {candidate.candidate_id: read_clock() for candidate in candidates}
    while any(retries.values()):
        published_at = read_clock()
        jobs: list[dict[str, Any]] = []
        for candidate in candidates:
            candidate_id = candidate.candidate_id
            state = states[candidate_id]
            if not retries[candidate_id]:
                continue
            try:
                actual_due_pages = _due_pages(
                    state,
                    published_at,
                    candidate_id=candidate_id,
                )
            except MissedProbeWindow:
                missed.add(candidate_id)
                missed_before_launch.add(candidate_id)
                terminal_clocks[candidate_id] = max(
                    terminal_clocks[candidate_id],
                    published_at,
                )
                retries[candidate_id] = []
                continue
            expected_ordinals = [page["page"]["ordinal"] for page in retries[candidate_id]]
            actual_ordinals = [page["page"]["ordinal"] for page in actual_due_pages]
            if actual_ordinals != expected_ordinals:
                raise ValueError("probe due set changed before active-batch publication")
            for page_state in retries[candidate_id]:
                probe_index = len(page_state["observations"])
                probe_id = STABILITY_PROBE_WINDOWS[probe_index].probe_id
                attempts = [
                    item
                    for item in page_state.setdefault("probe_attempts", [])
                    if item.get("probe_id") == probe_id
                ]
                attempt = len(attempts) + 1
                if attempt > MAX_PROBE_ATTEMPTS:
                    page_state["rejection"] = {
                        "kind": "probe-retry-exhausted",
                        "reason": (
                            f"recoverable acquisition failures exhausted "
                            f"{MAX_PROBE_ATTEMPTS} attempts"
                        ),
                    }
                    continue
                observed_at = _format_time(published_at)
                workload_id = _probe_attempt_workload_id(
                    candidate_id,
                    page_state["page"]["ordinal"],
                    probe_id,
                    attempt,
                )
                page_state["pending_probe"] = {
                    "probe_id": probe_id,
                    "workload_id": workload_id,
                    "attempt": attempt,
                    "observed_at": observed_at,
                }
                jobs.append(
                    {
                        "candidate_id": candidate_id,
                        "page_ordinal": page_state["page"]["ordinal"],
                        "probe_id": probe_id,
                        "workload_id": workload_id,
                        "attempt": attempt,
                        "started_at": observed_at,
                        "page": dict(page_state["page"]),
                        "navigation_observed_origins": tuple(
                            page_state["navigation_observed_origins"]
                        ),
                        "baseline_started_at": state["baseline_started_at"],
                    }
                )
        if not jobs:
            break
        if len(jobs) > GLOBAL_LIVE_PAGE_CAP:
            raise AssertionError("acquisition page batch exceeds its global cap")
        if len({job["probe_id"] for job in jobs}) != 1:
            raise AssertionError("acquisition page batch mixes probe windows")
        publish(
            _new_active_batch(
                "probe",
                published_at=published_at,
                attempts=[
                    {
                        key: job[key]
                        for key in (
                            "candidate_id",
                            "page_ordinal",
                            "probe_id",
                            "workload_id",
                            "attempt",
                            "started_at",
                        )
                    }
                    for job in jobs
                ],
            )
        )

        def acquire(job: Mapping[str, Any]) -> dict[str, Any]:
            page = PageCandidate(**job["page"])
            probe_started = _timestamp(job["started_at"])
            try:
                approved, discovery = _converge_origins(
                    backend,
                    page.url,
                    seed_origins=job["navigation_observed_origins"],
                )
                prepared = backend.prepare(
                    job["workload_id"],
                    page.url,
                    approved,
                    runner / "prepared-probes",
                    origin_ip_pins=discovery.origin_ip_pins,
                )
                elapsed = round(
                    (probe_started - _timestamp(job["baseline_started_at"])).total_seconds() * 1000
                )
                document_response_receipt = _create_document_response_receipt(
                    runner,
                    workload_id=job["workload_id"],
                    requested_url=page.url,
                    approved_origins=approved,
                    origin_ip_pins=discovery.origin_ip_pins,
                    probe_started_at=job["started_at"],
                    prepared=prepared,
                    runner_provenance_sha256=sha256_file(provenance_path),
                    runner_provenance=provenance_payload,
                )
                observation = StabilityObservation(
                    probe_id=job["probe_id"],
                    observed_at=job["started_at"],
                    elapsed_ms=elapsed,
                    final_url=prepared.final_url,
                    status=prepared.status,
                    content_type=prepared.content_type,
                    body_bytes=prepared.body_bytes,
                    body_sha256=prepared.body_sha256,
                    resource_graph_sha256=prepared.resource_graph_sha256,
                    prepared_workload_sha256=prepared.prepared.sha256,
                    passive_render_contract_sha256=(prepared.passive_render_contract_sha256),
                    render_observation_sha256=prepared.render_observation_sha256,
                    discovery_event_audit_sha256=(prepared.discovery_event_audit_sha256),
                    document_response_receipt_path=document_response_receipt["path"],
                    document_response_receipt_sha256=document_response_receipt["sha256"],
                )
                result: dict[str, Any] = {
                    "outcome": "completed",
                    "reason": None,
                    "policy_evidence": None,
                    "approved_origins": approved,
                    "observation": {
                        **observation.as_dict(),
                        "runner_provenance_sha256": sha256_file(provenance_path),
                        "approved_origins": approved,
                        "discovery_observed_origins": discovery.observed_origins,
                        "discovery_expandable_origins": discovery.expandable_origins,
                        "discovery_origin_ip_pins": discovery.origin_ip_pins,
                        "preparation_origin_ip_pins": dict(
                            prepared.preparation_origin_ip_pins or discovery.origin_ip_pins
                        ),
                        "discovery_instrumentation_policy": (discovery.instrumentation_policy),
                        "passive_render_contract_sha256": (prepared.passive_render_contract_sha256),
                        "render_observation": dict(prepared.render_observation or {}),
                        "render_observation_sha256": (prepared.render_observation_sha256),
                        "discovery_event_audit_sha256": (prepared.discovery_event_audit_sha256),
                        "chromium_version": prepared.chromium_version,
                        "neqo_provenance": dict(prepared.neqo_provenance),
                        "prepared_path": str(prepared.prepared.path.resolve()),
                        "probe_completed_at": prepared.observed_at,
                    },
                }
            except TerminalAcquisitionPolicyError as error:
                result = {
                    "outcome": "terminal-policy-rejection",
                    "reason": str(error),
                    "policy_evidence": (
                        _validated_terminal_policy_evidence(
                            error.evidence,
                            allow_non_replayable_egress=True,
                            acquisition_schema_version=SCHEMA_VERSION,
                        )
                        if error.evidence is not None
                        else None
                    ),
                }
            except RecoverableAcquisitionError as error:
                result = {
                    "outcome": "recoverable-failure",
                    "reason": str(error),
                    "policy_evidence": None,
                }
            except Exception as error:  # noqa: BLE001 - coordinator records every result
                result = {
                    "outcome": "internal-acquisition-error",
                    "reason": _exception_reason(error),
                    "policy_evidence": None,
                    "internal_exception": error,
                }
            result["completed_at"] = _format_time(read_clock())
            return result

        with ThreadPoolExecutor(max_workers=len(jobs)) as executor:
            outcomes = tuple(executor.map(acquire, jobs))

        next_retries = {candidate.candidate_id: [] for candidate in candidates}
        internal_failures: list[tuple[Any, dict[str, Any], BaseException]] = []
        candidate_by_id = {candidate.candidate_id: candidate for candidate in candidates}
        for job, outcome in zip(jobs, outcomes, strict=True):
            candidate_id = job["candidate_id"]
            state = states[candidate_id]
            page_state = next(
                page for page in state["pages"] if page["page"]["ordinal"] == job["page_ordinal"]
            )
            pending_attempt = page_state.pop("pending_probe")
            if (
                pending_attempt["workload_id"] != job["workload_id"]
                or pending_attempt["attempt"] != job["attempt"]
            ):
                raise AssertionError("probe worker identity changed before merge")
            attempt_record = {
                **pending_attempt,
                "completed_at": outcome["completed_at"],
                "outcome": outcome["outcome"],
                "reason": outcome["reason"],
                "policy_evidence": outcome.get("policy_evidence"),
            }
            if outcome["outcome"] == "completed":
                page_state["approved_origins"] = outcome["approved_origins"]
                page_state["observations"].append(outcome["observation"])
            elif outcome["outcome"] == "terminal-policy-rejection":
                page_state["rejection"] = {
                    "kind": "probe-policy-rejection",
                    "reason": outcome["reason"],
                }
            elif outcome["outcome"] == "recoverable-failure":
                if pending_attempt["attempt"] >= MAX_PROBE_ATTEMPTS:
                    page_state["rejection"] = {
                        "kind": "probe-retry-exhausted",
                        "reason": (
                            f"recoverable acquisition failures exhausted "
                            f"{MAX_PROBE_ATTEMPTS} attempts: {outcome['reason']}"
                        ),
                    }
                else:
                    next_retries[candidate_id].append(page_state)
            elif outcome["outcome"] == "internal-acquisition-error":
                error = outcome.get("internal_exception")
                if not isinstance(error, BaseException):
                    raise AssertionError("internal acquisition result lost its exception")
                internal_failures.append((candidate_by_id[candidate_id], page_state, error))
            page_state["probe_attempts"].append(attempt_record)
            terminal_clocks[candidate_id] = max(
                terminal_clocks[candidate_id],
                _timestamp(outcome["completed_at"]),
            )

        for candidate in candidates:
            candidate_failures = [value for value in internal_failures if value[0] is candidate]
            if not candidate_failures:
                continue
            _failed_candidate, failed_page, failed_error = candidate_failures[0]
            failed_attempt = failed_page["probe_attempts"][-1]
            states[candidate.candidate_id]["internal_acquisition_error"] = _internal_error_record(
                stage="probe",
                attempt=failed_attempt["attempt"],
                recorded_at=_timestamp(failed_attempt["completed_at"]),
                error=failed_error,
                reason=failed_attempt["reason"],
                page_ordinal=failed_page["page"]["ordinal"],
                probe_id=failed_attempt["probe_id"],
            )
        clear()
        save_checkpoint()
        if internal_failures:
            first_candidate, _first_page, first_error = internal_failures[0]
            raise InternalAcquisitionError(
                "acquisition stopped after durable internal probe failure for "
                f"{first_candidate.candidate_id}: {_exception_reason(first_error)}"
            ) from first_error

        retry_clock = read_clock()
        for candidate in candidates:
            candidate_id = candidate.candidate_id
            if not next_retries[candidate_id]:
                continue
            terminal_clocks[candidate_id] = max(terminal_clocks[candidate_id], retry_clock)
            try:
                _due_pages(states[candidate_id], retry_clock, candidate_id=candidate_id)
            except MissedProbeWindow:
                missed.add(candidate_id)
                next_retries[candidate_id] = []
        retries = next_retries

    # Rejection fields created without a worker are durable before terminals.
    save_checkpoint()
    for candidate in candidates:
        candidate_id = candidate.candidate_id
        state = states[candidate_id]
        baseline_batch = _baseline_batch_for_candidate(baseline_batches, candidate_id=candidate_id)
        if candidate_id in missed:
            _terminalise(
                runner,
                state,
                candidate_id,
                "probe-window-missed",
                (
                    "bounded action passed the latest admissible probe window"
                    if candidate_id in missed_before_launch
                    else missed_reason
                ),
                provenance_path,
                terminalised_at=terminal_clocks[candidate_id],
                baseline_batch=baseline_batch,
            )
        else:
            _terminalise_completed_probe_candidate(
                candidate,
                state,
                runner=runner,
                provenance_path=provenance_path,
                candidate_catalogue_path=candidate_catalogue_path,
                stability_root=stability_root,
                workload_root=workload_root,
                terminalised_at=terminal_clocks[candidate_id],
                baseline_batch=baseline_batch,
            )
    save_checkpoint()


def _terminalise_completed_probe_candidate(
    candidate: Any,
    state: dict[str, Any],
    *,
    runner: Path,
    provenance_path: Path,
    candidate_catalogue_path: Path,
    stability_root: Path,
    workload_root: Path,
    terminalised_at: datetime,
    baseline_batch: Mapping[str, Any],
) -> None:
    if not all(
        page.get("rejection") is not None
        or len(page["observations"]) == len(STABILITY_PROBE_WINDOWS)
        for page in state["pages"]
    ):
        return
    _validate_candidate_observation_provenance(
        runner,
        provenance_path=provenance_path,
        candidate_id=candidate.candidate_id,
        state=state,
    )
    stable_receipts: list[Path] = []
    for page_state in state["pages"]:
        if page_state.get("rejection") is not None:
            continue
        page = PageCandidate(**page_state["page"])
        observations = tuple(
            StabilityObservation(
                **{key: item.get(key) for key in StabilityObservation.__dataclass_fields__}
            )
            for item in page_state["observations"]
        )
        from .class_pipeline import admit_stability_observations

        stability_destination = (
            stability_root / candidate.candidate_id / f"page-{page.ordinal:02d}.json"
        )
        _discard_owned_publication_temps(
            stability_destination,
            style="create-only-json",
        )
        receipt = admit_stability_observations(
            candidate_catalogue_path,
            stability_root,
            candidate_id=candidate.candidate_id,
            page=page,
            baseline_started_at=state["baseline_started_at"],
            observations=observations,
        )
        from .class_catalogue import load_stability_receipt

        _value, decision = load_stability_receipt(receipt)
        if decision.eligible:
            stable_receipts.append(receipt)
    if stable_receipts:
        selected = stable_receipts[0]
        selected_ordinal = int(selected.stem.removeprefix("page-"))
        selected_page = next(
            page for page in state["pages"] if page["page"]["ordinal"] == selected_ordinal
        )
        admitted_workload = workload_root / f"{candidate.candidate_id}.json"
        _publish_admitted_workload(
            Path(selected_page["observations"][0]["prepared_path"]),
            admitted_workload,
            selected_page["observations"][0]["prepared_workload_sha256"],
        )
        _terminalise(
            runner,
            state,
            candidate.candidate_id,
            "eligible",
            None,
            provenance_path,
            terminalised_at=terminalised_at,
            stability_receipt=selected,
            admitted_workload=admitted_workload,
            baseline_batch=baseline_batch,
        )
    else:
        _terminalise(
            runner,
            state,
            candidate.candidate_id,
            "stable-page-unavailable",
            "no page passed all stability gates",
            provenance_path,
            terminalised_at=terminalised_at,
            baseline_batch=baseline_batch,
        )


def _probe_candidate_is_finalisable(state: Mapping[str, Any]) -> bool:
    """Whether a probing checkpoint needs only deterministic publication."""

    pages = state.get("pages")
    return bool(
        state.get("state") == "probing"
        and state.get("terminal") is None
        and isinstance(pages, list)
        and pages
        and all(
            isinstance(page, Mapping)
            and "pending_probe" not in page
            and (
                page.get("rejection") is not None
                or (
                    isinstance(page.get("observations"), list)
                    and len(page["observations"]) == len(STABILITY_PROBE_WINDOWS)
                )
            )
            for page in pages
        )
    )


def _finalisable_probe_terminal_time(state: Mapping[str, Any]) -> datetime:
    """Recover the original final worker completion, never the resume time."""

    if not _probe_candidate_is_finalisable(state):
        raise ValueError("probe candidate is not ready for deterministic finalisation")
    completed = [
        _timestamp(attempt["completed_at"])
        for page in state["pages"]
        for attempt in page.get("probe_attempts", [])
        if isinstance(attempt, Mapping) and isinstance(attempt.get("completed_at"), str)
    ]
    if not completed:
        raise ValueError("finalisable probe candidate has no completed probe attempt")
    return max(completed)


def _scientific_terminal_eligibility(
    terminal: Mapping[str, Any], state: Mapping[str, Any]
) -> bool | None:
    """Project authenticated science outcomes; infrastructure is unresolved."""

    if terminal["kind"] == "probe-window-missed" or any(
        page.get("rejection", {}).get("kind") == "probe-retry-exhausted"
        for page in state.get("pages", [])
        if isinstance(page.get("rejection"), Mapping)
    ):
        return None
    if terminal["kind"] == "pre-probe-rejection":
        attempts = state.get("navigation_attempts", [])
        if not attempts or attempts[-1]["outcome"] != "terminal-policy-rejection":
            return None
    return terminal["kind"] == "eligible"


def _checkpoint_terminal_payloads(
    runner: Path, states: Mapping[str, Any]
) -> dict[str, dict[str, Any]]:
    """Read terminal projections only after the caller deeply validated checkpoint state."""

    terminals = {}
    for candidate_id, state in states.items():
        binding = state.get("terminal")
        if binding is None:
            continue
        path = runner / binding["path"]
        if path.is_symlink() or not path.is_file() or sha256_file(path) != binding["sha256"]:
            raise ValueError("acquisition terminal projection binding changed")
        envelope = load_json(path)
        if path.read_bytes() != canonical_json_bytes(envelope):
            raise ValueError("acquisition terminal projection is not canonical")
        terminal = validate_hash_bound_receipt(envelope, expected_type=TERMINAL_TYPE)
        if terminal["candidate_id"] != candidate_id:
            raise ValueError("acquisition terminal projection identity changed")
        terminals[candidate_id] = terminal
    return terminals


def _derive_checkpoint_selection(
    candidates: Sequence[Any],
    catalogue: Mapping[str, Any],
    states: Mapping[str, Any],
    terminal_payloads: Mapping[str, Mapping[str, Any]],
) -> tuple[dict[str, Any], list[str]]:
    outcomes = {
        candidate_id: _scientific_terminal_eligibility(terminal, states[candidate_id])
        for candidate_id, terminal in terminal_payloads.items()
    }
    selection = derive_acquisition_selection(
        candidates,
        tranco_list_sha256=catalogue["payload"]["tranco"]["list_sha256"],
        terminal_eligibility={
            candidate_id: outcome
            for candidate_id, outcome in outcomes.items()
            if outcome is not None
        },
    )
    blocked = [
        candidate_id
        for candidate_id in selection["candidate_ids"]
        if candidate_id in outcomes and outcomes[candidate_id] is None
    ]
    return selection, blocked


def _baseline_batch_reservations(
    batches: Sequence[Mapping[str, Any]],
    states: Mapping[str, Any],
    terminal_payloads: Mapping[str, Mapping[str, Any]],
) -> tuple[BaselineReservation, ...]:
    if not isinstance(batches, (list, tuple)):
        raise ValueError("acquisition baseline-batch ledger is malformed")
    reservations = []
    for batch in batches:
        if not isinstance(batch, Mapping) or not isinstance(batch.get("baseline_started_at"), str):
            raise ValueError("acquisition baseline-batch ledger is malformed")
        members = batch["candidate_ids"]
        if (
            not isinstance(members, list)
            or not members
            or any(
                not isinstance(candidate_id, str) or candidate_id not in states
                for candidate_id in members
            )
        ):
            raise ValueError("acquisition baseline-batch ledger is malformed")
        resolved = all(
            candidate_id in terminal_payloads
            and _scientific_terminal_eligibility(
                terminal_payloads[candidate_id], states[candidate_id]
            )
            is not None
            for candidate_id in members
        )
        terminalised = (
            max(
                _timestamp(terminal_payloads[candidate_id]["terminalised_at"])
                for candidate_id in members
            )
            if resolved
            else None
        )
        reservations.append(
            BaselineReservation(_timestamp(batch["baseline_started_at"]), terminalised)
        )
    return tuple(reservations)


def acquisition_status(
    root: Path,
    *,
    candidate_catalogue_path: Path,
    now: datetime | None = None,
) -> dict[str, Any]:
    current = now or datetime.now(UTC)
    if current.tzinfo is None:
        raise ValueError("status time must be timezone-aware")
    current = current.astimezone(UTC)
    checkpoint, recovery_required, _orphan_candidate_ids = _load_checkpoint_state(
        Path(root) / "checkpoint.json",
        Path(root) / "provenance.json",
        candidate_catalogue_path,
        persist_recoveries=False,
    )
    payload = checkpoint["payload"]
    states = payload["candidates"]
    provenance = validate_hash_bound_receipt(
        load_json(Path(root) / "provenance.json"), expected_type=PROVENANCE_TYPE
    )
    acquisition_schema_version = provenance["acquisition_schema_version"]
    selection = None
    selection_blocked: list[str] = []
    reservations = None
    scheduling_states = states
    if acquisition_schema_version in _SELECTION_SCHEMA_VERSIONS:
        catalogue, candidates = load_candidate_catalogue_receipt(candidate_catalogue_path)
        terminal_payloads = _checkpoint_terminal_payloads(Path(root), states)
        selection, selection_blocked = _derive_checkpoint_selection(
            candidates, catalogue, states, terminal_payloads
        )
        admission_ids = set(selection["admission_ids"]) if not selection_blocked else set()
        scheduling_states = {
            candidate_id: state
            for candidate_id, state in states.items()
            if state["state"] != "pending"
            or candidate_id in admission_ids
            or state.get("navigation_attempts")
        }
        reservations = _baseline_batch_reservations(
            payload["baseline_batches"], states, terminal_payloads
        )
    baseline_starts = (
        _baseline_batch_starts(payload["baseline_batches"])
        if acquisition_schema_version in _MODERN_CHECKPOINT_SCHEMA_VERSIONS
        else _checkpoint_baselines(states)
    )
    active = payload.get("active_batch")
    active_summary = (
        {
            "batch_id": active["batch_id"],
            "stage": active["stage"],
            "published_at": active["published_at"],
            "candidate_ids": list(active["candidate_ids"]),
            "live_page_count": active["live_page_count"],
            "attempt_count": len(active["attempts"]),
        }
        if isinstance(active, Mapping)
        else None
    )
    next_due: datetime | None = None
    pending = 0
    probing = 0
    due_now = 0
    finalisable = 0
    missed = 0
    for candidate_id, state in scheduling_states.items():
        if state["terminal"] is None and state["state"] in {
            "pending",
            "baseline-ready",
        }:
            pending += 1
        if state["terminal"] is None and state["state"] == "probing":
            probing += 1
            if (
                acquisition_schema_version in _POLICY_EVIDENCE_SCHEMA_VERSIONS
                and _probe_candidate_is_finalisable(state)
            ):
                finalisable += 1
                continue
            try:
                if _due_pages(state, current, candidate_id=candidate_id):
                    due_now += 1
            except MissedProbeWindow:
                missed += 1
            for page in state["pages"]:
                if page.get("rejection") is not None:
                    continue
                index = len(page["observations"])
                if index < len(STABILITY_PROBE_WINDOWS):
                    baseline = _timestamp(state["baseline_started_at"])
                    due = baseline + timedelta(
                        milliseconds=STABILITY_PROBE_WINDOWS[index].earliest_ms
                    )
                    if due > current:
                        next_due = due if next_due is None or due < next_due else next_due
    pending_due = _next_pending_start(
        scheduling_states,
        current,
        baseline_starts=baseline_starts,
        reservations=reservations,
    )
    if pending_due is not None:
        next_due = pending_due if next_due is None or pending_due < next_due else next_due
    terminal = sum(state["terminal"] is not None for state in states.values())
    pending_blocked = bool(pending) and _pending_baseline_blocked(
        scheduling_states,
        current,
        baseline_starts=baseline_starts,
        reservations=reservations,
    )
    started_nonterminal = any(
        state["terminal"] is None
        and (
            state["state"] in {"baseline-ready", "probing"}
            or state.get("navigation_attempts")
            or state.get("pending_navigation")
        )
        for state in states.values()
    )
    complete = (
        (
            terminal == len(states)
            if selection is None
            else (selection["complete"] and not selection_blocked and not started_nonterminal)
        )
        and recovery_required == 0
        and active is None
    )
    return {
        "acquisition_schema_version": acquisition_schema_version,
        "checkpoint_schema_version": payload.get("checkpoint_schema_version"),
        "maximum_candidates_per_action": MAX_CANDIDATES_PER_ACTION,
        "global_live_page_cap": GLOBAL_LIVE_PAGE_CAP,
        "active_batch": active_summary,
        "candidate_count": len(states),
        "terminal_count": terminal,
        "pending_count": pending,
        "probing_count": probing,
        "due_now_count": due_now,
        "finalisable_count": finalisable,
        "missed_window_count": missed,
        "recovery_required_count": recovery_required,
        "pending_start_blocked": pending_blocked,
        "work_due_now": bool(
            recovery_required
            or due_now
            or finalisable
            or missed
            or (pending and not pending_blocked)
        ),
        "complete": complete,
        **(
            {"selection": selection, "selection_blocked_candidate_ids": selection_blocked}
            if selection is not None
            else {}
        ),
        "next_due": _format_time(next_due) if next_due else None,
    }


def write_acquisition_completion(root: Path, *, candidate_catalogue_path: Path) -> Path:
    provenance_value = validate_hash_bound_receipt(
        load_json(Path(root) / "provenance.json"), expected_type=PROVENANCE_TYPE
    )
    if provenance_value.get("acquisition_schema_version") != SCHEMA_VERSION:
        raise ValueError("historical acquisition runners cannot publish new completion evidence")
    _validate_runner_runtime(provenance_value)
    status = acquisition_status(root, candidate_catalogue_path=candidate_catalogue_path)
    if not status["complete"]:
        raise ValueError(
            "acquisition completion requires a resolved deterministic prefix "
            "and no outstanding work"
        )
    runner = Path(root)
    checkpoint, persisted_terminal_recoveries = _load_checkpoint(
        runner / "checkpoint.json", runner / "provenance.json", candidate_catalogue_path
    )
    if persisted_terminal_recoveries:
        raise ValueError("acquisition completion checkpoint required terminal recovery")
    if checkpoint["payload"]["active_batch"] is not None:
        raise ValueError("acquisition completion cannot bind an active batch")
    terminals = checkpoint["payload"]["candidates"]
    baseline_batches = checkpoint["payload"]["baseline_batches"]
    provenance = validate_hash_bound_receipt(
        load_json(runner / "provenance.json"), expected_type=PROVENANCE_TYPE
    )
    observed_toolchain = _validate_observation_provenance(
        terminals,
        provenance_sha256=sha256_file(runner / "provenance.json"),
        runner_provenance=provenance,
        runner_root=runner,
    )
    receipt = bind_receipt(
        {
            "study_id": "classifier-multiorigin100-v1",
            "acquisition_schema_version": SCHEMA_VERSION,
            "completion_schema_version": COMPLETION_SCHEMA_VERSION,
            "checkpoint_schema_version": CHECKPOINT_SCHEMA_VERSION,
            "candidate_catalogue_sha256": sha256_file(candidate_catalogue_path),
            "provenance_sha256": sha256_file(runner / "provenance.json"),
            "checkpoint_payload_sha256": checkpoint["payload_sha256"],
            "baseline_batches": baseline_batches,
            "baseline_batches_sha256": evidence_sha256(baseline_batches),
            "observed_toolchain": observed_toolchain,
            "selection": bind_receipt(status["selection"], receipt_type=SELECTION_TYPE),
            "terminal_receipts": {
                candidate_id: state["terminal"]
                for candidate_id, state in terminals.items()
                if state["terminal"] is not None
            },
        },
        receipt_type=COMPLETION_TYPE,
    )
    destination = runner / "completion.json"
    encoded = canonical_json_bytes(receipt)
    _discard_owned_publication_temps(destination, style="durable-create")

    def validate_existing() -> bool:
        if not destination.exists() and not destination.is_symlink():
            return False
        if (
            destination.is_symlink()
            or not destination.is_file()
            or destination.read_bytes() != encoded
        ):
            raise FileExistsError("immutable acquisition completion already differs")
        return True

    if not validate_existing():
        try:
            durable_create(destination, encoded)
        except FileExistsError:
            if not validate_existing():  # pragma: no cover - link collision guarantees presence
                raise
    return destination


def validate_acquisition_completion(
    value: Mapping[str, Any], *, candidate_catalogue_path: Path, runner_root: Path
) -> Mapping[str, Any]:
    payload = validate_hash_bound_receipt(value, expected_type=COMPLETION_TYPE)
    _catalogue, candidates = load_candidate_catalogue_receipt(candidate_catalogue_path)
    provenance = validate_hash_bound_receipt(
        load_json(runner_root / "provenance.json"), expected_type=PROVENANCE_TYPE
    )
    acquisition_schema_version = provenance.get("acquisition_schema_version")
    legacy_fields = {
        "study_id",
        "acquisition_schema_version",
        "candidate_catalogue_sha256",
        "provenance_sha256",
        "checkpoint_payload_sha256",
        "observed_toolchain",
        "terminal_receipts",
    }
    current_fields = legacy_fields | {
        "completion_schema_version",
        "checkpoint_schema_version",
        "baseline_batches",
        "baseline_batches_sha256",
    }
    if acquisition_schema_version in _SELECTION_SCHEMA_VERSIONS:
        current_fields.add("selection")
    if acquisition_schema_version in _MODERN_CHECKPOINT_SCHEMA_VERSIONS:
        if acquisition_schema_version in _FIXED_PROVENANCE_SCHEMA_VERSIONS:
            _validate_current_provenance_contract(
                provenance,
                candidate_catalogue_path=candidate_catalogue_path,
            )
        if (
            set(payload) != current_fields
            or type(payload["completion_schema_version"]) is not int
            or payload["completion_schema_version"]
            != _completion_schema_for(acquisition_schema_version)
            or type(payload["checkpoint_schema_version"]) is not int
            or payload["checkpoint_schema_version"]
            != _checkpoint_schema_for(acquisition_schema_version)
        ):
            raise ValueError("acquisition completion schema is invalid")
    elif acquisition_schema_version in {1, 2, 3}:
        if set(payload) != legacy_fields:
            raise ValueError("historical acquisition completion shape is invalid")
    else:
        raise ValueError("acquisition completion uses an unsupported schema")
    if (
        payload["study_id"] != "classifier-multiorigin100-v1"
        or type(payload["acquisition_schema_version"]) is not int
        or payload["candidate_catalogue_sha256"] != sha256_file(candidate_catalogue_path)
        or payload["provenance_sha256"] != sha256_file(runner_root / "provenance.json")
        or payload["acquisition_schema_version"] != acquisition_schema_version
    ):
        raise ValueError("completion is bound to another catalogue")
    checkpoint, checkpoint_recoveries, _orphan_candidate_ids = _load_checkpoint_state(
        runner_root / "checkpoint.json",
        runner_root / "provenance.json",
        candidate_catalogue_path,
        persist_recoveries=False,
    )
    if checkpoint_recoveries:
        raise ValueError("completion binds a checkpoint requiring recovery")
    if acquisition_schema_version in _MODERN_CHECKPOINT_SCHEMA_VERSIONS and (
        checkpoint["payload"]["active_batch"] is not None
        or payload["baseline_batches"] != checkpoint["payload"]["baseline_batches"]
        or payload["baseline_batches_sha256"]
        != evidence_sha256(checkpoint["payload"]["baseline_batches"])
    ):
        raise ValueError("completion baseline-batch ledger does not verify")
    expected = {candidate.candidate_id for candidate in candidates}
    checkpoint_terminals = {
        candidate_id: state["terminal"]
        for candidate_id, state in checkpoint["payload"]["candidates"].items()
        if acquisition_schema_version not in _SELECTION_SCHEMA_VERSIONS
        or state["terminal"] is not None
    }
    if acquisition_schema_version in _SELECTION_SCHEMA_VERSIONS:
        states = checkpoint["payload"]["candidates"]
        terminal_payloads = _checkpoint_terminal_payloads(runner_root, states)
        selection, blocked = _derive_checkpoint_selection(
            candidates, _catalogue, states, terminal_payloads
        )
        sealed_selection = validate_hash_bound_receipt(
            payload["selection"], expected_type=SELECTION_TYPE
        )
        if (
            not selection["complete"]
            or blocked
            or not _matches_json_contract(sealed_selection, selection)
            or any(
                state["terminal"] is None
                and (
                    state["state"] in {"baseline-ready", "probing"}
                    or state.get("navigation_attempts")
                    or state.get("pending_navigation")
                )
                for state in states.values()
            )
        ):
            raise ValueError(
                "acquisition completion selection prefix or unassessed tail does not verify"
            )
        expected = set(selection["terminal_ids"])
    if (
        set(payload["terminal_receipts"]) != expected
        or payload["terminal_receipts"] != checkpoint_terminals
        or payload["checkpoint_payload_sha256"] != checkpoint["payload_sha256"]
    ):
        raise ValueError("completion does not bind the complete current checkpoint")
    observed_toolchain = _validate_observation_provenance(
        checkpoint["payload"]["candidates"],
        provenance_sha256=payload["provenance_sha256"],
        runner_provenance=provenance,
        runner_root=runner_root,
    )
    if payload.get("observed_toolchain") != observed_toolchain:
        raise ValueError("completion observed toolchain identity differs from checkpoint")
    candidate_by_id = {candidate.candidate_id: candidate for candidate in candidates}
    for candidate_id, binding in payload["terminal_receipts"].items():
        if not isinstance(binding, Mapping) or set(binding) != {"path", "sha256"}:
            raise ValueError("terminal evidence binding is malformed")
        if binding["path"] != f"terminals/{candidate_id}.json":
            raise ValueError("terminal evidence path is not canonical")
        verified = _validated_terminal_binding(
            runner_root / binding["path"],
            candidate=candidate_by_id[candidate_id],
            provenance_sha256=payload["provenance_sha256"],
            candidate_state=checkpoint["payload"]["candidates"][candidate_id],
            acquisition_schema_version=provenance["acquisition_schema_version"],
            baseline_batches=checkpoint["payload"].get("baseline_batches", ()),
        )
        if dict(binding) != verified:
            raise ValueError("terminal evidence SHA-256 mismatch")
    return payload


def _converge_origins(
    backend: AcquisitionBackend,
    url: str,
    *,
    seed_origins: Sequence[str] = (),
) -> tuple[list[str], DiscoveryResult]:
    initial = origin(url)
    if initial is None:
        raise TerminalProbePolicyError("page URL is not HTTPS")
    approved = {initial}
    for value in seed_origins:
        approved_origin = origin(value)
        if approved_origin is None:
            raise TerminalProbePolicyError("navigation supplied a non-HTTPS origin")
        approved.add(approved_origin)
    if len(approved) > MAX_APPROVED_ORIGINS:
        raise TerminalProbePolicyError("navigation origins exceeded the finite origin cap")
    for _pass in range(MAX_ORIGIN_PASSES):
        result = backend.discover(url, sorted(approved))
        if len(result.observed_origins) > MAX_OBSERVED_AUDIT_ORIGINS:
            raise TerminalProbePolicyError(
                "discovery exceeded its finite observed-origin audit cap"
            )
        expandable = result.expandable_origins
        if expandable is None:
            raise TerminalProbePolicyError(
                "discovery omitted its HTTPS-GET-only expandable-origin ledger"
            )
        if not isinstance(expandable, list):
            raise TerminalProbePolicyError(
                "discovery HTTPS-GET-only expandable-origin ledger is not a list"
            )
        canonical_expandable: list[str] = []
        for value in expandable:
            expandable_origin = origin(value) if isinstance(value, str) else None
            if expandable_origin is None or expandable_origin != value:
                raise TerminalProbePolicyError(
                    "discovery HTTPS-GET-only expandable-origin ledger contains a "
                    "non-canonical HTTPS origin"
                )
            canonical_expandable.append(expandable_origin)
        if canonical_expandable != sorted(set(canonical_expandable)):
            raise TerminalProbePolicyError(
                "discovery HTTPS-GET-only expandable-origin ledger is not sorted and unique"
            )
        audited_origins = {
            observed_origin
            for value in result.observed_origins
            if isinstance(value, str) and (observed_origin := origin(value)) is not None
        }
        if not set(canonical_expandable).issubset(audited_origins):
            raise TerminalProbePolicyError(
                "discovery HTTPS-GET-only expandable origins exceed its observed-origin ledger"
            )
        observed = set(canonical_expandable)
        expanded = approved | observed
        if len(expanded) > MAX_APPROVED_ORIGINS:
            raise TerminalProbePolicyError(
                "approved-origin discovery exceeded its finite origin cap"
            )
        if expanded == approved:
            return sorted(approved), result
        approved = expanded
    raise TerminalProbePolicyError("approved-origin discovery did not converge within its pass cap")


def browser_document_content_type(
    url: str,
    approved_origins: Sequence[str],
    timeout_ms: int,
    origin_ip_pins: Mapping[str, str] | None = None,
) -> BrowserDocumentResponse:
    """Observe the primary browser response MIME type under the frozen origin set."""

    if timeout_ms < 1:
        raise ValueError("content-type probe timeout must be positive")
    approved = {origin(value) for value in approved_origins}
    if None in approved or not approved or len(approved) > MAX_APPROVED_ORIGINS:
        raise TerminalProbePolicyError("content-type probe approved origins are invalid")
    canonical_approved = tuple(sorted(value for value in approved if value is not None))
    pins = _validated_frozen_origin_ip_pins(
        canonical_approved,
        origin_ip_pins if origin_ip_pins is not None else public_origin_ip_pins(canonical_approved),
    )
    try:
        from playwright.sync_api import Error as PlaywrightError
        from playwright.sync_api import sync_playwright
    except ImportError as error:
        raise RuntimeError(
            "content-type verification requires the discovery Docker image"
        ) from error
    try:
        validate_default_playwright_driver_once()
        # JavaScript is disabled and only the root page CDP session is used;
        # this response-only probe does not take recursive target ownership.
        with playwright_driver_session(sync_playwright, exclusive=False) as playwright:
            browser, _browser_egress_projection = launch_production_browser(
                playwright,
                approved_origins=canonical_approved,
                origin_ip_pins=pins,
            )
            try:
                chromium_version = str(browser.version)
                # The probe needs only the primary HTTP response metadata.
                # Disabling JavaScript before the first document removes every
                # author-script worker and non-URLLoader egress surface without
                # changing response status, final URL, or Content-Type semantics.
                context = browser.new_context(
                    ignore_https_errors=False,
                    java_script_enabled=False,
                    service_workers="block",
                )

                root_page: Any | None = None

                def route_request(route: Any) -> None:
                    request = route.request
                    try:
                        root_navigation = (
                            root_page is not None
                            and request.is_navigation_request()
                            and request.frame is root_page.main_frame
                        )
                    except Exception:  # noqa: BLE001 - unresolved ownership fails closed
                        root_navigation = False
                    if (
                        request.method != "GET"
                        or origin(request.url) not in approved
                        or not root_navigation
                    ):
                        route.abort()
                    else:
                        route.continue_()

                context.route("**/*", route_request)
                page = context.new_page()
                root_page = page
                session = context.new_cdp_session(page)
                frame_tree = session.send("Page.getFrameTree")
                root_frame = frame_tree.get("frameTree", {}).get("frame", {})
                root_frame_id = root_frame.get("id")
                if not isinstance(root_frame_id, str) or not root_frame_id:
                    raise RuntimeError("content-type probe could not identify its root frame")
                fetch_failure: list[Exception] = []

                def request_paused(event: Mapping[str, Any]) -> None:
                    request_id = event.get("requestId")
                    try:
                        request = event.get("request")
                        if (
                            not isinstance(request_id, str)
                            or not request_id
                            or not isinstance(request, Mapping)
                        ):
                            raise RuntimeError("content-type probe Fetch event is malformed")
                        allowed = (
                            request.get("method") == "GET"
                            and isinstance(request.get("url"), str)
                            and origin(request["url"]) in approved
                            and event.get("resourceType") == "Document"
                            and event.get("frameId") == root_frame_id
                        )
                        command = "Fetch.continueRequest" if allowed else "Fetch.failRequest"
                        parameters = (
                            {"requestId": request_id}
                            if allowed
                            else {
                                "requestId": request_id,
                                "errorReason": "BlockedByClient",
                            }
                        )
                        result = session.send(command, parameters)
                        if not isinstance(result, Mapping) or result:
                            raise RuntimeError(
                                "content-type probe Fetch decision was not acknowledged"
                            )
                    except Exception as error:  # noqa: BLE001 - callback failure is re-raised
                        fetch_failure.append(error)
                        if isinstance(request_id, str) and request_id:
                            try:
                                session.send(
                                    "Fetch.failRequest",
                                    {
                                        "requestId": request_id,
                                        "errorReason": "BlockedByClient",
                                    },
                                )
                            except Exception:
                                pass

                session.on("Fetch.requestPaused", request_paused)
                enabled = session.send(
                    "Fetch.enable",
                    {"patterns": [{"urlPattern": "*", "requestStage": "Request"}]},
                )
                if not isinstance(enabled, Mapping) or enabled:
                    raise RuntimeError("content-type probe Fetch boundary was not enabled")
                response = page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
                if fetch_failure:
                    raise fetch_failure[0]
                if response is None or origin(page.url) not in approved:
                    raise TerminalProbePolicyError(
                        "content-type probe did not finish on an approved origin"
                    )
                if challenge := browser_challenge_reason(page):
                    raise TerminalProbePolicyError(challenge)
                media_type = _normalise_content_type(str(response.headers.get("content-type", "")))
                final_url = page.url
                status = response.status
                page.close()
                if fetch_failure:
                    raise fetch_failure[0]
            finally:
                try:
                    if "context" in locals():
                        context.close()
                finally:
                    browser.close()
                if "fetch_failure" in locals() and fetch_failure:
                    raise fetch_failure[0]
    except PlaywrightError as error:
        raise RecoverableAcquisitionError(
            f"Playwright content-type probe failed: {error}"
        ) from error
    if media_type not in HTML_MEDIA_TYPES:
        raise TerminalProbePolicyError("primary response is not HTML")
    return BrowserDocumentResponse(
        final_url=final_url,
        status=status,
        content_type=media_type,
        chromium_version=chromium_version,
    )


def _normalise_content_type(value: str) -> str:
    return value.partition(";")[0].strip().lower()


def _navigation_request_allowed(method: str, url: str, boundary: str) -> bool:
    parts = urlsplit(url)
    hostname = (parts.hostname or "").lower().rstrip(".")
    frozen = boundary.lower().rstrip(".")
    return (
        method == "GET"
        and parts.scheme.lower() == "https"
        and (hostname == frozen or hostname.endswith(f".{frozen}"))
    )


def unsafe_catalogue_domain_reason(domain: str) -> str | None:
    canonical = domain.lower().rstrip(".")
    if canonical in DOMAIN_SAFETY_POLICY["denied_exact_domains"]:
        return "domain-safety-policy-rejected:exact-domain"
    for substring in DOMAIN_SAFETY_POLICY["denied_substrings"]:
        if any(substring in label for label in canonical.split(".")):
            return f"domain-safety-policy-rejected:{substring}"
    return None


def _is_public_network_address(
    value: str | ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> bool:
    """Mirror Neqo's exact ``QCSD_PUBLIC_ORIGIN_ONLY`` address policy."""

    if isinstance(value, str):
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            return False
    elif isinstance(value, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
        address = value
    else:
        return False

    octets = address.packed
    if isinstance(address, ipaddress.IPv4Address):
        a, b, c, _d = octets
        return not (
            a == 0
            or a == 10
            or a == 127
            or a >= 224
            or (a == 100 and 64 <= b <= 127)
            or (a == 169 and b == 254)
            or (a == 172 and 16 <= b <= 31)
            or (a == 192 and b == 0)
            or (a == 192 and b == 168)
            or (a == 192 and b == 88 and c == 99)
            or (a == 198 and b in {18, 19})
            or (a == 198 and b == 51 and c == 100)
            or (a == 203 and b == 0 and c == 113)
        )

    global_unicast = octets[0] & 0xE0 == 0x20
    ietf_special = octets[0] == 0x20 and octets[1] == 0x01 and octets[2] & 0xFE == 0
    deprecated_6to4 = octets[0] == 0x20 and octets[1] == 0x02
    documentation = octets[:4] == bytes((0x20, 0x01, 0x0D, 0xB8)) or (
        octets[0] == 0x3F and octets[1] == 0xFF and octets[2] & 0xF0 == 0
    )
    return global_unicast and not ietf_special and not deprecated_6to4 and not documentation


def public_origin_ip_pins(origins: Sequence[str]) -> dict[str, str]:
    """Resolve and pin public DNS answers, rejecting every non-public answer."""

    pins: dict[str, str] = {}
    pins_by_hostname: dict[str, str] = {}
    for value in sorted(set(origins)):
        approved = origin(value)
        if approved is None:
            raise TerminalProbePolicyError("public-origin policy requires absolute HTTPS origins")
        hostname = urlsplit(approved).hostname
        if hostname is None:
            raise TerminalProbePolicyError(
                "public-origin policy found an origin without a hostname"
            )
        canonical = hostname.lower().rstrip(".")
        try:
            ipaddress.ip_address(canonical)
        except ValueError:
            pass
        else:
            raise TerminalProbePolicyError("public-origin policy rejects IP-literal origins")
        if canonical == "localhost" or canonical.endswith(
            (".localhost", ".local", ".internal", ".home", ".lan")
        ):
            raise TerminalProbePolicyError("public-origin policy rejects local hostnames")
        if canonical in pins_by_hostname:
            pins[approved] = pins_by_hostname[canonical]
            continue
        port = urlsplit(approved).port or 443
        try:
            records = socket.getaddrinfo(
                canonical,
                port,
                family=socket.AF_UNSPEC,
                type=socket.SOCK_STREAM,
            )
        except socket.gaierror as error:
            raise RecoverableAcquisitionError(
                f"public-origin DNS lookup failed for {canonical}: {error}"
            ) from error
        answers = {ipaddress.ip_address(record[4][0]) for record in records}
        if not answers:
            raise RecoverableAcquisitionError(
                f"public-origin DNS lookup returned no answers for {canonical}"
            )
        if any(not _is_public_network_address(address) for address in answers):
            raise TerminalProbePolicyError(
                f"public-origin policy rejected DNS answers for {canonical}"
            )
        selected = min(answers, key=lambda address: (address.version, int(address)))
        pins_by_hostname[canonical] = selected.compressed
        pins[approved] = selected.compressed
    return pins


def _validated_frozen_origin_ip_pins(
    origins: Sequence[str], pins: Mapping[str, str]
) -> dict[str, str]:
    approved = sorted(set(origins))
    if not isinstance(pins, Mapping) or set(pins) != set(approved):
        raise TerminalProbePolicyError(
            "frozen origin-IP pins do not exactly cover approved origins"
        )
    result: dict[str, str] = {}
    pins_by_hostname: dict[str, str] = {}
    for approved_origin in approved:
        if origin(approved_origin) != approved_origin:
            raise TerminalProbePolicyError("frozen origin-IP pin key is not canonical")
        raw_address = pins[approved_origin]
        if not isinstance(raw_address, str):
            raise TerminalProbePolicyError("frozen origin-IP pin is malformed")
        try:
            address = ipaddress.ip_address(raw_address)
        except ValueError as error:
            raise TerminalProbePolicyError("frozen origin-IP pin is malformed") from error
        if address.compressed != raw_address or not _is_public_network_address(address):
            raise TerminalProbePolicyError("frozen origin-IP pin is not canonical public IP")
        hostname = urlsplit(approved_origin).hostname
        if hostname is None:
            raise TerminalProbePolicyError("frozen origin-IP pin key is not canonical")
        previous = pins_by_hostname.setdefault(hostname, raw_address)
        if previous != raw_address:
            raise TerminalProbePolicyError("frozen origin-IP pins conflict for a shared hostname")
        result[approved_origin] = raw_address
    return result


def browser_challenge_reason(page: Any) -> str | None:
    """Reject common interstitial/CAPTCHA documents before stability probing."""

    title = str(page.title()).casefold()
    body = str(page.locator("body").inner_text(timeout=5_000))[:200_000].casefold()
    selectors = (
        "iframe[src*='captcha' i]",
        "iframe[src*='challenge' i]",
        "[id*='captcha' i]",
        "[class*='captcha' i]",
        "script[src*='turnstile' i]",
        "script[src*='recaptcha' i]",
    )
    if any(page.locator(selector).count() for selector in selectors):
        return "page-safety-rejected:captcha-or-challenge-widget"
    phrases = (
        "verify you are human",
        "verify that you are human",
        "checking your browser",
        "complete the captcha",
        "security verification",
        "enable javascript and cookies to continue",
    )
    if any(phrase in title or phrase in body for phrase in phrases):
        return "page-safety-rejected:captcha-or-challenge-interstitial"
    return None


def _verified_navigation_link(
    candidate: PageCandidate,
    *,
    final_url: str,
    content_type: str,
    boundary: str,
) -> DiscoveredLink | None:
    if (
        _navigation_link_policy_rejection(
            final_url=final_url,
            content_type=content_type,
            boundary=boundary,
        )
        is not None
    ):
        return None
    media_type = _normalise_content_type(content_type)
    return DiscoveredLink(url=candidate.url, content_type=media_type)


def _navigation_link_policy_rejection(
    *, final_url: str, content_type: str, boundary: str
) -> tuple[str, str] | None:
    media_type = _normalise_content_type(content_type)
    if media_type not in HTML_MEDIA_TYPES:
        return (
            "non-html-primary-response",
            f"optional link returned unsupported media type {media_type!r}",
        )
    parts = urlsplit(final_url)
    if not _navigation_request_allowed("GET", final_url, boundary):
        return (
            "redirect-outside-candidate-boundary",
            "optional link redirected outside the frozen candidate-domain boundary",
        )
    if parts.username is not None or parts.password is not None or parts.query or parts.fragment:
        return (
            "redirect-has-query-fragment-or-userinfo",
            "optional link redirect introduced forbidden URL components",
        )
    return None


def _navigation_origins_by_page(
    navigation: NavigationDiscovery,
    pages: Sequence[PageCandidate],
) -> dict[str, tuple[str, ...]]:
    """Validate and retain navigation seeds for the page that observed them.

    Production navigation records each page independently so a redirect seen
    on one optional page cannot overconstrain a different page's discovery
    graph.  The global union remains in the checkpoint for audit, but is never
    substituted for missing page-specific evidence.
    """

    global_origins = _canonical_navigation_origins(
        navigation.observed_origins,
        label="global navigation origin ledger",
    )
    page_urls = {page.url for page in pages}
    raw_page_origins = navigation.page_observed_origins
    if not isinstance(raw_page_origins, tuple):
        raise TypeError("per-page navigation origin ledger is not a tuple")
    if not raw_page_origins:
        raise ValueError("per-page navigation origin ledger is required")
    result: dict[str, tuple[str, ...]] = {}
    for entry in raw_page_origins:
        if (
            not isinstance(entry, tuple)
            or len(entry) != 2
            or not isinstance(entry[0], str)
            or entry[0] in result
        ):
            raise ValueError("per-page navigation origin ledger is malformed")
        page_url, values = entry
        if page_url not in page_urls:
            raise ValueError("per-page navigation origin ledger names another page")
        origins = _canonical_navigation_origins(
            values,
            label="per-page navigation origin ledger",
        )
        if not set(origins).issubset(global_origins):
            raise ValueError("per-page navigation origins exceed the global ledger")
        result[page_url] = origins
    if set(result) != page_urls:
        raise ValueError("per-page navigation origin ledger is incomplete")
    return result


def _canonical_navigation_origins(
    values: object,
    *,
    label: str,
) -> tuple[str, ...]:
    if not isinstance(values, (list, tuple)):
        raise TypeError(f"{label} is not a sequence")
    if len(values) > MAX_APPROVED_ORIGINS:
        raise ValueError(f"{label} is malformed")
    canonical: list[str] = []
    for value in values:
        if not isinstance(value, str):
            raise TypeError(f"{label} contains a non-string origin")
        canonical_origin = origin(value)
        if canonical_origin is None or canonical_origin != value:
            raise ValueError(f"{label} contains a non-canonical HTTPS origin")
        canonical.append(canonical_origin)
    if canonical != sorted(set(canonical)):
        raise ValueError(f"{label} is not a sorted unique origin set")
    return tuple(canonical)


def _validate_navigation_rejections(value: object, *, boundary: str) -> None:
    if not isinstance(value, list) or len(value) > 4:
        raise ValueError("navigation rejection ledger is malformed")
    for rejection in value:
        if not isinstance(rejection, Mapping) or set(rejection) != {
            "url",
            "kind",
            "reason",
        }:
            raise ValueError("navigation rejection record is malformed")
        if (
            rejection["kind"] not in NAVIGATION_REJECTION_KINDS
            or not isinstance(rejection["reason"], str)
            or not _navigation_request_allowed("GET", rejection["url"], boundary)
        ):
            raise ValueError("navigation rejection record violates its policy")


def _verified_bound_file(binding: Mapping[str, Any], *, label: str) -> Path:
    if set(binding) != {"path", "sha256"} or not isinstance(binding["path"], str):
        raise ValueError(f"{label} binding is malformed")
    path = Path(binding["path"])
    if path.is_symlink() or not path.is_file() or sha256_file(path) != binding["sha256"]:
        raise ValueError(f"{label} binding does not verify")
    return path


def _terminal_source_state(kind: str) -> str:
    if kind == "pre-probe-rejection":
        return "pending"
    if kind in {"eligible", "stable-page-unavailable", "probe-window-missed"}:
        return "probing"
    raise ValueError("terminal evidence has an unsupported outcome kind")


def _normalised_terminal_state_sha256(state: Mapping[str, Any], *, kind: str) -> str:
    """Hash the exact state that existed immediately before terminalisation."""

    source_state = _terminal_source_state(kind)
    actual_state = state.get("state")
    terminal_binding = state.get("terminal")
    if actual_state == source_state:
        if terminal_binding is not None:
            raise ValueError("pre-terminal checkpoint unexpectedly has a terminal binding")
    elif actual_state == "terminal":
        if not isinstance(terminal_binding, Mapping) or set(terminal_binding) != {
            "path",
            "sha256",
        }:
            raise ValueError("terminal checkpoint binding is malformed")
    else:
        raise ValueError("terminal outcome is impossible from the checkpoint state")
    normalised = dict(state)
    normalised["state"] = source_state
    normalised["terminal"] = None
    return sha256_bytes(canonical_json_bytes(normalised))


def _checkpoint_stability_observations(
    page_state: Mapping[str, Any],
) -> tuple[StabilityObservation, ...]:
    observations: list[StabilityObservation] = []
    for raw in page_state.get("observations", []):
        if not isinstance(raw, Mapping) or set(raw) != CURRENT_OBSERVATION_FIELDS:
            raise ValueError("terminal checkpoint observation is malformed")
        observation = StabilityObservation(
            **{key: raw.get(key) for key in StabilityObservation.__dataclass_fields__}
        )
        expected = observation.as_dict()
        if any(key not in raw or raw[key] != value for key, value in expected.items()):
            raise ValueError("terminal checkpoint stability observation differs")
        if observation.document_response_receipt_sha256 is None:
            raise ValueError("current terminal lacks document-response evidence")
        observations.append(observation)
    return tuple(observations)


def _validate_terminal_page_rejection(page_state: Mapping[str, Any]) -> None:
    rejection = page_state.get("rejection")
    if not isinstance(rejection, Mapping) or set(rejection) != {"kind", "reason"}:
        raise ValueError("terminal checkpoint page rejection is malformed")
    if not isinstance(rejection["reason"], str) or not rejection["reason"]:
        raise ValueError("terminal checkpoint page rejection has no reason")
    observation_count = len(page_state["observations"])
    if observation_count >= len(STABILITY_PROBE_WINDOWS):
        raise ValueError("completed terminal page cannot also be rejected")
    probe_id = STABILITY_PROBE_WINDOWS[observation_count].probe_id
    attempts = [item for item in page_state["probe_attempts"] if item.get("probe_id") == probe_id]
    if not attempts:
        raise ValueError("terminal page rejection has no matching probe attempt")
    final = attempts[-1]
    if rejection["kind"] == "probe-policy-rejection":
        if (
            final["outcome"] != "terminal-policy-rejection"
            or rejection["reason"] != final["reason"]
        ):
            raise ValueError("terminal policy rejection differs from its probe attempt")
        return
    if rejection["kind"] != "probe-retry-exhausted":
        raise ValueError("terminal checkpoint page rejection kind is invalid")
    if len(attempts) != MAX_PROBE_ATTEMPTS or final["outcome"] not in {
        "interrupted",
        "recoverable-failure",
    }:
        raise ValueError("probe exhaustion is not supported by its attempt ledger")
    generic_reason = f"recoverable acquisition failures exhausted {MAX_PROBE_ATTEMPTS} attempts"
    detailed_reason = f"{generic_reason}: {final['reason']}"
    if rejection["reason"] not in {generic_reason, detailed_reason}:
        raise ValueError("probe exhaustion reason differs from its attempt ledger")
    if rejection["reason"] == detailed_reason and final["outcome"] != "recoverable-failure":
        raise ValueError("detailed probe exhaustion lacks a recoverable failure")


def _validate_probing_terminal_state(
    state: Mapping[str, Any],
    *,
    candidate: Any,
    acquisition_schema_version: int,
    terminalised_at: datetime,
    enforce_duration_limit: bool,
) -> tuple[
    tuple[
        Mapping[str, Any],
        PageCandidate,
        tuple[StabilityObservation, ...],
        Any,
    ],
    ...,
]:
    expected_state_fields = {
        "state",
        "pages",
        "terminal",
        "navigation_attempts",
        "baseline_started_at",
        "navigation_observed_origins",
        "navigation_rejections",
    }
    if set(state) != expected_state_fields:
        raise ValueError("probing terminal checkpoint fields differ from the contract")
    attempts = state["navigation_attempts"]
    if (
        not isinstance(attempts, list)
        or not attempts
        or attempts[-1].get("outcome") != "completed"
        or sum(item.get("outcome") == "completed" for item in attempts) != 1
    ):
        raise ValueError("probing terminal lacks one completed navigation")
    baseline = _timestamp(state["baseline_started_at"])
    if baseline < _timestamp(attempts[-1]["completed_at"]):
        raise ValueError("probing baseline predates completed navigation")
    if terminalised_at < baseline:
        raise ValueError("terminal timestamp predates the probing baseline")
    global_origins = _canonical_navigation_origins(
        state["navigation_observed_origins"],
        label="terminal global navigation origin ledger",
    )
    _validate_navigation_rejections(state["navigation_rejections"], boundary=candidate.domain)
    raw_pages = state["pages"]
    if not isinstance(raw_pages, list) or not 1 <= len(raw_pages) <= 5:
        raise ValueError("terminal checkpoint page sequence is invalid")
    page_records: list[
        tuple[
            Mapping[str, Any],
            PageCandidate,
            tuple[StabilityObservation, ...],
            Any,
        ]
    ] = []
    seen_urls: set[str] = set()
    for ordinal, page_state in enumerate(raw_pages):
        base_fields = {
            "page",
            "observations",
            "probe_attempts",
            "approved_origins",
            "navigation_observed_origins",
        }
        if not isinstance(page_state, Mapping) or set(page_state) not in {
            frozenset(base_fields),
            frozenset(base_fields | {"pending_probe"}),
            frozenset(base_fields | {"rejection"}),
        }:
            raise ValueError("terminal checkpoint page fields differ from the contract")
        raw_page = page_state["page"]
        page_fields = set(PageCandidate.__dataclass_fields__)
        if not isinstance(raw_page, Mapping) or set(raw_page) != page_fields:
            raise ValueError("terminal checkpoint page identity is malformed")
        page = PageCandidate(**dict(raw_page))
        validate_page_candidate(page)
        if (
            page.candidate_domain != candidate.domain
            or page.registrable_domain != candidate.domain
            or page.ordinal != ordinal
            or page.url in seen_urls
        ):
            raise ValueError("terminal checkpoint page sequence differs from its candidate")
        seen_urls.add(page.url)
        navigation_origins = _canonical_navigation_origins(
            page_state["navigation_observed_origins"],
            label="terminal per-page navigation origin ledger",
        )
        if not set(navigation_origins).issubset(global_origins):
            raise ValueError("terminal page navigation origins exceed the global ledger")
        approved_origins = _canonical_navigation_origins(
            page_state["approved_origins"],
            label="terminal page approved-origin ledger",
        )
        _validate_probe_attempts(
            page_state,
            candidate_id=candidate.candidate_id,
            acquisition_schema_version=acquisition_schema_version,
            baseline_started_at=state["baseline_started_at"],
            enforce_duration_limit=enforce_duration_limit,
        )
        observations = _checkpoint_stability_observations(page_state)
        if observations:
            final_approved = page_state["observations"][-1].get("approved_origins")
            if list(approved_origins) != final_approved:
                raise ValueError("terminal page approved origins differ from its last probe")
        elif approved_origins:
            raise ValueError("unobserved terminal page carries approved origins")
        if "rejection" in page_state:
            _validate_terminal_page_rejection(page_state)
            decision = None
        else:
            decision = (
                derive_stability_decision(
                    page,
                    baseline_started_at=state["baseline_started_at"],
                    observations=observations,
                )
                if len(observations) == len(STABILITY_PROBE_WINDOWS)
                else None
            )
        for attempt in page_state["probe_attempts"]:
            if terminalised_at < _timestamp(attempt["completed_at"]):
                raise ValueError("terminal timestamp predates completed probe work")
        page_records.append((page_state, page, observations, decision))
    return tuple(page_records)


def _validate_live_probing_state(
    state: Mapping[str, Any],
    *,
    candidate: Any,
) -> None:
    """Validate mutable probing evidence structurally without replaying history."""

    expected_fields = {
        "state",
        "pages",
        "terminal",
        "navigation_attempts",
        "baseline_started_at",
        "navigation_observed_origins",
        "navigation_rejections",
    }
    actual_fields = set(state)
    if actual_fields not in {
        frozenset(expected_fields),
        frozenset(expected_fields | {"internal_acquisition_error"}),
    }:
        raise ValueError("live probing checkpoint fields differ from the contract")
    if state.get("state") != "probing" or state.get("terminal") is not None:
        raise ValueError("live probing checkpoint state is invalid")
    structural_state = dict(state)
    structural_state.pop("internal_acquisition_error", None)
    _validate_probing_terminal_state(
        structural_state,
        candidate=candidate,
        acquisition_schema_version=SCHEMA_VERSION,
        terminalised_at=datetime.max.replace(tzinfo=UTC),
        enforce_duration_limit=True,
    )


def _validate_current_pending_state(state: Mapping[str, Any]) -> None:
    """Enforce the exact schema-4 pending candidate variants."""

    base_fields = {"state", "pages", "terminal"}
    attempted_fields = base_fields | {"navigation_attempts"}
    actual_fields = set(state)
    if actual_fields not in {
        frozenset(base_fields),
        frozenset(attempted_fields),
        frozenset(attempted_fields | {"pending_navigation"}),
        frozenset(attempted_fields | {"internal_acquisition_error"}),
    }:
        raise ValueError("pending checkpoint fields differ from the current contract")
    if (
        state.get("state") != "pending"
        or state.get("pages") != []
        or state.get("terminal") is not None
    ):
        raise ValueError("pending checkpoint state differs from the current contract")
    if "navigation_attempts" not in state and actual_fields != base_fields:
        raise ValueError("pending checkpoint attempt state is incomplete")


def _validate_current_terminal_state(
    state: Mapping[str, Any],
    *,
    candidate: Any,
    acquisition_schema_version: int,
    kind: str,
    reason: str | None,
    terminalised_at: datetime,
    enforce_duration_limit: bool,
) -> tuple[Mapping[str, Any], PageCandidate, tuple[StabilityObservation, ...]] | None:
    if kind == "pre-probe-rejection":
        if set(state) != {"state", "pages", "terminal", "navigation_attempts"}:
            raise ValueError("pre-probe terminal checkpoint fields differ from the contract")
        attempts = state["navigation_attempts"]
        if not isinstance(attempts, list) or not attempts or state["pages"] != []:
            raise ValueError("pre-probe terminal checkpoint is malformed")
        final = attempts[-1]
        if terminalised_at < _timestamp(final["completed_at"]):
            raise ValueError("terminal timestamp predates navigation completion")
        if final["outcome"] == "terminal-policy-rejection":
            expected_reason = final["reason"]
        elif len(attempts) == MAX_PROBE_ATTEMPTS and final["outcome"] in {
            "interrupted",
            "recoverable-failure",
        }:
            expected_reason = (
                f"recoverable navigation failures exhausted {MAX_PROBE_ATTEMPTS} "
                f"attempts: {final['reason']}"
            )
        else:
            raise ValueError("pre-probe terminal has no legal producer outcome")
        if reason != expected_reason:
            raise ValueError("pre-probe terminal reason differs from its attempt ledger")
        return None

    pages = _validate_probing_terminal_state(
        state,
        candidate=candidate,
        acquisition_schema_version=acquisition_schema_version,
        terminalised_at=terminalised_at,
        enforce_duration_limit=enforce_duration_limit,
    )
    incomplete = tuple(
        record
        for record in pages
        if "rejection" not in record[0] and len(record[2]) < len(STABILITY_PROBE_WINDOWS)
    )
    if kind == "probe-window-missed":
        if not incomplete:
            raise ValueError("missed-window terminal has no incomplete page")
        try:
            _due_pages(state, terminalised_at, candidate_id=candidate.candidate_id)
        except MissedProbeWindow:
            pass
        else:
            raise ValueError("missed-window terminal timestamp is still admissible")
        retry_reason = "recoverable probe retries exceeded the latest admissible window"
        if reason == retry_reason:
            retry_supported = False
            for page_state, _page, observations, _decision in incomplete:
                probe_id = STABILITY_PROBE_WINDOWS[len(observations)].probe_id
                current_attempts = [
                    item
                    for item in page_state["probe_attempts"]
                    if item.get("probe_id") == probe_id
                ]
                retry_supported |= bool(
                    current_attempts and current_attempts[-1]["outcome"] == "recoverable-failure"
                )
            if not retry_supported:
                raise ValueError("retry-missed terminal lacks a recoverable probe attempt")
        elif reason not in {
            "host resumed after the latest admissible probe window",
            "bounded action passed the latest admissible probe window",
        }:
            raise ValueError("missed-window terminal reason is not a producer outcome")
        return None

    if incomplete:
        raise ValueError("stability terminal retains an incomplete page")
    eligible = tuple(record for record in pages if record[3] is not None and record[3].eligible)
    if kind == "stable-page-unavailable":
        if reason != "no page passed all stability gates" or eligible:
            raise ValueError("stable-page-unavailable differs from derived page decisions")
        return None
    if kind != "eligible" or reason is not None or not eligible:
        raise ValueError("eligible terminal differs from derived page decisions")
    page_state, page, observations, _decision = eligible[0]
    return page_state, page, observations


def _validated_terminal_binding(
    terminal: Path,
    *,
    candidate: Any,
    provenance_sha256: str,
    candidate_state: Mapping[str, Any],
    acquisition_schema_version: int,
    baseline_batches: Sequence[Mapping[str, Any]],
) -> dict[str, str]:
    """Validate an immutable terminal deeply enough to recover its checkpoint."""

    if terminal.is_symlink() or not terminal.is_file():
        raise ValueError("terminal evidence is not a regular file")
    receipt = load_json(terminal)
    if terminal.read_bytes() != canonical_json_bytes(receipt):
        raise ValueError("terminal evidence is not canonically encoded")
    payload = validate_hash_bound_receipt(receipt, expected_type=TERMINAL_TYPE)
    legacy_fields = {
        "candidate_id",
        "kind",
        "reason",
        "provenance_sha256",
        "stability_receipt",
        "admitted_workload",
    }
    terminal_v2_fields = legacy_fields | {
        "terminal_schema_version",
        "terminalised_at",
        "checkpoint_state_sha256",
    }
    terminal_v3_fields = terminal_v2_fields | {
        "checkpoint_schema_version",
        "baseline_batch",
    }
    if acquisition_schema_version == 1:
        if set(payload) != legacy_fields:
            raise ValueError("legacy terminal evidence fields differ from the contract")
    elif acquisition_schema_version in {2, 3}:
        if set(payload) != terminal_v2_fields:
            raise ValueError("terminal evidence fields differ from the contract")
        if (
            type(payload["terminal_schema_version"]) is not int
            or payload["terminal_schema_version"] != 2
        ):
            raise ValueError("terminal evidence schema differs from the current contract")
    elif acquisition_schema_version in _MODERN_CHECKPOINT_SCHEMA_VERSIONS:
        if set(payload) != terminal_v3_fields:
            raise ValueError("terminal evidence fields differ from the contract")
        if (
            type(payload["terminal_schema_version"]) is not int
            or payload["terminal_schema_version"]
            != _terminal_schema_for(acquisition_schema_version)
            or type(payload["checkpoint_schema_version"]) is not int
            or payload["checkpoint_schema_version"]
            != _checkpoint_schema_for(acquisition_schema_version)
        ):
            raise ValueError("terminal evidence schema differs from the current contract")
    else:
        raise ValueError("terminal evidence belongs to an unsupported acquisition schema")
    if acquisition_schema_version in _TERMINAL_STATE_SCHEMA_VERSIONS and not isinstance(
        candidate_state, Mapping
    ):
        raise ValueError("terminal evidence fields differ from the contract")
    if (
        payload["candidate_id"] != candidate.candidate_id
        or payload["provenance_sha256"] != provenance_sha256
    ):
        raise ValueError("terminal evidence identity/provenance mismatch")
    kind = payload["kind"]
    reason = payload["reason"]
    if kind not in TERMINAL_KINDS:
        raise ValueError("terminal evidence has an unsupported outcome kind")
    if (kind == "eligible" and reason is not None) or (
        kind != "eligible" and (not isinstance(reason, str) or not reason)
    ):
        raise ValueError("terminal evidence reason differs from its outcome kind")
    if acquisition_schema_version in _MODERN_CHECKPOINT_SCHEMA_VERSIONS:
        expected_baseline_batch = (
            None
            if kind == "pre-probe-rejection"
            else _baseline_batch_for_candidate(
                baseline_batches, candidate_id=candidate.candidate_id
            )
        )
        if payload["baseline_batch"] != expected_baseline_batch:
            raise ValueError("terminal evidence baseline-batch binding differs")
    selected_checkpoint = None
    if acquisition_schema_version in _TERMINAL_STATE_SCHEMA_VERSIONS:
        terminalised_raw = payload["terminalised_at"]
        if (
            not isinstance(terminalised_raw, str)
            or _format_time(_timestamp(terminalised_raw)) != terminalised_raw
        ):
            raise ValueError("terminal evidence timestamp is not canonical UTC")
        if payload["checkpoint_state_sha256"] != _normalised_terminal_state_sha256(
            candidate_state, kind=kind
        ):
            raise ValueError("terminal evidence does not bind the checkpoint state")
        selected_checkpoint = _validate_current_terminal_state(
            candidate_state,
            candidate=candidate,
            acquisition_schema_version=acquisition_schema_version,
            kind=kind,
            reason=reason,
            terminalised_at=_timestamp(terminalised_raw),
            enforce_duration_limit=(acquisition_schema_version in _DURATION_LIMIT_SCHEMA_VERSIONS),
        )
    stability_binding = payload["stability_receipt"]
    workload_binding = payload["admitted_workload"]
    if kind == "eligible":
        if not isinstance(stability_binding, Mapping) or not isinstance(workload_binding, Mapping):
            raise ValueError("eligible terminal lacks transitive evidence bindings")
        stability_path = _verified_bound_file(stability_binding, label="eligible stability receipt")
        workload_path = _verified_bound_file(workload_binding, label="eligible admitted workload")
        from .class_catalogue import load_stability_receipt

        stability_value, decision = load_stability_receipt(stability_path)
        stability_payload = validate_hash_bound_receipt(
            stability_value, expected_type="qcsd-class-study-page-stability"
        )
        if (
            not decision.eligible
            or stability_payload["candidate"]["candidate_id"] != candidate.candidate_id
            or stability_payload["candidate"]["domain"] != candidate.domain
            or stability_payload["decision"]["stable_values"]["prepared_workload_sha256"]
            != sha256_file(workload_path)
        ):
            raise ValueError("eligible terminal stability/workload binding is invalid")
        if acquisition_schema_version in _TERMINAL_STATE_SCHEMA_VERSIONS:
            if selected_checkpoint is None:
                raise ValueError("eligible terminal has no selected checkpoint page")
            page_state, page, observations = selected_checkpoint
            expected_candidate = {
                "candidate_id": candidate.candidate_id,
                "domain": candidate.domain,
                "rank": candidate.rank,
                "stratum": candidate.stratum.id,
            }
            if (
                stability_path.name != f"page-{page.ordinal:02d}.json"
                or stability_path.parent.name != candidate.candidate_id
                or workload_path.name != f"{candidate.candidate_id}.json"
                or stability_payload["candidate"] != expected_candidate
                or stability_payload["page"] != page.as_dict()
                or stability_payload["baseline_started_at"]
                != candidate_state["baseline_started_at"]
                or stability_payload["observations"]
                != [observation.as_dict() for observation in observations]
                or stability_payload["decision"]
                != derive_stability_decision(
                    page,
                    baseline_started_at=candidate_state["baseline_started_at"],
                    observations=observations,
                ).as_dict()
                or page_state["observations"][0]["prepared_workload_sha256"]
                != sha256_file(workload_path)
            ):
                raise ValueError("eligible terminal does not match its exact checkpoint selection")
    elif stability_binding is not None or workload_binding is not None:
        raise ValueError("ineligible terminal unexpectedly binds admitted evidence")
    return {
        "path": f"terminals/{candidate.candidate_id}.json",
        "sha256": sha256_file(terminal),
    }


def _foundation_attestation_binding(path: Path) -> dict[str, str]:
    """Deep-validate the exact foundation authority used by a live runner."""

    source = Path(os.path.abspath(path))
    if source.is_symlink() or not source.is_file():
        raise ValueError("class acquisition foundation must be a regular file")
    # Keep this import lazy: class_attestation validates acquisition completion
    # evidence and therefore imports this module.
    from .class_attestation import validate_class_foundation_attestation

    validated = validate_class_foundation_attestation(
        source,
        deep_code_gate=True,
        runtime_role="prepare",
    )
    binding = {"path": str(source), "sha256": sha256_file(source)}
    if validated.get("path") != binding["path"] or validated.get("sha256") != binding["sha256"]:
        raise ValueError("class acquisition foundation validator returned another binding")
    return binding


def _acquisition_authority_binding(path: Path) -> dict[str, str]:
    """Validate narrow current authority, or the unchanged full-foundation fallback."""

    source = Path(os.path.abspath(path))
    if source.is_symlink() or not source.is_file():
        raise ValueError("class acquisition authority must be a regular file")
    value = load_json(source)
    if source.read_bytes() != canonical_json_bytes(value):
        raise ValueError("class acquisition authority is not canonically encoded")
    if value.get("receipt_type") == "qcsd-class-study-foundation-attestation":
        return _foundation_attestation_binding(source)
    from .class_attestation import (
        ACQUISITION_AUTHORITY_RECEIPT_TYPE,
        validate_class_acquisition_authority,
    )

    validate_hash_bound_receipt(value, expected_type=ACQUISITION_AUTHORITY_RECEIPT_TYPE)
    validated = validate_class_acquisition_authority(source, runtime_role="prepare")
    binding = {"path": str(source), "sha256": sha256_file(source)}
    if any(validated.get(key) != item for key, item in binding.items()):
        raise ValueError("class acquisition authority validator returned another binding")
    return binding


def _validate_current_provenance_contract(
    provenance: Mapping[str, Any],
    *,
    candidate_catalogue_path: Path | None = None,
) -> dict[str, Any]:
    """Reconstruct schema-five-through-nine provenance without schema collision.

    Historical acquisition schemas remain readable under their original
    contracts.  Current evidence, however, must retain every fixed acquisition
    choice and the exact pinned browser identity even when it is verified from
    a collection image or an exported evidence tree rather than the live
    prepare process that created it.
    """

    schema = (
        provenance.get("acquisition_schema_version") if isinstance(provenance, Mapping) else None
    )
    fields = SCHEMA_FIVE_PROVENANCE_FIELDS if schema == 5 else CURRENT_PROVENANCE_FIELDS
    if not isinstance(provenance, Mapping) or set(provenance) != fields:
        raise ValueError("versioned acquisition provenance fields differ from the contract")
    foundation = provenance.get(
        "foundation_attestation" if schema == 5 else "acquisition_authority"
    )
    source = provenance.get("source")
    candidate_count = provenance.get("candidate_count")
    image_digest = provenance.get("image_digest")
    started_at = provenance.get("started_at")
    if (
        type(provenance.get("acquisition_schema_version")) is not int
        or provenance["acquisition_schema_version"] not in _FIXED_PROVENANCE_SCHEMA_VERSIONS
        or provenance.get("study_id") != "classifier-multiorigin100-v1"
        or type(candidate_count) is not int
        or candidate_count < 1
        or not isinstance(provenance.get("candidate_catalogue_sha256"), str)
        or _SHA256_PATTERN.fullmatch(provenance["candidate_catalogue_sha256"]) is None
        or not isinstance(provenance.get("candidate_catalogue_payload_sha256"), str)
        or _SHA256_PATTERN.fullmatch(provenance["candidate_catalogue_payload_sha256"]) is None
        or not isinstance(foundation, Mapping)
        or set(foundation) != {"path", "sha256"}
        or not isinstance(foundation.get("path"), str)
        or not foundation["path"]
        or not isinstance(foundation.get("sha256"), str)
        or _SHA256_PATTERN.fullmatch(foundation["sha256"]) is None
        or not isinstance(started_at, str)
        or _format_time(_timestamp(started_at)) != started_at
        or not isinstance(image_digest, str)
        or image_digest != "native"
        and _IMAGE_DIGEST_PATTERN.fullmatch(image_digest) is None
        or not isinstance(source, Mapping)
        or set(source) != _SOURCE_FIELDS
    ):
        raise ValueError("versioned acquisition provenance identity is invalid")
    fixed_fields = set(_FIXED_PROVENANCE_FIELDS)
    if schema in _SELECTION_SCHEMA_VERSIONS:
        fixed_fields.add("acquisition_selection_policy")
    fixed_projection = {field: provenance.get(field) for field in fixed_fields}
    if schema in {5, 6, 7, 8}:
        try:
            contract = _historical_evidence_contract_for(
                schema,
                instrumentation_policy=provenance.get("cdp_target_instrumentation_policy"),
            )
        except ValueError as error:
            raise ValueError(
                "versioned acquisition provenance policy differs from the contract"
            ) from error
        expected_fixed_sha256 = contract["fixed_provenance_sha256"]
        if not isinstance(expected_fixed_sha256, str):
            raise ValueError("versioned acquisition provenance contract is incomplete")
        source_lab_commits = contract["source_lab_commits"]
        fixed_contract_valid = (
            sha256_bytes(canonical_json_bytes(fixed_projection)) == expected_fixed_sha256
            and isinstance(source_lab_commits, tuple)
            and source.get("lab_commit") in source_lab_commits
        )
    else:
        expected_fixed = {
            "browser_tool": expected_browser_tool_identity(),
            "navigation_implementation": NAVIGATION_IMPLEMENTATION,
            "cdp_target_instrumentation_policy": CDP_TARGET_INSTRUMENTATION_POLICY,
            "non_replayable_egress_contract": NON_REPLAYABLE_EGRESS_CONTRACT,
            "passive_render_contract": PASSIVE_RENDER_CONTRACT,
            "passive_render_contract_sha256": PASSIVE_RENDER_CONTRACT_SHA256,
            "browser_navigation_timeout_ms": MAX_ACQUISITION_BACKEND_TIMEOUT_MS,
            "passive_render_hard_cap_after_load_ms": MAX_PASSIVE_RENDER_AFTER_LOAD_MS,
            "acquisition_action_timing_contract": ACTION_TIMING_CONTRACT,
            "baseline_scheduling_contract": TERMINAL_RELEASE_BASELINE_SCHEDULING_CONTRACT,
            "acquisition_selection_policy": ACQUISITION_SELECTION_POLICY,
            "registrable_domain_policy": REGISTRABLE_DOMAIN_POLICY,
            "domain_safety_policy": DOMAIN_SAFETY_POLICY,
            "domain_safety_policy_sha256": sha256_bytes(canonical_json_bytes(DOMAIN_SAFETY_POLICY)),
            "origin_policy": ORIGIN_POLICY,
            "eligibility_inputs": ELIGIBILITY_INPUTS,
            "prohibited_inputs": PROHIBITED_INPUTS,
        }
        fixed_contract_valid = _matches_json_contract(fixed_projection, expected_fixed)
    if not fixed_contract_valid:
        raise ValueError("versioned acquisition provenance policy differs from the contract")
    browser_tool = provenance["browser_tool"]
    if (
        not isinstance(browser_tool, Mapping)
        or type(browser_tool.get("schema_version")) is not int
        or browser_tool["schema_version"] != 1
    ):
        raise ValueError("versioned acquisition browser identity is invalid")

    # A native unit-test runner cannot claim immutable image provenance.  Any
    # actual image-bound acquisition can and must carry one clean source.
    if image_digest == "native":
        if source.get("image_digest") not in {None, "native"}:
            raise ValueError("native versioned acquisition source is inconsistent")
    elif (
        source.get("image_digest") != image_digest
        or not isinstance(source.get("lab_commit"), str)
        or _COMMIT_PATTERN.fullmatch(source["lab_commit"]) is None
        or not isinstance(source.get("neqo_commit"), str)
        or _COMMIT_PATTERN.fullmatch(source["neqo_commit"]) is None
        or source.get("neqo_pinned_commit") != source.get("neqo_commit")
        or source.get("lab_dirty") is not False
        or source.get("neqo_dirty") is not False
        or source.get("lab_patch_sha256") != _EMPTY_SHA256
        or source.get("neqo_patch_sha256") != _EMPTY_SHA256
    ):
        raise ValueError("versioned acquisition source is not one clean immutable image")

    if candidate_catalogue_path is not None:
        catalogue_path = Path(candidate_catalogue_path)
        catalogue, candidates = load_candidate_catalogue_receipt(catalogue_path)
        if (
            provenance["candidate_catalogue_sha256"] != sha256_file(catalogue_path)
            or provenance["candidate_catalogue_payload_sha256"] != catalogue["payload_sha256"]
            or candidate_count != len(candidates)
        ):
            raise ValueError("versioned acquisition provenance binds another catalogue")
    return dict(provenance)


def _validate_runner_runtime(provenance: Mapping[str, Any]) -> None:
    """Prevent later stability probes from changing the frozen prepare image."""

    schema_version = provenance.get("acquisition_schema_version")
    uses_acquisition_authority = schema_version in _SELECTION_SCHEMA_VERSIONS
    foundation = provenance.get(
        "acquisition_authority" if uses_acquisition_authority else "foundation_attestation"
    )
    if not isinstance(foundation, Mapping):
        raise ValueError("class acquisition provenance has no foundation binding")
    foundation_path = _verified_bound_file(foundation, label="class acquisition foundation")
    validate_authority = (
        _acquisition_authority_binding
        if uses_acquisition_authority
        else _foundation_attestation_binding
    )
    if validate_authority(foundation_path) != dict(foundation):
        raise ValueError("class acquisition foundation binding changed")
    current_image = os.environ.get("QCSD_LAB_IMAGE_DIGEST", "native")
    current_source = source_metadata()
    if type(schema_version) is int and schema_version in _FIXED_PROVENANCE_SCHEMA_VERSIONS:
        _validate_current_provenance_contract(provenance)
    if (
        provenance.get("image_digest") != current_image
        or provenance.get("source") != current_source
        or type(schema_version) is not int
        or schema_version not in SUPPORTED_SCHEMA_VERSIONS
    ):
        raise ValueError("class acquisition runtime differs from its frozen source/prepare image")


def _validate_document_response_receipt(
    observation: Mapping[str, Any],
    *,
    page: Mapping[str, Any],
    prepared_path: Path,
    runner_root: Path,
    provenance_sha256: str,
    runner_provenance: Mapping[str, Any],
    approved_origins: Sequence[str],
    origin_ip_pins: Mapping[str, str],
    chromium_version: str,
    neqo_provenance: Mapping[str, str],
) -> None:
    workload_id = prepared_path.stem
    runner = Path(os.path.abspath(runner_root))
    prepared_root = runner / "prepared-probes"
    expected_prepared = (prepared_root / f"{workload_id}.json").resolve(strict=False)
    if (
        prepared_root.is_symlink()
        or not prepared_root.is_dir()
        or str(prepared_path) != str(expected_prepared)
    ):
        raise ValueError("checkpoint prepared workload path is not canonical")
    relative = f"document-response-receipts/{workload_id}.json"
    if observation.get("document_response_receipt_path") != relative:
        raise ValueError("checkpoint document-response receipt path is not canonical")
    receipt_path = runner / relative
    if receipt_path.is_symlink() or not receipt_path.is_file():
        raise ValueError("checkpoint document-response receipt is not a regular file")
    receipt = load_json(receipt_path)
    if receipt_path.read_bytes() != canonical_json_bytes(receipt):
        raise ValueError("checkpoint document-response receipt is not canonical JSON")
    if sha256_file(receipt_path) != observation.get("document_response_receipt_sha256"):
        raise ValueError("checkpoint document-response receipt SHA-256 does not verify")
    payload = validate_hash_bound_receipt(receipt, expected_type=DOCUMENT_RESPONSE_RECEIPT_TYPE)
    page_identity = page.get("page")
    requested_url = page_identity.get("url") if isinstance(page_identity, Mapping) else None
    content_type = _normalise_content_type(str(observation.get("content_type", "")))
    if observation.get("content_type") != content_type:
        raise ValueError("checkpoint document response content type is not normalised")
    expected_payload = {
        "document_response_schema_version": _document_response_schema_for(
            runner_provenance["acquisition_schema_version"],
            instrumentation_policy=runner_provenance.get("cdp_target_instrumentation_policy"),
        ),
        "workload_id": workload_id,
        "requested_url": requested_url,
        "final_url": observation.get("final_url"),
        "status": observation.get("status"),
        "content_type": content_type,
        "body_bytes": observation.get("body_bytes"),
        "body_sha256": observation.get("body_sha256"),
        "resource_graph_sha256": observation.get("resource_graph_sha256"),
        "prepared_workload_sha256": observation.get("prepared_workload_sha256"),
        "probe_started_at": observation.get("observed_at"),
        "response_observed_at": observation.get("probe_completed_at"),
        "approved_origins": list(approved_origins),
        "origin_ip_pins": dict(origin_ip_pins),
        "origin_ip_pins_sha256": evidence_sha256(origin_ip_pins),
        "chromium_version": chromium_version,
        "preparation_chromium_version": chromium_version,
        "neqo_provenance": dict(neqo_provenance),
        "cdp_target_instrumentation_policy": _instrumentation_policy_for(
            runner_provenance["acquisition_schema_version"],
            recorded_policy=runner_provenance.get("cdp_target_instrumentation_policy"),
        ),
        "browser_tool": runner_provenance["browser_tool"],
        "runner_provenance_sha256": provenance_sha256,
        "image_digest": runner_provenance["image_digest"],
        "source": runner_provenance["source"],
    }
    if payload != expected_payload:
        raise ValueError("checkpoint document-response receipt differs from its observation")


def _validate_observation_provenance(
    states: Mapping[str, Any],
    *,
    provenance_sha256: str,
    runner_provenance: Mapping[str, Any],
    runner_root: Path | None = None,
    include_nonterminal: bool = False,
) -> dict[str, Any] | None:
    identities: dict[str, dict[str, Any]] = {}
    acquisition_schema_version = runner_provenance.get("acquisition_schema_version")
    require_instrumentation_evidence = (
        acquisition_schema_version in _INSTRUMENTATION_EVIDENCE_SCHEMA_VERSIONS
    )
    require_current_evidence = acquisition_schema_version in _RENDER_EVIDENCE_SCHEMA_VERSIONS
    expected_instrumentation_policy = (
        _instrumentation_policy_for(
            acquisition_schema_version,
            recorded_policy=runner_provenance.get("cdp_target_instrumentation_policy"),
        )
        if require_instrumentation_evidence
        else None
    )
    expected_passive_render_sha256 = (
        _passive_render_contract_sha256_for(acquisition_schema_version)
        if require_current_evidence
        else None
    )
    prepared_root: Path | None = None
    if require_current_evidence:
        if runner_root is None:
            raise ValueError("current checkpoint validation requires its runner root")
        prepared_root = Path(os.path.abspath(runner_root)) / "prepared-probes"
        if prepared_root.is_symlink() or not prepared_root.is_dir():
            raise ValueError("acquisition prepared-probe root is not a regular directory")
    for state in states.values():
        if state.get("terminal") is None and not include_nonterminal:
            continue
        for page in state.get("pages", []):
            approved = page.get("approved_origins", [])
            if not isinstance(approved, list) or len(approved) > MAX_APPROVED_ORIGINS:
                raise ValueError("checkpoint approved-origin evidence is invalid")
            for observation in page.get("observations", []):
                if not isinstance(observation, Mapping):
                    raise ValueError("checkpoint observation is not an object")
                if acquisition_schema_version == 1 and set(observation) != (
                    SCHEMA_ONE_OBSERVATION_FIELDS
                ):
                    raise ValueError(
                        "schema-one checkpoint observation fields differ from the contract"
                    )
                # No schema-two producer or artifact exists in repository history.
                # Preserve bbc0be9's declared verifier contract for that version:
                # instrumentation is required below, but its observation set was
                # intentionally non-exact.  Schemas three and four bind the full
                # render/preparation shape and therefore require the exact set.
                if require_current_evidence and set(observation) != CURRENT_OBSERVATION_FIELDS:
                    raise ValueError(
                        "checkpoint observation fields differ from the versioned contract"
                    )
                observation_approved = observation.get("approved_origins")
                discovered = observation.get("discovery_observed_origins")
                expandable = observation.get("discovery_expandable_origins")
                pins = observation.get("discovery_origin_ip_pins")
                neqo = observation.get("neqo_provenance")
                chromium = observation.get("chromium_version")
                render_observation = observation.get("render_observation")
                render_observation_sha256 = observation.get("render_observation_sha256")
                discovery_event_audit_sha256 = observation.get("discovery_event_audit_sha256")
                prepared_path_value = observation.get("prepared_path")
                prepared_path = (
                    Path(prepared_path_value) if isinstance(prepared_path_value, str) else None
                )
                approved_ledger_valid = _is_canonical_origin_ledger(
                    observation_approved,
                    maximum=MAX_APPROVED_ORIGINS,
                    allow_empty=False,
                )
                pins_valid = False
                if approved_ledger_valid and isinstance(pins, Mapping):
                    try:
                        pins_valid = _validated_frozen_origin_ip_pins(
                            observation_approved, pins
                        ) == dict(pins)
                    except TerminalProbePolicyError:
                        pass
                current_evidence_invalid = require_current_evidence and (
                    observation.get("discovery_instrumentation_policy")
                    != expected_instrumentation_policy
                    or observation.get("passive_render_contract_sha256")
                    != expected_passive_render_sha256
                    or not isinstance(render_observation, Mapping)
                    or not isinstance(render_observation_sha256, str)
                    or evidence_sha256(render_observation) != render_observation_sha256
                    or not isinstance(discovery_event_audit_sha256, str)
                    or len(discovery_event_audit_sha256) != 64
                    or any(
                        character not in "0123456789abcdef"
                        for character in discovery_event_audit_sha256
                    )
                    or prepared_path is None
                    or prepared_root is None
                    or Path(os.path.abspath(prepared_path)).parent != prepared_root
                    or str(prepared_path)
                    != str((prepared_root / prepared_path.name).resolve(strict=False))
                    or prepared_path.is_symlink()
                    or not prepared_path.is_file()
                    or sha256_file(prepared_path) != observation.get("prepared_workload_sha256")
                )
                if (
                    observation.get("runner_provenance_sha256") != provenance_sha256
                    or (
                        require_instrumentation_evidence
                        and observation.get("discovery_instrumentation_policy")
                        != expected_instrumentation_policy
                    )
                    or not approved_ledger_valid
                    or not _is_canonical_origin_ledger(
                        discovered,
                        maximum=MAX_OBSERVED_AUDIT_ORIGINS,
                        allow_empty=False,
                    )
                    or not _is_canonical_origin_ledger(
                        expandable,
                        maximum=MAX_APPROVED_ORIGINS,
                        allow_empty=False,
                    )
                    or not set(expandable).issubset(discovered)
                    or not set(expandable).issubset(observation_approved)
                    or not pins_valid
                    or not isinstance(chromium, str)
                    or not chromium
                    or current_evidence_invalid
                    or not isinstance(neqo, Mapping)
                    or not neqo
                    or _timestamp(observation["probe_completed_at"])
                    < _timestamp(observation["observed_at"])
                ):
                    raise ValueError("checkpoint observation provenance is invalid")
                if require_current_evidence:
                    assert isinstance(render_observation, Mapping)
                    assert prepared_path is not None
                    try:
                        _validate_versioned_render_observation(
                            render_observation,
                            acquisition_schema_version=acquisition_schema_version,
                        )
                        prepared_manifest = load_json(prepared_path)
                        _validate_versioned_class_study_preparation(
                            prepared_manifest,
                            workload_id=prepared_path.stem,
                            acquisition_schema_version=acquisition_schema_version,
                            instrumentation_policy=expected_instrumentation_policy,
                        )
                    except (OSError, TypeError, ValueError) as error:
                        raise ValueError(
                            "checkpoint bounded-render preparation evidence is invalid"
                        ) from error
                    prepared_evidence = prepared_manifest["preparation"]
                    expected = _prepared_primary_response(prepared_manifest)
                    expected_neqo = {
                        key: str(prepared_evidence[key])
                        for key in (
                            "neqo_version",
                            "neqo_base_commit",
                            "published_qcsd_commit",
                            "migration_commit",
                        )
                    }
                    preparation_pins = prepared_evidence.get("origin_ip_pins")
                    expected_runner_source = dict(runner_provenance.get("source", {}))
                    if (
                        runner_provenance.get("image_digest") == "native"
                        and expected_runner_source.get("image_digest") is None
                    ):
                        expected_runner_source["image_digest"] = "native"
                    if (
                        prepared_evidence["passive_render_contract_sha256"]
                        != observation["passive_render_contract_sha256"]
                        or prepared_evidence["render_observation_sha256"]
                        != render_observation_sha256
                        or prepared_evidence["render_observation"] != render_observation
                        or prepared_evidence["discovery_event_audit_sha256"]
                        != discovery_event_audit_sha256
                        or observation.get("final_url") != prepared_evidence["final_url"]
                        or observation.get("status") != expected["status"]
                        or observation.get("body_bytes") != expected["bytes"]
                        or observation.get("body_sha256") != expected["body_sha256"]
                        or observation.get("resource_graph_sha256")
                        != _prepared_replay_identity_sha256(
                            prepared_manifest,
                            acquisition_schema_version=acquisition_schema_version,
                        )
                        or observation_approved != prepared_evidence["approved_origins"]
                        or observation.get("preparation_origin_ip_pins") != preparation_pins
                        or pins != preparation_pins
                        or chromium != prepared_evidence["chromium_version"]
                        or neqo != expected_neqo
                        or prepared_evidence.get("prepare_image_digest")
                        != runner_provenance.get("image_digest")
                        or prepared_evidence.get("lab_source") != expected_runner_source
                    ):
                        raise ValueError(
                            "checkpoint observation differs from its prepared discovery evidence"
                        )
                    _validate_document_response_receipt(
                        observation,
                        page=page,
                        prepared_path=prepared_path,
                        runner_root=runner_root,
                        provenance_sha256=provenance_sha256,
                        runner_provenance=runner_provenance,
                        approved_origins=observation_approved,
                        origin_ip_pins=preparation_pins,
                        chromium_version=chromium,
                        neqo_provenance=expected_neqo,
                    )
                identity = {"chromium_version": chromium, "neqo_provenance": dict(neqo)}
                identities[sha256_bytes(canonical_json_bytes(identity))] = identity
    if not identities:
        return None
    if len(identities) != 1:
        raise ValueError("checkpoint mixes browser or Neqo toolchain identities")
    [identity] = identities.values()
    return {
        **identity,
        "image_digest": runner_provenance["image_digest"],
        "source": runner_provenance["source"],
    }


def _is_canonical_origin_ledger(
    value: object,
    *,
    maximum: int,
    allow_empty: bool,
) -> bool:
    if (
        not isinstance(value, list)
        or (not allow_empty and not value)
        or len(value) > maximum
        or any(not isinstance(candidate, str) for candidate in value)
        or value != sorted(set(value))
    ):
        return False
    return all(origin(candidate) == candidate for candidate in value)


def _probe_attempt_workload_id(
    candidate_id: str, page_ordinal: int, probe_id: str, attempt: int
) -> str:
    if (
        not isinstance(candidate_id, str)
        or not candidate_id
        or type(page_ordinal) is not int
        or page_ordinal < 0
        or probe_id not in {window.probe_id for window in STABILITY_PROBE_WINDOWS}
        or type(attempt) is not int
        or attempt < 1
    ):
        raise ValueError("acquisition probe attempt identity is invalid")
    return f"{candidate_id}-p{page_ordinal:02d}-{probe_id.replace('+', '')}-a{attempt:03d}"


def _validate_pending_probe(
    pending: object,
    *,
    candidate_id: str,
    page_ordinal: int,
    probe_id: str,
) -> tuple[int, datetime]:
    if not isinstance(pending, Mapping) or set(pending) != {
        "probe_id",
        "workload_id",
        "attempt",
        "observed_at",
    }:
        raise ValueError("pending acquisition probe checkpoint is malformed")
    attempt = pending["attempt"]
    if (
        type(attempt) is not int
        or attempt < 1
        or pending["probe_id"] != probe_id
        or pending["workload_id"]
        != _probe_attempt_workload_id(candidate_id, page_ordinal, probe_id, attempt)
        or not isinstance(pending["observed_at"], str)
    ):
        raise ValueError("pending acquisition probe checkpoint is malformed")
    return attempt, _timestamp(pending["observed_at"])


def _validate_pending_navigation(pending: object) -> tuple[int, datetime]:
    if not isinstance(pending, Mapping) or set(pending) != {"attempt", "started_at"}:
        raise ValueError("pending acquisition navigation checkpoint is malformed")
    attempt = pending["attempt"]
    if (
        type(attempt) is not int
        or not 1 <= attempt <= MAX_PROBE_ATTEMPTS
        or not isinstance(pending["started_at"], str)
    ):
        raise ValueError("pending acquisition navigation checkpoint is malformed")
    return attempt, _timestamp(pending["started_at"])


def _validate_navigation_attempts(
    state: Mapping[str, Any],
    *,
    acquisition_schema_version: int = SCHEMA_VERSION,
    enforce_duration_limit: bool = False,
    require_canonical_timestamps: bool = False,
) -> None:
    if acquisition_schema_version not in SUPPORTED_SCHEMA_VERSIONS:
        raise ValueError("acquisition navigation-attempt schema is unsupported")
    attempts = state.get("navigation_attempts", [])
    if not isinstance(attempts, list) or len(attempts) > MAX_PROBE_ATTEMPTS:
        raise ValueError("acquisition navigation-attempt ledger is malformed")
    expected_attempt = 1
    completed = 0
    finalised = False
    for item in attempts:
        expected_fields = {
            "attempt",
            "started_at",
            "completed_at",
            "outcome",
            "reason",
        }
        if acquisition_schema_version in _POLICY_EVIDENCE_SCHEMA_VERSIONS:
            expected_fields.add("policy_evidence")
        if not isinstance(item, Mapping) or set(item) != expected_fields:
            raise ValueError("acquisition navigation-attempt ledger is malformed")
        policy_evidence = item.get("policy_evidence")
        if policy_evidence is not None:
            if item.get("outcome") != "terminal-policy-rejection":
                raise ValueError("acquisition navigation policy evidence is misplaced")
            validate_non_replayable_egress_failure_evidence(policy_evidence)
        started_at = (
            _timestamp(item["started_at"]) if isinstance(item.get("started_at"), str) else None
        )
        completed_at = (
            _timestamp(item["completed_at"]) if isinstance(item.get("completed_at"), str) else None
        )
        if (
            type(item["attempt"]) is not int
            or item["attempt"] != expected_attempt
            or finalised
            or item["outcome"]
            not in {
                "completed",
                "interrupted",
                "internal-acquisition-error",
                "recoverable-failure",
                "terminal-policy-rejection",
            }
            or not isinstance(item["started_at"], str)
            or not isinstance(item["completed_at"], str)
            or started_at is None
            or completed_at is None
            or (
                require_canonical_timestamps
                and (
                    _format_time(started_at) != item["started_at"]
                    or _format_time(completed_at) != item["completed_at"]
                )
            )
            or completed_at < started_at
            or (
                enforce_duration_limit
                and item["outcome"] == "completed"
                and (completed_at - started_at).total_seconds() * 1_000
                > ACTION_TIMING_CONTRACT["successful_ledger_attempt_duration_limit_ms"]
            )
            or (item["outcome"] == "completed" and item["reason"] is not None)
            or (
                item["outcome"] != "completed"
                and (not isinstance(item["reason"], str) or not item["reason"])
            )
            or (
                acquisition_schema_version in _POLICY_EVIDENCE_SCHEMA_VERSIONS
                and item["outcome"] != "terminal-policy-rejection"
                and policy_evidence is not None
            )
        ):
            raise ValueError("acquisition navigation-attempt ledger is malformed")
        completed += item["outcome"] == "completed"
        finalised = item["outcome"] in {
            "completed",
            "internal-acquisition-error",
            "terminal-policy-rejection",
        }
        expected_attempt += 1
    if completed > 1:
        raise ValueError("acquisition navigation-attempt ledger duplicates success")
    if completed and state.get("state") == "pending":
        raise ValueError("pending acquisition candidate already completed navigation")
    pending = state.get("pending_navigation")
    if pending is not None:
        attempt, _started = _validate_pending_navigation(pending)
        if attempt != expected_attempt:
            raise ValueError("pending acquisition navigation attempt is not sequential")


def _validated_terminal_policy_evidence(
    value: object,
    *,
    allow_non_replayable_egress: bool,
    acquisition_schema_version: int = SCHEMA_VERSION,
) -> dict[str, Any]:
    """Validate the closed union of content-minimised terminal-policy receipts."""

    if not isinstance(value, Mapping):
        raise ValueError("acquisition policy evidence is malformed")
    if set(value) == {
        "non_replayable_egress",
        "non_replayable_egress_sha256",
    }:
        if not allow_non_replayable_egress:
            raise ValueError("historical acquisition cannot contain egress policy evidence")
        return validate_non_replayable_egress_failure_evidence(value)
    expected_policy_fields = {
        "passive_render_contract",
        "passive_render_contract_sha256",
        "render_observation",
        "render_observation_sha256",
    }
    passive_render_contract = _passive_render_contract_for(acquisition_schema_version)
    passive_render_contract_sha256 = _passive_render_contract_sha256_for(acquisition_schema_version)
    if (
        set(value) != expected_policy_fields
        or not _matches_json_contract(value["passive_render_contract"], passive_render_contract)
        or value["passive_render_contract_sha256"] != passive_render_contract_sha256
        or evidence_sha256(value["render_observation"]) != value["render_observation_sha256"]
    ):
        raise ValueError("acquisition passive-render policy evidence does not verify")
    _validate_versioned_render_observation(
        value["render_observation"],
        acquisition_schema_version=acquisition_schema_version,
        allow_failure=True,
    )
    return deepcopy(dict(value))


def _validate_probe_attempts(
    page: Mapping[str, Any],
    *,
    candidate_id: str,
    acquisition_schema_version: int = SCHEMA_VERSION,
    baseline_started_at: str | None = None,
    enforce_duration_limit: bool = False,
    require_canonical_timestamps: bool = False,
    require_observation_attempt_bindings: bool = False,
) -> None:
    attempts = page.get("probe_attempts", [])
    if not isinstance(attempts, list):
        raise ValueError("acquisition probe-attempt ledger is malformed")
    seen: set[tuple[str, int]] = set()
    successful: set[str] = set()
    completed_attempts: dict[str, Mapping[str, Any]] = {}
    finalised: set[str] = set()
    probe_ids = tuple(window.probe_id for window in STABILITY_PROBE_WINDOWS)
    expected_attempts = {probe_id: 1 for probe_id in probe_ids}
    for item in attempts:
        base_fields = {
            "probe_id",
            "workload_id",
            "attempt",
            "observed_at",
            "completed_at",
            "outcome",
            "reason",
        }
        expected_fields = (
            base_fields | {"policy_evidence"}
            if acquisition_schema_version in _POLICY_EVIDENCE_SCHEMA_VERSIONS
            else base_fields
        )
        if not isinstance(item, Mapping) or set(item) != expected_fields:
            raise ValueError("acquisition probe-attempt ledger is malformed")
        policy_evidence = item.get("policy_evidence")
        if policy_evidence is not None:
            if item.get("outcome") != "terminal-policy-rejection":
                raise ValueError("acquisition probe policy evidence is malformed")
            _validated_terminal_policy_evidence(
                policy_evidence,
                allow_non_replayable_egress=(
                    acquisition_schema_version in _POLICY_EVIDENCE_SCHEMA_VERSIONS
                ),
                acquisition_schema_version=acquisition_schema_version,
            )
        probe_id = item["probe_id"]
        attempt = item["attempt"]
        probe_index = probe_ids.index(probe_id) if probe_id in probe_ids else -1
        observed_at = (
            _timestamp(item["observed_at"]) if isinstance(item.get("observed_at"), str) else None
        )
        start_in_window = True
        if observed_at is not None and baseline_started_at is not None and probe_index >= 0:
            window = STABILITY_PROBE_WINDOWS[probe_index]
            elapsed = observed_at - _timestamp(baseline_started_at)
            start_in_window = (
                timedelta(milliseconds=window.earliest_ms)
                <= elapsed
                <= timedelta(milliseconds=window.latest_ms)
            )
        completed_at = (
            _timestamp(item["completed_at"]) if isinstance(item.get("completed_at"), str) else None
        )
        if (
            probe_index < 0
            or any(previous not in successful for previous in probe_ids[:probe_index])
            or type(attempt) is not int
            or not 1 <= attempt <= MAX_PROBE_ATTEMPTS
            or attempt != expected_attempts.get(probe_id)
            or probe_id in finalised
            or item["workload_id"]
            != _probe_attempt_workload_id(
                candidate_id,
                page["page"]["ordinal"],
                probe_id,
                attempt,
            )
            or (probe_id, attempt) in seen
            or item["outcome"]
            not in {
                "completed",
                "interrupted",
                "internal-acquisition-error",
                "recoverable-failure",
                "terminal-policy-rejection",
            }
            or not isinstance(item["observed_at"], str)
            or not start_in_window
            or not isinstance(item["completed_at"], str)
            or completed_at is None
            or observed_at is None
            or (
                require_canonical_timestamps
                and (
                    _format_time(observed_at) != item["observed_at"]
                    or _format_time(completed_at) != item["completed_at"]
                )
            )
            or completed_at < observed_at
            or (
                enforce_duration_limit
                and item["outcome"] == "completed"
                and (completed_at - observed_at).total_seconds() * 1_000
                > ACTION_TIMING_CONTRACT["successful_ledger_attempt_duration_limit_ms"]
            )
            or (item["outcome"] == "completed" and item["reason"] is not None)
            or (
                item["outcome"] != "completed"
                and (not isinstance(item["reason"], str) or not item["reason"])
            )
        ):
            raise ValueError("acquisition probe-attempt ledger is malformed")
        seen.add((probe_id, attempt))
        expected_attempts[probe_id] += 1
        if item["outcome"] == "completed":
            if probe_id in successful:
                raise ValueError("acquisition probe-attempt ledger duplicates success")
            successful.add(probe_id)
            completed_attempts[probe_id] = item
            finalised.add(probe_id)
        elif item["outcome"] == "terminal-policy-rejection":
            finalised.add(probe_id)
        elif item["outcome"] == "internal-acquisition-error":
            finalised.add(probe_id)
    observations = page.get("observations", [])
    if (
        not isinstance(observations, list)
        or len(observations) > len(probe_ids)
        or any(not isinstance(observation, Mapping) for observation in observations)
    ):
        raise ValueError("acquisition probe observation sequence is malformed")
    observation_sequence = [observation.get("probe_id") for observation in observations]
    if observation_sequence != list(probe_ids[: len(observation_sequence)]):
        raise ValueError("acquisition probe observation sequence is malformed")
    observation_ids = set(observation_sequence)
    if successful != observation_ids:
        raise ValueError("acquisition probe-attempt success ledger is inconsistent")
    if require_observation_attempt_bindings:
        for observation in observations:
            probe_id = observation.get("probe_id")
            completed_attempt = completed_attempts.get(probe_id)
            prepared_path = observation.get("prepared_path")
            receipt_path = observation.get("document_response_receipt_path")
            probe_completed_at = observation.get("probe_completed_at")
            if (
                completed_attempt is None
                or observation.get("observed_at") != completed_attempt.get("observed_at")
                or not isinstance(prepared_path, str)
                or Path(prepared_path).stem != completed_attempt.get("workload_id")
                or receipt_path
                != f"document-response-receipts/{completed_attempt.get('workload_id')}.json"
                or not isinstance(probe_completed_at, str)
                or _format_time(_timestamp(probe_completed_at)) != probe_completed_at
                or _timestamp(probe_completed_at) < _timestamp(completed_attempt["observed_at"])
                or _timestamp(probe_completed_at) > _timestamp(completed_attempt["completed_at"])
            ):
                raise ValueError("acquisition observation differs from its completed attempt")
    pending = page.get("pending_probe")
    if pending is not None:
        observation_count = len(page.get("observations", []))
        if observation_count >= len(STABILITY_PROBE_WINDOWS):
            raise ValueError("completed acquisition page retains a pending probe")
        probe_id = STABILITY_PROBE_WINDOWS[observation_count].probe_id
        attempt, _started = _validate_pending_probe(
            pending,
            candidate_id=candidate_id,
            page_ordinal=page["page"]["ordinal"],
            probe_id=probe_id,
        )
        if attempt != expected_attempts[probe_id] or probe_id in finalised:
            raise ValueError("pending acquisition probe attempt is not sequential")


def _validate_baseline_ready_state(state: Mapping[str, Any], *, candidate: Any) -> None:
    expected_fields = {
        "state",
        "pages",
        "terminal",
        "navigation_attempts",
        "navigation_observed_origins",
        "navigation_rejections",
    }
    if set(state) != expected_fields or state.get("terminal") is not None:
        raise ValueError("baseline-ready checkpoint fields differ from the contract")
    attempts = state["navigation_attempts"]
    if (
        not isinstance(attempts, list)
        or not attempts
        or attempts[-1].get("outcome") != "completed"
        or sum(item.get("outcome") == "completed" for item in attempts) != 1
    ):
        raise ValueError("baseline-ready checkpoint lacks one completed navigation")
    global_origins = set(
        _canonical_navigation_origins(
            state["navigation_observed_origins"],
            label="baseline-ready global navigation origin ledger",
        )
    )
    _validate_navigation_rejections(state["navigation_rejections"], boundary=candidate.domain)
    pages = state["pages"]
    if not isinstance(pages, list) or not 1 <= len(pages) <= 5:
        raise ValueError("baseline-ready checkpoint page sequence is invalid")
    seen_urls: set[str] = set()
    expected_page_fields = {
        "page",
        "observations",
        "probe_attempts",
        "approved_origins",
        "navigation_observed_origins",
    }
    for ordinal, page_state in enumerate(pages):
        if not isinstance(page_state, Mapping) or set(page_state) != expected_page_fields:
            raise ValueError("baseline-ready checkpoint page fields differ from the contract")
        raw_page = page_state["page"]
        if not isinstance(raw_page, Mapping) or set(raw_page) != set(
            PageCandidate.__dataclass_fields__
        ):
            raise ValueError("baseline-ready checkpoint page identity is malformed")
        page = PageCandidate(**dict(raw_page))
        validate_page_candidate(page)
        if (
            page.candidate_domain != candidate.domain
            or page.registrable_domain != candidate.domain
            or page.ordinal != ordinal
            or page.url in seen_urls
        ):
            raise ValueError("baseline-ready checkpoint page sequence differs")
        seen_urls.add(page.url)
        page_origins = set(
            _canonical_navigation_origins(
                page_state["navigation_observed_origins"],
                label="baseline-ready per-page navigation origin ledger",
            )
        )
        if not page_origins.issubset(global_origins):
            raise ValueError("baseline-ready per-page navigation origins exceed the global ledger")
        if (
            page_state["observations"] != []
            or page_state["probe_attempts"] != []
            or page_state["approved_origins"] != []
        ):
            raise ValueError("baseline-ready checkpoint already contains probe evidence")


def _validate_internal_acquisition_error(state: Mapping[str, Any]) -> Mapping[str, Any] | None:
    value = state.get("internal_acquisition_error")
    if value is None:
        return None
    keys = {
        "schema_version",
        "stage",
        "attempt",
        "page_ordinal",
        "probe_id",
        "exception_type",
        "message",
        "recorded_at",
    }
    if (
        not isinstance(value, Mapping)
        or set(value) != keys
        or value["schema_version"] != 1
        or isinstance(value["schema_version"], bool)
        or value["stage"] not in {"navigation", "probe"}
        or type(value["attempt"]) is not int
        or value["attempt"] < 1
        or not isinstance(value["exception_type"], str)
        or not value["exception_type"]
        or not isinstance(value["message"], str)
        or not value["message"]
        or not isinstance(value["recorded_at"], str)
        or state.get("terminal") is not None
        or state.get("state") == "terminal"
    ):
        raise ValueError("internal acquisition error checkpoint is malformed")
    _timestamp(value["recorded_at"])
    expected_reason = f"{value['exception_type']}: {value['message']}"
    if value["stage"] == "navigation":
        if value["page_ordinal"] is not None or value["probe_id"] is not None:
            raise ValueError("navigation internal acquisition error has probe identity")
        matches = [
            item
            for item in state.get("navigation_attempts", [])
            if item.get("attempt") == value["attempt"]
            and item.get("outcome") == "internal-acquisition-error"
            and item.get("reason") == expected_reason
            and item.get("completed_at") == value["recorded_at"]
        ]
    else:
        if (
            type(value["page_ordinal"]) is not int
            or value["page_ordinal"] < 0
            or not isinstance(value["probe_id"], str)
            or value["probe_id"] not in {window.probe_id for window in STABILITY_PROBE_WINDOWS}
        ):
            raise ValueError("probe internal acquisition error identity is malformed")
        matches = [
            item
            for page in state.get("pages", [])
            if page.get("page", {}).get("ordinal") == value["page_ordinal"]
            for item in page.get("probe_attempts", [])
            if item.get("probe_id") == value["probe_id"]
            and item.get("attempt") == value["attempt"]
            and item.get("outcome") == "internal-acquisition-error"
            and item.get("reason") == expected_reason
            and item.get("completed_at") == value["recorded_at"]
        ]
    if len(matches) != 1:
        raise ValueError("internal acquisition error is not bound to one failed attempt")
    return value


def _due_pages(
    state: Mapping[str, Any], now: datetime, *, candidate_id: str
) -> list[dict[str, Any]]:
    baseline = _timestamp(state["baseline_started_at"])
    result: list[dict[str, Any]] = []
    for page in state["pages"]:
        if page.get("rejection") is not None:
            continue
        index = len(page["observations"])
        if index >= len(STABILITY_PROBE_WINDOWS):
            continue
        window = STABILITY_PROBE_WINDOWS[index]
        pending = page.get("pending_probe")
        if pending is not None:
            _attempt, pending_started = _validate_pending_probe(
                pending,
                candidate_id=candidate_id,
                page_ordinal=page["page"]["ordinal"],
                probe_id=window.probe_id,
            )
            pending_elapsed = pending_started - baseline
            elapsed = now - baseline
            if (
                not timedelta(milliseconds=window.earliest_ms)
                <= pending_elapsed
                <= timedelta(milliseconds=window.latest_ms)
                or now < pending_started
            ):
                raise ValueError("pending acquisition probe time is malformed")
            # A start checkpoint proves only that work was about to begin.  It
            # is not evidence that a completed network acquisition occurred.
            # Once the outer window closes, never run fresh work under that old
            # timestamp; terminalise the candidate as a missed probe instead.
            if elapsed > timedelta(milliseconds=window.latest_ms):
                raise MissedProbeWindow(f"missed mandatory acquisition window {window.probe_id}")
            result.append(page)
            continue
        elapsed = now - baseline
        if elapsed > timedelta(milliseconds=window.latest_ms):
            raise MissedProbeWindow(f"missed mandatory acquisition window {window.probe_id}")
        if elapsed >= timedelta(milliseconds=window.earliest_ms):
            result.append(page)
    return result


def _record_pending_probe_interruptions(state: dict[str, Any], *, recovered_at: datetime) -> None:
    """Resolve durable probe starts without inventing a network completion."""

    recovery = recovered_at.astimezone(UTC)
    for page in state.get("pages", []):
        pending = page.get("pending_probe")
        if pending is None:
            continue
        started = _timestamp(pending["observed_at"])
        if recovery < started:
            raise ValueError("pending acquisition probe recovery predates its start")
        page.setdefault("probe_attempts", []).append(
            {
                **pending,
                "completed_at": _format_time(recovery),
                "outcome": "interrupted",
                "reason": "prior invocation ended before recording an outcome",
                "policy_evidence": None,
            }
        )
        page.pop("pending_probe")


def _baseline_batch_starts(
    baseline_batches: Sequence[Mapping[str, Any]],
) -> tuple[datetime, ...]:
    return tuple(_timestamp(batch["baseline_started_at"]) for batch in baseline_batches)


def _baseline_batch_for_candidate(
    baseline_batches: Sequence[Mapping[str, Any]], *, candidate_id: str
) -> Mapping[str, Any]:
    if not isinstance(candidate_id, str) or not isinstance(baseline_batches, (list, tuple)):
        raise ValueError("acquisition baseline-batch ledger is malformed")
    if any(
        not isinstance(batch, Mapping)
        or not isinstance(batch.get("candidate_ids"), list)
        or any(not isinstance(member, str) for member in batch["candidate_ids"])
        for batch in baseline_batches
    ):
        raise ValueError("acquisition baseline-batch ledger is malformed")
    matches = [batch for batch in baseline_batches if candidate_id in batch["candidate_ids"]]
    if len(matches) != 1:
        raise ValueError("candidate does not belong to exactly one baseline batch")
    return matches[0]


def _recover_active_batch(
    states: Mapping[str, dict[str, Any]],
    active_batch: Mapping[str, Any],
    *,
    recovered_at: datetime,
) -> None:
    """Resolve every prepublished attempt without inventing a completion."""

    recovery = recovered_at.astimezone(UTC)
    for attempt in active_batch["attempts"]:
        candidate_id = attempt["candidate_id"]
        state = states[candidate_id]
        started = _timestamp(attempt["started_at"])
        if recovery < started:
            raise ValueError("active acquisition recovery predates its publication")
        if active_batch["stage"] == "navigation":
            pending = state.pop("pending_navigation")
            state.setdefault("navigation_attempts", []).append(
                {
                    **pending,
                    "completed_at": _format_time(recovery),
                    "outcome": "interrupted",
                    "reason": "prior invocation ended before recording an outcome",
                    "policy_evidence": None,
                }
            )
            continue
        page_state = next(
            page for page in state["pages"] if page["page"]["ordinal"] == attempt["page_ordinal"]
        )
        pending = page_state.pop("pending_probe")
        page_state.setdefault("probe_attempts", []).append(
            {
                **pending,
                "completed_at": _format_time(recovery),
                "outcome": "interrupted",
                "reason": "prior invocation ended before recording an outcome",
                "policy_evidence": None,
            }
        )


def _checkpoint_baselines(states: Mapping[str, Any]) -> tuple[datetime, ...]:
    """Return every already-armed baseline, including terminal candidates."""

    return tuple(
        _timestamp(state["baseline_started_at"])
        for state in states.values()
        if isinstance(state, Mapping) and isinstance(state.get("baseline_started_at"), str)
    )


def _incomplete_probe_starts(
    states: Mapping[str, Any],
) -> tuple[datetime, ...]:
    starts: set[datetime] = set()
    for state in states.values():
        if state.get("terminal") is not None or state.get("state") != "probing":
            continue
        baseline = _timestamp(state["baseline_started_at"])
        for page in state["pages"]:
            if page.get("rejection") is not None:
                continue
            index = len(page["observations"])
            if index >= len(STABILITY_PROBE_WINDOWS) or page.get("pending_probe"):
                continue
            earliest = baseline + timedelta(milliseconds=STABILITY_PROBE_WINDOWS[index].earliest_ms)
            starts.add(earliest)
    return tuple(sorted(starts))


def _pending_navigation_blocked(states: Mapping[str, Any], now: datetime) -> bool:
    """Protect the next watcher-launched probe from a long navigation action."""

    reservation = timedelta(milliseconds=PENDING_BASELINE_GUARD_MS)
    return any(now < start < now + reservation for start in _incomplete_probe_starts(states))


def _next_pending_start(
    states: Mapping[str, Any],
    now: datetime,
    *,
    baseline_starts: Sequence[datetime],
    reservations: Sequence[BaselineReservation] | None = None,
) -> datetime | None:
    candidates: list[datetime] = []
    if any(
        state.get("terminal") is None and state.get("state") == "baseline-ready"
        for state in states.values()
    ):
        safe = (
            earliest_safe_baseline(now, baseline_starts)
            if reservations is None
            else earliest_safe_baseline_with_releases(now, reservations)
        )
        if safe > now:
            candidates.append(safe)
    candidates.extend(start for start in _incomplete_probe_starts(states) if start > now)
    return min(candidates) if candidates else None


def _pending_baseline_blocked(
    states: Mapping[str, Any],
    now: datetime,
    *,
    baseline_starts: Sequence[datetime],
    reservations: Sequence[BaselineReservation] | None = None,
) -> bool:
    ready = any(
        state.get("terminal") is None and state.get("state") == "baseline-ready"
        for state in states.values()
    )
    safe = (
        baseline_is_safe(now, baseline_starts)
        if reservations is None
        else baseline_is_safe_with_releases(now, reservations)
    )
    if ready and safe:
        return False
    pending_navigation = any(
        state.get("terminal") is None and state.get("state") == "pending"
        for state in states.values()
    )
    if pending_navigation and not _pending_navigation_blocked(states, now):
        return False
    return ready or pending_navigation


def _terminalise(
    root: Path,
    state: dict[str, Any],
    candidate_id: str,
    kind: str,
    reason: str | None,
    provenance_path: Path,
    *,
    terminalised_at: datetime,
    stability_receipt: Path | None = None,
    admitted_workload: Path | None = None,
    baseline_batch: Mapping[str, Any] | None,
) -> None:
    if (kind == "pre-probe-rejection") != (baseline_batch is None):
        raise ValueError("terminal baseline-batch binding differs from its outcome")
    if baseline_batch is not None and (
        candidate_id not in baseline_batch.get("candidate_ids", [])
        or state.get("baseline_started_at") != baseline_batch.get("baseline_started_at")
    ):
        raise ValueError("terminal baseline-batch binding differs from candidate state")
    provenance_sha256 = sha256_file(provenance_path)
    _validate_candidate_observation_provenance(
        root,
        provenance_path=provenance_path,
        candidate_id=candidate_id,
        state=state,
    )
    source_state_sha256 = _normalised_terminal_state_sha256(state, kind=kind)
    recorded_at = terminalised_at.astimezone(UTC)
    recorded_timestamps = [
        _timestamp(item["completed_at"])
        for item in state.get("navigation_attempts", [])
        if isinstance(item, Mapping) and isinstance(item.get("completed_at"), str)
    ]
    for page in state.get("pages", []):
        if not isinstance(page, Mapping):
            continue
        recorded_timestamps.extend(
            _timestamp(item["completed_at"])
            for item in page.get("probe_attempts", [])
            if isinstance(item, Mapping) and isinstance(item.get("completed_at"), str)
        )
    if recorded_timestamps:
        recorded_at = max(recorded_at, *recorded_timestamps)
    payload = {
        "terminal_schema_version": TERMINAL_SCHEMA_VERSION,
        "checkpoint_schema_version": CHECKPOINT_SCHEMA_VERSION,
        "candidate_id": candidate_id,
        "kind": kind,
        "reason": reason,
        "terminalised_at": _format_time(recorded_at),
        "checkpoint_state_sha256": source_state_sha256,
        "provenance_sha256": provenance_sha256,
        "baseline_batch": dict(baseline_batch) if baseline_batch is not None else None,
        "stability_receipt": (
            {
                "path": str(stability_receipt.resolve()),
                "sha256": sha256_file(stability_receipt),
            }
            if stability_receipt
            else None
        ),
        "admitted_workload": (
            {
                "path": str(admitted_workload.resolve()),
                "sha256": sha256_file(admitted_workload),
            }
            if admitted_workload
            else None
        ),
    }
    receipt = bind_receipt(payload, receipt_type=TERMINAL_TYPE)
    relative = f"terminals/{candidate_id}.json"
    (root / "terminals").mkdir(exist_ok=True)
    destination = root / relative
    if destination.exists() or destination.is_symlink():
        if (
            destination.is_symlink()
            or not destination.is_file()
            or destination.read_bytes() != canonical_json_bytes(receipt)
        ):
            raise FileExistsError(f"immutable acquisition terminal already differs: {destination}")
    else:
        _create_json(destination, receipt)
    state["terminal"] = {"path": relative, "sha256": sha256_file(root / relative)}
    state["state"] = "terminal"


def _validate_candidate_observation_provenance(
    runner: Path,
    *,
    provenance_path: Path,
    candidate_id: str,
    state: Mapping[str, Any],
) -> None:
    """Replay one candidate's transitive evidence before immutable publication."""

    runner_provenance = validate_hash_bound_receipt(
        load_json(provenance_path),
        expected_type=PROVENANCE_TYPE,
    )
    if runner_provenance.get("acquisition_schema_version") != SCHEMA_VERSION:
        return
    _validate_observation_provenance(
        {candidate_id: state},
        provenance_sha256=sha256_file(provenance_path),
        runner_provenance=runner_provenance,
        runner_root=runner,
        include_nonterminal=True,
    )


def _publish_admitted_workload(source: Path, destination: Path, expected_sha256: str) -> None:
    if source.is_symlink() or not source.is_file():
        raise ValueError("selected prepared workload does not match its observation")
    encoded = source.read_bytes()
    if sha256_bytes(encoded) != expected_sha256:
        raise ValueError("selected prepared workload does not match its observation")
    validate_class_study_preparation(load_json(source), workload_id=destination.stem)
    destination.parent.mkdir(parents=True, exist_ok=True)
    _discard_owned_publication_temps(destination, style="durable-create")

    def validate_existing() -> bool:
        if not destination.exists() and not destination.is_symlink():
            return False
        if (
            destination.is_symlink()
            or not destination.is_file()
            or destination.read_bytes() != encoded
        ):
            raise FileExistsError("immutable admitted workload already differs")
        return True

    if validate_existing():
        return
    try:
        durable_create(destination, encoded)
    except FileExistsError:
        if not validate_existing():  # pragma: no cover - link collision guarantees presence
            raise


def _discard_owned_publication_temps(destination: Path, *, style: str) -> None:
    """Discard only exact, uncommitted siblings created for ``destination``."""

    parent = Path(os.path.abspath(destination.parent))
    if not parent.exists() and not parent.is_symlink():
        return
    if parent.is_symlink() or not parent.is_dir():
        raise ValueError("immutable publication parent is not a regular directory")
    pattern = _owned_publication_temp_pattern(destination, style=style)
    removed = False
    for entry in parent.iterdir():
        if pattern.fullmatch(entry.name) is None:
            continue
        if entry.is_symlink() or not entry.is_file():
            raise ValueError(f"immutable publication temporary path is unsafe: {entry}")
        entry.unlink()
        removed = True
    if removed:
        fsync_directory(parent)


def _owned_publication_temp_pattern(destination: Path, *, style: str) -> re.Pattern[str]:
    """Return the closed filename grammar used by one create-only publisher."""

    escaped = re.escape(destination.name)
    if style == "create-only-json":
        return re.compile(rf"\.{escaped}\.[A-Za-z0-9_-]+\.qcsd-tmp\Z")
    if style == "durable-create":
        return re.compile(rf"\.{escaped}{re.escape(ATOMIC_TEMP_MARKER)}[A-Za-z0-9_-]+\Z")
    raise ValueError("unknown immutable publication temporary style")


def _checkpoint(
    *,
    provenance_sha256: str,
    catalogue_sha256: str,
    baseline_batches: Sequence[Mapping[str, Any]],
    active_batch: Mapping[str, Any] | None,
    candidates: Mapping[str, Any],
) -> dict[str, Any]:
    return bind_receipt(
        {
            "checkpoint_schema_version": CHECKPOINT_SCHEMA_VERSION,
            "provenance_sha256": provenance_sha256,
            "candidate_catalogue_sha256": catalogue_sha256,
            "baseline_batches": list(baseline_batches),
            "active_batch": dict(active_batch) if active_batch is not None else None,
            "candidates": candidates,
        },
        receipt_type=CHECKPOINT_TYPE,
    )


def _save_acquisition_checkpoint(
    path: Path,
    *,
    provenance_path: Path,
    catalogue_path: Path,
    baseline_batches: Sequence[Mapping[str, Any]],
    active_batch: Mapping[str, Any] | None,
    candidates: Mapping[str, Any],
) -> None:
    atomic_json(
        path,
        _checkpoint(
            provenance_sha256=sha256_file(provenance_path),
            catalogue_sha256=sha256_file(catalogue_path),
            baseline_batches=baseline_batches,
            active_batch=active_batch,
            candidates=candidates,
        ),
    )


def _load_checkpoint(
    path: Path,
    provenance_path: Path,
    catalogue_path: Path,
    *,
    maximum_recovery_candidates: int = MAX_CANDIDATES_PER_ACTION,
) -> tuple[dict[str, Any], int]:
    value, _recoveries, persisted_terminal_recoveries = _load_checkpoint_state(
        path,
        provenance_path,
        catalogue_path,
        persist_recoveries=True,
        maximum_recovery_candidates=maximum_recovery_candidates,
    )
    return value, len(persisted_terminal_recoveries)


def _validate_baseline_batches(
    value: object,
    *,
    states: Mapping[str, Any],
    candidate_order: Sequence[str],
    reservations: Sequence[BaselineReservation] | None = None,
) -> tuple[Mapping[str, Any], ...]:
    if not isinstance(value, list):
        raise ValueError("acquisition baseline-batch ledger is malformed")
    order = {candidate_id: index for index, candidate_id in enumerate(candidate_order)}
    flattened: list[str] = []
    seen_ids: set[str] = set()
    seen_batch_ids: set[str] = set()
    validated: list[Mapping[str, Any]] = []
    for batch in value:
        if not isinstance(batch, Mapping) or set(batch) != {
            "batch_id",
            "baseline_started_at",
            "candidate_ids",
            "live_page_count",
        }:
            raise ValueError("acquisition baseline-batch ledger is malformed")
        candidate_ids = batch["candidate_ids"]
        if (
            not isinstance(candidate_ids, list)
            or not 1 <= len(candidate_ids) <= MAX_CANDIDATES_PER_ACTION
            or any(not isinstance(candidate_id, str) for candidate_id in candidate_ids)
            or any(candidate_id not in order for candidate_id in candidate_ids)
            or candidate_ids != sorted(set(candidate_ids), key=order.__getitem__)
            or seen_ids.intersection(candidate_ids)
            or not isinstance(batch["baseline_started_at"], str)
            or _format_time(_timestamp(batch["baseline_started_at"]))
            != batch["baseline_started_at"]
            or not isinstance(batch["batch_id"], str)
        ):
            raise ValueError("acquisition baseline-batch ledger is malformed")
        body = {
            "baseline_started_at": batch["baseline_started_at"],
            "candidate_ids": candidate_ids,
            "live_page_count": batch["live_page_count"],
        }
        page_ledgers = [states[candidate_id].get("pages") for candidate_id in candidate_ids]
        if any(not isinstance(pages, list) for pages in page_ledgers):
            raise ValueError("acquisition baseline-batch ledger is malformed")
        live_page_count = sum(len(pages) for pages in page_ledgers)
        if (
            type(batch["live_page_count"]) is not int
            or batch["live_page_count"] != live_page_count
            or not 1 <= live_page_count <= GLOBAL_LIVE_PAGE_CAP
            or batch["batch_id"] != _batch_identifier("baseline", body)
            or batch["batch_id"] in seen_batch_ids
            or any(
                states[candidate_id].get("baseline_started_at") != batch["baseline_started_at"]
                for candidate_id in candidate_ids
            )
        ):
            raise ValueError("acquisition baseline-batch ledger is malformed")
        flattened.extend(candidate_ids)
        seen_ids.update(candidate_ids)
        seen_batch_ids.add(batch["batch_id"])
        validated.append(batch)
    expected = {
        candidate_id
        for candidate_id in candidate_order
        if isinstance(states[candidate_id].get("baseline_started_at"), str)
    }
    if set(flattened) != expected or len(flattened) != len(expected):
        raise ValueError("baseline batches do not exactly cover armed candidates")
    starts = _baseline_batch_starts(validated)
    if tuple(sorted(starts)) != starts:
        raise ValueError("baseline batches are not append-ordered by start")
    if reservations is None:
        validate_baseline_schedule(starts)
    else:
        if tuple(reservation.baseline_started_at for reservation in reservations) != starts:
            raise ValueError("baseline reservation identities differ from their ledger")
        validate_baseline_schedule_with_releases(reservations)
    return tuple(validated)


def _validate_active_batch(
    value: object,
    *,
    states: Mapping[str, Any],
    candidate_order: Sequence[str],
    baseline_batches: Sequence[Mapping[str, Any]],
) -> int:
    order = {candidate_id: index for index, candidate_id in enumerate(candidate_order)}
    pending_navigation = {
        candidate_id
        for candidate_id, state in states.items()
        if state.get("pending_navigation") is not None
    }
    pending_probes = {
        (candidate_id, page["page"]["ordinal"])
        for candidate_id, state in states.items()
        for page in state.get("pages", [])
        if page.get("pending_probe") is not None
    }
    if value is None:
        if pending_navigation or pending_probes:
            raise ValueError("pending attempts lack an active acquisition batch")
        return 0
    expected_fields = {
        "active_batch_schema_version",
        "batch_id",
        "stage",
        "published_at",
        "candidate_ids",
        "live_page_count",
        "attempts",
    }
    if not isinstance(value, Mapping) or set(value) != expected_fields:
        raise ValueError("active acquisition batch is malformed")
    candidate_ids = value["candidate_ids"]
    attempts = value["attempts"]
    if (
        type(value["active_batch_schema_version"]) is not int
        or value["active_batch_schema_version"] != ACTIVE_BATCH_SCHEMA_VERSION
        or not isinstance(value["batch_id"], str)
        or not isinstance(value["stage"], str)
        or value["stage"] not in {"navigation", "probe"}
        or not isinstance(value["published_at"], str)
        or _format_time(_timestamp(value["published_at"])) != value["published_at"]
        or not isinstance(candidate_ids, list)
        or not 1 <= len(candidate_ids) <= MAX_CANDIDATES_PER_ACTION
        or any(not isinstance(candidate_id, str) for candidate_id in candidate_ids)
        or any(candidate_id not in order for candidate_id in candidate_ids)
        or candidate_ids != sorted(set(candidate_ids), key=order.__getitem__)
        or not isinstance(attempts, list)
        or not 1 <= len(attempts) <= GLOBAL_LIVE_PAGE_CAP
        or type(value["live_page_count"]) is not int
        or value["live_page_count"] != len(attempts)
    ):
        raise ValueError("active acquisition batch is malformed")
    body = {key: value[key] for key in expected_fields if key != "batch_id"}
    if value["batch_id"] != _batch_identifier("active", body):
        raise ValueError("active acquisition batch identifier is invalid")
    attempt_fields = {
        "candidate_id",
        "page_ordinal",
        "probe_id",
        "workload_id",
        "attempt",
        "started_at",
    }
    for attempt in attempts:
        if (
            not isinstance(attempt, Mapping)
            or set(attempt) != attempt_fields
            or not isinstance(attempt["candidate_id"], str)
            or attempt["candidate_id"] not in candidate_ids
            or type(attempt["attempt"]) is not int
            or not 1 <= attempt["attempt"] <= MAX_PROBE_ATTEMPTS
            or attempt["started_at"] != value["published_at"]
        ):
            raise ValueError("active acquisition attempt is malformed")
    observed_candidate_ids = list(dict.fromkeys(attempt["candidate_id"] for attempt in attempts))
    if observed_candidate_ids != candidate_ids:
        raise ValueError("active acquisition candidate ordering is invalid")
    if value["stage"] == "navigation":
        if (
            len(attempts) != len(candidate_ids)
            or pending_probes
            or pending_navigation != set(candidate_ids)
            or any(
                states[attempt["candidate_id"]].get("state") != "pending"
                or attempt["page_ordinal"] is not None
                or attempt["probe_id"] is not None
                or attempt["workload_id"] is not None
                or states[attempt["candidate_id"]].get("pending_navigation")
                != {
                    "attempt": attempt["attempt"],
                    "started_at": attempt["started_at"],
                }
                for attempt in attempts
            )
        ):
            raise ValueError("active navigation batch is inconsistent")
        return len(attempts)
    if pending_navigation or set(candidate_ids) != {
        candidate_id for candidate_id, _ordinal in pending_probes
    }:
        raise ValueError("active probe batch is inconsistent")
    if any(
        type(attempt["page_ordinal"]) is not int
        or not isinstance(attempt["probe_id"], str)
        or not isinstance(attempt["workload_id"], str)
        for attempt in attempts
    ):
        raise ValueError("active probe attempt identity is malformed")
    active_probe_identities = [
        (attempt["candidate_id"], attempt["page_ordinal"]) for attempt in attempts
    ]
    if (
        len(active_probe_identities) != len(set(active_probe_identities))
        or set(active_probe_identities) != pending_probes
    ):
        raise ValueError("active probe attempt identity set is inconsistent")
    probe_ids = {attempt["probe_id"] for attempt in attempts}
    if len(probe_ids) != 1:
        raise ValueError("active probe batch mixes probe windows")
    expected_order = sorted(
        attempts,
        key=lambda attempt: (order[attempt["candidate_id"]], attempt["page_ordinal"]),
    )
    if attempts != expected_order:
        raise ValueError("active probe attempts are not deterministically ordered")
    for attempt in attempts:
        candidate_id = attempt["candidate_id"]
        page_ordinal = attempt["page_ordinal"]
        baseline_batch = _baseline_batch_for_candidate(baseline_batches, candidate_id=candidate_id)
        if (
            states[candidate_id].get("state") != "probing"
            or states[candidate_id].get("baseline_started_at")
            != baseline_batch.get("baseline_started_at")
            or type(page_ordinal) is not int
            or (candidate_id, page_ordinal) not in pending_probes
        ):
            raise ValueError("active probe attempt page is invalid")
        page = next(
            page
            for page in states[candidate_id]["pages"]
            if page["page"]["ordinal"] == page_ordinal
        )
        pending = page["pending_probe"]
        if (
            not isinstance(attempt["probe_id"], str)
            or not isinstance(attempt["workload_id"], str)
            or pending
            != {
                "probe_id": attempt["probe_id"],
                "workload_id": attempt["workload_id"],
                "attempt": attempt["attempt"],
                "observed_at": attempt["started_at"],
            }
        ):
            raise ValueError("active probe attempt is inconsistent")
    return len(attempts)


def _load_checkpoint_state(
    path: Path,
    provenance_path: Path,
    catalogue_path: Path,
    *,
    persist_recoveries: bool,
    maximum_recovery_candidates: int = MAX_CANDIDATES_PER_ACTION,
) -> tuple[dict[str, Any], int, tuple[str, ...]]:
    if (
        type(maximum_recovery_candidates) is not int
        or not 1 <= maximum_recovery_candidates <= MAX_CANDIDATES_PER_ACTION
    ):
        raise ValueError("checkpoint recovery candidate bound is invalid")
    value = load_json(path)
    payload = validate_hash_bound_receipt(value, expected_type=CHECKPOINT_TYPE)
    provenance_payload = validate_hash_bound_receipt(
        load_json(provenance_path), expected_type=PROVENANCE_TYPE
    )
    acquisition_schema_version = provenance_payload.get("acquisition_schema_version")
    if (
        type(acquisition_schema_version) is not int
        or acquisition_schema_version not in SUPPORTED_SCHEMA_VERSIONS
    ):
        raise ValueError("acquisition checkpoint uses an unsupported schema")
    current_schema = acquisition_schema_version == SCHEMA_VERSION
    selection_schema = acquisition_schema_version in _SELECTION_SCHEMA_VERSIONS
    modern_checkpoint_schema = acquisition_schema_version in _MODERN_CHECKPOINT_SCHEMA_VERSIONS
    if acquisition_schema_version in _FIXED_PROVENANCE_SCHEMA_VERSIONS:
        _validate_current_provenance_contract(
            provenance_payload,
            candidate_catalogue_path=catalogue_path,
        )
    legacy_fields = {
        "provenance_sha256",
        "candidate_catalogue_sha256",
        "candidates",
    }
    current_fields = legacy_fields | {
        "checkpoint_schema_version",
        "baseline_batches",
        "active_batch",
    }
    if modern_checkpoint_schema:
        if (
            set(payload) != current_fields
            or type(payload.get("checkpoint_schema_version")) is not int
            or payload.get("checkpoint_schema_version")
            != _checkpoint_schema_for(acquisition_schema_version)
        ):
            raise ValueError("modern acquisition checkpoint shape is invalid")
        baseline_batches = payload["baseline_batches"]
        active_batch = payload["active_batch"]
    else:
        if set(payload) != legacy_fields:
            raise ValueError("historical acquisition checkpoint shape is invalid")
        baseline_batches = []
        active_batch = None
    if payload["provenance_sha256"] != sha256_file(provenance_path) or payload[
        "candidate_catalogue_sha256"
    ] != sha256_file(catalogue_path):
        raise ValueError("acquisition checkpoint bindings do not verify")
    _catalogue, candidates = load_candidate_catalogue_receipt(catalogue_path)
    states = payload.get("candidates")
    expected_ids = {candidate.candidate_id for candidate in candidates}
    if not isinstance(states, Mapping) or set(states) != expected_ids:
        raise ValueError("acquisition checkpoint candidate set is invalid")
    terminals = path.parent / "terminals"
    if terminals.exists() or terminals.is_symlink():
        if terminals.is_symlink() or not terminals.is_dir():
            raise ValueError("acquisition terminal root is not a regular directory")
    elif persist_recoveries:
        terminals.mkdir()
        fsync_directory(path.parent)
    else:
        raise ValueError("acquisition terminal root does not exist")
    expected_names = {f"{candidate_id}.json" for candidate_id in expected_ids}
    terminal_temp_pattern = re.compile(
        rf"\.(?P<destination>.+\.json){re.escape(ATOMIC_TEMP_MARKER)}"
        rf"[A-Za-z0-9_-]+\Z"
    )
    terminal_temps: list[Path] = []
    for entry in terminals.iterdir():
        temporary_match = terminal_temp_pattern.fullmatch(entry.name)
        if temporary_match is not None and temporary_match.group("destination") in expected_names:
            if entry.is_symlink() or not entry.is_file():
                raise ValueError("acquisition terminal temporary path is unsafe")
            terminal_temps.append(entry)
            continue
        if entry.name not in expected_names:
            raise ValueError(f"unexpected acquisition terminal path: {entry}")

    provenance_sha256 = sha256_file(provenance_path)
    recoveries: list[tuple[str, dict[str, Any], dict[str, str]]] = []
    internal_failures: list[str] = []
    for candidate in candidates:
        state = states[candidate.candidate_id]
        permitted_states = {"pending", "probing", "terminal"}
        if acquisition_schema_version in _DURATION_LIMIT_SCHEMA_VERSIONS:
            permitted_states.add("baseline-ready")
        if not isinstance(state, dict) or state.get("state") not in permitted_states:
            raise ValueError("acquisition checkpoint candidate state is invalid")
        if (
            modern_checkpoint_schema
            and "pending_navigation" in state
            and state["pending_navigation"] is None
        ):
            raise ValueError("current acquisition pending navigation is null")
        _validate_navigation_attempts(
            state,
            acquisition_schema_version=acquisition_schema_version,
            enforce_duration_limit=(acquisition_schema_version in _DURATION_LIMIT_SCHEMA_VERSIONS),
            require_canonical_timestamps=modern_checkpoint_schema,
        )
        if "navigation_rejections" in state:
            _validate_navigation_rejections(
                state["navigation_rejections"], boundary=candidate.domain
            )
        if "navigation_observed_origins" in state:
            global_origins = _canonical_navigation_origins(
                state["navigation_observed_origins"],
                label="checkpoint global navigation origin ledger",
            )
            pages = state.get("pages")
            if not isinstance(pages, list):
                raise TypeError("checkpoint page ledger is not a list")
            for page_state in pages:
                if not isinstance(page_state, Mapping):
                    raise TypeError("checkpoint page ledger contains a non-object")
                if (
                    modern_checkpoint_schema
                    and "pending_probe" in page_state
                    and page_state["pending_probe"] is None
                ):
                    raise ValueError("current acquisition pending probe is null")
                _validate_probe_attempts(
                    page_state,
                    candidate_id=candidate.candidate_id,
                    acquisition_schema_version=acquisition_schema_version,
                    baseline_started_at=state.get("baseline_started_at"),
                    enforce_duration_limit=(
                        acquisition_schema_version in _DURATION_LIMIT_SCHEMA_VERSIONS
                    ),
                    require_canonical_timestamps=modern_checkpoint_schema,
                    require_observation_attempt_bindings=modern_checkpoint_schema,
                )
                page_origins = _canonical_navigation_origins(
                    page_state.get("navigation_observed_origins"),
                    label="checkpoint per-page navigation origin ledger",
                )
                if not set(page_origins).issubset(global_origins):
                    raise ValueError(
                        "checkpoint per-page navigation origins exceed the global ledger"
                    )
        elif state["state"] in {"baseline-ready", "probing"} or state.get("pages"):
            raise ValueError("checkpoint lacks its navigation origin ledger")
        if modern_checkpoint_schema and state["state"] == "pending":
            _validate_current_pending_state(state)
        if modern_checkpoint_schema and state["state"] == "probing":
            _validate_live_probing_state(state, candidate=candidate)
        if state["state"] == "baseline-ready":
            _validate_baseline_ready_state(state, candidate=candidate)
        if _validate_internal_acquisition_error(state) is not None:
            internal_failures.append(candidate.candidate_id)
        binding = state.get("terminal")
        terminal = terminals / f"{candidate.candidate_id}.json"
        if terminal.exists() or terminal.is_symlink():
            verified = _validated_terminal_binding(
                terminal,
                candidate=candidate,
                provenance_sha256=provenance_sha256,
                candidate_state=state,
                acquisition_schema_version=acquisition_schema_version,
                baseline_batches=baseline_batches,
            )
            if binding is None:
                recoveries.append((candidate.candidate_id, state, verified))
            elif state["state"] != "terminal" or binding != verified:
                raise ValueError("checkpoint terminal binding is inconsistent")
        elif binding is not None or state["state"] == "terminal":
            raise ValueError("checkpoint references missing terminal evidence")
    candidate_order = [candidate.candidate_id for candidate in candidates]
    if modern_checkpoint_schema:
        reservations = (
            _baseline_batch_reservations(
                baseline_batches, states, _checkpoint_terminal_payloads(path.parent, states)
            )
            if selection_schema
            else None
        )
        validated_baseline_batches = _validate_baseline_batches(
            baseline_batches,
            states=states,
            candidate_order=candidate_order,
            reservations=reservations,
        )
        active_recoveries = _validate_active_batch(
            active_batch,
            states=states,
            candidate_order=candidate_order,
            baseline_batches=validated_baseline_batches,
        )
    else:
        if acquisition_schema_version == 3:
            validate_baseline_schedule(_checkpoint_baselines(states))
        validated_baseline_batches = ()
        active_recoveries = 0
    orphan_candidate_ids = tuple(candidate_id for candidate_id, _state, _binding in recoveries)
    active_candidate_ids = (
        tuple(active_batch["candidate_ids"]) if isinstance(active_batch, Mapping) else ()
    )
    if recoveries and active_candidate_ids:
        raise ValueError("acquisition checkpoint combines incompatible recovery actions")
    if len(set(orphan_candidate_ids) | set(active_candidate_ids)) > maximum_recovery_candidates:
        raise ValueError("acquisition checkpoint recovery exceeds the candidate action bound")
    if current_schema and persist_recoveries:
        for temporary in terminal_temps:
            temporary.unlink()
        if terminal_temps:
            fsync_directory(terminals)
    _validate_document_response_receipt_namespace(
        path.parent,
        states,
        required=(acquisition_schema_version in _INSTRUMENTATION_EVIDENCE_SCHEMA_VERSIONS),
    )
    _validate_prepared_probe_namespace(
        path.parent,
        states,
        required=(acquisition_schema_version in _INSTRUMENTATION_EVIDENCE_SCHEMA_VERSIONS),
    )
    if internal_failures:
        raise InternalAcquisitionError(
            "acquisition checkpoint contains durable internal failures for: "
            + ", ".join(internal_failures)
        )
    if recoveries and persist_recoveries and current_schema:
        for _candidate_id, state, binding in recoveries:
            state["state"] = "terminal"
            state["terminal"] = binding
        _save_acquisition_checkpoint(
            path,
            provenance_path=provenance_path,
            catalogue_path=catalogue_path,
            baseline_batches=validated_baseline_batches,
            active_batch=active_batch,
            candidates=states,
        )
        value = load_json(path)
    return value, len(recoveries) + active_recoveries, orphan_candidate_ids


def _validate_document_response_receipt_namespace(
    root: Path,
    states: Mapping[str, Any],
    *,
    required: bool,
) -> None:
    """Reject evidence files outside the checkpointed create-only namespace."""

    receipt_root = root / "document-response-receipts"
    if not receipt_root.exists() and not receipt_root.is_symlink():
        if required:
            raise ValueError("acquisition document-response receipt root does not exist")
        return
    if receipt_root.is_symlink() or not receipt_root.is_dir():
        raise ValueError("acquisition document-response receipt root is not a regular directory")
    expected_workload_ids = _expected_probe_workload_ids(states)
    temporary_pattern = re.compile(
        rf"\.(?P<workload_id>.+)\.json{re.escape(ATOMIC_TEMP_MARKER)}"
        rf"[A-Za-z0-9_-]+\Z"
    )
    for entry in receipt_root.iterdir():
        if entry.is_symlink() or not entry.is_file():
            raise ValueError("acquisition document-response receipt namespace is unsafe")
        if (
            entry.name.endswith(".json")
            and entry.name.removesuffix(".json") in expected_workload_ids
        ):
            continue
        temporary_match = temporary_pattern.fullmatch(entry.name)
        if (
            temporary_match is not None
            and temporary_match.group("workload_id") in expected_workload_ids
        ):
            continue
        raise ValueError(f"unexpected acquisition document-response receipt path: {entry}")


def _expected_probe_workload_ids(states: Mapping[str, Any]) -> set[str]:
    """Collect the exact attempt namespace once for O(1) entry checks."""

    expected: set[str] = set()
    for state in states.values():
        if not isinstance(state, Mapping):
            continue
        for page in state.get("pages", []):
            if not isinstance(page, Mapping):
                continue
            attempts = page.get("probe_attempts", [])
            for attempt in attempts if isinstance(attempts, list) else ():
                if isinstance(attempt, Mapping) and isinstance(attempt.get("workload_id"), str):
                    expected.add(attempt["workload_id"])
            pending = page.get("pending_probe")
            if isinstance(pending, Mapping) and isinstance(pending.get("workload_id"), str):
                expected.add(pending["workload_id"])
    return expected


def _validate_prepared_probe_namespace(
    root: Path,
    states: Mapping[str, Any],
    *,
    required: bool,
) -> None:
    """Keep every probe manifest inside the create-only runner namespace."""

    prepared_root = root / "prepared-probes"
    if not prepared_root.exists() and not prepared_root.is_symlink():
        if required:
            raise ValueError("acquisition prepared-probe root does not exist")
        return
    if prepared_root.is_symlink() or not prepared_root.is_dir():
        raise ValueError("acquisition prepared-probe root is not a regular directory")
    expected_workload_ids = _expected_probe_workload_ids(states)
    temporary_file_pattern = re.compile(
        rf"\.(?P<workload_id>.+)\.json{re.escape(ATOMIC_TEMP_MARKER)}"
        rf"[A-Za-z0-9_-]+\Z"
    )
    temporary_directory_pattern = re.compile(r"\.(?P<workload_id>.+)-prepare-[A-Za-z0-9_-]+\Z")
    for entry in prepared_root.iterdir():
        if entry.is_symlink():
            raise ValueError("acquisition prepared-probe namespace is unsafe")
        if (
            entry.is_file()
            and entry.name.endswith(".json")
            and entry.name.removesuffix(".json") in expected_workload_ids
        ):
            continue
        temporary_file_match = temporary_file_pattern.fullmatch(entry.name)
        if (
            entry.is_file()
            and temporary_file_match is not None
            and temporary_file_match.group("workload_id") in expected_workload_ids
        ):
            continue
        temporary_directory_match = temporary_directory_pattern.fullmatch(entry.name)
        if (
            entry.is_dir()
            and temporary_directory_match is not None
            and temporary_directory_match.group("workload_id") in expected_workload_ids
        ):
            continue
        raise ValueError(f"unexpected acquisition prepared-probe path: {entry}")


def _new_directory(path: Path) -> Path:
    target = Path(os.path.abspath(path))
    target.mkdir(parents=True, exist_ok=False)
    return target


def _regular_directory(path: Path) -> Path:
    target = Path(os.path.abspath(path))
    if target.is_symlink() or not target.is_dir():
        raise ValueError("acquisition root must be a regular directory")
    return target


def _create_json(path: Path, value: Mapping[str, Any]) -> None:
    durable_create(path, canonical_json_bytes(value))


def _timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include a UTC offset")
    return parsed.astimezone(UTC)


def _format_time(value: datetime | None) -> str | None:
    return None if value is None else value.astimezone(UTC).isoformat().replace("+00:00", "Z")
