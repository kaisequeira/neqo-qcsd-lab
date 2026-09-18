"""Versioned evidence contracts for public-page browser discovery.

The runtime workload deliberately contains only stable resource identities.  This
module validates the separate, content-minimised CDP projection that proves how
each ephemeral browser request occurrence became one runtime resource or one
audited exclusion.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from copy import deepcopy
from typing import Any
from urllib.parse import urlsplit

from .browser_egress import (
    NON_REPLAYABLE_EGRESS_POLICY,
    validate_non_replayable_egress_success_summary,
)
from .cdp_targets import (
    CDP_TARGET_INSTRUMENTATION_POLICY,
    validate_bootstrap_prearm_summary,
    validate_egress_prearm_summary,
    validate_srcdoc_pseudo_document_summary,
)

PASSIVE_RENDER_CONTRACT_SCHEMA_VERSION = 4
RENDER_OBSERVATION_SCHEMA_VERSION = 4
DISCOVERY_EVENT_AUDIT_SCHEMA_VERSION = 5

PASSIVE_RENDER_CONTRACT: dict[str, Any] = {
    "schema_version": PASSIVE_RENDER_CONTRACT_SCHEMA_VERSION,
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
    "non_replayable_egress_policy": NON_REPLAYABLE_EGRESS_POLICY,
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
        "terminal-root-srcdoc-loader-bound-orphan-abort-lifecycle",
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


def canonical_json_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def evidence_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


PASSIVE_RENDER_CONTRACT_SHA256 = evidence_sha256(PASSIVE_RENDER_CONTRACT)


def passive_render_contract() -> dict[str, Any]:
    """Return a caller-owned copy of the preregistered passive-render policy."""

    return deepcopy(PASSIVE_RENDER_CONTRACT)


def validate_passive_render_contract(value: Any, *, digest: object = None) -> None:
    if value != PASSIVE_RENDER_CONTRACT:
        raise ValueError("passive-render contract differs from the preregistered policy")
    if digest is not None and digest != PASSIVE_RENDER_CONTRACT_SHA256:
        raise ValueError("passive-render contract SHA-256 does not verify")


def validate_render_observation(value: Any, *, allow_failure: bool = False) -> None:
    """Validate one relative-monotonic render cutoff receipt."""

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
        "internal_document_lifecycle_summary",
        "non_replayable_egress_summary",
        "browser_context_service_worker_count",
        "cutoff_reason",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise ValueError("render observation fields differ from the contract")
    if (
        type(value["schema_version"]) is not int
        or value["schema_version"] != RENDER_OBSERVATION_SCHEMA_VERSION
        or value["clock"] != "monotonic-relative-ms"
    ):
        raise ValueError("render observation schema or clock is invalid")
    timing_fields = (
        "navigation_started_ms",
        "load_event_ms",
        "last_relevant_event_ms",
        "quiet_started_ms",
        "cutoff_ms",
    )
    if any(
        type(value[field]) is not int or value[field] < 0 for field in timing_fields
    ):
        raise ValueError("render observation timestamps must be non-negative integers")
    navigation = value["navigation_started_ms"]
    load = value["load_event_ms"]
    last = value["last_relevant_event_ms"]
    quiet = value["quiet_started_ms"]
    cutoff = value["cutoff_ms"]
    minimum_boundary = load + PASSIVE_RENDER_CONTRACT["minimum_after_load_ms"]
    if (
        not navigation <= load <= quiet <= cutoff
        or last > cutoff
        or quiet != max(minimum_boundary, last)
    ):
        raise ValueError("render observation monotonic ordering is invalid")
    active = value["active_request_ids"]
    if (
        not isinstance(active, list)
        or any(not isinstance(item, str) or not item for item in active)
        or active != sorted(set(active))
        or value["active_request_count"] != len(active)
    ):
        raise ValueError("render observation active-request ledger is invalid")
    elapsed = cutoff - load
    quiet_elapsed = cutoff - quiet
    reason = value["cutoff_reason"]
    router_shutdown_ready = value["router_shutdown_ready"]
    if type(router_shutdown_ready) is not bool:
        raise ValueError("render observation router readiness is invalid")
    validate_bootstrap_prearm_summary(
        value["bootstrap_prearm_summary"],
        require_terminal=reason == "quiescent",
    )
    validate_egress_prearm_summary(
        value["egress_prearm_summary"],
        require_terminal=reason == "quiescent",
    )
    validate_srcdoc_pseudo_document_summary(
        value["internal_document_lifecycle_summary"],
        require_terminal=reason == "quiescent",
    )
    validate_non_replayable_egress_success_summary(
        value["non_replayable_egress_summary"]
    )
    service_worker_count = value["browser_context_service_worker_count"]
    if type(service_worker_count) is not int or service_worker_count < 0:
        raise ValueError("render observation service-worker count is invalid")
    if reason == "quiescent":
        if (
            active
            or not router_shutdown_ready
            or service_worker_count != 0
            or elapsed < PASSIVE_RENDER_CONTRACT["minimum_after_load_ms"]
        ):
            raise ValueError("quiescent render cutoff is premature or retains active requests")
        if quiet_elapsed < PASSIVE_RENDER_CONTRACT["quiet_window_ms"]:
            raise ValueError("quiescent render cutoff lacks the required quiet interval")
        if elapsed >= PASSIVE_RENDER_CONTRACT["hard_cap_after_load_ms"]:
            raise ValueError("quiescent render cutoff exceeds its hard cap")
    elif reason == "hard-cap-non-quiescent" and allow_failure:
        hard_cap = PASSIVE_RENDER_CONTRACT["hard_cap_after_load_ms"]
        if elapsed < hard_cap:
            raise ValueError("hard-cap render rejection was recorded outside its boundary")
        # The hard cap has strict precedence at the observation boundary.  A
        # delayed scheduler wake-up must still preserve the typed hard-cap
        # rejection even when quiescence also became true in the meantime.
    else:
        raise ValueError("render observation cutoff reason is invalid")


_SOURCE_FIELDS = {
    "session_path",
    "target_id",
    "target_type",
    "generation",
    "parent_session_path",
    "parent_frame_id",
}
_COMMON_EVENT_FIELDS = {"sequence", "monotonic_ms", "kind", "source"}
_NETWORK_EVENT_FIELDS = _COMMON_EVENT_FIELDS | {
    "network_id",
    "occurrence_id",
    "occurrence_index",
    "method",
    "url",
    "frame_id",
    "resource_type",
    "safe_request_headers",
    "interception_required",
    "redirected",
    "redirect_from_occurrence_id",
    "mapping",
    "dependency_evidence",
    "resolved_dependency_resource_ids",
}
_FETCH_EVENT_FIELDS = _COMMON_EVENT_FIELDS | {
    "fetch_id",
    "network_id",
    "redirected_fetch_id",
    "network_occurrence_id",
    "method",
    "url",
    "frame_id",
    "policy_decision",
    "policy_reason",
    "relationship",
}
_TERMINAL_EVENT_FIELDS = _COMMON_EVENT_FIELDS | {
    "network_id",
    "outcome",
    "network_occurrence_ids",
}
_TARGET_EVENT_FIELDS = _COMMON_EVENT_FIELDS | {"target_event"}
_BROWSER_INTERNAL_DOCUMENT_EVENT_FIELDS = _COMMON_EVENT_FIELDS | {"diagnostic"}
_DEPENDENCY_EVIDENCE_FIELDS = {"kind", "value", "resolved_resource_id"}


def _https_origin(value: str) -> str | None:
    try:
        parts = urlsplit(value)
        port = parts.port
    except (TypeError, ValueError):
        return None
    if (
        parts.scheme.lower() != "https"
        or parts.hostname is None
        or parts.username is not None
        or parts.password is not None
    ):
        return None
    host = parts.hostname.lower()
    if ":" in host:
        host = f"[{host}]"
    return f"https://{host}" if port in {None, 443} else f"https://{host}:{port}"


def _exclusion_reason(method: str, url: str, approved: set[str]) -> str | None:
    if method != "GET":
        return f"unsafe method: {method or 'unknown'}"
    request_origin = _https_origin(url)
    if request_origin is None:
        return "not an absolute HTTPS request"
    if request_origin not in approved:
        return "origin not approved"
    return None


def _interception_required(url: str) -> bool:
    try:
        return urlsplit(url).scheme.lower() in {"http", "https"}
    except (TypeError, ValueError):
        return False


def _event_scope(event: Mapping[str, Any]) -> str:
    source = event["source"]
    return (
        event.get("frame_id")
        or source.get("parent_frame_id")
        or source["target_id"]
    )


def _same_source(left: Mapping[str, Any], right: Mapping[str, Any]) -> bool:
    return (
        left["session_path"] == right["session_path"]
        and left["target_id"] == right["target_id"]
        and left["generation"] == right["generation"]
    )


def _network_fetch_sources_compatible(
    network: Mapping[str, Any], fetch: Mapping[str, Any]
) -> bool:
    """Independently mirror the documented worker-to-owner interception route."""

    network_source = network["source"]
    fetch_source = fetch["source"]
    if _same_source(network_source, fetch_source):
        return True
    if network_source["target_type"] in {"page", "iframe"} and fetch_source[
        "target_type"
    ] in {"page", "iframe"}:
        if (
            network_source["target_id"] == fetch_source["target_id"]
            and network_source["generation"] != fetch_source["generation"]
        ):
            return False
        return (
            network_source["session_path"] == fetch_source["parent_session_path"]
            or fetch_source["session_path"] == network_source["parent_session_path"]
            or (
                fetch.get("frame_id") is not None
                and fetch["frame_id"]
                in {network_source["target_id"], fetch_source["target_id"]}
            )
        )
    if network_source["target_type"] not in {"worker", "shared_worker"}:
        return False
    if fetch_source["target_type"] not in {"page", "iframe"}:
        return False
    return (
        network_source["parent_session_path"] == fetch_source["session_path"]
        or (
            fetch.get("frame_id") is not None
            and network_source["parent_frame_id"] == fetch["frame_id"]
        )
    )


def _fetch_redirect_sources_compatible(
    previous: Mapping[str, Any], current: Mapping[str, Any]
) -> bool:
    """Reproduce the page/iframe hand-off allowed during OOPIF migration."""

    previous_source = previous["source"]
    current_source = current["source"]
    if _same_source(previous_source, current_source):
        return True
    if (
        previous_source["target_id"] == current_source["target_id"]
        and previous_source["generation"] != current_source["generation"]
    ):
        return False
    if previous_source["target_type"] not in {"page", "iframe"} or current_source[
        "target_type"
    ] not in {"page", "iframe"}:
        return False
    return (
        previous_source["session_path"] == current_source["parent_session_path"]
        or current_source["session_path"] == previous_source["parent_session_path"]
        or (
            current.get("frame_id") is not None
            and current["frame_id"]
            in {previous_source["target_id"], current_source["target_id"]}
        )
    )


def _independent_url_dependency(
    previous: Sequence[Mapping[str, Any]],
    *,
    current: Mapping[str, Any],
    url: str,
) -> int | None:
    """Reconstruct latest-preceding scope resolution without production state."""

    current_source = current["source"]
    current_scope = _event_scope(current)
    candidates: list[tuple[int, Mapping[str, Any]]] = []
    for candidate in previous:
        if candidate["url"] != url:
            continue
        candidate_source = candidate["source"]
        candidate_scope = _event_scope(candidate)
        if candidate_scope == current_scope:
            rank = 0
        elif _same_source(candidate_source, current_source):
            rank = 1
        elif (
            current_source.get("parent_frame_id") is not None
            and candidate_scope == current_source["parent_frame_id"]
        ):
            rank = 2
        elif (
            candidate_source.get("parent_frame_id") is not None
            and candidate_source["parent_frame_id"] == current_scope
        ):
            rank = 2
        elif (
            candidate_source["session_path"] == current_source.get("parent_session_path")
            or current_source["session_path"] == candidate_source.get("parent_session_path")
        ):
            rank = 3
        else:
            continue
        candidates.append((rank, candidate))
    if not candidates:
        return None
    best_rank = min(rank for rank, _candidate in candidates)
    best = [candidate for rank, candidate in candidates if rank == best_rank]
    scopes = {
        (
            tuple(candidate["source"]["session_path"]),
            candidate["source"]["target_id"],
            candidate["source"]["generation"],
            _event_scope(candidate),
        )
        for candidate in best
    }
    if len(scopes) > 1:
        raise ValueError("discovery URL dependency scope is ambiguous")
    return max(best, key=lambda candidate: candidate["mapping"]["resource_id"])[
        "mapping"
    ]["resource_id"]


def _independent_request_id_dependency(
    previous: Sequence[Mapping[str, Any]],
    *,
    current: Mapping[str, Any],
    network_id: str,
) -> int | None:
    current_source = current["source"]
    current_scope = _event_scope(current)
    candidates: list[Mapping[str, Any]] = []
    for candidate in previous:
        candidate_source = candidate["source"]
        if (
            candidate["network_id"] == network_id
            and _event_scope(candidate) == current_scope
            and (
                _same_source(candidate_source, current_source)
                or candidate_source["parent_session_path"]
                == current_source["session_path"]
                or current_source["parent_session_path"]
                == candidate_source["session_path"]
            )
        ):
            candidates.append(candidate)
    scopes = {
        (
            tuple(candidate["source"]["session_path"]),
            candidate["source"]["target_id"],
            candidate["source"]["generation"],
            _event_scope(candidate),
        )
        for candidate in candidates
    }
    if len(scopes) > 1:
        raise ValueError("discovery initiator request dependency is ambiguous")
    return (
        max(candidates, key=lambda candidate: candidate["mapping"]["resource_id"])[
            "mapping"
        ]["resource_id"]
        if candidates
        else None
    )


def _validate_source(value: Any) -> tuple[tuple[str, ...], str, int]:
    if not isinstance(value, Mapping) or set(value) != _SOURCE_FIELDS:
        raise ValueError("discovery event target source is malformed")
    session_path = value["session_path"]
    parent = value["parent_session_path"]
    if (
        not isinstance(session_path, list)
        or any(not isinstance(item, str) or not item for item in session_path)
        or (
            parent is not None
            and (
                not isinstance(parent, list)
                or any(not isinstance(item, str) or not item for item in parent)
            )
        )
        or not isinstance(value["target_id"], str)
        or not value["target_id"]
        or not isinstance(value["target_type"], str)
        or not value["target_type"]
        or type(value["generation"]) is not int
        or value["generation"] < 0
        or (
            value["parent_frame_id"] is not None
            and (
                not isinstance(value["parent_frame_id"], str)
                or not value["parent_frame_id"]
            )
        )
    ):
        raise ValueError("discovery event target source is malformed")
    return tuple(session_path), value["target_id"], value["generation"]


def verify_discovery_event_audit(
    value: Any,
    *,
    render_observation: Mapping[str, Any],
    resources: Sequence[Mapping[str, Any]],
    exclusions: Sequence[Mapping[str, Any]],
    approved_origins: Sequence[str],
    observed_request_count: int,
    expected_root_document_url: str | None = None,
    expected_final_document_url: str | None = None,
    expected_observed_origins: Sequence[str] | None = None,
) -> dict[str, int]:
    """Independently replay a sanitised CDP projection into its final mappings."""

    fields = {
        "schema_version",
        "instrumentation_policy",
        "passive_render_contract_sha256",
        "render_observation_sha256",
        "events",
        "summary",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise ValueError("discovery event audit fields differ from the contract")
    if (
        type(value["schema_version"]) is not int
        or value["schema_version"] != DISCOVERY_EVENT_AUDIT_SCHEMA_VERSION
    ):
        raise ValueError("discovery event audit schema is invalid")
    validate_render_observation(render_observation)
    if (
        value["instrumentation_policy"] != CDP_TARGET_INSTRUMENTATION_POLICY
        or value["passive_render_contract_sha256"] != PASSIVE_RENDER_CONTRACT_SHA256
        or value["render_observation_sha256"] != evidence_sha256(render_observation)
    ):
        raise ValueError("discovery event audit provenance is invalid")
    events = value["events"]
    if not isinstance(events, list) or not events:
        raise ValueError("discovery event audit requires a non-empty event sequence")
    resource_by_id = {item.get("id"): item for item in resources}
    if len(resource_by_id) != len(resources):
        raise ValueError("discovery audit resources have duplicate IDs")
    approved = set(approved_origins)
    if any(
        not isinstance(item, Mapping)
        or set(item) != {"url", "reason"}
        or not isinstance(item["url"], str)
        or not isinstance(item["reason"], str)
        or not item["reason"]
        for item in exclusions
    ):
        raise ValueError("discovery audit exclusion summary is malformed")
    exclusion_pairs = {(item["url"], item["reason"]) for item in exclusions}
    if len(exclusion_pairs) != len(exclusions):
        raise ValueError("discovery audit exclusion summary contains duplicates")
    networks: dict[str, Mapping[str, Any]] = {}
    fetches: list[Mapping[str, Any]] = []
    terminals: list[Mapping[str, Any]] = []
    internal_document_diagnostics: list[Mapping[str, Any]] = []
    mapped_resources: set[int] = set()
    exclusion_occurrences: set[int] = set()
    mapped_exclusion_pairs: set[tuple[str, str]] = set()
    counts: Counter[str] = Counter()
    previous_ms = -1
    previous_network_by_chain: dict[tuple[tuple[str, ...], str, int, str], str] = {}
    occurrence_count_by_chain: Counter[
        tuple[tuple[str, ...], str, int, str]
    ] = Counter()
    fetch_identity: set[tuple[tuple[str, ...], str, int, str]] = set()
    redirect_consumed_fetch_sequences: set[int] = set()
    prior_resource_events: list[Mapping[str, Any]] = []
    network_events_by_chain: dict[
        tuple[tuple[str, ...], str, int, str], list[Mapping[str, Any]]
    ] = defaultdict(list)
    active_target_sources: set[tuple[tuple[str, ...], str, int]] = set()
    detached_target_sources: set[tuple[tuple[str, ...], str, int]] = set()
    seen_session_paths: set[tuple[str, ...]] = set()
    root_source_key: tuple[tuple[str, ...], str, int] | None = None
    source_shapes: dict[tuple[tuple[str, ...], str, int], dict[str, Any]] = {}
    active_target_ids: dict[str, tuple[tuple[str, ...], str, int]] = {}
    active_session_ids: dict[
        str, tuple[tuple[str, ...], str, int]
    ] = {}
    last_target_generation: dict[str, int] = {}
    terminal_events_by_chain: dict[
        tuple[tuple[str, ...], str, int, str], list[Mapping[str, Any]]
    ] = defaultdict(list)

    for expected_sequence, event in enumerate(events, 1):
        if not isinstance(event, Mapping):
            raise ValueError("discovery event audit contains a non-object")
        if event.get("sequence") != expected_sequence:
            raise ValueError("discovery event audit sequence is not contiguous")
        monotonic_ms = event.get("monotonic_ms")
        if type(monotonic_ms) is not int or monotonic_ms < previous_ms:
            raise ValueError("discovery event audit monotonic time regressed")
        previous_ms = monotonic_ms
        source_key = _validate_source(event.get("source"))
        kind = event.get("kind")
        if (
            kind != "target-activity"
            and monotonic_ms < render_observation["navigation_started_ms"]
        ):
            raise ValueError("discovery network activity predates navigation start")
        source_value = event["source"]
        prior_shape = source_shapes.setdefault(source_key, dict(source_value))
        if prior_shape != dict(source_value):
            raise ValueError("discovery target source identity changes shape")
        if not source_key[0]:
            if (
                source_value["target_type"] != "page"
                or source_value["generation"] != 0
                or source_value["parent_session_path"] is not None
                or source_value["parent_frame_id"] is not None
            ):
                raise ValueError("root discovery target source is malformed")
            if root_source_key is None:
                root_source_key = source_key
                if (
                    source_key[1] in active_target_ids
                    or source_key[1] in last_target_generation
                ):
                    raise ValueError(
                        "root target identity collides with historical child activity"
                    )
                active_target_ids[source_key[1]] = source_key
                last_target_generation[source_key[1]] = 0
            elif root_source_key != source_key:
                raise ValueError("discovery audit changes its root target identity")
        elif kind != "target-activity" and source_key not in active_target_sources:
            raise ValueError("non-root discovery event is outside target lifecycle brackets")
        counts[str(kind)] += 1
        if kind == "network-request":
            if set(event) != _NETWORK_EVENT_FIELDS:
                raise ValueError("network request audit event fields are invalid")
            occurrence_id = event["occurrence_id"]
            if not isinstance(occurrence_id, str) or not occurrence_id or occurrence_id in networks:
                raise ValueError("network request occurrence identity is invalid")
            if (
                not isinstance(event["network_id"], str)
                or not event["network_id"]
                or type(event["occurrence_index"]) is not int
                or event["occurrence_index"] < 0
                or not isinstance(event["method"], str)
                or not isinstance(event["url"], str)
                or event["frame_id"] is not None
                and (not isinstance(event["frame_id"], str) or not event["frame_id"])
                or not isinstance(event["resource_type"], str)
                or (
                    event["safe_request_headers"] is not None
                    and (
                        not isinstance(event["safe_request_headers"], list)
                        or any(
                            not isinstance(header, list)
                            or len(header) != 2
                            or any(not isinstance(value, str) for value in header)
                            for header in event["safe_request_headers"]
                        )
                        or event["safe_request_headers"]
                        != sorted(event["safe_request_headers"])
                    )
                )
                or type(event["redirected"]) is not bool
                or type(event["interception_required"]) is not bool
                or event["interception_required"] != _interception_required(event["url"])
                or event["redirected"] != (event["occurrence_index"] > 0)
            ):
                raise ValueError("network request audit identity is malformed")
            chain = (*source_key, event["network_id"])
            if event["occurrence_index"] != occurrence_count_by_chain[chain]:
                raise ValueError("network request occurrence index is not contiguous")
            occurrence_count_by_chain[chain] += 1
            predecessor = previous_network_by_chain.get(chain)
            if event["redirected"]:
                if event["redirect_from_occurrence_id"] != predecessor:
                    raise ValueError("network redirect does not name its immediate predecessor")
            elif event["redirect_from_occurrence_id"] is not None:
                raise ValueError("non-redirect network request names a predecessor")
            previous_network_by_chain[chain] = occurrence_id
            network_events_by_chain[chain].append(event)
            mapping = event["mapping"]
            if not isinstance(mapping, Mapping):
                raise ValueError("network request occurrence mapping is malformed")
            expected_reason = _exclusion_reason(event["method"], event["url"], approved)
            dependencies = event["resolved_dependency_resource_ids"]
            evidence = event["dependency_evidence"]
            if (
                not isinstance(dependencies, list)
                or dependencies != sorted(set(dependencies))
                or any(type(item) is not int for item in dependencies)
                or not isinstance(evidence, list)
                or any(
                    not isinstance(item, Mapping)
                    or set(item) != _DEPENDENCY_EVIDENCE_FIELDS
                    or item["kind"]
                    not in {
                        "document-url",
                        "initiator-url",
                        "stack-call-frame",
                        "initiator-request-id",
                        "redirect",
                    }
                    or not isinstance(item["value"], str)
                    or (
                        item["resolved_resource_id"] is not None
                        and type(item["resolved_resource_id"]) is not int
                    )
                    for item in evidence
                )
            ):
                raise ValueError("network request dependency evidence is malformed")
            resolved_from_evidence = sorted(
                {
                    item["resolved_resource_id"]
                    for item in evidence
                    if item["resolved_resource_id"] is not None
                }
            )
            if resolved_from_evidence != dependencies:
                raise ValueError("network dependency evidence does not derive its dependency set")
            independently_resolved: list[int] = []
            redirect_evidence = [
                item for item in evidence if item["kind"] == "redirect"
            ]
            if (event["redirected"] and len(redirect_evidence) != 1) or (
                not event["redirected"] and redirect_evidence
            ):
                raise ValueError("redirect dependency evidence does not match the redirect")
            for item in evidence:
                if item["kind"] in {
                    "document-url",
                    "initiator-url",
                    "stack-call-frame",
                }:
                    expected_dependency = _independent_url_dependency(
                        prior_resource_events,
                        current=event,
                        url=item["value"],
                    )
                elif item["kind"] == "initiator-request-id":
                    expected_dependency = _independent_request_id_dependency(
                        prior_resource_events,
                        current=event,
                        network_id=item["value"],
                    )
                else:
                    predecessor_event = networks.get(event["redirect_from_occurrence_id"])
                    predecessor_mapping = (
                        predecessor_event.get("mapping")
                        if isinstance(predecessor_event, Mapping)
                        else None
                    )
                    expected_dependency = (
                        predecessor_mapping.get("resource_id")
                        if isinstance(predecessor_mapping, Mapping)
                        and predecessor_mapping.get("kind") == "resource"
                        else None
                    )
                    if item["value"] != event["redirect_from_occurrence_id"]:
                        raise ValueError("redirect dependency evidence names the wrong occurrence")
                if item["resolved_resource_id"] != expected_dependency:
                    raise ValueError(
                        "dependency evidence does not match independent latest-preceding resolution"
                    )
                if expected_dependency is not None:
                    independently_resolved.append(expected_dependency)
            if sorted(set(independently_resolved)) != dependencies:
                raise ValueError("independently reconstructed dependencies differ from the graph")
            if expected_reason is None:
                if set(mapping) != {"kind", "resource_id"} or mapping["kind"] != "resource":
                    raise ValueError("eligible network occurrence is not mapped to a resource")
                resource_id = mapping["resource_id"]
                resource = resource_by_id.get(resource_id)
                predecessor_event = (
                    networks.get(event["redirect_from_occurrence_id"])
                    if event["redirected"]
                    else None
                )
                if (
                    type(resource_id) is not int
                    or resource is None
                    or resource_id in mapped_resources
                    or resource_id != len(mapped_resources)
                    or resource.get("url") != event["url"]
                    or resource.get("type") != event["resource_type"]
                    or resource.get("headers", [])
                    != event["safe_request_headers"]
                    or resource.get("depends_on", []) != dependencies
                    or any(dependency >= resource_id for dependency in dependencies)
                    or (
                        event["redirected"]
                        and (
                            not isinstance(predecessor_event, Mapping)
                            or not isinstance(predecessor_event.get("mapping"), Mapping)
                            or predecessor_event["mapping"].get("kind") != "resource"
                        )
                    )
                ):
                    raise ValueError("network occurrence/resource mapping does not verify")
                mapped_resources.add(resource_id)
                prior_resource_events.append(event)
            else:
                if (
                    set(mapping) != {"kind", "exclusion_occurrence_id", "reason"}
                    or mapping["kind"] != "exclusion"
                    or type(mapping["exclusion_occurrence_id"]) is not int
                    or mapping["exclusion_occurrence_id"] in exclusion_occurrences
                    or mapping["exclusion_occurrence_id"] != len(exclusion_occurrences)
                    or mapping["reason"] != expected_reason
                    or (event["url"], expected_reason) not in exclusion_pairs
                    or event["safe_request_headers"] is not None
                ):
                    raise ValueError("network occurrence/exclusion mapping does not verify")
                exclusion_occurrences.add(mapping["exclusion_occurrence_id"])
                mapped_exclusion_pairs.add((event["url"], expected_reason))
            networks[occurrence_id] = event
        elif kind == "fetch-request":
            if set(event) != _FETCH_EVENT_FIELDS:
                raise ValueError("Fetch interception audit event fields are invalid")
            occurrence_id = event["network_occurrence_id"]
            if occurrence_id not in networks:
                # Fetch may precede Network in the raw stream, but final replay
                # identities still name exactly one eventual Network occurrence.
                pass
            if (
                any(
                    not isinstance(event[field], str) or not event[field]
                    for field in ("fetch_id", "network_id")
                )
                or not isinstance(event["method"], str)
                or not isinstance(event["url"], str)
                or (
                    event["redirected_fetch_id"] is not None
                    and (
                        not isinstance(event["redirected_fetch_id"], str)
                        or not event["redirected_fetch_id"]
                    )
                )
                or (
                    event["network_occurrence_id"] is not None
                    and (
                        not isinstance(event["network_occurrence_id"], str)
                        or not event["network_occurrence_id"]
                    )
                )
                or (
                    event["frame_id"] is not None
                    and (not isinstance(event["frame_id"], str) or not event["frame_id"])
                )
                or event["policy_decision"] not in {"continue", "fail"}
                or (
                    event["policy_reason"] is not None
                    and not isinstance(event["policy_reason"], str)
                )
                or event["relationship"] not in {"primary", "internal-restart"}
            ):
                raise ValueError("Fetch interception audit identity is malformed")
            identity = (*source_key, event["fetch_id"])
            if identity in fetch_identity:
                raise ValueError("Fetch interception identity is reused")
            fetch_identity.add(identity)
            predecessor_id = event["redirected_fetch_id"]
            if predecessor_id is not None:
                compatible = [
                    previous
                    for previous in fetches
                    if previous["network_id"] == event["network_id"]
                    and _fetch_redirect_sources_compatible(previous, event)
                ]
                if not compatible or compatible[-1]["fetch_id"] != predecessor_id:
                    raise ValueError("Fetch redirect does not name its immediate predecessor")
                matching = [
                    previous
                    for previous in compatible
                    if previous["fetch_id"] == predecessor_id
                ]
                if (
                    len(matching) != 1
                    or matching[0]["sequence"] in redirect_consumed_fetch_sequences
                ):
                    raise ValueError("Fetch redirect predecessor is ambiguous")
                redirect_consumed_fetch_sequences.add(matching[0]["sequence"])
            fetches.append(event)
        elif kind == "network-terminal":
            if set(event) != _TERMINAL_EVENT_FIELDS:
                raise ValueError("network terminal audit event fields are invalid")
            if (
                not isinstance(event["network_id"], str)
                or not event["network_id"]
                or event["outcome"] not in {"finished", "failed"}
                or not isinstance(event["network_occurrence_ids"], list)
                or not event["network_occurrence_ids"]
            ):
                raise ValueError("network terminal audit event is malformed")
            terminals.append(event)
            terminal_events_by_chain[(*source_key, event["network_id"])].append(event)
        elif kind == "target-activity":
            if set(event) != _TARGET_EVENT_FIELDS or event["target_event"] not in set(
                PASSIVE_RENDER_CONTRACT["relevant_events"]
            ):
                raise ValueError("target activity audit event is malformed")
            target_event = event["target_event"]
            if target_event == "target-attached":
                parent_path = source_value["parent_session_path"]
                route = source_key[0]
                parent_route = tuple(parent_path) if isinstance(parent_path, list) else None
                parent_active = parent_route == () or any(
                    key[0] == parent_route
                    for key in active_target_sources
                )
                if (
                    root_source_key is None
                    or not route
                    or parent_route != route[:-1]
                    or source_value["target_type"]
                    not in {"iframe", "shared_worker", "worker"}
                    or route in seen_session_paths
                    or route[-1] in active_session_ids
                    or source_key in active_target_sources
                    or source_key in detached_target_sources
                    or not parent_active
                    or source_key[1] in active_target_ids
                    or source_key[2]
                    != last_target_generation.get(source_key[1], -1) + 1
                ):
                    raise ValueError("target attachment lifecycle is invalid")
                seen_session_paths.add(route)
                active_target_sources.add(source_key)
                active_target_ids[source_key[1]] = source_key
                active_session_ids[route[-1]] = source_key
                last_target_generation[source_key[1]] = source_key[2]
            elif target_event == "target-info-changed":
                if source_key[0] and source_key not in active_target_sources:
                    raise ValueError("target-info event is outside its active lifecycle")
            elif target_event == "target-detached":
                route = source_key[0]
                active_descendant = any(
                    len(key[0]) > len(route) and key[0][: len(route)] == route
                    for key in active_target_sources
                )
                if source_key not in active_target_sources or active_descendant:
                    raise ValueError("target detach is outside its active lifecycle")
                active_target_sources.remove(source_key)
                active_target_ids.pop(source_key[1], None)
                if active_session_ids.pop(route[-1], None) != source_key:
                    raise ValueError("target detach session identity is inconsistent")
                detached_target_sources.add(source_key)
            elif target_event == "target-destroyed":
                route = source_key[0]
                active_descendant = any(
                    len(key[0]) > len(route) and key[0][: len(route)] == route
                    for key in active_target_sources
                )
                latest_detached = max(
                    (
                        key
                        for key in detached_target_sources
                        if key[1] == source_key[1]
                    ),
                    key=lambda key: key[2],
                    default=None,
                )
                if (
                    source_key not in detached_target_sources
                    or active_descendant
                    or source_key[1] in active_target_ids
                    or latest_detached != source_key
                ):
                    raise ValueError("target destruction did not follow a detach")
                detached_target_sources.remove(source_key)
            else:
                raise ValueError("discovery target activity is unsupported")
        elif kind == "browser-internal-document":
            if set(event) != _BROWSER_INTERNAL_DOCUMENT_EVENT_FIELDS:
                raise ValueError(
                    "browser internal-document audit event fields are invalid"
                )
            if source_key != root_source_key:
                raise ValueError(
                    "browser internal-document audit event must use the root source"
                )
            diagnostic = event["diagnostic"]
            if not isinstance(diagnostic, Mapping):
                raise ValueError(
                    "browser internal-document audit diagnostic is malformed"
                )
            internal_document_diagnostics.append(diagnostic)
        else:
            raise ValueError("discovery event audit contains an unsupported event kind")

    if internal_document_diagnostics != render_observation[
        "internal_document_lifecycle_summary"
    ]["diagnostics"]:
        raise ValueError(
            "browser internal-document audit diagnostics differ from the render summary"
        )

    primary_events = [
        event
        for event in networks.values()
        if isinstance(event.get("mapping"), Mapping)
        and event["mapping"].get("kind") == "resource"
        and event["mapping"].get("resource_id") == 0
    ]
    if (
        root_source_key is None
        or len(primary_events) != 1
        or _validate_source(primary_events[0]["source"]) != root_source_key
        or primary_events[0]["resource_type"] != "Document"
    ):
        raise ValueError("primary navigation resource is not bound to the root page target")
    if (
        expected_root_document_url is not None
        and primary_events[0]["url"] != expected_root_document_url
    ):
        raise ValueError(
            "primary navigation resource URL differs from the prepared source URL"
        )
    primary = primary_events[0]
    if primary["monotonic_ms"] > render_observation["load_event_ms"]:
        raise ValueError("primary navigation request occurs after page load")
    primary_chain = network_events_by_chain[
        (*root_source_key, primary["network_id"])
    ]
    root_frame_documents = [
        event
        for event in networks.values()
        if _validate_source(event["source"]) == root_source_key
        and event["resource_type"] == "Document"
        and event["frame_id"] == primary["frame_id"]
    ]
    if (
        not root_frame_documents
        or root_frame_documents[0] is not primary
        or primary_chain[0] is not primary
        or any(
            event["resource_type"] != "Document"
            or event["frame_id"] != primary["frame_id"]
            for event in primary_chain
        )
        or any(event["network_id"] != primary["network_id"] for event in root_frame_documents)
    ):
        raise ValueError(
            "root-frame identity/resource type is not one contiguous primary redirect chain"
        )
    primary_documents = [
        event for event in primary_chain if event["resource_type"] == "Document"
    ]
    if (
        expected_final_document_url is not None
        and (
            not primary_documents
            or primary_documents[-1]["url"] != expected_final_document_url
        )
    ):
        raise ValueError(
            "primary navigation redirect chain differs from the prepared final URL"
        )

    # Fetch events can occur before their matching Network event. Reconstruct
    # the production FIFO association independently rather than trusting the
    # claimed occurrence ID or primary/internal-restart label.
    unmatched_networks: dict[str, list[Mapping[str, Any]]] = {}
    unmatched_fetches: dict[str, list[Mapping[str, Any]]] = {}
    matched_network_occurrences: set[str] = set()
    matched_fetch_sequences: set[int] = set()
    independently_matched: dict[int, tuple[str, str]] = {}

    def reconcile_primary(network_id: str) -> None:
        candidates_network = unmatched_networks.setdefault(network_id, [])
        candidates_fetch = unmatched_fetches.setdefault(network_id, [])
        progress = True
        while progress:
            progress = False
            for fetch in candidates_fetch:
                if fetch["sequence"] in matched_fetch_sequences:
                    continue
                candidates = [
                    network
                    for network in candidates_network
                    if network["occurrence_id"] not in matched_network_occurrences
                    and network["method"] == fetch["method"]
                    and network["url"] == fetch["url"]
                    and _network_fetch_sources_compatible(network, fetch)
                ]
                source_keys = {
                    (
                        tuple(network["source"]["session_path"]),
                        network["source"]["target_id"],
                        network["source"]["generation"],
                    )
                    for network in candidates
                }
                if len(source_keys) > 1:
                    raise ValueError("Network/Fetch request occurrence is ambiguous")
                if candidates:
                    network = candidates[0]
                    matched_network_occurrences.add(network["occurrence_id"])
                    matched_fetch_sequences.add(fetch["sequence"])
                    independently_matched[fetch["sequence"]] = (
                        network["occurrence_id"],
                        "primary",
                    )
                    progress = True

    for event in events:
        if event["kind"] == "network-request" and event["interception_required"]:
            unmatched_networks.setdefault(event["network_id"], []).append(event)
            reconcile_primary(event["network_id"])
        elif event["kind"] == "fetch-request":
            unmatched_fetches.setdefault(event["network_id"], []).append(event)
            reconcile_primary(event["network_id"])

    terminal_sequence_by_occurrence: dict[str, int] = {}
    for terminal in terminals:
        for occurrence_id in terminal["network_occurrence_ids"]:
            terminal_sequence_by_occurrence[occurrence_id] = terminal["sequence"]
    for network_id, candidates_fetch in unmatched_fetches.items():
        candidates_network = unmatched_networks.get(network_id, [])
        for fetch in candidates_fetch:
            if fetch["sequence"] in matched_fetch_sequences:
                continue
            candidates = [
                network
                for network in candidates_network
                if network["occurrence_id"] in matched_network_occurrences
                and network["sequence"] < fetch["sequence"]
                and fetch["sequence"]
                < terminal_sequence_by_occurrence.get(network["occurrence_id"], 1 << 62)
                and network["method"] == fetch["method"]
                and network["url"] == fetch["url"]
                and _network_fetch_sources_compatible(network, fetch)
                and fetch["redirected_fetch_id"] is None
            ]
            source_keys = {
                (
                    tuple(network["source"]["session_path"]),
                    network["source"]["target_id"],
                    network["source"]["generation"],
                )
                for network in candidates
            }
            if len(source_keys) > 1:
                raise ValueError("Network/Fetch internal restart is ambiguous")
            if candidates:
                network = candidates[-1]
                independently_matched[fetch["sequence"]] = (
                    network["occurrence_id"],
                    "internal-restart",
                )
                matched_fetch_sequences.add(fetch["sequence"])

    if len(independently_matched) != len(fetches):
        raise ValueError("Network/Fetch occurrence reconciliation is incomplete")

    fetch_by_sequence = {event["sequence"]: event for event in fetches}
    primary_fetch_by_occurrence: dict[str, Mapping[str, Any]] = {}
    for sequence, (occurrence_id, relationship) in independently_matched.items():
        fetch = fetch_by_sequence[sequence]
        terminal_sequence = terminal_sequence_by_occurrence.get(occurrence_id)
        if terminal_sequence is not None and sequence >= terminal_sequence:
            raise ValueError("Fetch interception occurred after Network terminal closure")
        if relationship == "primary":
            primary_fetch_by_occurrence[occurrence_id] = fetch
    primary_fetch = primary_fetch_by_occurrence.get(primary["occurrence_id"])
    if (
        primary_fetch is None
        or primary_fetch["monotonic_ms"] > render_observation["load_event_ms"]
    ):
        raise ValueError("primary navigation interception occurs after page load")
    fetch_count_by_network: Counter[str] = Counter()
    primary_count_by_network: Counter[str] = Counter()
    for event in fetches:
        if (
            event["network_occurrence_id"],
            event["relationship"],
        ) != independently_matched[event["sequence"]]:
            raise ValueError(
                "Fetch occurrence mapping differs from independent FIFO reconciliation"
            )
        occurrence = networks.get(event["network_occurrence_id"])
        if (
            occurrence is None
            or occurrence["network_id"] != event["network_id"]
            or occurrence["method"] != event["method"]
            or occurrence["url"] != event["url"]
        ):
            raise ValueError("Fetch interception does not map to its Network occurrence")
        expected_reason = _exclusion_reason(event["method"], event["url"], approved)
        if (
            expected_reason is None
            and (event["policy_decision"], event["policy_reason"]) != ("continue", None)
        ) or (
            expected_reason is not None
            and (event["policy_decision"], event["policy_reason"])
            != ("fail", expected_reason)
        ):
            raise ValueError("Fetch interception policy decision does not verify")
        fetch_count_by_network[event["network_occurrence_id"]] += 1
        primary_count_by_network[event["network_occurrence_id"]] += (
            event["relationship"] == "primary"
        )
    required_networks = {
        occurrence_id
        for occurrence_id, event in networks.items()
        if event["interception_required"]
    }
    for occurrence_id in required_networks:
        occurrence = networks[occurrence_id]
        primary = primary_fetch_by_occurrence.get(occurrence_id)
        if primary is None or occurrence["redirected"] != (
            primary["redirected_fetch_id"] is not None
        ):
            raise ValueError("Network and Fetch redirect identities do not correspond")
    if set(fetch_count_by_network) != required_networks or any(
        primary_count_by_network[occurrence_id] != 1
        for occurrence_id in required_networks
    ):
        raise ValueError("Network/Fetch occurrence reconciliation is incomplete")

    terminal_counts: Counter[str] = Counter()
    if set(terminal_events_by_chain) != set(network_events_by_chain):
        raise ValueError("network request terminal chains are incomplete")
    for chain, chain_networks in network_events_by_chain.items():
        chain_terminals = terminal_events_by_chain[chain]
        if len(chain_terminals) != 1:
            raise ValueError("network request chain is split across terminal events")
        [terminal] = chain_terminals
        expected_occurrences = [event["occurrence_id"] for event in chain_networks]
        if (
            terminal["network_occurrence_ids"] != expected_occurrences
            or any(event["sequence"] >= terminal["sequence"] for event in chain_networks)
        ):
            raise ValueError(
                "network terminal does not close the complete preceding redirect chain"
            )
    for terminal in terminals:
        for occurrence_id in terminal["network_occurrence_ids"]:
            occurrence = networks.get(occurrence_id)
            if (
                occurrence is None
                or occurrence["network_id"] != terminal["network_id"]
                or not _same_source(occurrence["source"], terminal["source"])
            ):
                raise ValueError("network terminal names an unknown occurrence")
            terminal_counts[occurrence_id] += 1
    if terminal_counts != Counter({key: 1 for key in networks}):
        raise ValueError("network request terminal closure is incomplete or duplicated")
    if mapped_resources != set(resource_by_id):
        raise ValueError("discovery audit does not map every retained resource exactly once")
    if mapped_exclusion_pairs != exclusion_pairs:
        raise ValueError("discovery audit does not account for every exclusion summary row")
    if observed_request_count != len(networks):
        raise ValueError("discovery audit request count differs from preparation metadata")
    observed_origins = sorted(
        {
            request_origin
            for event in networks.values()
            if (request_origin := _https_origin(event["url"])) is not None
        }
    )
    if (
        expected_observed_origins is not None
        and list(expected_observed_origins) != observed_origins
    ):
        raise ValueError(
            "discovery audit observed-origin ledger differs from preparation metadata"
        )

    summary = {
        "event_count": len(events),
        "target_event_count": counts["target-activity"],
        "browser_internal_document_count": counts["browser-internal-document"],
        "network_request_count": counts["network-request"],
        "fetch_request_count": counts["fetch-request"],
        "fetch_internal_restart_count": sum(
            event["relationship"] == "internal-restart" for event in fetches
        ),
        "terminal_event_count": counts["network-terminal"],
        "resource_occurrence_count": len(mapped_resources),
        "exclusion_occurrence_count": len(exclusion_occurrences),
    }
    if value["summary"] != summary:
        raise ValueError("discovery event audit summary does not verify")
    if any(event["monotonic_ms"] > render_observation["cutoff_ms"] for event in events):
        raise ValueError("discovery audit contains an event after the render cutoff")
    if render_observation["last_relevant_event_ms"] != max(
        event["monotonic_ms"] for event in events
    ):
        raise ValueError("render last-event time differs from the discovery audit")
    return summary
