"""Opt-in root CDP trace for a short, non-evidentiary acquisition rehearsal.

``install(emit)`` patches the navigation and discovery router references only
in the current Python process. It leaves production router policy, retries,
and source data untouched. Request identities and URLs are hashed before emission.
"""

from collections import OrderedDict, deque
from hashlib import sha256
from typing import Any, Callable, Mapping

import qcsd_lab.class_acquisition as class_acquisition
import qcsd_lab.cdp_targets as cdp_targets
import qcsd_lab.discover as discover
from qcsd_lab.cdp_targets import (
    CdpTargetIntegrityError,
    RecursiveCdpTargetRouter,
    _RootInvalidInterception,
)


_ERROR_DOCUMENT_ORDER_ERROR = "Chromium error-document resources were duplicated or reordered"
_ERROR_DOCUMENT_COLUMN_ERROR = (
    "Chromium error-document resource parser columns were inconsistent"
)
_ERROR_DOCUMENT_REQUEST_SIGNATURE_ERROR = (
    "Chromium error-document resource request signature was invalid"
)
_SHUTDOWN_FETCH_OCCURRENCE_ERROR = (
    "normal shutdown Fetch pause has no exact Network occurrence"
)
_SHUTDOWN_NETWORK_OCCURRENCE_ERROR = (
    "normal shutdown Network-only occurrence lacked exact local cancellation"
)
_UNMATCHED_LOADING_TERMINAL_ERROR = (
    "CDP loading terminal event has no active request occurrence"
)


def _digest(value: object) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    return sha256(value.encode("utf-8")).hexdigest()


def _event_summary(source: object, method: str, event: Mapping[str, Any]) -> dict[str, Any]:
    request = event.get("request")
    if not isinstance(request, Mapping):
        request = {}
    summary = {
        "cdp_method": method,
        "session_depth": len(getattr(source, "session_path", ())),
        "source_target_type": getattr(source, "target_type", None),
        "source_target_id_sha256": _digest(getattr(source, "target_id", None)),
        "request_id_sha256": _digest(event.get("requestId")),
        "network_id_sha256": _digest(event.get("networkId")),
        "loader_id_sha256": _digest(event.get("loaderId")),
        "frame_id_sha256": _digest(event.get("frameId")),
        "document_url_sha256": _digest(event.get("documentURL")),
        "resource_type": event.get("resourceType", event.get("type")),
        "request_method": request.get("method"),
        "url_sha256": _digest(request.get("url")),
        "redirect_response": event.get("redirectResponse") is not None,
        "response_stage": any(
            key in event
            for key in (
                "responseStatusCode",
                "responseStatusText",
                "responseHeaders",
                "responseErrorReason",
            )
        ),
    }
    if method == "Network.loadingFailed":
        summary["terminal_failure"] = _safe_terminal_failure(
            {
                "error_text": event.get("errorText"),
                "canceled": event.get("canceled"),
                "blocked_reason": event.get("blockedReason"),
                "cors_error_status_present": event.get("corsErrorStatus") is not None,
            }
        )
    return summary


def _keyset_projection(
    value: object, expected: frozenset[str]
) -> dict[str, Any]:
    """Name missing protocol fields; hash unexpected field names and omit values."""

    if not isinstance(value, Mapping):
        return {"is_mapping": False, "missing_fields": sorted(expected), "unexpected_field_hashes": []}
    actual = set(value)
    unexpected = sorted(
        sha256(str(key).encode("utf-8")).hexdigest()
        for key in actual - expected
    )
    return {
        "is_mapping": True,
        "missing_fields": sorted(expected - actual),
        "unexpected_field_hashes": unexpected[:16],
        "unexpected_fields_truncated": len(unexpected) > 16,
    }


def _error_document_request_signature_projection(
    router: RecursiveCdpTargetRouter,
    source: object,
    event: Mapping[str, Any],
) -> dict[str, Any]:
    """Mirror each strict signature check without exporting protocol values."""

    lifecycle = router._error_document_resources_for_loader(source, event.get("loaderId"))
    request = event.get("request")
    initiator = event.get("initiator")
    headers = request.get("headers") if isinstance(request, Mapping) else None
    request_id = event.get("requestId")
    timestamp = event.get("timestamp")
    wall_time = event.get("wallTime")
    initiator_line = (
        initiator.get("lineNumber") if isinstance(initiator, Mapping) else None
    )
    finite_timestamp = cdp_targets._is_finite_protocol_number(timestamp)
    finite_wall_time = cdp_targets._is_finite_protocol_number(wall_time)
    checks = {
        "source_is_root": source == router.root_source,
        "source_matches_owner": lifecycle is not None and source == lifecycle.source,
        "outer_fields_exact": frozenset(event) == cdp_targets._ERROR_DOCUMENT_RESOURCE_REQUEST_FIELDS,
        "request_id_nonempty_string": isinstance(request_id, str) and bool(request_id),
        "request_id_differs_loader": lifecycle is not None and request_id != lifecycle.loader_id,
        "loader_id_matches_owner": lifecycle is not None and event.get("loaderId") == lifecycle.loader_id,
        "frame_id_matches_owner": lifecycle is not None and event.get("frameId") == lifecycle.frame_id,
        "document_url_pinned": event.get("documentURL") == cdp_targets._ERROR_DOCUMENT_URL,
        "resource_type_image": event.get("type") == "Image",
        "redirect_has_extra_info_false": event.get("redirectHasExtraInfo") is False,
        "has_user_gesture_false": event.get("hasUserGesture") is False,
        "timestamp_finite": finite_timestamp,
        "timestamp_after_owner": (
            lifecycle is not None
            and finite_timestamp
            and float(timestamp) > lifecycle.latest_timestamp
        ),
        "wall_time_finite": finite_wall_time,
        "wall_time_positive": finite_wall_time and float(wall_time) > 0,
        "request_mapping": isinstance(request, Mapping),
        "inner_fields_exact": (
            isinstance(request, Mapping)
            and frozenset(request) == cdp_targets._ERROR_DOCUMENT_RESOURCE_INNER_REQUEST_FIELDS
        ),
        "method_get": isinstance(request, Mapping) and request.get("method") == "GET",
        "headers_exact": headers == {
            "User-Agent": cdp_targets._PINNED_ERROR_DOCUMENT_USER_AGENT,
            "Referer": "",
        },
        "headers_user_agent_pinned": (
            isinstance(headers, Mapping)
            and headers.get("User-Agent") == cdp_targets._PINNED_ERROR_DOCUMENT_USER_AGENT
        ),
        "headers_referer_empty": isinstance(headers, Mapping) and headers.get("Referer") == "",
        "mixed_content_none": isinstance(request, Mapping) and request.get("mixedContentType") == "none",
        "initial_priority_low": isinstance(request, Mapping) and request.get("initialPriority") == "Low",
        "referrer_policy_strict_origin": (
            isinstance(request, Mapping)
            and request.get("referrerPolicy") == "strict-origin-when-cross-origin"
        ),
        "is_same_site_false": isinstance(request, Mapping) and request.get("isSameSite") is False,
        "initiator_mapping": isinstance(initiator, Mapping),
        "initiator_fields_exact": (
            isinstance(initiator, Mapping)
            and frozenset(initiator) == cdp_targets._ERROR_DOCUMENT_RESOURCE_INITIATOR_FIELDS
        ),
        "initiator_type_parser": isinstance(initiator, Mapping) and initiator.get("type") == "parser",
        "initiator_url_pinned": (
            isinstance(initiator, Mapping)
            and initiator.get("url") == cdp_targets._ERROR_DOCUMENT_URL
        ),
        "initiator_line_bounded": (
            isinstance(initiator, Mapping)
            and type(initiator.get("lineNumber")) is int
            and 0 <= initiator.get("lineNumber") <= cdp_targets._ERROR_DOCUMENT_PARSER_LINE_MAX
        ),
        "initiator_column_bounded": (
            isinstance(initiator, Mapping)
            and type(initiator.get("columnNumber")) is int
            and 0 <= initiator.get("columnNumber") <= cdp_targets._ERROR_DOCUMENT_PARSER_COLUMN_MAX
        ),
        "initiator_column_plain_int": (
            isinstance(initiator, Mapping)
            and type(initiator.get("columnNumber")) is int
        ),
    }
    return {
        "checks": checks,
        "failed_checks": [name for name, passed in checks.items() if not passed],
        "observed_initiator_line_bounded": (
            initiator_line
            if type(initiator_line) is int and 0 <= initiator_line <= 4_095
            else None
        ),
        "field_sets": {
            "outer": _keyset_projection(event, cdp_targets._ERROR_DOCUMENT_RESOURCE_REQUEST_FIELDS),
            "request": _keyset_projection(request, cdp_targets._ERROR_DOCUMENT_RESOURCE_INNER_REQUEST_FIELDS),
            "headers": _keyset_projection(headers, frozenset({"User-Agent", "Referer"})),
            "initiator": _keyset_projection(initiator, cdp_targets._ERROR_DOCUMENT_RESOURCE_INITIATOR_FIELDS),
        },
    }


def _shutdown_ledger_summary(ledger: object) -> dict[str, Any]:
    """Explain unmatched disposal occurrences without exporting CDP IDs or URLs."""

    fetches = getattr(ledger, "_fetches")
    networks = getattr(ledger, "_networks")
    all_fetches = [fetch for group in fetches.values() for fetch in group]
    all_networks = [network for group in networks.values() for network in group]
    unmatched = [fetch for fetch in all_fetches if fetch.matched_network is None]
    unmatched_networks = [
        network for network in all_networks if network.matched_fetch is None
    ]
    network_details = []
    for network in unmatched_networks[:16]:
        active = network.active
        same_id_fetches = fetches.get(active.request_id, ())
        network_details.append(
            {
                "network_id_sha256": _digest(active.request_id),
                "url_sha256": _digest(active.url),
                "source_target_type": active.source.target_type,
                "source_target_id_sha256": _digest(active.source.target_id),
                "session_depth": len(active.source.session_path),
                "frame_id_sha256": _digest(active.frame_id),
                "resource_type": active.resource_type,
                "request_method": active.method,
                "leg_index": network.leg_index,
                "has_predecessor": network.predecessor is not None,
                "has_successor": network.successor is not None,
                "terminal_outcome": network.terminal_outcome,
                "same_id_fetch_total": len(same_id_fetches),
                "same_id_fetches": [
                    {
                        "fetch_request_id_sha256": _digest(fetch.fetch_request_id),
                        "url_sha256": _digest(fetch.url),
                        "source_target_type": fetch.source.target_type,
                        "source_target_id_sha256": _digest(fetch.source.target_id),
                        "frame_id_sha256": _digest(fetch.frame_id),
                        "resource_type": fetch.resource_type,
                        "request_method": fetch.method,
                        "leg_index": fetch.leg_index,
                        "pre_shutdown_network_id_seen": (
                            fetch.pre_shutdown_network_id_seen
                        ),
                        "root_page_context_disposal_candidate": (
                            fetch.root_page_context_disposal_candidate
                        ),
                    }
                    for fetch in same_id_fetches[:4]
                ],
                "same_id_fetches_truncated": len(same_id_fetches) > 4,
            }
        )
    details = []
    for fetch in unmatched[:16]:
        same_id_networks = networks.get(fetch.network_id, ())
        details.append(
            {
                "fetch_request_id_sha256": _digest(fetch.fetch_request_id),
                "network_id_sha256": _digest(fetch.network_id),
                "url_sha256": _digest(fetch.url),
                "source_target_type": fetch.source.target_type,
                "source_target_id_sha256": _digest(fetch.source.target_id),
                "session_depth": len(fetch.source.session_path),
                "frame_id_sha256": _digest(fetch.frame_id),
                "resource_type": fetch.resource_type,
                "request_method": fetch.method,
                "leg_index": fetch.leg_index,
                "has_predecessor": fetch.predecessor is not None,
                "has_successor": fetch.successor is not None,
                "pre_shutdown_network_id_seen": fetch.pre_shutdown_network_id_seen,
                "root_page_context_disposal_candidate": (
                    fetch.root_page_context_disposal_candidate
                ),
                "global_fetch_total": len(all_fetches),
                "same_id_fetch_total": len(fetches.get(fetch.network_id, ())),
                "same_id_network_total": len(same_id_networks),
                "same_id_networks": [
                    {
                        "url_sha256": _digest(network.active.url),
                        "source_target_type": network.active.source.target_type,
                        "source_target_id_sha256": _digest(
                            network.active.source.target_id
                        ),
                        "frame_id_sha256": _digest(network.active.frame_id),
                        "resource_type": network.active.resource_type,
                        "request_method": network.active.method,
                        "leg_index": network.leg_index,
                        "terminal_outcome": network.terminal_outcome,
                    }
                    for network in same_id_networks[:4]
                ],
            }
        )
    return {
        "network_total": len(all_networks),
        "fetch_total": len(all_fetches),
        "unmatched_network_total": len(unmatched_networks),
        "unmatched_networks_truncated": len(unmatched_networks) > len(network_details),
        "unmatched_networks": network_details,
        "unmatched_fetch_total": len(unmatched),
        "unmatched_fetches_truncated": len(unmatched) > len(details),
        "unmatched_fetches": details,
    }


_SAFE_EXCLUSION_REASONS = frozenset(
    {
        "unsafe method: OPTIONS",
        "unsafe method: POST",
        "origin not approved",
        "not an absolute HTTPS request",
    }
)


def _safe_reason(value: object) -> dict[str, str | None]:
    """Keep known policy labels legible without exporting arbitrary page text."""

    return {
        "code": (
            value if isinstance(value, str) and value in _SAFE_EXCLUSION_REASONS else None
        ),
        "sha256": _digest(value),
    }


def _safe_terminal_failure(value: object) -> dict[str, Any] | None:
    """Bound a CDP loading failure to protocol codes and hashed unknown text."""

    if not isinstance(value, Mapping):
        return None
    error_text = value.get("error_text")
    error_code = None
    if isinstance(error_text, str) and error_text.startswith("net::ERR_"):
        suffix = error_text[len("net::ERR_") :]
        if 0 < len(suffix) <= 64 and all(
            character in "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_" for character in suffix
        ):
            error_code = error_text
    blocked_reason = value.get("blocked_reason")
    return {
        "error_code": error_code,
        "error_text_sha256": _digest(error_text),
        "canceled": value.get("canceled") if type(value.get("canceled")) is bool else None,
        "blocked_reason_code": (
            blocked_reason
            if isinstance(blocked_reason, str)
            and blocked_reason in {"inspector", "other"}
            else None
        ),
        "blocked_reason_sha256": _digest(blocked_reason),
        "cors_error_status_present": value.get("cors_error_status_present") is True,
    }


def _safe_audit_mapping(value: object) -> dict[str, Any] | None:
    if not isinstance(value, Mapping):
        return None
    mapping = value.get("mapping")
    if not isinstance(mapping, Mapping):
        return None
    kind = mapping.get("kind")
    return {
        "kind": kind if isinstance(kind, str) and kind in {"resource", "exclusion"} else None,
        "kind_sha256": _digest(kind),
        "reason": _safe_reason(mapping.get("reason")),
    }


def _observation_ledger_summary(ledger: object) -> dict[str, Any]:
    """Describe an unfinished discovery reconciliation without raw URLs or IDs."""

    networks = [
        item for group in ledger._network.values() for item in group
    ]
    fetches = [
        item for group in ledger._intercepted.values() for item in group
    ]
    unmatched_networks = [item for item in networks if not item.matched]
    unmatched_fetches = [item for item in fetches if not item.matched]

    def preflight_candidates(network: object) -> dict[str, Any]:
        candidates = [
            item
            for item in networks
            if item is not network
            and item.source == network.source
            and item.request.method == "OPTIONS"
            and item.request.url == network.request.url
        ]
        details = []
        for candidate in candidates[:4]:
            matching_fetches = [
                item
                for item in fetches
                if item.matched_occurrence_id == candidate.occurrence_id
            ]
            details.append(
                {
                    "network_id_sha256": _digest(candidate.network_id),
                    "occurrence_id_sha256": _digest(candidate.occurrence_id),
                    "initiator_request_id_sha256": _digest(candidate.initiator_request_id),
                    "causes_unmatched_request": (
                        candidate.initiator_request_id == network.network_id
                    ),
                    "resource_type": candidate.resource_type,
                    "initiator_type": candidate.initiator_type,
                    "redirected": candidate.redirected,
                    "response_observed": candidate.response_observed,
                    "terminal": candidate.terminal,
                    "terminal_outcome": candidate.terminal_outcome,
                    "terminal_failure": _safe_terminal_failure(candidate.terminal_failure),
                    "sequence": candidate.sequence,
                    "terminal_sequence": candidate.terminal_sequence,
                    "fetch_matches": candidate.fetch_matches,
                    "audit_mapping": _safe_audit_mapping(candidate.audit_event),
                    "matching_fetch_total": len(matching_fetches),
                    "matching_fetches_truncated": len(matching_fetches) > 4,
                    "matching_fetches": [
                        {
                            "fetch_id_sha256": _digest(item.fetch_id),
                            "policy_decision": (
                                item.policy_decision
                                if item.policy_decision in {"continue", "fail"}
                                else None
                            ),
                            "policy_reason": _safe_reason(item.policy_reason),
                            "redirected_request_id_sha256": _digest(
                                item.redirected_request_id
                            ),
                            "sequence": item.sequence,
                        }
                        for item in matching_fetches[:4]
                    ],
                }
            )
        return {
            "preflight_candidate_total": len(candidates),
            "preflight_candidates_truncated": len(candidates) > len(details),
            "preflight_candidates": details,
        }

    return {
        "network_total": len(networks),
        "fetch_total": len(fetches),
        "unmatched_network_total": len(unmatched_networks),
        "unmatched_fetch_total": len(unmatched_fetches),
        "unmatched_networks_truncated": len(unmatched_networks) > 16,
        "unmatched_fetches_truncated": len(unmatched_fetches) > 16,
        "unmatched_networks": [
            {
                "network_id_sha256": _digest(item.network_id),
                "occurrence_id_sha256": _digest(item.occurrence_id),
                "initiator_request_id_sha256": _digest(item.initiator_request_id),
                "source_target_type": item.source.target_type,
                "source_target_id_sha256": _digest(item.source.target_id),
                "session_depth": len(item.source.session_path),
                "request_method": item.request.method,
                "url_sha256": _digest(item.request.url),
                "resource_type": item.resource_type,
                "initiator_type": item.initiator_type,
                "redirected": item.redirected,
                "response_observed": item.response_observed,
                "terminal": item.terminal,
                "terminal_outcome": item.terminal_outcome,
                "terminal_failure": _safe_terminal_failure(item.terminal_failure),
                "sequence": item.sequence,
                "terminal_sequence": item.terminal_sequence,
                "fetch_matches": item.fetch_matches,
                "audit_mapping": _safe_audit_mapping(item.audit_event),
                "preflight_exception_applied": (
                    item.blocked_preflight_occurrence_id is not None
                ),
                **preflight_candidates(item),
            }
            for item in unmatched_networks[:16]
        ],
        "unmatched_fetches": [
            {
                "fetch_id_sha256": _digest(item.fetch_id),
                "network_id_sha256": _digest(item.network_id),
                "source_target_type": item.source.target_type,
                "source_target_id_sha256": _digest(item.source.target_id),
                "session_depth": len(item.source.session_path),
                "frame_id_sha256": _digest(item.frame_id),
                "request_method": item.request.method,
                "url_sha256": _digest(item.request.url),
                "redirected_request_id_sha256": _digest(item.redirected_request_id),
                "policy_decision": item.policy_decision,
                "sequence": item.sequence,
            }
            for item in unmatched_fetches[:16]
        ],
    }


def install(emit: Callable[..., None]) -> type[RecursiveCdpTargetRouter]:
    """Observe the active router; activate only under an explicit rehearsal flag."""

    class TracedRouter(RecursiveCdpTargetRouter):
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            super().__init__(*args, **kwargs)
            self._diagnostic_events: deque[dict[str, Any]] = deque(maxlen=128)
            self._diagnostic_request_events: OrderedDict[
                str, deque[dict[str, Any]]
            ] = OrderedDict()
            self._diagnostic_root_fetches: deque[
                tuple[object, Mapping[str, Any]]
            ] = deque(maxlen=128)
            self._diagnostic_current_event: tuple[object, str, Mapping[str, Any]] | None = None

        def _handle_forwarded(
            self, source: object, method: str, event: Mapping[str, Any]
        ) -> None:
            previous = self._diagnostic_current_event
            self._diagnostic_current_event = (source, method, event)
            try:
                if method in {
                    "Fetch.requestPaused",
                    "Network.requestWillBeSent",
                    "Network.requestServedFromCache",
                    "Network.responseReceived",
                    "Network.loadingFinished",
                    "Network.loadingFailed",
                }:
                    summary = _event_summary(source, method, event)
                    if source == self.root_source or getattr(self, "_shutting_down", False):
                        self._diagnostic_events.append(summary)
                    # A busy page can evict its request start from the global
                    # ring. Keep a separately bounded, in-process history by
                    # raw CDP identity and emit only hashed summaries.
                    identities = {
                        value
                        for value in (event.get("requestId"), event.get("networkId"))
                        if isinstance(value, str) and value
                    }
                    for identity in identities:
                        history = self._diagnostic_request_events.get(identity)
                        if history is None:
                            history = deque(maxlen=16)
                            self._diagnostic_request_events[identity] = history
                        history.append(summary)
                        self._diagnostic_request_events.move_to_end(identity)
                    while len(self._diagnostic_request_events) > 256:
                        self._diagnostic_request_events.popitem(last=False)
                if source == self.root_source and method == "Fetch.requestPaused":
                    # Keep only a bounded in-process reference. The emitted
                    # record below contains hashes, never raw CDP identities.
                    self._diagnostic_root_fetches.append((source, event))
            except Exception:
                # A malformed diagnostic summary must not replace the real
                # router result for this event.
                pass
            try:
                return super()._handle_forwarded(source, method, event)
            except CdpTargetIntegrityError as error:
                if str(error) == _UNMATCHED_LOADING_TERMINAL_ERROR:
                    try:
                        request_id = event.get("requestId")
                        history = self._diagnostic_request_events.get(request_id, ())
                        active = self._active_requests.get(request_id, ())
                        emit(
                            "unmatched-loading-terminal-trace",
                            error=str(error),
                            current_event=_event_summary(source, method, event),
                            matching_identity_events=list(history),
                            matching_identity_events_at_capacity=(len(history) == 16),
                            active_same_id_count=len(active),
                            active_same_id=[
                                {
                                    "source_target_type": item.source.target_type,
                                    "source_target_id_sha256": _digest(
                                        item.source.target_id
                                    ),
                                    "session_depth": len(item.source.session_path),
                                    "loader_id_sha256": _digest(item.loader_id),
                                    "frame_id_sha256": _digest(item.frame_id),
                                    "resource_type": item.resource_type,
                                    "request_method": item.method,
                                    "url_sha256": _digest(item.url),
                                }
                                for item in active[:4]
                            ],
                            active_same_id_truncated=(len(active) > 4),
                            shutting_down=self._shutting_down,
                            aborting=self._aborting,
                            recent_protocol_events=list(self._diagnostic_events),
                        )
                    except Exception:
                        # Diagnostics cannot replace the integrity failure.
                        pass
                if str(error) == _ERROR_DOCUMENT_REQUEST_SIGNATURE_ERROR:
                    try:
                        emit(
                            "root-error-document-request-signature-trace",
                            error=str(error),
                            current_event=_event_summary(source, method, event),
                            signature=_error_document_request_signature_projection(
                                self, source, event
                            ),
                            shutting_down=self._shutting_down,
                            aborting=self._aborting,
                        )
                    except Exception:
                        # Diagnostics cannot replace the integrity failure.
                        pass
                elif str(error) in {_ERROR_DOCUMENT_ORDER_ERROR, _ERROR_DOCUMENT_COLUMN_ERROR}:
                    try:
                        request = event.get("request")
                        if not isinstance(request, Mapping):
                            request = {}
                        initiator = event.get("initiator")
                        if not isinstance(initiator, Mapping):
                            initiator = {}
                        signature = self._error_document_resource_signature(
                            request.get("url")
                        )
                        lifecycle = self._error_document_resources_for_loader(
                            source, event.get("loaderId")
                        )
                        active = lifecycle.active if lifecycle is not None else None
                        base_column = (
                            lifecycle.initiator_column_base
                            if lifecycle is not None
                            else None
                        )
                        emit(
                            (
                                "root-error-document-column-trace"
                                if str(error) == _ERROR_DOCUMENT_COLUMN_ERROR
                                else "root-error-document-order-trace"
                            ),
                            error=str(error),
                            current_event=_event_summary(source, method, event),
                            initiator_url_sha256=_digest(initiator.get("url")),
                            initiator_column=initiator.get("columnNumber"),
                            expected_initiator_column=(
                                base_column + (1 if signature[0] == 2 else 0)
                                if signature is not None and base_column is not None
                                else None
                            ),
                            observed_first_initiator_column=base_column,
                            historical_reference_column=(
                                cdp_targets._ERROR_DOCUMENT_RESOURCE_SIGNATURES[
                                    signature[0]
                                ][2]
                                if signature is not None else None
                            ),
                            observed_signature_index=(
                                signature[0] if signature is not None else None
                            ),
                            expected_signature_index=(
                                lifecycle.next_signature_index
                                if lifecycle is not None
                                else None
                            ),
                            lifecycle_complete=(
                                lifecycle.complete if lifecycle is not None else None
                            ),
                            active_signature_index=(
                                active.signature_index if active is not None else None
                            ),
                            active_phase=(active.phase if active is not None else None),
                            recent_protocol_events=list(self._diagnostic_events),
                        )
                    except Exception:
                        # Diagnostics cannot replace the integrity failure.
                        pass
                elif str(error) != _UNMATCHED_LOADING_TERMINAL_ERROR:
                    try:
                        request_id = event.get("requestId")
                        history = self._diagnostic_request_events.get(request_id, ())
                        emit(
                            "router-integrity-trace",
                            error_type=type(error).__name__,
                            error_message_sha256=sha256(
                                str(error).encode("utf-8")
                            ).hexdigest(),
                            current_event=_event_summary(source, method, event),
                            matching_identity_events=list(history),
                            matching_identity_events_at_capacity=(len(history) == 16),
                            shutting_down=self._shutting_down,
                            aborting=self._aborting,
                            recent_protocol_events=list(self._diagnostic_events),
                        )
                    except Exception:
                        # Diagnostics cannot replace the integrity failure.
                        pass
                raise
            finally:
                self._diagnostic_current_event = previous

        def finish(self) -> None:
            try:
                return super().finish()
            except CdpTargetIntegrityError as error:
                if str(error) in {
                    _SHUTDOWN_FETCH_OCCURRENCE_ERROR,
                    _SHUTDOWN_NETWORK_OCCURRENCE_ERROR,
                }:
                    try:
                        emit(
                            (
                                "normal-shutdown-fetch-occurrence-trace"
                                if str(error) == _SHUTDOWN_FETCH_OCCURRENCE_ERROR
                                else "normal-shutdown-network-occurrence-trace"
                            ),
                            error=str(error),
                            ledger=_shutdown_ledger_summary(
                                self._normal_shutdown_disposal
                            ),
                            recent_protocol_events=list(self._diagnostic_events),
                        )
                    except Exception:
                        # Diagnostics cannot replace the integrity failure.
                        pass
                else:
                    try:
                        emit(
                            "router-finish-integrity-trace",
                            error_type=type(error).__name__,
                            error_message_sha256=sha256(
                                str(error).encode("utf-8")
                            ).hexdigest(),
                            shutting_down=self._shutting_down,
                            aborting=self._aborting,
                            recent_protocol_events=list(self._diagnostic_events),
                        )
                    except Exception:
                        pass
                raise

        def _root_send(self, method: str, params: Mapping[str, Any]) -> dict[str, Any]:
            try:
                return super()._root_send(method, params)
            except _RootInvalidInterception as error:
                try:
                    current = self._diagnostic_current_event
                    current_summary = (
                        _event_summary(*current) if current is not None else None
                    )
                    request_id = params.get("requestId")
                    decision = self._root_fetch_by_policy_identity.get(
                        (self.root_source, request_id)
                    )
                    command_fetches = [
                        event
                        for source, event in self._diagnostic_root_fetches
                        if source == self.root_source
                        and event.get("requestId") == request_id
                    ]
                    command_fetch = command_fetches[-1] if command_fetches else None
                    network_id = (
                        decision.network_id
                        if decision is not None
                        else command_fetch.get("networkId")
                        if command_fetch is not None
                        else None
                    )
                    network_key = (self.root_source, network_id)
                    active = self._active_requests.get(network_id, ())
                    active_root_count = sum(
                        item.source == self.root_source for item in active
                    )
                    command_request = (
                        command_fetch.get("request")
                        if command_fetch is not None
                        else None
                    )
                    command_request = (
                        command_request
                        if isinstance(command_request, Mapping)
                        else {}
                    )
                    exact_active_count = sum(
                        item.source == self.root_source
                        and command_fetch is not None
                        and item.frame_id == command_fetch.get("frameId")
                        and item.resource_type == command_fetch.get("resourceType")
                        and item.method == command_request.get("method")
                        and item.url == command_request.get("url")
                        for item in active
                    )
                    network_id_hash = _digest(network_id)
                    identity_events = list(
                        self._diagnostic_request_events.get(network_id, ())
                    )
                    indexed_identity_events = [
                        {"identity_index": index, **item}
                        for index, item in enumerate(identity_events)
                    ]
                    command_fetch_indices = [
                        index
                        for index, item in enumerate(identity_events)
                        if item["cdp_method"] == "Fetch.requestPaused"
                        and item["request_id_sha256"] == _digest(request_id)
                        and item["network_id_sha256"] == network_id_hash
                    ]
                    command_fetch_identity_index = (
                        command_fetch_indices[-1] if command_fetch_indices else None
                    )
                    failed_terminals = [
                        {
                            "identity_index": index,
                            "relative_to_command_fetch": (
                                "before"
                                if index < command_fetch_identity_index
                                else "after"
                                if index > command_fetch_identity_index
                                else "same"
                            )
                            if command_fetch_identity_index is not None
                            else "unknown",
                            **item,
                        }
                        for index, item in enumerate(identity_events)
                        if item["cdp_method"] == "Network.loadingFailed"
                        and item["request_id_sha256"] == network_id_hash
                        and item["source_target_id_sha256"]
                        == _digest(getattr(self.root_source, "target_id", None))
                        and item["session_depth"] == 0
                    ]
                    recent_network_events = [
                        {"recent_index": index, **item}
                        for index, item in enumerate(self._diagnostic_events)
                        if item["request_id_sha256"] == network_id_hash
                    ]
                    terminal = self._root_terminal_requests.get(network_key)
                    emit(
                        "root-invalid-interception-trace",
                        error=str(error),
                        command=method,
                        command_request_id_sha256=_digest(request_id),
                        current_event=current_summary,
                        command_fetch_event=(
                            _event_summary(
                                self.root_source, "Fetch.requestPaused", command_fetch
                            )
                            if command_fetch is not None
                            else None
                        ),
                        command_fetch_identity_count=len(command_fetches),
                        command_recent_network_events=recent_network_events[-8:],
                        command_recent_network_events_truncated=(
                            len(recent_network_events) > 8
                        ),
                        command_identity_events=indexed_identity_events,
                        command_identity_events_at_capacity=(len(identity_events) == 16),
                        command_fetch_identity_index=command_fetch_identity_index,
                        command_failed_terminal_count=len(failed_terminals),
                        command_failed_terminals=failed_terminals,
                        registered_recovery_decision=decision is not None,
                        decision_resource_type=(
                            decision.resource_type if decision is not None else None
                        ),
                        decision_root_frame_match=(
                            decision.frame_id == self._root_frame_id
                            if decision is not None
                            else None
                        ),
                        active_root_network_occurrences=active_root_count,
                        exact_active_root_network_occurrences=exact_active_count,
                        terminal_root_network_occurrence=terminal is not None,
                        terminal_root_network_method=(
                            terminal.terminal_method if terminal is not None else None
                        ),
                        recovery_disabled_for_network=(
                            network_key in self._disabled_root_invalid_interception_networks
                        ),
                        recent_protocol_events=list(self._diagnostic_events),
                    )
                except Exception:
                    # Logging must never change the fail-closed router outcome.
                    pass
                raise

    class TracedObservationLedger(discover._RequestObservationLedger):
        def finish(self) -> None:
            try:
                return super().finish()
            except CdpTargetIntegrityError as error:
                try:
                    emit(
                        "discovery-ledger-integrity-trace",
                        error_type=type(error).__name__,
                        error_message_sha256=sha256(
                            str(error).encode("utf-8")
                        ).hexdigest(),
                        ledger=_observation_ledger_summary(self),
                    )
                except Exception:
                    # The original fail-closed reconciliation still wins.
                    pass
                raise

    class_acquisition.RecursiveCdpTargetRouter = TracedRouter
    discover.RecursiveCdpTargetRouter = TracedRouter
    discover._RequestObservationLedger = TracedObservationLedger
    return TracedRouter
