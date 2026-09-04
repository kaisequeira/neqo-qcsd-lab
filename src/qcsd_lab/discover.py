from __future__ import annotations

import ipaddress
import os
import time
from collections.abc import Hashable, Mapping
from copy import deepcopy
from dataclasses import dataclass, field
from typing import Any, Callable, Sequence
from urllib.parse import urlsplit

from .acquisition_errors import PassiveRenderPolicyError, RecoverableAcquisitionError
from .cdp_targets import (
    CDP_TARGET_INSTRUMENTATION_POLICY,
    CdpTargetIntegrityError,
    CdpTargetSource,
    RecursiveCdpTargetRouter,
)
from .manifest import https_origin, safe_discovery_headers
from .discovery_evidence import (
    DISCOVERY_EVENT_AUDIT_SCHEMA_VERSION,
    PASSIVE_RENDER_CONTRACT,
    PASSIVE_RENDER_CONTRACT_SHA256,
    evidence_sha256,
    passive_render_contract,
    validate_render_observation,
    verify_discovery_event_audit,
)

# Historical manifests expose this scalar.  New evidence binds the complete
# passive-render contract; the scalar remains its minimum post-load duration.
SETTLE_MS = int(PASSIVE_RENDER_CONTRACT["minimum_after_load_ms"])


# One integrity taxonomy covers both target instrumentation and the request
# ledger.  Callers must never retry either class of incomplete observation into
# an ordinary class rejection.
DiscoveryIntegrityError = CdpTargetIntegrityError


@dataclass
class DiscoveredRequest:
    url: str
    resource_type: str
    headers: dict[str, str]
    initiator_urls: set[str] = field(default_factory=set)
    # These fields are discovery-only.  The frozen runtime identity remains the
    # existing resource ID plus its dependency IDs, so no Rust manifest change
    # is needed to retain repeated occurrences or redirect predecessors.
    dependency_indices: set[int] = field(default_factory=set)
    redirect_from_index: int | None = None
    request_instance_id: tuple[tuple[str, ...], str, int, str, int] | None = None
    dependency_scope: str = "legacy"


@dataclass
class _ExtraInfoOccurrence:
    """One CDP request occurrence awaiting an optional wire-header event."""

    request: DiscoveredRequest | None
    expects_extra_info: bool | None = None
    extra_info_applied: bool = False


@dataclass
class _ExtraInfoChain:
    """FIFO association state for one potentially redirect-reused request ID."""

    occurrences: list[_ExtraInfoOccurrence] = field(default_factory=list)
    pending_headers: list[dict[str, str]] = field(default_factory=list)
    next_occurrence: int = 0
    terminal_failed: bool | None = None


@dataclass(frozen=True)
class _ObservedGet:
    method: str
    url: str


@dataclass
class _NetworkObservation:
    source: CdpTargetSource
    request: _ObservedGet
    matched: bool = False
    terminal: bool = False
    sequence: int = 0
    terminal_sequence: int | None = None
    occurrence_id: str = ""
    audit_event: dict[str, Any] | None = None
    fetch_matches: int = 0


@dataclass
class _FetchObservation:
    source: CdpTargetSource
    fetch_id: str
    network_id: str
    request: _ObservedGet
    redirected_request_id: str | None
    frame_id: str | None
    matched: bool = False
    sequence: int = 0
    redirect_consumed: bool = False
    audit_event: dict[str, Any] | None = None


class _RequestObservationLedger:
    """Reconcile every eligible Network occurrence with request-stage Fetch.

    Fetch and Network use different interception IDs, but Fetch supplies the
    Network request ID in ``networkId``.  Retaining positional ledgers per
    source/request chain proves that a replay occurrence was both observed and
    subjected to the request-stage policy, including redirect-ID reuse.
    """

    def __init__(self, *, eligible: Callable[[str, str], bool] | None = None) -> None:
        self._network: dict[str, list[_NetworkObservation]] = {}
        self._intercepted: dict[str, list[_FetchObservation]] = {}
        self._fetches: list[_FetchObservation] = []
        self._fetch_identities: set[tuple[tuple[str, ...], str, int, str]] = set()
        self._sequence = 0
        self._eligible = eligible or (
            lambda method, url: method == "GET" and origin(url) is not None
        )

    def add_network(
        self,
        source: CdpTargetSource,
        *,
        request_id: str,
        method: str,
        url: str,
        occurrence_id: str | None = None,
        audit_event: dict[str, Any] | None = None,
    ) -> None:
        if not self._eligible(method, url):
            return
        if any(
            item.source == source and item.terminal
            for item in self._network.get(request_id, ())
        ):
            raise DiscoveryIntegrityError(
                "Chromium reused a terminated Network request identity"
            )
        self._sequence += 1
        identity = occurrence_id or (
            f"unsealed-{len(self._network.get(request_id, ())):06d}-{request_id}"
        )
        self._network.setdefault(request_id, []).append(
            _NetworkObservation(
                source,
                _ObservedGet(method, url),
                sequence=self._sequence,
                occurrence_id=identity,
                audit_event=audit_event,
            )
        )
        self._reconcile(request_id)

    def add_interception(
        self,
        source: CdpTargetSource,
        event: Mapping[str, Any],
        *,
        audit_event: dict[str, Any] | None = None,
    ) -> None:
        request = event.get("request", {})
        if not isinstance(request, Mapping):
            raise DiscoveryIntegrityError("Chromium request interception payload is malformed")
        method = str(request.get("method", ""))
        url = str(request.get("url", ""))
        if not self._eligible(method, url):
            return
        network_id = event.get("networkId")
        if not isinstance(network_id, str) or not network_id:
            raise DiscoveryIntegrityError(
                "eligible HTTPS GET interception omitted its Network request ID"
            )
        redirected = event.get("redirectedRequestId")
        if redirected is not None and (not isinstance(redirected, str) or not redirected):
            raise DiscoveryIntegrityError("Chromium interception redirect identity is malformed")
        fetch_id = event.get("requestId")
        if not isinstance(fetch_id, str) or not fetch_id:
            raise DiscoveryIntegrityError("Chromium interception identity is malformed")
        identity = (*source.request_chain_key(fetch_id)[:-1], fetch_id)
        if identity in self._fetch_identities:
            raise DiscoveryIntegrityError("Chromium reused a Fetch interception identity")
        if redirected == fetch_id:
            raise DiscoveryIntegrityError("Chromium Fetch redirect identity forms a loop")
        predecessor: _FetchObservation | None = None
        if isinstance(redirected, str):
            compatible = [
                item
                for item in self._fetches
                if item.network_id == network_id
                and self._fetch_sources_compatible(item.source, source, _frame_id(event))
            ]
            if not compatible or compatible[-1].fetch_id != redirected:
                raise DiscoveryIntegrityError(
                    "Chromium Fetch redirect does not name its immediate predecessor"
                )
            matching = [item for item in compatible if item.fetch_id == redirected]
            if len(matching) != 1 or matching[0].redirect_consumed:
                raise DiscoveryIntegrityError("Chromium Fetch redirect predecessor is ambiguous")
            predecessor = matching[0]
            if any(
                network.matched
                and network.terminal
                and network.request == predecessor.request
                and self._sources_compatible(
                    network.source, predecessor.source, predecessor.frame_id
                )
                for network in self._network.get(network_id, ())
            ):
                raise DiscoveryIntegrityError(
                    "Chromium Fetch redirect follows a terminated request chain"
                )
        self._sequence += 1
        observation = _FetchObservation(
                source,
                fetch_id,
                network_id,
                _ObservedGet(method, url),
                redirected if isinstance(redirected, str) else None,
                _frame_id(event),
                sequence=self._sequence,
                audit_event=audit_event,
            )
        self._intercepted.setdefault(network_id, []).append(observation)
        self._fetches.append(observation)
        self._fetch_identities.add(identity)
        if predecessor is not None:
            predecessor.redirect_consumed = True
        self._reconcile(network_id)

    def add_terminal(self, source: CdpTargetSource, request_id: str) -> tuple[str, ...]:
        self._sequence += 1
        candidates = [
            item
            for item in self._network.get(request_id, ())
            if item.source == source and item.matched and not item.terminal
        ]
        if not candidates:
            return ()
        # One loading terminal closes a complete redirect chain.
        for item in candidates:
            item.terminal = True
            item.terminal_sequence = self._sequence
        return tuple(item.occurrence_id for item in candidates)

    def finish(self) -> None:
        for request_id in set(self._network) | set(self._intercepted):
            self._reconcile(request_id)
            self._reconcile_internal_restarts(request_id)
        if any(
            not item.matched
            for values in (*self._network.values(), *self._intercepted.values())
            for item in values
        ):
            raise DiscoveryIntegrityError(
                "eligible HTTPS GET observation and request-stage interception ledgers differ"
            )
        if any(
            not item.terminal for values in self._network.values() for item in values
        ):
            raise DiscoveryIntegrityError(
                "eligible HTTPS GET observation omitted its loading terminal event"
            )

    def _reconcile_internal_restarts(self, request_id: str) -> None:
        networks = self._network.get(request_id, [])
        for fetch in (item for item in self._intercepted.get(request_id, []) if not item.matched):
            if fetch.redirected_request_id is not None:
                continue
            candidates = [
                network
                for network in networks
                if network.matched
                and network.sequence < fetch.sequence
                and (
                    network.terminal_sequence is None
                    or fetch.sequence < network.terminal_sequence
                )
                and network.request == fetch.request
                and self._sources_compatible(network.source, fetch.source, fetch.frame_id)
            ]
            sources = {candidate.source for candidate in candidates}
            if len(sources) > 1:
                raise DiscoveryIntegrityError("Chromium internal request restart is ambiguous")
            if candidates:
                network = candidates[-1]
                fetch.matched = True
                self._bind_audit_match(network, fetch)

    def _reconcile(self, request_id: str) -> None:
        networks = self._network.get(request_id, [])
        fetches = self._intercepted.get(request_id, [])
        progress = True
        while progress:
            progress = False
            for fetch in (item for item in fetches if not item.matched):
                candidates = [
                    network
                    for network in networks
                    if not network.matched
                    and network.request == fetch.request
                    and self._sources_compatible(
                        network.source,
                        fetch.source,
                        fetch.frame_id,
                    )
                ]
                # Redirect loops legitimately repeat method/URL under one
                # source and request ID. Their occurrence order is FIFO. A
                # collision across sources has no protocol ordering proof.
                source_keys = {candidate.source for candidate in candidates}
                if len(source_keys) > 1:
                    raise DiscoveryIntegrityError(
                        "Chromium Network/Fetch request occurrence is ambiguous"
                    )
                if candidates:
                    network = candidates[0]
                    network.matched = True
                    fetch.matched = True
                    self._bind_audit_match(network, fetch)
                    progress = True

    @staticmethod
    def _bind_audit_match(
        network: _NetworkObservation, fetch: _FetchObservation
    ) -> None:
        if fetch.audit_event is not None:
            fetch.audit_event["network_occurrence_id"] = network.occurrence_id
            fetch.audit_event["relationship"] = (
                "primary" if network.fetch_matches == 0 else "internal-restart"
            )
        network.fetch_matches += 1

    @staticmethod
    def _fetch_sources_compatible(
        previous: CdpTargetSource,
        current: CdpTargetSource,
        frame_id: str | None,
    ) -> bool:
        if previous == current:
            return True
        # A detached target can later reappear with the same target ID while
        # raw Fetch and Network IDs are reused.  That new target generation is
        # never the redirect successor of an interception from the old one.
        if (
            previous.target_id == current.target_id
            and previous.generation != current.generation
        ):
            return False
        if previous.target_type not in {"page", "iframe"} or current.target_type not in {
            "page",
            "iframe",
        }:
            return False
        return (
            previous.session_path == current.parent_session_path
            or current.session_path == previous.parent_session_path
            or (frame_id is not None and frame_id in {previous.target_id, current.target_id})
        )

    @staticmethod
    def _sources_compatible(
        network: CdpTargetSource,
        fetch: CdpTargetSource,
        frame_id: str | None,
    ) -> bool:
        if network == fetch:
            return True
        if network.target_type in {"page", "iframe"} and fetch.target_type in {
            "page",
            "iframe",
        }:
            return _RequestObservationLedger._fetch_sources_compatible(
                network, fetch, frame_id
            )
        if network.target_type not in {"worker", "shared_worker"}:
            return False
        if fetch.target_type not in {"page", "iframe"}:
            return False
        return network.parent_session_path == fetch.session_path or (
            frame_id is not None and network.parent_frame_id is not None
            and network.parent_frame_id == frame_id
        )


def _frame_id(event: Mapping[str, Any]) -> str | None:
    value = event.get("frameId")
    return value if isinstance(value, str) and value else None


def _source_evidence(source: CdpTargetSource) -> dict[str, Any]:
    return {
        "session_path": list(source.session_path),
        "target_id": source.target_id,
        "target_type": source.target_type,
        "generation": source.generation,
        "parent_session_path": (
            list(source.parent_session_path)
            if source.parent_session_path is not None
            else None
        ),
        "parent_frame_id": source.parent_frame_id,
    }


def _active_request_identity(source: CdpTargetSource, request_id: str) -> str:
    route = "/".join(source.session_path) if source.session_path else "root"
    return f"{route}|{source.target_id}|{source.generation}|{request_id}"


class _SanitizedEventProjection:
    """Append-only, secret-minimised evidence for the bounded browser pass."""

    def __init__(self, *, clock_ns: Callable[[], int] | None = None) -> None:
        self._clock_ns = clock_ns or time.monotonic_ns
        self._origin_ns = self._clock_ns()
        self._events: list[dict[str, Any]] = []
        self._network_occurrences = 0
        self._exclusion_occurrences = 0
        self._chain_occurrences: dict[
            tuple[tuple[str, ...], str, int, str], int
        ] = {}
        self._previous_chain_occurrence: dict[
            tuple[tuple[str, ...], str, int, str], str
        ] = {}
        self._active_chain_occurrences: dict[
            tuple[tuple[str, ...], str, int, str], list[str]
        ] = {}
        self._last_relevant_event_ms = 0
        self._frozen = False

    @property
    def frozen(self) -> bool:
        return self._frozen

    @property
    def last_relevant_event_ms(self) -> int:
        return self._last_relevant_event_ms

    def now_ms(self) -> int:
        return max(0, (self._clock_ns() - self._origin_ns) // 1_000_000)

    def freeze(self) -> None:
        self._frozen = True

    def _append(
        self, source: CdpTargetSource, kind: str, fields: Mapping[str, Any]
    ) -> dict[str, Any]:
        event = {
            "sequence": len(self._events) + 1,
            "monotonic_ms": self.now_ms(),
            "kind": kind,
            "source": _source_evidence(source),
            **dict(fields),
        }
        if self._frozen:
            # Context disposal happens after the scientific cutoff.  Its
            # synthetic cancellations remain live integrity input but are not
            # misrepresented as observations inside the render window.
            return event
        self._events.append(event)
        self._last_relevant_event_ms = event["monotonic_ms"]
        return event

    def record_target(self, source: CdpTargetSource, target_event: str) -> None:
        self._append(
            source,
            "target-activity",
            {"target_event": target_event},
        )

    def record_network(
        self, source: CdpTargetSource, event: Mapping[str, Any]
    ) -> dict[str, Any]:
        request = event.get("request", {})
        if not isinstance(request, Mapping):
            raise DiscoveryIntegrityError("Chromium network request payload is malformed")
        request_id = str(event.get("requestId", ""))
        chain = (*source.request_chain_key(request_id)[:3], request_id)
        occurrence_index = self._chain_occurrences.get(chain, 0)
        self._chain_occurrences[chain] = occurrence_index + 1
        occurrence_id = f"request-{self._network_occurrences:08d}"
        self._network_occurrences += 1
        redirected = event.get("redirectResponse") is not None
        predecessor = self._previous_chain_occurrence.get(chain)
        self._previous_chain_occurrence[chain] = occurrence_id
        self._active_chain_occurrences.setdefault(chain, []).append(occurrence_id)
        return self._append(
            source,
            "network-request",
            {
                "network_id": request_id,
                "occurrence_id": occurrence_id,
                "occurrence_index": occurrence_index,
                "method": str(request.get("method", "")),
                "url": str(request.get("url", "")),
                "frame_id": _frame_id(event),
                "resource_type": str(event.get("type", "Other")),
                "safe_request_headers": None,
                "interception_required": _network_interception_required(
                    str(request.get("url", ""))
                ),
                "redirected": redirected,
                "redirect_from_occurrence_id": predecessor if redirected else None,
                "mapping": None,
                "dependency_evidence": [],
                "resolved_dependency_resource_ids": [],
            },
        )

    def exclusion_mapping(self, reason: str) -> dict[str, Any]:
        result = {
            "kind": "exclusion",
            "exclusion_occurrence_id": self._exclusion_occurrences,
            "reason": reason,
        }
        self._exclusion_occurrences += 1
        return result

    def record_fetch(
        self,
        source: CdpTargetSource,
        event: Mapping[str, Any],
        *,
        decision: str,
        reason: str | None,
    ) -> dict[str, Any]:
        request = event.get("request", {})
        if not isinstance(request, Mapping):
            raise DiscoveryIntegrityError("Chromium request interception payload is malformed")
        redirected = event.get("redirectedRequestId")
        return self._append(
            source,
            "fetch-request",
            {
                "fetch_id": str(event.get("requestId", "")),
                "network_id": str(event.get("networkId", "")),
                "redirected_fetch_id": redirected if isinstance(redirected, str) else None,
                "network_occurrence_id": None,
                "method": str(request.get("method", "")),
                "url": str(request.get("url", "")),
                "frame_id": _frame_id(event),
                "policy_decision": decision,
                "policy_reason": reason,
                "relationship": None,
            },
        )

    def record_terminal(
        self,
        source: CdpTargetSource,
        event: Mapping[str, Any],
        *,
        outcome: str,
        occurrence_ids: Sequence[str],
    ) -> None:
        request_id = str(event.get("requestId", ""))
        chain = (*source.request_chain_key(request_id)[:3], request_id)
        all_occurrences = self._active_chain_occurrences.pop(chain, [])
        if not self._frozen and not all_occurrences:
            raise DiscoveryIntegrityError(
                "terminal audit event has no active Network occurrence"
            )
        if not set(occurrence_ids).issubset(all_occurrences):
            raise DiscoveryIntegrityError(
                "terminal audit event disagrees with Network/Fetch reconciliation"
            )
        self._append(
            source,
            "network-terminal",
            {
                "network_id": request_id,
                "outcome": outcome,
                "network_occurrence_ids": all_occurrences,
            },
        )

    def build(
        self,
        *,
        instrumentation_policy: str,
        render_observation: Mapping[str, Any],
        resources: Sequence[Mapping[str, Any]],
        exclusions: Sequence[Mapping[str, Any]],
        approved_origins: Sequence[str],
        observed_origins: Sequence[str],
        observed_request_count: int,
    ) -> dict[str, Any]:
        if not self._frozen:
            raise DiscoveryIntegrityError("discovery event audit was not frozen at cutoff")
        counts: dict[str, int] = {
            "target-activity": 0,
            "network-request": 0,
            "fetch-request": 0,
            "network-terminal": 0,
        }
        resource_count = 0
        exclusion_count = 0
        resource_by_id = {resource["id"]: resource for resource in resources}
        for event in self._events:
            counts[event["kind"]] += 1
            if event["kind"] == "network-request":
                mapping = event["mapping"]
                if isinstance(mapping, Mapping) and mapping.get("kind") == "resource":
                    resource = resource_by_id.get(mapping.get("resource_id"))
                    if not isinstance(resource, Mapping):
                        raise DiscoveryIntegrityError(
                            "resource-mapped audit event has no derived resource"
                        )
                    event["safe_request_headers"] = deepcopy(
                        resource.get("headers", [])
                    )
                    resource_count += 1
                elif isinstance(mapping, Mapping) and mapping.get("kind") == "exclusion":
                    exclusion_count += 1
        audit = {
            "schema_version": DISCOVERY_EVENT_AUDIT_SCHEMA_VERSION,
            "instrumentation_policy": instrumentation_policy,
            "passive_render_contract_sha256": PASSIVE_RENDER_CONTRACT_SHA256,
            "render_observation_sha256": evidence_sha256(render_observation),
            "events": self._events,
            "summary": {
                "event_count": len(self._events),
                "target_event_count": counts["target-activity"],
                "network_request_count": counts["network-request"],
                "fetch_request_count": counts["fetch-request"],
                "fetch_internal_restart_count": sum(
                    event.get("relationship") == "internal-restart"
                    for event in self._events
                    if event["kind"] == "fetch-request"
                ),
                "terminal_event_count": counts["network-terminal"],
                "resource_occurrence_count": resource_count,
                "exclusion_occurrence_count": exclusion_count,
            },
        }
        verify_discovery_event_audit(
            audit,
            render_observation=render_observation,
            resources=resources,
            exclusions=exclusions,
            approved_origins=approved_origins,
            observed_request_count=observed_request_count,
            expected_observed_origins=observed_origins,
        )
        return audit


def _render_observation(
    audit: _SanitizedEventProjection,
    router: RecursiveCdpTargetRouter,
    *,
    navigation_started_ms: int,
    load_event_ms: int,
    cutoff_reason: str,
) -> dict[str, Any]:
    cutoff_ms = audit.now_ms()
    active = sorted(
        _active_request_identity(source, request_id)
        for source, request_id in router.active_request_identities
    )
    last = audit.last_relevant_event_ms
    minimum_boundary = load_event_ms + int(
        PASSIVE_RENDER_CONTRACT["minimum_after_load_ms"]
    )
    return {
        "schema_version": 1,
        "clock": "monotonic-relative-ms",
        "navigation_started_ms": navigation_started_ms,
        "load_event_ms": load_event_ms,
        "last_relevant_event_ms": last,
        "quiet_started_ms": max(minimum_boundary, last),
        "cutoff_ms": cutoff_ms,
        "active_request_ids": active,
        "active_request_count": len(active),
        "cutoff_reason": cutoff_reason,
    }


def _wait_for_passive_render(
    page: Any,
    router: RecursiveCdpTargetRouter,
    audit: _SanitizedEventProjection,
    *,
    navigation_started_ms: int,
    load_event_ms: int,
) -> dict[str, Any]:
    """Wait for the preregistered minimum plus network/target quiescence."""

    minimum = int(PASSIVE_RENDER_CONTRACT["minimum_after_load_ms"])
    quiet_window = int(PASSIVE_RENDER_CONTRACT["quiet_window_ms"])
    hard_cap = int(PASSIVE_RENDER_CONTRACT["hard_cap_after_load_ms"])
    poll = int(PASSIVE_RENDER_CONTRACT["poll_interval_ms"])
    while True:
        router.raise_if_failed()
        now = audit.now_ms()
        last = audit.last_relevant_event_ms
        quiet_started = max(load_event_ms + minimum, last)
        active = router.active_request_identities
        if not active and now - quiet_started >= quiet_window:
            result = _render_observation(
                audit,
                router,
                navigation_started_ms=navigation_started_ms,
                load_event_ms=load_event_ms,
                cutoff_reason="quiescent",
            )
            validate_render_observation(result)
            return result
        if now - load_event_ms >= hard_cap:
            result = _render_observation(
                audit,
                router,
                navigation_started_ms=navigation_started_ms,
                load_event_ms=load_event_ms,
                cutoff_reason="hard-cap-non-quiescent",
            )
            validate_render_observation(result, allow_failure=True)
            raise PassiveRenderPolicyError(
                "passive render did not quiesce within 30000 ms after load",
                evidence={
                    "passive_render_contract": passive_render_contract(),
                    "passive_render_contract_sha256": PASSIVE_RENDER_CONTRACT_SHA256,
                    "render_observation": result,
                    "render_observation_sha256": evidence_sha256(result),
                },
            )
        next_boundary = min(
            load_event_ms + hard_cap,
            quiet_started + quiet_window,
        )
        wait_ms = max(1, min(poll, next_boundary - now))
        page.wait_for_timeout(wait_ms)


@dataclass(frozen=True)
class _DependencyOccurrence:
    source: CdpTargetSource
    scope: str
    url: str
    resource_id: int


def _stack_frame_urls(value: Any) -> list[str]:
    """Return every URL in a CDP StackTrace, including recursively present parents."""

    if value is None:
        return []
    if not isinstance(value, Mapping):
        raise DiscoveryIntegrityError("Chromium initiator stack is malformed")
    frames = value.get("callFrames", [])
    if not isinstance(frames, list):
        raise DiscoveryIntegrityError("Chromium initiator stack frames are malformed")
    result: list[str] = []
    for frame in frames:
        if not isinstance(frame, Mapping):
            raise DiscoveryIntegrityError("Chromium initiator stack frame is malformed")
        frame_url = frame.get("url")
        if frame_url is not None and not isinstance(frame_url, str):
            raise DiscoveryIntegrityError("Chromium initiator stack URL is malformed")
        if frame_url:
            result.append(frame_url)
    parent = value.get("parent")
    if parent is not None:
        result.extend(_stack_frame_urls(parent))
    return result


def _network_interception_required(url: str) -> bool:
    try:
        return urlsplit(url).scheme.lower() in {"http", "https"}
    except (TypeError, ValueError):
        return False


def _resolve_dependency_url(
    occurrences: Sequence[_DependencyOccurrence],
    *,
    source: CdpTargetSource,
    scope: str,
    url: str,
) -> int | None:
    candidates: list[tuple[int, _DependencyOccurrence]] = []
    for candidate in occurrences:
        if candidate.url != url:
            continue
        if candidate.scope == scope:
            rank = 0
        elif candidate.source == source:
            rank = 1
        elif source.parent_frame_id is not None and candidate.scope == source.parent_frame_id:
            rank = 2
        elif (
            candidate.source.parent_frame_id is not None
            and candidate.source.parent_frame_id == scope
        ):
            rank = 2
        elif (
            candidate.source.session_path == source.parent_session_path
            or source.session_path == candidate.source.parent_session_path
        ):
            rank = 3
        else:
            continue
        candidates.append((rank, candidate))
    if not candidates:
        return None
    best_rank = min(rank for rank, _candidate in candidates)
    best = [candidate for rank, candidate in candidates if rank == best_rank]
    scopes = {(candidate.source, candidate.scope) for candidate in best}
    if len(scopes) > 1:
        raise DiscoveryIntegrityError("Chromium stack dependency scope is ambiguous")
    return max(best, key=lambda candidate: candidate.resource_id).resource_id


class _RequestExtraInfoAssociator:
    """Match CDP ExtraInfo events to request occurrences without ID aliasing.

    Chromium deliberately reuses ``Network.RequestId`` across a redirect chain.
    The two request events may also arrive in either order.  Association is
    therefore positional: redirect/response metadata says which occurrences
    have ExtraInfo, and ExtraInfo itself is consumed in occurrence order.
    """

    def __init__(self) -> None:
        self._chains: dict[Hashable, _ExtraInfoChain] = {}

    def add_request(
        self,
        request_id: Hashable,
        request: DiscoveredRequest | None,
        *,
        redirected: bool,
        redirect_has_extra_info: object = None,
    ) -> None:
        if request_id is None or request_id == "":
            raise DiscoveryIntegrityError(
                "Chromium network event omitted its request identifier"
            )
        chain = self._chains.setdefault(request_id, _ExtraInfoChain())
        if redirected:
            if not chain.occurrences:
                raise DiscoveryIntegrityError(
                    "Chromium redirect event has no observed predecessor"
                )
            if type(redirect_has_extra_info) is not bool:
                raise DiscoveryIntegrityError(
                    "Chromium redirect event omitted a boolean ExtraInfo flag"
                )
            self._set_expectation(
                request_id,
                chain,
                len(chain.occurrences) - 1,
                redirect_has_extra_info,
            )
        elif chain.occurrences:
            raise DiscoveryIntegrityError(
                "Chromium reused a request identifier outside a redirect chain"
            )
        elif redirect_has_extra_info is not None:
            raise DiscoveryIntegrityError(
                "Chromium supplied redirect ExtraInfo metadata without a redirect"
            )
        chain.occurrences.append(_ExtraInfoOccurrence(request=request))
        self._sync(chain)

    def add_response(self, request_id: Hashable, has_extra_info: object) -> None:
        if request_id is None or request_id == "":
            raise DiscoveryIntegrityError(
                "Chromium response event omitted its request identifier"
            )
        if type(has_extra_info) is not bool:
            raise DiscoveryIntegrityError(
                "Chromium response event omitted a boolean ExtraInfo flag"
            )
        chain = self._chains.get(request_id)
        if chain is None or not chain.occurrences:
            raise DiscoveryIntegrityError("Chromium response event has no observed request")
        self._set_expectation(
            request_id,
            chain,
            len(chain.occurrences) - 1,
            has_extra_info,
        )

    def add_extra_info(self, request_id: Hashable, headers: object) -> None:
        if request_id is None or request_id == "":
            raise DiscoveryIntegrityError(
                "Chromium ExtraInfo event omitted its request identifier"
            )
        if not isinstance(headers, Mapping):
            raise DiscoveryIntegrityError(
                "Chromium ExtraInfo event supplied malformed headers"
            )
        normalized: dict[str, str] = {}
        merge_request_headers(normalized, headers)
        chain = self._chains.setdefault(request_id, _ExtraInfoChain())
        chain.pending_headers.append(normalized)
        self._sync(chain)

    def add_terminal(self, request_id: Hashable, *, failed: bool) -> None:
        """Bind the one chain-terminal event to its observed final occurrence."""

        chain = self._chains.get(request_id)
        if chain is None or not chain.occurrences:
            raise DiscoveryIntegrityError(
                "Chromium loading terminal event has no observed request chain"
            )
        if chain.terminal_failed is not None:
            raise DiscoveryIntegrityError(
                "Chromium request chain supplied duplicate loading terminal events"
            )
        chain.terminal_failed = failed

    def finish(self) -> None:
        """Reject missing or surplus events instead of silently misassociating them."""

        for request_id, chain in self._chains.items():
            self._sync(chain)
            if chain.occurrences and chain.terminal_failed is None:
                raise DiscoveryIntegrityError(
                    "Chromium request chain omitted its loading terminal event for "
                    "one request occurrence"
                )
            # A failed request can omit responseReceived and therefore its
            # hasExtraInfo flag. If exactly one final occurrence and one FIFO
            # header remain, their association is nevertheless unambiguous.
            if (
                chain.terminal_failed is True
                and len(chain.pending_headers) == 1
                and chain.next_occurrence == len(chain.occurrences) - 1
                and chain.occurrences[chain.next_occurrence].expects_extra_info is None
            ):
                chain.occurrences[chain.next_occurrence].expects_extra_info = True
                self._sync(chain)
            if chain.pending_headers:
                raise DiscoveryIntegrityError(
                    "Chromium ExtraInfo event could not be associated with a request "
                    "occurrence"
                )
            if any(
                occurrence.expects_extra_info is True
                and not occurrence.extra_info_applied
                for occurrence in chain.occurrences
            ):
                raise DiscoveryIntegrityError(
                    "Chromium declared but did not deliver request ExtraInfo for "
                    "one request occurrence"
                )
            if (
                chain.occurrences
                and chain.terminal_failed is False
                and chain.occurrences[-1].expects_extra_info is None
            ):
                raise DiscoveryIntegrityError(
                    "successful Chromium request omitted response ExtraInfo metadata for "
                    "one request occurrence"
                )

    @staticmethod
    def _set_expectation(
        request_id: Hashable,
        chain: _ExtraInfoChain,
        occurrence_index: int,
        has_extra_info: bool,
    ) -> None:
        occurrence = chain.occurrences[occurrence_index]
        if occurrence.expects_extra_info is not None:
            raise DiscoveryIntegrityError(
                "Chromium supplied duplicate ExtraInfo presence metadata for "
                "one request occurrence"
            )
        occurrence.expects_extra_info = has_extra_info
        _RequestExtraInfoAssociator._sync(chain)

    @staticmethod
    def _sync(chain: _ExtraInfoChain) -> None:
        while chain.next_occurrence < len(chain.occurrences):
            occurrence = chain.occurrences[chain.next_occurrence]
            if occurrence.expects_extra_info is None:
                return
            if occurrence.expects_extra_info:
                if not chain.pending_headers:
                    return
                headers = chain.pending_headers.pop(0)
                if occurrence.request is not None:
                    # ExtraInfo contains Chromium's final wire request headers,
                    # so it deliberately wins over requestWillBeSent.
                    merge_request_headers(occurrence.request.headers, headers)
                occurrence.extra_info_applied = True
            chain.next_occurrence += 1


@dataclass
class DiscoveryResult:
    """Browser request graph and the evidence needed to audit its preparation."""

    source_url: str
    final_url: str
    chromium_version: str
    settle_ms: int
    observed_request_count: int
    observed_origins: list[str]
    approved_origins: list[str]
    exclusions: list[dict[str, str]]
    resources: list[dict[str, Any]]
    origin_ip_pins: dict[str, str] = field(default_factory=dict)
    # Production supplies the exact HTTPS-GET-only set that an iterative
    # caller may promote into the next approved-origin pass.  ``None`` records
    # an absent ledger; class-study convergence rejects that absence.
    expandable_origins: list[str] | None = None
    instrumentation_policy: str = CDP_TARGET_INSTRUMENTATION_POLICY
    passive_render_contract: dict[str, Any] | None = None
    passive_render_contract_sha256: str | None = None
    render_observation: dict[str, Any] | None = None
    render_observation_sha256: str | None = None
    discovery_event_audit: dict[str, Any] | None = None
    discovery_event_audit_sha256: str | None = None


@dataclass
class _RequestAdmission:
    """Record and enforce the discovery request policy before network I/O."""

    approved_origins: set[str]
    observed_request_count: int = 0
    observed_origins: set[str] = field(default_factory=set)
    expandable_origins: set[str] = field(default_factory=set)
    exclusions: dict[tuple[str, str], dict[str, str]] = field(default_factory=dict)

    def exclude(self, url: str, reason: str) -> None:
        self.exclusions[(url, reason)] = {"url": url, "reason": reason}

    def command(self, event: Mapping[str, Any]) -> tuple[str, dict[str, str]]:
        """Return the exact request-stage decision and record its audit evidence."""

        if "responseStatusCode" in event or "responseErrorReason" in event:
            raise DiscoveryIntegrityError(
                "Chromium Fetch interception unexpectedly occurred at response stage"
            )
        request_id = str(event.get("requestId", ""))
        if not request_id:
            raise DiscoveryIntegrityError(
                "Chromium request interception omitted its request identifier"
            )
        request = event.get("request", {})
        if not isinstance(request, Mapping):
            raise DiscoveryIntegrityError("Chromium request interception payload is malformed")
        url = str(request.get("url", ""))
        method = str(request.get("method", ""))
        reason = exclusion_reason(method, url, self.approved_origins)
        if reason:
            # Record before failing so an interception error cannot erase the
            # audit reason for a request that was denied network admission.
            self.exclude(url, reason)
            return (
                "Fetch.failRequest",
                {"requestId": request_id, "errorReason": "BlockedByClient"},
            )
        return "Fetch.continueRequest", {"requestId": request_id}

    def observe_network(self, method: str, url: str) -> None:
        """Count one actual Network occurrence independently of Fetch restarts."""

        self.observed_request_count += 1
        request_origin = origin(url)
        if request_origin:
            self.observed_origins.add(request_origin)
            if method == "GET":
                self.expandable_origins.add(request_origin)

    def enforce(self, session: Any, event: Mapping[str, Any]) -> None:
        """Continue an approved HTTPS GET or fail it while still request-stage paused."""

        method, params = self.command(event)
        session.send(method, params)


def origin(url: str) -> str | None:
    return https_origin(url)


def discover_page(
    url: str,
    *,
    allow_origins: list[str],
    timeout_ms: int,
    origin_ip_pins: Mapping[str, str] | None = None,
) -> DiscoveryResult:
    """Discover one page graph while retaining only explicitly approved origins."""

    if origin(url) is None:
        raise ValueError(f"source URL is not absolute HTTPS: {url}")
    if timeout_ms < 1:
        raise ValueError("discovery timeout must be positive")
    approved = sorted({_normalize_origin(value) for value in allow_origins})
    if not approved:
        raise ValueError("workload preparation requires at least one approved origin")
    pins = _validate_origin_ip_pins(approved, origin_ip_pins)
    try:
        from playwright.sync_api import Error as PlaywrightError
        from playwright.sync_api import sync_playwright
    except ImportError as error:
        raise RuntimeError("discovery requires the discovery Docker image") from error

    admission = _RequestAdmission(set(approved))
    discovered: list[DiscoveredRequest] = []
    final_url = url
    router: RecursiveCdpTargetRouter | None = None
    render_observation: dict[str, Any] | None = None
    audit = _SanitizedEventProjection()
    try:
        with sync_playwright() as playwright:
            launch_args = ["--disable-quic=false", "--enable-quic", "--no-sandbox"]
            if pins:
                launch_args.append("--host-resolver-rules=" + _host_resolver_rules(pins))
            browser = playwright.chromium.launch(
                headless=True,
                executable_path=os.environ.get("PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH"),
                args=launch_args,
            )
            try:
                chromium_version = browser.version
                # Fetch interception does not see frame-owned requests already handled
                # by a service worker. Blocking registration makes request-stage
                # interception the only path from this context to the network.
                context = browser.new_context(
                    ignore_https_errors=False,
                    service_workers="block",
                    viewport={
                        "width": PASSIVE_RENDER_CONTRACT["viewport"]["width"],
                        "height": PASSIVE_RENDER_CONTRACT["viewport"]["height"],
                    },
                    device_scale_factor=PASSIVE_RENDER_CONTRACT["viewport"][
                        "deviceScaleFactor"
                    ],
                )
                page = context.new_page()
                session = context.new_cdp_session(page)
                request_indices: dict[tuple[tuple[str, ...], str, str], int] = {}
                occurrence_counts: dict[tuple[tuple[str, ...], str, str], int] = {}
                latest_url_indices: dict[tuple[str, str], int] = {}
                latest_request_indices: dict[str, list[tuple[CdpTargetSource, str, int]]] = {}
                dependency_occurrences: list[_DependencyOccurrence] = []
                extra_info = _RequestExtraInfoAssociator()
                observation_ledger = _RequestObservationLedger(
                    eligible=lambda _method, candidate_url: _network_interception_required(
                        candidate_url
                    )
                )

                def request_seen(
                    source: CdpTargetSource,
                    event: Mapping[str, Any],
                    audit_event: dict[str, Any],
                ) -> None:
                    request = event.get("request", {})
                    if not isinstance(request, Mapping):
                        raise DiscoveryIntegrityError(
                            "Chromium network request payload is malformed"
                        )
                    request_url = str(request.get("url", ""))
                    method = str(request.get("method", ""))
                    reason = exclusion_reason(method, request_url, admission.approved_origins)
                    admission.observe_network(method, request_url)
                    request_id = str(event.get("requestId", ""))
                    if not request_id:
                        raise DiscoveryIntegrityError(
                            "Chromium network event omitted its request identifier"
                        )
                    chain_key = source.request_chain_key(request_id)
                    observation_ledger.add_network(
                        source,
                        request_id=request_id,
                        method=method,
                        url=request_url,
                        occurrence_id=str(audit_event["occurrence_id"]),
                        audit_event=audit_event,
                    )
                    occurrence = occurrence_counts.get(chain_key, 0)
                    occurrence_counts[chain_key] = occurrence + 1
                    redirected = event.get("redirectResponse") is not None
                    redirect_has_extra_info = (
                        event.get("redirectHasExtraInfo") if redirected else None
                    )
                    if redirected and type(redirect_has_extra_info) is not bool:
                        raise DiscoveryIntegrityError(
                            "Chromium redirect event omitted a boolean ExtraInfo flag"
                        )
                    if reason:
                        # Network.requestWillBeSent can precede Fetch.requestPaused.
                        # Keep this defensive record, while Fetch remains the only
                        # callback that decides whether bytes may leave Chromium.
                        admission.exclude(request_url, reason)
                        # Retain this occurrence in the ExtraInfo FIFO even though
                        # it cannot become a replay resource. Otherwise a later
                        # event sharing its redirect-chain ID could shift headers.
                        extra_info.add_request(
                            chain_key,
                            None,
                            redirected=redirected,
                            redirect_has_extra_info=redirect_has_extra_info,
                        )
                        audit_event["mapping"] = audit.exclusion_mapping(reason)
                        request_indices.pop(chain_key, None)
                        return
                    frame_id = _frame_id(event)
                    scope = frame_id or source.parent_frame_id or source.target_id
                    initiator = event.get("initiator", {})
                    if not isinstance(initiator, Mapping):
                        raise DiscoveryIntegrityError(
                            "Chromium request initiator payload is malformed"
                        )
                    raw_dependency_urls: list[tuple[str, str]] = []
                    document_url = event.get("documentURL")
                    if document_url:
                        raw_dependency_urls.append(("document-url", str(document_url)))
                    initiator_url = initiator.get("url")
                    if initiator_url:
                        raw_dependency_urls.append(("initiator-url", str(initiator_url)))
                    raw_dependency_urls.extend(
                        ("stack-call-frame", stack_url)
                        for stack_url in _stack_frame_urls(initiator.get("stack"))
                    )
                    initiators = {value for _kind, value in raw_dependency_urls}
                    redirect_from = request_indices.get(chain_key)
                    if redirected and redirect_from is None:
                        raise DiscoveryIntegrityError(
                            "Chromium redirect event has no observed predecessor"
                        )
                    dependencies: set[int] = set()
                    dependency_evidence: list[dict[str, Any]] = []
                    for dependency_kind, dependency_url in raw_dependency_urls:
                        resolved = _resolve_dependency_url(
                            dependency_occurrences,
                            source=source,
                            scope=scope,
                            url=dependency_url,
                        )
                        dependency_evidence.append(
                            {
                                "kind": dependency_kind,
                                "value": dependency_url,
                                "resolved_resource_id": resolved,
                            }
                        )
                        if resolved is not None:
                            dependencies.add(resolved)
                    initiator_request_id = initiator.get("requestId")
                    if isinstance(initiator_request_id, str) and initiator_request_id:
                        candidates = [
                            (candidate_source, candidate_scope, index)
                            for candidate_source, candidate_scope, index in (
                                latest_request_indices.get(initiator_request_id, ())
                            )
                            if candidate_scope == scope
                            and (
                                candidate_source == source
                                or candidate_source.parent_session_path == source.session_path
                                or source.parent_session_path == candidate_source.session_path
                            )
                        ]
                        scopes = {
                            (candidate_source, candidate_scope)
                            for candidate_source, candidate_scope, _index in candidates
                        }
                        if len(scopes) > 1:
                            raise DiscoveryIntegrityError(
                                "Chromium initiator request dependency is ambiguous"
                            )
                        resolved_request = (
                            max(candidates, key=lambda candidate: candidate[2])[2]
                            if candidates
                            else None
                        )
                        dependency_evidence.append(
                            {
                                "kind": "initiator-request-id",
                                "value": initiator_request_id,
                                "resolved_resource_id": resolved_request,
                            }
                        )
                        if resolved_request is not None:
                            dependencies.add(resolved_request)
                    if redirected:
                        assert redirect_from is not None
                        dependencies.add(redirect_from)
                        dependency_evidence.append(
                            {
                                "kind": "redirect",
                                "value": str(audit_event["redirect_from_occurrence_id"]),
                                "resolved_resource_id": redirect_from,
                            }
                        )
                    entry = DiscoveredRequest(
                        url=request_url,
                        resource_type=str(event.get("type", "Other")),
                        headers={},
                        initiator_urls=initiators,
                        dependency_indices=dependencies,
                        redirect_from_index=redirect_from if redirected else None,
                        request_instance_id=(
                            source.session_path,
                            source.target_id,
                            source.generation,
                            request_id,
                            occurrence,
                        ),
                        dependency_scope=scope,
                    )
                    merge_request_headers(entry.headers, request.get("headers", {}))
                    extra_info.add_request(
                        chain_key,
                        entry,
                        redirected=redirected,
                        redirect_has_extra_info=redirect_has_extra_info,
                    )
                    discovered.append(entry)
                    request_index = len(discovered) - 1
                    audit_event["mapping"] = {
                        "kind": "resource",
                        "resource_id": request_index,
                    }
                    audit_event["dependency_evidence"] = dependency_evidence
                    audit_event["resolved_dependency_resource_ids"] = sorted(dependencies)
                    request_indices[chain_key] = request_index
                    latest_url_indices[(scope, request_url)] = request_index
                    dependency_occurrences.append(
                        _DependencyOccurrence(source, scope, request_url, request_index)
                    )
                    latest_request_indices.setdefault(request_id, []).append(
                        (source, scope, request_index)
                    )

                def extra_headers_seen(
                    source: CdpTargetSource, event: Mapping[str, Any]
                ) -> None:
                    request_id = str(event.get("requestId", ""))
                    extra_info.add_extra_info(
                        source.request_chain_key(request_id), event.get("headers")
                    )

                def response_seen(
                    source: CdpTargetSource, event: Mapping[str, Any]
                ) -> None:
                    response = event.get("response")
                    if not isinstance(response, Mapping):
                        raise DiscoveryIntegrityError(
                            "Chromium network response payload is malformed"
                        )
                    if any(
                        response.get(flag) is True
                        for flag in ("fromDiskCache", "fromPrefetchCache", "fromServiceWorker")
                    ):
                        raise DiscoveryIntegrityError(
                            "Chromium response bypassed the fresh network policy"
                        )
                    request_id = str(event.get("requestId", ""))
                    extra_info.add_response(
                        source.request_chain_key(request_id), event.get("hasExtraInfo")
                    )

                def protocol_event(
                    source: CdpTargetSource,
                    method: str,
                    event: Mapping[str, Any],
                ) -> None:
                    if method == "Network.requestWillBeSent":
                        audit_event = audit.record_network(source, event)
                        request_seen(source, event, audit_event)
                    elif method == "Network.requestWillBeSentExtraInfo":
                        extra_headers_seen(source, event)
                    elif method == "Network.responseReceived":
                        response_seen(source, event)
                    elif method in {"Network.loadingFinished", "Network.loadingFailed"}:
                        request_id = str(event.get("requestId", ""))
                        closed = observation_ledger.add_terminal(source, request_id)
                        audit.record_terminal(
                            source,
                            event,
                            outcome=(
                                "shutdown-cancelled"
                                if event.get("qcsdShutdown") is True
                                else "failed"
                                if method == "Network.loadingFailed"
                                else "finished"
                            ),
                            occurrence_ids=closed,
                        )
                        extra_info.add_terminal(
                            source.request_chain_key(request_id),
                            failed=method == "Network.loadingFailed",
                        )
                    elif method == "Fetch.requestPaused":
                        command, params = admission.command(event)
                        intercepted_request = event.get("request", {})
                        if not isinstance(intercepted_request, Mapping):
                            raise DiscoveryIntegrityError(
                                "Chromium request interception payload is malformed"
                            )
                        intercepted_url = str(intercepted_request.get("url", ""))
                        reason = exclusion_reason(
                            str(intercepted_request.get("method", "")),
                            intercepted_url,
                            admission.approved_origins,
                        )
                        if _network_interception_required(intercepted_url):
                            audit_event = audit.record_fetch(
                                source,
                                event,
                                decision=(
                                    "continue"
                                    if command == "Fetch.continueRequest"
                                    else "fail"
                                ),
                                reason=reason,
                            )
                            observation_ledger.add_interception(
                                source, event, audit_event=audit_event
                            )
                        assert router is not None
                        router.send(
                            source,
                            command,
                            params,
                            label=f"request-stage-policy:{command}",
                        )

                router = RecursiveCdpTargetRouter(
                    session,
                    on_event=protocol_event,
                    on_target_activity=audit.record_target,
                )
                router.start()
                navigation_started_ms = audit.now_ms()
                page.goto(url, wait_until="load", timeout=timeout_ms)
                load_event_ms = audit.now_ms()
                try:
                    render_observation = _wait_for_passive_render(
                        page,
                        router,
                        audit,
                        navigation_started_ms=navigation_started_ms,
                        load_event_ms=load_event_ms,
                    )
                except PassiveRenderPolicyError:
                    audit.freeze()
                    router.begin_shutdown()
                    context.close()
                    router.finish()
                    extra_info.finish()
                    observation_ledger.finish()
                    raise
                # Quiescence is established from the router's live active set,
                # before shutdown can synthesize any cancellation terminal.
                if router.active_request_identities:
                    raise DiscoveryIntegrityError(
                        "passive render accepted with active network requests"
                    )
                audit.freeze()
                final_url = page.url
                router.begin_shutdown()
                context.close()
                router.finish()
                extra_info.finish()
                observation_ledger.finish()
                _validate_request_instance_ledger(discovered)
            finally:
                browser.close()
    except PlaywrightError as error:
        if router is not None:
            router.raise_if_failed()
        if isinstance(error, DiscoveryIntegrityError):
            raise
        raise RecoverableAcquisitionError(f"Playwright discovery failed: {error}") from error

    if origin(final_url) not in approved:
        raise ValueError("the final page origin was not explicitly approved")
    resources = build_resources(discovered)
    if not resources:
        raise ValueError("browser discovery left no approved HTTPS GET resources")
    if render_observation is None:
        raise DiscoveryIntegrityError("browser discovery omitted its render observation")
    event_audit = audit.build(
        instrumentation_policy=CDP_TARGET_INSTRUMENTATION_POLICY,
        render_observation=render_observation,
        resources=resources,
        exclusions=sorted(
            admission.exclusions.values(), key=lambda item: (item["url"], item["reason"])
        ),
        approved_origins=approved,
        observed_origins=sorted(admission.observed_origins),
        observed_request_count=admission.observed_request_count,
    )
    contract = passive_render_contract()
    return DiscoveryResult(
        source_url=url,
        final_url=final_url,
        chromium_version=chromium_version,
        settle_ms=SETTLE_MS,
        observed_request_count=admission.observed_request_count,
        observed_origins=sorted(admission.observed_origins),
        approved_origins=approved,
        exclusions=sorted(
            admission.exclusions.values(), key=lambda item: (item["url"], item["reason"])
        ),
        resources=resources,
        origin_ip_pins=pins,
        expandable_origins=sorted(admission.expandable_origins),
        instrumentation_policy=CDP_TARGET_INSTRUMENTATION_POLICY,
        passive_render_contract=contract,
        passive_render_contract_sha256=PASSIVE_RENDER_CONTRACT_SHA256,
        render_observation=render_observation,
        render_observation_sha256=evidence_sha256(render_observation),
        discovery_event_audit=event_audit,
        discovery_event_audit_sha256=evidence_sha256(event_audit),
    )


def exclusion_reason(method: str, url: str, approved: set[str]) -> str | None:
    if method != "GET":
        return f"unsafe method: {method or 'unknown'}"
    request_origin = origin(url)
    if request_origin is None:
        return "not an absolute HTTPS request"
    if request_origin not in approved:
        return "origin not approved"
    return None


def merge_request_headers(target: dict[str, str], headers: dict[str, Any]) -> None:
    """Merge HTTP headers case-insensitively, with the new observation winning."""

    for raw_name, raw_value in headers.items():
        target[str(raw_name).lower()] = str(raw_value)


def build_resources(ordered: list[DiscoveredRequest]) -> list[dict[str, Any]]:
    """Project every observed request occurrence into one runtime resource.

    URLs are deliberately not deduplicated.  Resource IDs are deterministic
    observation-order instance identities; each URL initiator resolves to its
    latest preceding occurrence, while an observed redirect always depends on
    the immediately preceding occurrence carrying the same Chromium request ID.
    """

    preceding_by_url: dict[tuple[str, str], int] = {}
    resources = []
    for resource_id, request in enumerate(ordered):
        dependencies = set(request.dependency_indices)
        dependencies.update(
            preceding_by_url[(request.dependency_scope, initiator)]
            for initiator in request.initiator_urls
            if (request.dependency_scope, initiator) in preceding_by_url
        )
        if request.redirect_from_index is not None:
            dependencies.add(request.redirect_from_index)
        if any(type(value) is not int or not 0 <= value < resource_id for value in dependencies):
            raise ValueError("discovered request dependency is not a preceding instance")
        resources.append(
            {
                "id": resource_id,
                "url": request.url,
                "type": request.resource_type,
                "content_length": None,
                "data_length": 0,
                "chaff_priority": False,
                "known_valid": False,
                "depends_on": sorted(dependencies),
                "headers": safe_discovery_headers(request.headers),
            }
        )
        preceding_by_url[(request.dependency_scope, request.url)] = resource_id
    return resources


def _validate_request_instance_ledger(ordered: list[DiscoveredRequest]) -> None:
    """Require one well-formed, globally unique browser identity per retained request."""

    identities: set[tuple[tuple[str, ...], str, int, str, int]] = set()
    for request in ordered:
        identity = request.request_instance_id
        if (
            not isinstance(identity, tuple)
            or len(identity) != 5
            or not isinstance(identity[0], tuple)
            or any(not isinstance(value, str) or not value for value in identity[0])
            or not isinstance(identity[1], str)
            or not identity[1]
            or type(identity[2]) is not int
            or identity[2] < 0
            or not isinstance(identity[3], str)
            or not identity[3]
            or type(identity[4]) is not int
            or identity[4] < 0
            or identity in identities
        ):
            raise DiscoveryIntegrityError(
                "Chromium request-instance ledger is malformed or collision-prone"
            )
        identities.add(identity)


def _normalize_origin(value: str) -> str:
    normalized = origin(value)
    if normalized is None:
        raise ValueError(f"approved origin is not absolute HTTPS: {value}")
    parts = urlsplit(value)
    if parts.path not in {"", "/"} or parts.query or parts.fragment:
        raise ValueError(f"approved origin must not contain a path: {value}")
    return normalized


def _validate_origin_ip_pins(approved: list[str], pins: Mapping[str, str] | None) -> dict[str, str]:
    if pins is None:
        return {}
    if not isinstance(pins, Mapping) or set(pins) != set(approved):
        raise ValueError("origin IP pins must cover the approved origin set exactly")
    result: dict[str, str] = {}
    for approved_origin in approved:
        raw = pins[approved_origin]
        if not isinstance(raw, str):
            raise ValueError("origin IP pin must be a string")
        try:
            address = ipaddress.ip_address(raw)
        except ValueError as error:
            raise ValueError("origin IP pin is not a canonical address") from error
        if address.compressed != raw:
            raise ValueError("origin IP pin must use canonical text")
        result[approved_origin] = raw
    _pins_by_hostname(result)
    return result


def _pins_by_hostname(pins: Mapping[str, str]) -> dict[str, str]:
    """Collapse origin pins to Chromium's hostname-wide resolver semantics."""

    result: dict[str, str] = {}
    for approved_origin, address in sorted(pins.items()):
        hostname = urlsplit(approved_origin).hostname
        if hostname is None:
            raise ValueError("origin IP pin has no hostname")
        previous = result.setdefault(hostname, address)
        if previous != address:
            raise ValueError("origin IP pins conflict for a shared hostname")
    return result


def _host_resolver_rules(pins: Mapping[str, str]) -> str:
    rules: list[str] = []
    for hostname, address in sorted(_pins_by_hostname(pins).items()):
        destination = f"[{address}]" if ":" in address else address
        rules.append(f"MAP {hostname} {destination}")
    rules.append("MAP * ~NOTFOUND")
    return ",".join(rules)
