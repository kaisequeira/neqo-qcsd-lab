from __future__ import annotations

from copy import deepcopy

import pytest

from qcsd_lab.browser_egress import (
    NON_REPLAYABLE_EGRESS_POLICY,
    NON_REPLAYABLE_EGRESS_SCHEMA_VERSION,
    TARGET_EGRESS_APIS,
    target_egress_apis,
)
from qcsd_lab.cdp_targets import (
    CDP_TARGET_INSTRUMENTATION_POLICY,
    EGRESS_PREARM_SUMMARY_SCHEMA_VERSION,
    SRCDOC_PSEUDO_DOCUMENT_POLICY,
    SRCDOC_PSEUDO_DOCUMENT_SUMMARY_SCHEMA_VERSION,
)
from qcsd_lab.discovery_evidence import (
    DISCOVERY_EVENT_AUDIT_SCHEMA_VERSION,
    PASSIVE_RENDER_CONTRACT,
    PASSIVE_RENDER_CONTRACT_SCHEMA_VERSION,
    PASSIVE_RENDER_CONTRACT_SHA256,
    RENDER_OBSERVATION_SCHEMA_VERSION,
    _independent_url_dependency,
    evidence_sha256,
    validate_render_observation,
    verify_discovery_event_audit,
)

ROOT = {
    "session_path": [],
    "target_id": "root-page",
    "target_type": "page",
    "generation": 0,
    "parent_session_path": None,
    "parent_frame_id": None,
}


def _bootstrap_prearm_summary(
    *,
    held: int = 0,
    released: int = 0,
    released_after_setup: int = 0,
) -> dict:
    """Build a structurally complete shared-worker prearm summary."""

    return {
        "schema_version": 1,
        "held_total": held,
        "released_total": released,
        "pending_total": held - released,
        "release_before_setup_envelopes_total": 0,
        "by_worker_type": {
            "worker": {
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
            },
            "shared_worker": {
                "held": held,
                "released": released,
                "pending": held - released,
                "released_after_setup_envelopes": released_after_setup,
                "owner_target_types": {
                    "page": held,
                    "iframe": 0,
                    "worker": 0,
                    "shared_worker": 0,
                },
            },
        },
    }


def _egress_prearm_summary() -> dict:
    return {
        "schema_version": EGRESS_PREARM_SUMMARY_SCHEMA_VERSION,
        "policy": NON_REPLAYABLE_EGRESS_POLICY,
        "target_total": 1,
        "installed_total": 1,
        "pending_total": 0,
        "popup_guard_required_total": 1,
        "popup_guard_installed_total": 1,
        "by_target_type": {
            target_type: {
                "target_count": int(target_type == "page"),
                "installed_count": int(target_type == "page"),
                "pending_count": 0,
                "protected_api_observations": len(target_egress_apis("page"))
                if target_type == "page"
                else 0,
                "unavailable_api_observations": 0,
                "popup_guard_required_count": int(target_type == "page"),
                "popup_guard_installed_count": int(target_type == "page"),
            }
            for target_type in ("page", "iframe", "worker", "shared_worker")
        },
    }


def _non_replayable_egress_summary() -> dict:
    return {
        "schema_version": NON_REPLAYABLE_EGRESS_SCHEMA_VERSION,
        "policy": NON_REPLAYABLE_EGRESS_POLICY,
        "attempt_count": 0,
        "protected_apis": list(TARGET_EGRESS_APIS),
        "context_init_script_installed": True,
        "context_navigation_route_installed": True,
        "root_page_bound": True,
        "context_websocket_route_installed": True,
        "context_service_worker_listener_installed": True,
        "cdp_tripwires_are_pre_io": False,
        "packet_level_completeness_claimed": False,
    }


def _srcdoc_diagnostic(
    request_hash_character: str = "a",
    *,
    frame_hash_character: str = "f",
    ordinal_offset: int = 0,
) -> dict:
    loader_hash = request_hash_character * 64
    return {
        "schema_version": 3,
        "source_role": "root-page",
        "frame_id_sha256": frame_hash_character * 64,
        "loader_id_sha256": loader_hash,
        "request_id_sha256": loader_hash,
        "requested_event_ordinal": ordinal_offset + 1,
        "started_navigating_event_ordinal": ordinal_offset + 2,
        "started_event_ordinal": ordinal_offset + 3,
        "terminal_event_ordinal": ordinal_offset + 4,
        "stopped_event_ordinal": ordinal_offset + 5,
        "navigation_reason": "initialFrameNavigation",
        "navigation_type": "differentDocument",
        "disposition": "currentTab",
        "url_kind": "about:srcdoc",
        "loader_binding": "Page.frameStartedNavigating.loaderId",
        "request_id_matches_loader": True,
        "terminal_variant": "loading-failed-document-abort",
        "terminal_method": "Network.loadingFailed",
        "terminal_fields": sorted(
            {"requestId", "timestamp", "type", "errorText", "canceled"}
        ),
        "resource_type": "Document",
        "error_text": "net::ERR_ABORTED",
        "canceled": True,
        "encoded_data_length": None,
        "network_request_seen": False,
        "fetch_pause_seen": False,
        "frame_stopped_after_terminal": True,
    }


def _internal_document_lifecycle_summary(
    *,
    diagnostics: list[dict] | None = None,
    pending: int = 0,
    aborted: int = 0,
    open_candidates: int | None = None,
    enabled: bool = True,
    network_history_saturated: bool = False,
    fetch_history_saturated: bool = False,
    candidate_limit_saturated: bool = False,
) -> dict:
    resolved_diagnostics = deepcopy(diagnostics or [])
    terminal_outcome_counts = {
        "Network.loadingFailed": pending + aborted,
        "Network.loadingFinished": 0,
    }
    for diagnostic in resolved_diagnostics:
        terminal_outcome_counts[diagnostic["terminal_method"]] += 1
    return {
        "schema_version": SRCDOC_PSEUDO_DOCUMENT_SUMMARY_SCHEMA_VERSION,
        "policy": SRCDOC_PSEUDO_DOCUMENT_POLICY,
        "enabled": enabled,
        "total": len(resolved_diagnostics) + pending + aborted,
        "resolved": len(resolved_diagnostics),
        "pending": pending,
        "aborted": aborted,
        "open_candidates": pending if open_candidates is None else open_candidates,
        "network_history_saturated": network_history_saturated,
        "fetch_history_saturated": fetch_history_saturated,
        "candidate_limit_saturated": candidate_limit_saturated,
        "terminal_outcome_counts": terminal_outcome_counts,
        "diagnostics": resolved_diagnostics,
    }


def _source(
    session: str,
    target: str,
    *,
    generation: int = 0,
    parent_frame: str = "root-frame",
) -> dict:
    return {
        "session_path": [session],
        "target_id": target,
        "target_type": "iframe",
        "generation": generation,
        "parent_session_path": [],
        "parent_frame_id": parent_frame,
    }


def _network(
    *,
    source: dict = ROOT,
    network_id: str,
    occurrence_id: str,
    resource_id: int | None,
    url: str,
    frame_id: str | None = "root-frame",
    occurrence_index: int = 0,
    redirected: bool = False,
    redirect_from: str | None = None,
    dependencies: list[int] | None = None,
    evidence: list[dict] | None = None,
    exclusion_id: int | None = None,
    reason: str | None = None,
    interception_required: bool = True,
    safe_request_headers: list[list[str]] | None = None,
    resource_type: str | None = None,
) -> dict:
    mapping = (
        {"kind": "resource", "resource_id": resource_id}
        if resource_id is not None
        else {
            "kind": "exclusion",
            "exclusion_occurrence_id": exclusion_id,
            "reason": reason,
        }
    )
    return {
        "sequence": 0,
        "monotonic_ms": 0,
        "kind": "network-request",
        "source": source,
        "network_id": network_id,
        "occurrence_id": occurrence_id,
        "occurrence_index": occurrence_index,
        "method": "GET",
        "url": url,
        "frame_id": frame_id,
        "resource_type": resource_type or ("Script" if resource_id else "Document"),
        "safe_request_headers": (
            (safe_request_headers or []) if resource_id is not None else None
        ),
        "interception_required": interception_required,
        "redirected": redirected,
        "redirect_from_occurrence_id": redirect_from,
        "mapping": mapping,
        "dependency_evidence": evidence or [],
        "resolved_dependency_resource_ids": dependencies or [],
    }


def _fetch(
    *,
    source: dict = ROOT,
    fetch_id: str,
    network_id: str,
    occurrence_id: str,
    url: str,
    frame_id: str | None = "root-frame",
    redirected_fetch_id: str | None = None,
    relationship: str = "primary",
) -> dict:
    return {
        "sequence": 0,
        "monotonic_ms": 0,
        "kind": "fetch-request",
        "source": source,
        "fetch_id": fetch_id,
        "network_id": network_id,
        "redirected_fetch_id": redirected_fetch_id,
        "network_occurrence_id": occurrence_id,
        "method": "GET",
        "url": url,
        "frame_id": frame_id,
        "policy_decision": "continue",
        "policy_reason": None,
        "relationship": relationship,
    }


def _terminal(
    *, source: dict = ROOT, network_id: str, occurrences: list[str]
) -> dict:
    return {
        "sequence": 0,
        "monotonic_ms": 0,
        "kind": "network-terminal",
        "source": source,
        "network_id": network_id,
        "outcome": "finished",
        "network_occurrence_ids": occurrences,
    }


def _target(source: dict, target_event: str) -> dict:
    return {
        "sequence": 0,
        "monotonic_ms": 0,
        "kind": "target-activity",
        "source": source,
        "target_event": target_event,
    }


def _internal_document(diagnostic: dict, *, source: dict = ROOT) -> dict:
    return {
        "sequence": 0,
        "monotonic_ms": 0,
        "kind": "browser-internal-document",
        "source": source,
        "diagnostic": deepcopy(diagnostic),
    }


def _resource(resource_id: int, url: str, dependencies: list[int] | None = None) -> dict:
    return {
        "id": resource_id,
        "url": url,
        "type": "Script" if resource_id else "Document",
        "depends_on": dependencies or [],
    }


def _audit(events: list[dict]) -> dict:
    for sequence, event in enumerate(events, 1):
        event["sequence"] = sequence
        event["monotonic_ms"] = sequence
    return {
        "schema_version": DISCOVERY_EVENT_AUDIT_SCHEMA_VERSION,
        "instrumentation_policy": CDP_TARGET_INSTRUMENTATION_POLICY,
        "passive_render_contract_sha256": PASSIVE_RENDER_CONTRACT_SHA256,
        "render_observation_sha256": "a" * 64,
        "events": events,
        "summary": {
            "event_count": len(events),
            "target_event_count": sum(
                event["kind"] == "target-activity" for event in events
            ),
            "browser_internal_document_count": sum(
                event["kind"] == "browser-internal-document" for event in events
            ),
            "network_request_count": sum(
                event["kind"] == "network-request" for event in events
            ),
            "fetch_request_count": sum(
                event["kind"] == "fetch-request" for event in events
            ),
            "fetch_internal_restart_count": sum(
                event["kind"] == "fetch-request"
                and event["relationship"] == "internal-restart"
                for event in events
            ),
            "terminal_event_count": sum(
                event["kind"] == "network-terminal" for event in events
            ),
            "resource_occurrence_count": sum(
                event["kind"] == "network-request"
                and event["mapping"]["kind"] == "resource"
                for event in events
            ),
            "exclusion_occurrence_count": sum(
                event["kind"] == "network-request"
                and event["mapping"]["kind"] == "exclusion"
                for event in events
            ),
        },
    }


def _render_for(audit: dict) -> dict:
    last_event = max(event["monotonic_ms"] for event in audit["events"])
    return {
        "schema_version": RENDER_OBSERVATION_SCHEMA_VERSION,
        "clock": "monotonic-relative-ms",
        "navigation_started_ms": 0,
        "load_event_ms": last_event,
        "last_relevant_event_ms": last_event,
        "quiet_started_ms": last_event + 10_000,
        "cutoff_ms": last_event + 13_000,
        "active_request_ids": [],
        "active_request_count": 0,
        "router_shutdown_ready": True,
        "bootstrap_prearm_summary": _bootstrap_prearm_summary(),
        "egress_prearm_summary": _egress_prearm_summary(),
        "internal_document_lifecycle_summary": (
            _internal_document_lifecycle_summary(
                diagnostics=[
                    event["diagnostic"]
                    for event in audit["events"]
                    if event["kind"] == "browser-internal-document"
                ]
            )
        ),
        "non_replayable_egress_summary": _non_replayable_egress_summary(),
        "browser_context_service_worker_count": 0,
        "cutoff_reason": "quiescent",
    }


def _verify(audit: dict, resources: list[dict], exclusions: list[dict] | None = None):
    render = _render_for(audit)
    audit["render_observation_sha256"] = evidence_sha256(render)
    return verify_discovery_event_audit(
        audit,
        render_observation=render,
        resources=resources,
        exclusions=exclusions or [],
        approved_origins=["https://page.test"],
        observed_request_count=sum(
            event["kind"] == "network-request" for event in audit["events"]
        ),
    )


def _root_resource_audit(*extra_events: dict) -> tuple[dict, list[dict]]:
    url = "https://page.test/"
    return (
        _audit(
            [
                _network(
                    network_id="root-network",
                    occurrence_id="root-request",
                    resource_id=0,
                    url=url,
                ),
                _fetch(
                    fetch_id="root-fetch",
                    network_id="root-network",
                    occurrence_id="root-request",
                    url=url,
                ),
                _terminal(network_id="root-network", occurrences=["root-request"]),
                *extra_events,
            ]
        ),
        [_resource(0, url)],
    )


def test_internal_document_lifecycle_bumps_discovery_evidence_schemas() -> None:
    assert PASSIVE_RENDER_CONTRACT_SCHEMA_VERSION == 4
    assert RENDER_OBSERVATION_SCHEMA_VERSION == 4
    assert DISCOVERY_EVENT_AUDIT_SCHEMA_VERSION == 5
    assert PASSIVE_RENDER_CONTRACT["policy"] == "bounded-passive-render-quiescence-v4"
    assert (
        "terminal-root-srcdoc-loader-bound-orphan-abort-or-33-byte-finish-lifecycle"
        in PASSIVE_RENDER_CONTRACT["quiescence_requires"]
    )
    assert "browser-internal-document" in PASSIVE_RENDER_CONTRACT["relevant_events"]
    assert SRCDOC_PSEUDO_DOCUMENT_SUMMARY_SCHEMA_VERSION == 3
    assert SRCDOC_PSEUDO_DOCUMENT_POLICY == (
        "chromium-143-root-about-srcdoc-loader-bound-orphan-abort-or-33-byte-finish-v2"
    )


def test_quiescent_render_requires_router_shutdown_readiness() -> None:
    audit, _resources = _root_resource_audit()
    render = _render_for(audit)
    render["router_shutdown_ready"] = False

    with pytest.raises(ValueError, match="premature"):
        validate_render_observation(render)


def test_quiescent_render_requires_terminal_shared_worker_prearm() -> None:
    audit, _resources = _root_resource_audit()
    render = _render_for(audit)
    render["bootstrap_prearm_summary"] = _bootstrap_prearm_summary(held=1)

    with pytest.raises(ValueError, match="valid terminal state"):
        validate_render_observation(render)


def test_quiescent_render_accepts_released_shared_worker_prearm() -> None:
    audit, _resources = _root_resource_audit()
    render = _render_for(audit)
    render["bootstrap_prearm_summary"] = _bootstrap_prearm_summary(
        held=1,
        released=1,
        released_after_setup=1,
    )

    validate_render_observation(render)


def test_quiescent_render_requires_terminal_internal_document_lifecycle() -> None:
    audit, _resources = _root_resource_audit()
    render = _render_for(audit)
    render["internal_document_lifecycle_summary"] = (
        _internal_document_lifecycle_summary(pending=1)
    )

    with pytest.raises(ValueError, match="lifecycle is not terminal"):
        validate_render_observation(render)


def test_quiescent_render_accepts_resolved_internal_document_lifecycle() -> None:
    diagnostic = _srcdoc_diagnostic()
    audit, _resources = _root_resource_audit(_internal_document(diagnostic))

    validate_render_observation(_render_for(audit))


@pytest.mark.parametrize(
    ("mutation", "message"),
    (
        (
            lambda diagnostic: diagnostic.update(loader_id_sha256="e" * 64),
            "diagnostic is inconsistent",
        ),
        (
            lambda diagnostic: diagnostic.pop("started_navigating_event_ordinal"),
            "diagnostic fields",
        ),
        (
            lambda diagnostic: diagnostic.update(
                loader_binding="Page.frameStartedLoading.loaderId"
            ),
            "diagnostic strings are invalid",
        ),
        (
            lambda diagnostic: diagnostic.update(navigation_type="sameDocument"),
            "diagnostic strings are invalid",
        ),
        (
            lambda diagnostic: diagnostic.update(request_id_matches_loader=False),
            "diagnostic is inconsistent",
        ),
    ),
)
def test_internal_document_summary_requires_exact_loader_binding(
    mutation,
    message: str,
) -> None:
    diagnostic = _srcdoc_diagnostic()
    mutation(diagnostic)
    audit, _resources = _root_resource_audit(_internal_document(diagnostic))

    with pytest.raises(ValueError, match=message):
        validate_render_observation(_render_for(audit))


def test_internal_document_summary_requires_globally_unique_event_ordinals() -> None:
    first = _srcdoc_diagnostic("a")
    second = _srcdoc_diagnostic("b", frame_hash_character="e", ordinal_offset=10)
    second["requested_event_ordinal"] = first["stopped_event_ordinal"]
    audit, _resources = _root_resource_audit(
        _internal_document(first),
        _internal_document(second),
    )

    with pytest.raises(ValueError, match="ordinals are not globally unique"):
        validate_render_observation(_render_for(audit))


def test_internal_document_summary_requires_diagnostics_in_emitted_order() -> None:
    first = _srcdoc_diagnostic("a")
    second = _srcdoc_diagnostic("b", frame_hash_character="e", ordinal_offset=10)
    audit, _resources = _root_resource_audit(
        _internal_document(second),
        _internal_document(first),
    )

    with pytest.raises(ValueError, match="diagnostics are not in emitted order"):
        validate_render_observation(_render_for(audit))


def test_internal_document_summary_rejects_reused_frame_identity() -> None:
    first = _srcdoc_diagnostic("a")
    second = _srcdoc_diagnostic("b", ordinal_offset=10)
    audit, _resources = _root_resource_audit(
        _internal_document(first),
        _internal_document(second),
    )

    with pytest.raises(ValueError, match="diagnostic is inconsistent"):
        validate_render_observation(_render_for(audit))


def test_hard_cap_render_can_record_an_unready_router_without_active_requests() -> None:
    audit, _resources = _root_resource_audit()
    render = _render_for(audit)
    load = render["load_event_ms"]
    render.update(
        {
            "quiet_started_ms": load + 10_000,
            "cutoff_ms": load + 30_000,
            "router_shutdown_ready": False,
            "bootstrap_prearm_summary": _bootstrap_prearm_summary(held=1),
            "internal_document_lifecycle_summary": (
                _internal_document_lifecycle_summary(pending=1)
            ),
            "cutoff_reason": "hard-cap-non-quiescent",
        }
    )

    validate_render_observation(render, allow_failure=True)


def test_internal_document_audit_event_matches_the_render_diagnostics() -> None:
    diagnostic = _srcdoc_diagnostic()
    audit, resources = _root_resource_audit(_internal_document(diagnostic))

    summary = _verify(audit, resources)

    assert summary["browser_internal_document_count"] == 1


def test_internal_document_audit_event_requires_exact_fields_and_root_source() -> None:
    diagnostic = _srcdoc_diagnostic()
    extra_field = _internal_document(diagnostic)
    extra_field["unexpected"] = True
    audit, resources = _root_resource_audit(extra_field)
    with pytest.raises(ValueError, match="event fields"):
        _verify(audit, resources)

    child = _source("child-session", "child-target")
    audit, resources = _root_resource_audit(
        _target(child, "target-attached"),
        _internal_document(diagnostic, source=child),
    )
    with pytest.raises(ValueError, match="must use the root source"):
        _verify(audit, resources)


def test_internal_document_audit_diagnostics_preserve_exact_render_order() -> None:
    first = _srcdoc_diagnostic("a")
    second = _srcdoc_diagnostic("b", frame_hash_character="e", ordinal_offset=10)
    audit, resources = _root_resource_audit(
        _internal_document(first),
        _internal_document(second),
    )
    render = _render_for(audit)
    internal_events = [
        event
        for event in audit["events"]
        if event["kind"] == "browser-internal-document"
    ]
    internal_events[0]["diagnostic"] = deepcopy(second)
    internal_events[1]["diagnostic"] = deepcopy(first)
    audit["render_observation_sha256"] = evidence_sha256(render)

    with pytest.raises(ValueError, match="diagnostics differ from the render summary"):
        verify_discovery_event_audit(
            audit,
            render_observation=render,
            resources=resources,
            exclusions=[],
            approved_origins=["https://page.test"],
            observed_request_count=1,
        )


def test_internal_document_audit_summary_count_is_exact() -> None:
    diagnostic = _srcdoc_diagnostic()
    audit, resources = _root_resource_audit(_internal_document(diagnostic))
    audit["summary"]["browser_internal_document_count"] = 0

    with pytest.raises(ValueError, match="summary does not verify"):
        _verify(audit, resources)


def test_target_replay_requires_exact_parent_route_and_never_reuses_a_route() -> None:
    skipped_parent = {
        **_source("child-session", "child-target"),
        "session_path": ["unrecorded-parent", "child-session"],
    }
    audit, resources = _root_resource_audit(
        _target(skipped_parent, "target-attached")
    )
    with pytest.raises(ValueError, match="target attachment lifecycle"):
        _verify(audit, resources)

    first = _source("reused-session", "first-target")
    second = _source("reused-session", "second-target")
    audit, resources = _root_resource_audit(
        _target(first, "target-attached"),
        _target(first, "target-detached"),
        _target(first, "target-destroyed"),
        _target(second, "target-attached"),
    )
    with pytest.raises(ValueError, match="target attachment lifecycle"):
        _verify(audit, resources)


def test_child_target_cannot_precede_or_reuse_the_future_root_identity() -> None:
    future_root = _source("pre-root-session", ROOT["target_id"])
    audit, resources = _root_resource_audit()
    audit = _audit(
        [
            _target(future_root, "target-attached"),
            _target(future_root, "target-detached"),
            _target(future_root, "target-destroyed"),
            *audit["events"],
        ]
    )

    with pytest.raises(ValueError, match="target attachment lifecycle"):
        _verify(audit, resources)


def test_network_activity_cannot_precede_recorded_navigation_start() -> None:
    audit, resources = _root_resource_audit()
    render = _render_for(audit)
    render["navigation_started_ms"] = 2
    audit["render_observation_sha256"] = evidence_sha256(render)

    with pytest.raises(ValueError, match="predates navigation start"):
        verify_discovery_event_audit(
            audit,
            render_observation=render,
            resources=resources,
            exclusions=[],
            approved_origins=["https://page.test"],
            observed_request_count=1,
        )


def test_primary_request_and_interception_cannot_follow_recorded_page_load() -> None:
    audit, resources = _root_resource_audit()
    render = _render_for(audit)
    render["load_event_ms"] = 0
    render["quiet_started_ms"] = 10_000
    render["cutoff_ms"] = 13_000
    audit["render_observation_sha256"] = evidence_sha256(render)

    with pytest.raises(ValueError, match="after page load"):
        verify_discovery_event_audit(
            audit,
            render_observation=render,
            resources=resources,
            exclusions=[],
            approved_origins=["https://page.test"],
            observed_request_count=1,
            expected_root_document_url="https://page.test/",
            expected_final_document_url="https://page.test/",
            expected_observed_origins=["https://page.test"],
        )


def test_root_frame_rejects_a_second_independent_document_navigation_chain() -> None:
    audit, resources = _root_resource_audit()
    second = _network(
        network_id="second-root-network",
        occurrence_id="second-root-request",
        resource_id=1,
        url="https://page.test/",
    )
    second["resource_type"] = "Document"
    audit = _audit(
        [
            *audit["events"],
            second,
            _fetch(
                fetch_id="second-root-fetch",
                network_id="second-root-network",
                occurrence_id="second-root-request",
                url="https://page.test/",
            ),
            _terminal(
                network_id="second-root-network",
                occurrences=["second-root-request"],
            ),
        ]
    )
    resources.append(
        {
            "id": 1,
            "url": "https://page.test/",
            "type": "Document",
            "depends_on": [],
        }
    )

    with pytest.raises(ValueError, match="contiguous primary redirect chain"):
        _verify(audit, resources)


def test_target_replay_forbids_detaching_a_parent_with_an_active_descendant() -> None:
    parent = _source("parent-session", "parent-target")
    child = {
        **_source("child-session", "child-target"),
        "session_path": ["parent-session", "child-session"],
        "parent_session_path": ["parent-session"],
    }
    audit, resources = _root_resource_audit(
        _target(parent, "target-attached"),
        _target(child, "target-attached"),
        _target(parent, "target-detached"),
        _target(parent, "target-destroyed"),
    )
    with pytest.raises(ValueError, match="target detach is outside"):
        _verify(audit, resources)


def test_target_replay_requires_root_primary_and_unique_active_session_ids() -> None:
    child = _source("child-session", "child-target")
    url = "https://page.test/"
    all_child = _audit(
        [
            _target(child, "target-attached"),
            _network(
                source=child,
                network_id="network",
                occurrence_id="request",
                resource_id=0,
                url=url,
            ),
            _fetch(
                source=child,
                fetch_id="fetch",
                network_id="network",
                occurrence_id="request",
                url=url,
            ),
            _terminal(source=child, network_id="network", occurrences=["request"]),
            _target(child, "target-detached"),
            _target(child, "target-destroyed"),
        ]
    )
    with pytest.raises(
        ValueError, match="target attachment lifecycle|primary navigation resource"
    ):
        _verify(all_child, [_resource(0, url)])

    parent_a = _source("parent-a", "parent-a-target")
    parent_b = _source("parent-b", "parent-b-target")
    child_a = {
        **_source("duplicate", "child-a-target"),
        "session_path": ["parent-a", "duplicate"],
        "parent_session_path": ["parent-a"],
    }
    child_b = {
        **_source("duplicate", "child-b-target"),
        "session_path": ["parent-b", "duplicate"],
        "parent_session_path": ["parent-b"],
    }
    audit, resources = _root_resource_audit(
        _target(parent_a, "target-attached"),
        _target(parent_b, "target-attached"),
        _target(child_a, "target-attached"),
        _target(child_b, "target-attached"),
    )
    with pytest.raises(ValueError, match="target attachment lifecycle"):
        _verify(audit, resources)


def test_target_replay_rejects_destroying_an_old_generation_while_new_is_active() -> None:
    old = _source("old-session", "reused-target")
    new = _source("new-session", "reused-target", generation=1)
    audit, resources = _root_resource_audit(
        _target(old, "target-attached"),
        _target(old, "target-detached"),
        _target(new, "target-attached"),
        _target(old, "target-destroyed"),
    )
    with pytest.raises(ValueError, match="target destruction"):
        _verify(audit, resources)


def test_network_occurrence_binds_exact_safe_browser_request_headers() -> None:
    audit, resources = _three_resource_dependency_audit()
    headers = (["accept", "text/html"], ["user-agent", "fixture"])
    for index, header in enumerate(headers):
        audit["events"][index * 3]["safe_request_headers"] = [list(header)]
        resources[index]["headers"] = [list(header)]
    _verify(audit, resources)

    forged = deepcopy(resources)
    forged[0]["headers"], forged[1]["headers"] = (
        forged[1]["headers"],
        forged[0]["headers"],
    )
    with pytest.raises(ValueError, match="mapping"):
        _verify(audit, forged)


def _three_resource_dependency_audit(
    *, duplicate_scope: bool = False
) -> tuple[dict, list[dict]]:
    duplicate = "https://page.test/script.js"
    child_frame = "other-frame" if duplicate_scope else "root-frame"
    resources = [
        _resource(0, duplicate),
        _resource(1, duplicate),
        _resource(2, "https://page.test/data", [0 if duplicate_scope else 1]),
    ]
    events: list[dict] = []
    for resource_id, frame_id in ((0, "root-frame"), (1, child_frame)):
        occurrence = f"request-{resource_id}"
        network_id = f"network-{resource_id}"
        events.extend(
            [
                _network(
                    network_id=network_id,
                    occurrence_id=occurrence,
                    resource_id=resource_id,
                    url=duplicate,
                    frame_id=frame_id,
                ),
                _fetch(
                    fetch_id=f"fetch-{resource_id}",
                    network_id=network_id,
                    occurrence_id=occurrence,
                    url=duplicate,
                    frame_id=frame_id,
                ),
                _terminal(network_id=network_id, occurrences=[occurrence]),
            ]
        )
    dependency = 0 if duplicate_scope else 1
    events.extend(
        [
            _network(
                network_id="network-2",
                occurrence_id="request-2",
                resource_id=2,
                url=resources[2]["url"],
                dependencies=[dependency],
                evidence=[
                    {
                        "kind": "stack-call-frame",
                        "value": duplicate,
                        "resolved_resource_id": dependency,
                    }
                ],
            ),
            _fetch(
                fetch_id="fetch-2",
                network_id="network-2",
                occurrence_id="request-2",
                url=resources[2]["url"],
            ),
            _terminal(network_id="network-2", occurrences=["request-2"]),
        ]
    )
    return _audit(events), resources


def test_dependency_verifier_selects_latest_preceding_duplicate_url() -> None:
    audit, resources = _three_resource_dependency_audit()
    _verify(audit, resources)

    forged = deepcopy(audit)
    event = forged["events"][6]
    event["dependency_evidence"][0]["resolved_resource_id"] = 0
    event["resolved_dependency_resource_ids"] = [0]
    forged_resources = deepcopy(resources)
    forged_resources[2]["depends_on"] = [0]
    with pytest.raises(ValueError, match="latest-preceding"):
        _verify(forged, forged_resources)


def test_dependency_verifier_does_not_cross_frame_scope_for_a_later_duplicate() -> None:
    audit, resources = _three_resource_dependency_audit(duplicate_scope=True)
    _verify(audit, resources)

    forged = deepcopy(audit)
    event = forged["events"][6]
    event["dependency_evidence"][0]["resolved_resource_id"] = 1
    event["resolved_dependency_resource_ids"] = [1]
    forged_resources = deepcopy(resources)
    forged_resources[2]["depends_on"] = [1]
    with pytest.raises(ValueError, match="latest-preceding"):
        _verify(forged, forged_resources)


def test_independent_dependency_selects_latest_across_exact_frame_sources() -> None:
    duplicate = "https://page.test/script.js"
    worker = _source("worker-session", "worker-target")
    previous = [
        _network(
            source=ROOT,
            network_id="root-network",
            occurrence_id="root-request",
            resource_id=3,
            url=duplicate,
        ),
        _network(
            source=worker,
            network_id="worker-network",
            occurrence_id="worker-request",
            resource_id=7,
            url=duplicate,
        ),
    ]
    current = _network(
        source=worker,
        network_id="current-network",
        occurrence_id="current-request",
        resource_id=8,
        url="https://page.test/data",
    )

    assert (
        _independent_url_dependency(previous, current=current, url=duplicate) == 7
    )


def test_independent_dependency_keeps_parent_frame_fallback_ambiguity_closed() -> None:
    duplicate = "https://page.test/script.js"
    current_source = _source(
        "current-session",
        "current-target",
        parent_frame="parent-frame",
    )
    previous = [
        _network(
            source=_source("first-session", "first-target"),
            network_id="first-network",
            occurrence_id="first-request",
            resource_id=3,
            url=duplicate,
            frame_id="parent-frame",
        ),
        _network(
            source=_source("second-session", "second-target"),
            network_id="second-network",
            occurrence_id="second-request",
            resource_id=7,
            url=duplicate,
            frame_id="parent-frame",
        ),
    ]
    current = _network(
        source=current_source,
        network_id="current-network",
        occurrence_id="current-request",
        resource_id=8,
        url="https://page.test/data",
        frame_id="current-frame",
    )

    with pytest.raises(ValueError, match="scope is ambiguous"):
        _independent_url_dependency(previous, current=current, url=duplicate)


def test_dependency_verifier_rejects_a_future_resource_edge() -> None:
    audit, resources = _three_resource_dependency_audit()
    forged = deepcopy(audit)
    first = forged["events"][0]
    first["dependency_evidence"] = [
        {
            "kind": "initiator-url",
            "value": resources[1]["url"],
            "resolved_resource_id": 1,
        }
    ]
    first["resolved_dependency_resource_ids"] = [1]
    forged_resources = deepcopy(resources)
    forged_resources[0]["depends_on"] = [1]
    with pytest.raises(ValueError, match="latest-preceding"):
        _verify(forged, forged_resources)


def _redirect_audit(*, fetch_source: dict = ROOT) -> tuple[dict, list[dict]]:
    first_url = "https://page.test/first"
    final_url = "https://page.test/final"
    resources = [_resource(0, first_url), _resource(1, final_url, [0])]
    resources[1]["type"] = "Document"
    events = [
        _network(
            network_id="chain",
            occurrence_id="request-0",
            resource_id=0,
            url=first_url,
        ),
        _fetch(
            fetch_id="fetch-0",
            network_id="chain",
            occurrence_id="request-0",
            url=first_url,
        ),
        *(
            [_target(fetch_source, "target-attached")]
            if fetch_source is not ROOT
            else []
        ),
        _network(
            network_id="chain",
            occurrence_id="request-1",
            resource_id=1,
            url=final_url,
            occurrence_index=1,
            redirected=True,
            redirect_from="request-0",
            dependencies=[0],
            resource_type="Document",
            evidence=[
                {
                    "kind": "redirect",
                    "value": "request-0",
                    "resolved_resource_id": 0,
                }
            ],
        ),
        _fetch(
            source=fetch_source,
            fetch_id="fetch-1",
            network_id="chain",
            occurrence_id="request-1",
            url=final_url,
            frame_id=(
                str(fetch_source["parent_frame_id"])
                if fetch_source is not ROOT
                else "root-frame"
            ),
            redirected_fetch_id="fetch-0",
        ),
        _terminal(network_id="chain", occurrences=["request-0", "request-1"]),
    ]
    return _audit(events), resources


def test_redirect_verifier_requires_exact_network_predecessor() -> None:
    audit, resources = _redirect_audit()
    _verify(audit, resources)
    forged = deepcopy(audit)
    forged["events"][2]["redirect_from_occurrence_id"] = "request-1"
    with pytest.raises(ValueError, match="immediate predecessor"):
        _verify(forged, resources)


def test_primary_document_redirect_cannot_change_root_frame_identity() -> None:
    audit, resources = _redirect_audit()
    audit["events"][2]["resource_type"] = "Document"
    audit["events"][2]["frame_id"] = "different-frame"
    resources[1]["type"] = "Document"
    render = _render_for(audit)
    audit["render_observation_sha256"] = evidence_sha256(render)

    with pytest.raises(ValueError, match="root-frame identity"):
        verify_discovery_event_audit(
            audit,
            render_observation=render,
            resources=resources,
            exclusions=[],
            approved_origins=["https://page.test"],
            observed_request_count=2,
            expected_root_document_url="https://page.test/first",
            expected_final_document_url="https://page.test/final",
        )


def test_fetch_redirect_allows_unambiguous_oopif_migration() -> None:
    audit, resources = _redirect_audit(fetch_source=_source("oopif", "iframe"))
    _verify(audit, resources)

    missing_attach = deepcopy(audit)
    missing_attach["events"] = [
        event
        for event in missing_attach["events"]
        if event["kind"] != "target-activity"
    ]
    missing_attach = _audit(missing_attach["events"])
    with pytest.raises(ValueError, match="lifecycle brackets"):
        _verify(missing_attach, resources)


@pytest.mark.parametrize(
    "source",
    [
        {
            **_source("other", "unrelated", parent_frame="unrelated-frame"),
            "parent_session_path": ["unrelated-parent"],
        },
        _source("oopif", "root-page", generation=1),
    ],
)
def test_fetch_redirect_rejects_wrong_scope_or_cross_generation(source: dict) -> None:
    audit, resources = _redirect_audit(fetch_source=source)
    with pytest.raises(ValueError, match="lifecycle|immediate predecessor"):
        _verify(audit, resources)


def test_initiator_request_id_uses_latest_redirect_occurrence() -> None:
    audit, resources = _redirect_audit()
    third = _resource(2, "https://page.test/data", [1])
    resources.append(third)
    terminal = audit["events"].pop()
    audit["events"].extend(
        [
            terminal,
            _network(
                network_id="data",
                occurrence_id="request-2",
                resource_id=2,
                url=third["url"],
                dependencies=[1],
                evidence=[
                    {
                        "kind": "initiator-request-id",
                        "value": "chain",
                        "resolved_resource_id": 1,
                    }
                ],
            ),
            _fetch(
                fetch_id="fetch-2",
                network_id="data",
                occurrence_id="request-2",
                url=third["url"],
            ),
            _terminal(network_id="data", occurrences=["request-2"]),
        ]
    )
    audit = _audit(audit["events"])
    _verify(audit, resources)
    forged = deepcopy(audit)
    forged["events"][5]["dependency_evidence"][0]["resolved_resource_id"] = 0
    forged["events"][5]["resolved_dependency_resource_ids"] = [0]
    forged_resources = deepcopy(resources)
    forged_resources[2]["depends_on"] = [0]
    with pytest.raises(ValueError, match="latest-preceding"):
        _verify(forged, forged_resources)


def test_verifier_rejects_missing_terminal_and_forged_resource_mapping() -> None:
    audit, resources = _three_resource_dependency_audit()
    missing = deepcopy(audit)
    del missing["events"][2]
    missing = _audit(missing["events"])
    with pytest.raises(ValueError, match="terminal"):
        _verify(missing, resources)

    forged = deepcopy(audit)
    forged["events"][0]["mapping"]["resource_id"] = 1
    forged["events"][3]["mapping"]["resource_id"] = 0
    with pytest.raises(ValueError, match="mapping"):
        _verify(forged, resources)


def test_terminal_must_follow_and_close_one_complete_network_chain() -> None:
    url = "https://page.test/"
    resources = [_resource(0, url)]
    terminal_before_network = _audit(
        [
            _terminal(network_id="network", occurrences=["request-0"]),
            _network(
                network_id="network",
                occurrence_id="request-0",
                resource_id=0,
                url=url,
            ),
            _fetch(
                fetch_id="fetch",
                network_id="network",
                occurrence_id="request-0",
                url=url,
            ),
        ]
    )
    with pytest.raises(ValueError, match="terminal"):
        _verify(terminal_before_network, resources)

    redirect, redirect_resources = _redirect_audit()
    split = deepcopy(redirect)
    split["events"].pop()
    split["events"].extend(
        [
            _terminal(network_id="chain", occurrences=["request-0"]),
            _terminal(network_id="chain", occurrences=["request-1"]),
        ]
    )
    split = _audit(split["events"])
    with pytest.raises(ValueError, match="split across terminal"):
        _verify(split, redirect_resources)

    reused = deepcopy(redirect)
    reused["events"].insert(
        5,
        _network(
            network_id="chain",
            occurrence_id="request-2",
            resource_id=2,
            url="https://page.test/after-terminal",
            occurrence_index=2,
            redirected=True,
            redirect_from="request-1",
            dependencies=[1],
            evidence=[
                {
                    "kind": "redirect",
                    "value": "request-1",
                    "resolved_resource_id": 1,
                }
            ],
        ),
    )
    reused["events"].insert(
        6,
        _fetch(
            fetch_id="fetch-2",
            network_id="chain",
            occurrence_id="request-2",
            url="https://page.test/after-terminal",
            redirected_fetch_id="fetch-1",
        ),
    )
    reused["events"].insert(
        7,
        _terminal(network_id="chain", occurrences=["request-2"]),
    )
    reused_resources = [
        *redirect_resources,
        _resource(2, "https://page.test/after-terminal", [1]),
    ]
    reused = _audit(reused["events"])
    with pytest.raises(ValueError, match="split across terminal|resource type"):
        _verify(reused, reused_resources)


def test_retained_redirect_cannot_depend_on_an_excluded_predecessor() -> None:
    first_url = "https://page.test/post"
    final_url = "https://page.test/final"
    reason = "unsafe method: POST"
    first_network = _network(
        network_id="chain",
        occurrence_id="request-0",
        resource_id=None,
        url=first_url,
        exclusion_id=0,
        reason=reason,
    )
    first_network["method"] = "POST"
    first_fetch = _fetch(
        fetch_id="fetch-0",
        network_id="chain",
        occurrence_id="request-0",
        url=first_url,
    )
    first_fetch.update(
        {"method": "POST", "policy_decision": "fail", "policy_reason": reason}
    )
    audit = _audit(
        [
            first_network,
            first_fetch,
            _network(
                network_id="chain",
                occurrence_id="request-1",
                resource_id=0,
                url=final_url,
                occurrence_index=1,
                redirected=True,
                redirect_from="request-0",
                evidence=[
                    {
                        "kind": "redirect",
                        "value": "request-0",
                        "resolved_resource_id": None,
                    }
                ],
            ),
            _fetch(
                fetch_id="fetch-1",
                network_id="chain",
                occurrence_id="request-1",
                url=final_url,
                redirected_fetch_id="fetch-0",
            ),
            _terminal(network_id="chain", occurrences=["request-0", "request-1"]),
        ]
    )
    with pytest.raises(ValueError, match="mapping"):
        _verify(
            audit,
            [_resource(0, final_url)],
            [{"url": first_url, "reason": reason}],
        )


def test_internal_fetch_restart_is_explicit_and_independently_replayed() -> None:
    url = "https://page.test/"
    resources = [_resource(0, url)]
    audit = _audit(
        [
            _network(
                network_id="network",
                occurrence_id="request-0",
                resource_id=0,
                url=url,
            ),
            _fetch(
                fetch_id="fetch-primary",
                network_id="network",
                occurrence_id="request-0",
                url=url,
            ),
            _fetch(
                fetch_id="fetch-restart",
                network_id="network",
                occurrence_id="request-0",
                url=url,
                relationship="internal-restart",
            ),
            _terminal(network_id="network", occurrences=["request-0"]),
        ]
    )
    assert _verify(audit, resources)["fetch_internal_restart_count"] == 1

    forged = deepcopy(audit)
    forged["events"][2]["relationship"] = "primary"
    forged["summary"]["fetch_internal_restart_count"] = 0
    with pytest.raises(ValueError, match="independent FIFO"):
        _verify(forged, resources)


def test_non_network_scheme_is_an_audited_non_interceptable_exclusion() -> None:
    url = "data:text/plain,fixture"
    root_url = "https://page.test/"
    exclusions = [{"url": url, "reason": "not an absolute HTTPS request"}]
    audit = _audit(
        [
            _network(
                network_id="root",
                occurrence_id="root-request",
                resource_id=0,
                url=root_url,
            ),
            _fetch(
                fetch_id="root-fetch",
                network_id="root",
                occurrence_id="root-request",
                url=root_url,
            ),
            _terminal(network_id="root", occurrences=["root-request"]),
            _network(
                network_id="data",
                occurrence_id="request-0",
                resource_id=None,
                url=url,
                frame_id=None,
                exclusion_id=0,
                reason=exclusions[0]["reason"],
                interception_required=False,
            ),
            _terminal(network_id="data", occurrences=["request-0"]),
        ]
    )
    summary = _verify(audit, [_resource(0, root_url)], exclusions)
    assert summary["fetch_request_count"] == 1
    assert summary["exclusion_occurrence_count"] == 1

    with pytest.raises(ValueError, match="every exclusion summary row"):
        _verify(
            audit,
            [_resource(0, root_url)],
            [
                *exclusions,
                {
                    "url": "data:text/plain,stale",
                    "reason": "not an absolute HTTPS request",
                },
            ],
        )
    with pytest.raises(ValueError, match="contains duplicates"):
        _verify(audit, [_resource(0, root_url)], [*exclusions, *exclusions])


def test_repeated_excluded_occurrences_remain_distinct_in_the_audit() -> None:
    url = "data:text/plain,repeated"
    root_url = "https://page.test/"
    reason = "not an absolute HTTPS request"
    events = [
        _network(
            network_id="root",
            occurrence_id="root-request",
            resource_id=0,
            url=root_url,
        ),
        _fetch(
            fetch_id="root-fetch",
            network_id="root",
            occurrence_id="root-request",
            url=root_url,
        ),
        _terminal(network_id="root", occurrences=["root-request"]),
    ]
    for index in range(2):
        occurrence = f"request-{index}"
        network = f"data-{index}"
        events.extend(
            [
                _network(
                    network_id=network,
                    occurrence_id=occurrence,
                    resource_id=None,
                    url=url,
                    frame_id=None,
                    exclusion_id=index,
                    reason=reason,
                    interception_required=False,
                ),
                _terminal(network_id=network, occurrences=[occurrence]),
            ]
        )
    audit = _audit(events)
    summary = _verify(
        audit, [_resource(0, root_url)], [{"url": url, "reason": reason}]
    )
    assert summary["network_request_count"] == 3
    assert summary["exclusion_occurrence_count"] == 2


def test_render_and_audit_times_are_joined_and_shutdown_events_are_excluded() -> None:
    url = "https://page.test/"
    resources = [_resource(0, url)]
    audit = _audit(
        [
            _network(
                network_id="network",
                occurrence_id="request-0",
                resource_id=0,
                url=url,
            ),
            _fetch(
                fetch_id="fetch",
                network_id="network",
                occurrence_id="request-0",
                url=url,
            ),
            _terminal(network_id="network", occurrences=["request-0"]),
        ]
    )
    render = _render_for(audit)
    audit["render_observation_sha256"] = evidence_sha256(render)
    _verify(audit, resources)

    after_cutoff = deepcopy(audit)
    after_cutoff["events"][-1]["monotonic_ms"] = render["cutoff_ms"] + 1
    after_cutoff["render_observation_sha256"] = evidence_sha256(render)
    with pytest.raises(ValueError, match="after the render cutoff"):
        verify_discovery_event_audit(
            after_cutoff,
            render_observation=render,
            resources=resources,
            exclusions=[],
            approved_origins=["https://page.test"],
            observed_request_count=1,
        )

    wrong_last = deepcopy(render)
    wrong_last["last_relevant_event_ms"] -= 1
    audit["render_observation_sha256"] = evidence_sha256(wrong_last)
    with pytest.raises(ValueError, match="last-event time"):
        verify_discovery_event_audit(
            audit,
            render_observation=wrong_last,
            resources=resources,
            exclusions=[],
            approved_origins=["https://page.test"],
            observed_request_count=1,
        )

    shutdown = deepcopy(audit)
    shutdown["events"][-1]["outcome"] = "shutdown-cancelled"
    shutdown_render = _render_for(shutdown)
    shutdown["render_observation_sha256"] = evidence_sha256(shutdown_render)
    with pytest.raises(ValueError, match="terminal audit event is malformed"):
        verify_discovery_event_audit(
            shutdown,
            render_observation=shutdown_render,
            resources=resources,
            exclusions=[],
            approved_origins=["https://page.test"],
            observed_request_count=1,
        )
