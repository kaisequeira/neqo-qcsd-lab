import hashlib
import json
import sys
from types import ModuleType

import pytest

import qcsd_lab.discover as discover_module
from qcsd_lab.acquisition_errors import (
    NonReplayableEgressPolicyError,
    PassiveRenderPolicyError,
    RecoverableAcquisitionError,
)
from qcsd_lab.browser_egress import (
    NON_REPLAYABLE_EGRESS_POLICY,
    NonReplayableEgressGuard,
    target_egress_apis,
)
from qcsd_lab.cdp_targets import (
    CdpTargetIntegrityError,
    CdpTargetSource,
    EGRESS_PREARM_SUMMARY_SCHEMA_VERSION,
)
from qcsd_lab.discovery_evidence import (
    PASSIVE_RENDER_CONTRACT_SHA256,
    RENDER_OBSERVATION_SCHEMA_VERSION,
)
from qcsd_lab.discover import (
    _DependencyOccurrence,
    DiscoveryIntegrityError,
    DiscoveredRequest,
    _SanitizedEventProjection,
    _RequestExtraInfoAssociator,
    _RequestAdmission,
    _RequestObservationLedger,
    _validate_request_instance_ledger,
    _resolve_dependency_url,
    _stack_frame_urls,
    _wait_for_navigation_load,
    _wait_for_passive_render,
    build_resources,
    discover_page,
    exclusion_reason,
    merge_request_headers,
)


def _bootstrap_prearm_summary(
    *,
    held: int = 0,
    released: int = 0,
    released_after_setup: int = 0,
) -> dict:
    """Build the content-minimised router summary used at render cutoffs."""

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


def _successful_egress_guard() -> NonReplayableEgressGuard:
    guard = NonReplayableEgressGuard()
    guard.mark_context_guards_installed()
    guard.bind_root_page(object())
    return guard


class _NoServiceWorkerContext:
    service_workers: tuple = ()


def test_dependency_extraction_keeps_all_resolvable_initiators():
    requests = [
        DiscoveredRequest("https://page.test/", "Document", {}),
        DiscoveredRequest(
            "https://page.test/app.js",
            "Script",
            {},
            {"https://page.test/"},
        ),
        DiscoveredRequest(
            "https://cdn.test/image.png",
            "Image",
            {},
            {"https://page.test/", "https://page.test/app.js", "about:blank"},
        ),
    ]
    resources = build_resources(requests)
    assert resources[2]["depends_on"] == [0, 1]


def test_dependency_urls_do_not_alias_across_frame_scopes() -> None:
    requests = [
        DiscoveredRequest("https://same.test/", "Document", {}, dependency_scope="frame-a"),
        DiscoveredRequest("https://same.test/", "Document", {}, dependency_scope="frame-b"),
        DiscoveredRequest(
            "https://same.test/app.js",
            "Script",
            {},
            {"https://same.test/"},
            dependency_scope="frame-a",
        ),
    ]
    assert build_resources(requests)[2]["depends_on"] == [0]


def test_request_instance_ledger_rejects_cross_target_identity_collision():
    identity = (("parent", "session"), "target", 2, "request", 0)
    requests = [
        DiscoveredRequest("https://page.test/a", "Fetch", {}, request_instance_id=identity),
        DiscoveredRequest("https://page.test/b", "Fetch", {}, request_instance_id=identity),
    ]

    with pytest.raises(RuntimeError, match="collision-prone"):
        _validate_request_instance_ledger(requests)


def test_chromium_host_resolver_rejects_conflicting_origin_pins_for_one_hostname():
    with pytest.raises(ValueError, match="conflict for a shared hostname"):
        discover_module._pins_by_hostname(
            {
                "https://example.com": "1.1.1.1",
                "https://example.com:8443": "8.8.8.8",
            }
        )

    assert (
        discover_module._pins_by_hostname(
            {
                "https://example.com": "1.1.1.1",
                "https://example.com:8443": "1.1.1.1",
            }
        )
        == {"example.com": "1.1.1.1"}
    )


def test_ephemeral_cdp_ids_do_not_change_the_canonical_resource_graph():
    first = [
        DiscoveredRequest(
            "https://page.test/",
            "Document",
            {"accept": "text/html"},
            request_instance_id=(("session-a",), "target-a", 1, "request-a", 0),
        ),
        DiscoveredRequest(
            "https://cdn.test/app.js",
            "Script",
            {"accept": "*/*"},
            {"https://page.test/"},
            request_instance_id=(("session-b",), "target-b", 2, "request-b", 0),
        ),
    ]
    second = [
        DiscoveredRequest(
            "https://page.test/",
            "Document",
            {"accept": "text/html"},
            request_instance_id=(
                ("different-parent", "different-session-1"),
                "different-target-1",
                8,
                "different-request-1",
                0,
            ),
        ),
        DiscoveredRequest(
            "https://cdn.test/app.js",
            "Script",
            {"accept": "*/*"},
            {"https://page.test/"},
            request_instance_id=(
                ("different-session-2",),
                "different-target-2",
                9,
                "different-request-2",
                0,
            ),
        ),
    ]

    _validate_request_instance_ledger(first)
    _validate_request_instance_ledger(second)
    first_graph = json.dumps(build_resources(first), sort_keys=True).encode()
    second_graph = json.dumps(build_resources(second), sort_keys=True).encode()
    assert hashlib.sha256(first_graph).hexdigest() == hashlib.sha256(second_graph).hexdigest()


def test_https_get_observation_requires_matching_source_aware_interception():
    ledger = _RequestObservationLedger()
    source = CdpTargetSource(("worker-session",), "worker-target")
    ledger.add_network(
        source,
        request_id="network-request",
        method="GET",
        url="https://worker.test/data",
    )
    ledger.add_interception(
        source,
        {
            "requestId": "fetch-request",
            "networkId": "network-request",
            "request": {"method": "GET", "url": "https://worker.test/data"},
        },
    )
    ledger.add_terminal(source, "network-request")
    ledger.finish()


def test_worker_network_occurrence_correlates_with_parent_page_fetch() -> None:
    ledger = _RequestObservationLedger()
    page = CdpTargetSource((), "page", "page")
    worker = CdpTargetSource(("worker-session",), "worker", "worker", parent_session_path=())
    ledger.add_network(
        worker, request_id="shared-network", method="GET", url="https://page.test/data"
    )
    ledger.add_interception(
        page,
        {
            "requestId": "fetch",
            "networkId": "shared-network",
            "request": {"method": "GET", "url": "https://page.test/data"},
        },
    )
    ledger.add_terminal(worker, "shared-network")
    ledger.finish()


def test_internal_fetch_restart_is_not_a_second_request_occurrence() -> None:
    ledger = _RequestObservationLedger()
    source = CdpTargetSource((), "page", "page")
    ledger.add_network(source, request_id="network", method="GET", url="https://page.test/a")
    event = {
        "requestId": "fetch-1",
        "networkId": "network",
        "request": {"method": "GET", "url": "https://page.test/a"},
    }
    ledger.add_interception(source, event)
    ledger.add_interception(source, {**event, "requestId": "fetch-2"})
    ledger.add_terminal(source, "network")
    ledger.finish()


def test_two_fetches_before_network_are_not_guessed_to_be_a_restart() -> None:
    ledger = _RequestObservationLedger()
    source = CdpTargetSource((), "page", "page")
    event = {
        "networkId": "network",
        "request": {"method": "GET", "url": "https://page.test/a"},
    }
    ledger.add_interception(source, {**event, "requestId": "fetch-1"})
    ledger.add_interception(source, {**event, "requestId": "fetch-2"})
    ledger.add_network(source, request_id="network", method="GET", url="https://page.test/a")
    ledger.add_terminal(source, "network")
    with pytest.raises(DiscoveryIntegrityError, match="ledgers differ"):
        ledger.finish()


def test_two_fetch_before_network_occurrences_are_not_collapsed_as_restart() -> None:
    ledger = _RequestObservationLedger()
    source = CdpTargetSource((), "page", "page")
    event = {
        "networkId": "network",
        "request": {"method": "GET", "url": "https://page.test/a"},
    }
    ledger.add_interception(source, {**event, "requestId": "fetch-1"})
    ledger.add_interception(source, {**event, "requestId": "fetch-2"})
    ledger.add_network(source, request_id="network", method="GET", url="https://page.test/a")
    ledger.add_network(source, request_id="network", method="GET", url="https://page.test/a")
    ledger.add_terminal(source, "network")
    ledger.finish()


def test_fetch_redirect_requires_the_exact_immediate_predecessor_once() -> None:
    ledger = _RequestObservationLedger()
    source = CdpTargetSource((), "page", "page")
    ledger.add_interception(
        source,
        {
            "requestId": "fetch-first",
            "networkId": "network",
            "request": {"method": "GET", "url": "https://page.test/first"},
        },
    )
    ledger.add_interception(
        source,
        {
            "requestId": "fetch-second",
            "networkId": "network",
            "redirectedRequestId": "fetch-first",
            "request": {"method": "GET", "url": "https://page.test/final"},
        },
    )
    ledger.add_network(source, request_id="network", method="GET", url="https://page.test/first")
    ledger.add_network(source, request_id="network", method="GET", url="https://page.test/final")
    ledger.add_terminal(source, "network")
    ledger.finish()


@pytest.mark.parametrize("kind", ("loop", "missing", "non-predecessor", "duplicate"))
def test_fetch_redirect_rejects_invalid_identity_graph(kind: str) -> None:
    ledger = _RequestObservationLedger()
    source = CdpTargetSource((), "page", "page")
    base = {
        "networkId": "network",
        "request": {"method": "GET", "url": "https://page.test/a"},
    }
    ledger.add_interception(source, {**base, "requestId": "first"})
    if kind == "non-predecessor":
        ledger.add_interception(source, {**base, "requestId": "intervening"})
    redirected = {
        "loop": "second",
        "missing": "absent",
        "non-predecessor": "first",
        "duplicate": "first",
    }[kind]
    if kind == "duplicate":
        ledger.add_interception(
            source,
            {**base, "requestId": "second", "redirectedRequestId": "first"},
        )
        request_id = "third"
    else:
        request_id = "second"
    with pytest.raises(DiscoveryIntegrityError, match="redirect|predecessor|loop|ambiguous"):
        ledger.add_interception(
            source,
            {**base, "requestId": request_id, "redirectedRequestId": redirected},
        )


def test_fetch_identity_is_scoped_by_full_target_generation() -> None:
    ledger = _RequestObservationLedger()
    event = {
        "requestId": "same-fetch",
        "networkId": "same-network",
        "request": {"method": "GET", "url": "https://page.test/a"},
    }
    first = CdpTargetSource(("session",), "target", "iframe", 0)
    second = CdpTargetSource(("session",), "target", "iframe", 1)
    ledger.add_interception(first, event)
    ledger.add_interception(second, event)
    ledger.add_network(first, request_id="same-network", method="GET", url="https://page.test/a")
    ledger.add_network(second, request_id="same-network", method="GET", url="https://page.test/a")
    ledger.add_terminal(first, "same-network")
    ledger.add_terminal(second, "same-network")
    ledger.finish()


def test_fetch_redirect_cannot_cross_target_generations() -> None:
    ledger = _RequestObservationLedger()
    first = CdpTargetSource(("first-session",), "target", "iframe", 0)
    second = CdpTargetSource(("second-session",), "target", "iframe", 1)
    ledger.add_interception(
        first,
        {
            "requestId": "first-fetch",
            "networkId": "same-network",
            "request": {"method": "GET", "url": "https://page.test/first"},
        },
    )
    with pytest.raises(DiscoveryIntegrityError, match="predecessor"):
        ledger.add_interception(
            second,
            {
                "requestId": "second-fetch",
                "networkId": "same-network",
                "redirectedRequestId": "first-fetch",
                "frameId": "target",
                "request": {"method": "GET", "url": "https://page.test/final"},
            },
        )


def test_fetch_redirect_and_network_reconcile_across_oopif_migration() -> None:
    ledger = _RequestObservationLedger()
    root = CdpTargetSource((), "page", "page")
    iframe = CdpTargetSource(
        ("iframe-session",),
        "iframe",
        "iframe",
        parent_session_path=(),
        parent_frame_id="page",
    )
    ledger.add_interception(
        root,
        {
            "requestId": "first-fetch",
            "networkId": "network",
            "request": {"method": "GET", "url": "https://page.test/first"},
        },
    )
    ledger.add_network(
        root,
        request_id="network",
        method="GET",
        url="https://page.test/first",
    )
    ledger.add_interception(
        iframe,
        {
            "requestId": "second-fetch",
            "networkId": "network",
            "redirectedRequestId": "first-fetch",
            "frameId": "page",
            "request": {"method": "GET", "url": "https://page.test/final"},
        },
    )
    # The recursive router preserves the root canonical Network source while
    # Chromium migrates the Fetch interception to the OOPIF session.
    ledger.add_network(
        root,
        request_id="network",
        method="GET",
        url="https://page.test/final",
    )
    ledger.add_terminal(root, "network")
    ledger.finish()


def test_fetch_redirect_cannot_follow_its_network_terminal() -> None:
    ledger = _RequestObservationLedger()
    source = CdpTargetSource((), "page", "page")
    first = {
        "requestId": "first-fetch",
        "networkId": "network",
        "request": {"method": "GET", "url": "https://page.test/first"},
    }
    ledger.add_interception(source, first)
    ledger.add_network(source, request_id="network", method="GET", url="https://page.test/first")
    ledger.add_terminal(source, "network")
    with pytest.raises(DiscoveryIntegrityError, match="terminated request chain"):
        ledger.add_interception(
            source,
            {
                "requestId": "second-fetch",
                "networkId": "network",
                "redirectedRequestId": "first-fetch",
                "request": {"method": "GET", "url": "https://page.test/final"},
            },
        )


def test_raw_network_identity_cannot_be_reused_after_terminal() -> None:
    ledger = _RequestObservationLedger()
    source = CdpTargetSource((), "page", "page")
    ledger.add_network(source, request_id="network", method="GET", url="https://page.test/first")
    ledger.add_interception(
        source,
        {
            "requestId": "fetch",
            "networkId": "network",
            "request": {"method": "GET", "url": "https://page.test/first"},
        },
    )
    ledger.add_terminal(source, "network")
    with pytest.raises(DiscoveryIntegrityError, match="terminated Network"):
        ledger.add_network(
            source, request_id="network", method="GET", url="https://page.test/second"
        )


def test_cross_source_network_collision_fails_closed() -> None:
    ledger = _RequestObservationLedger()
    page = CdpTargetSource((), "page", "page")
    for ordinal in (1, 2):
        ledger.add_network(
            CdpTargetSource(
                (f"worker-{ordinal}",),
                f"worker-{ordinal}",
                "worker",
                parent_session_path=(),
            ),
            request_id="collision",
            method="GET",
            url="https://page.test/a",
        )
    with pytest.raises(DiscoveryIntegrityError, match="ambiguous"):
        ledger.add_interception(
            page,
            {
                "requestId": "fetch",
                "networkId": "collision",
                "request": {"method": "GET", "url": "https://page.test/a"},
            },
        )

    wrong_source = _RequestObservationLedger()
    wrong_source.add_network(
        CdpTargetSource(("worker-session",), "worker-target"),
        request_id="duplicate",
        method="GET",
        url="https://worker.test/data",
    )
    with pytest.raises(RuntimeError, match="ledgers differ"):
        wrong_source.finish()


def test_https_get_interception_without_network_identity_fails_closed():
    ledger = _RequestObservationLedger()
    source = CdpTargetSource(("iframe-session",), "iframe-target")

    with pytest.raises(RuntimeError, match="omitted its Network request ID"):
        ledger.add_interception(
            source,
            {
                "requestId": "fetch-request",
                "request": {"method": "GET", "url": "https://frame.test/data"},
            },
        )


def test_discovery_excludes_unsafe_and_unreviewed_requests():
    reviewed = {"https://cdn.test", "https://page.test"}
    assert exclusion_reason("POST", "https://page.test/log", reviewed) == ("unsafe method: POST")
    assert exclusion_reason("GET", "data:text/plain,hello", reviewed) == (
        "not an absolute HTTPS request"
    )
    assert exclusion_reason("GET", "https://tracker.test/code.js", reviewed) == (
        "origin not approved"
    )
    assert exclusion_reason("GET", "https://page.test/app.js", reviewed) is None
    assert exclusion_reason("GET", "https://cdn.test/app.js", reviewed) is None


def test_request_stage_admission_continues_multi_origin_gets_and_blocks_tracker_and_post():
    class Session:
        def __init__(self) -> None:
            self.commands: list[tuple[str, dict[str, str]]] = []

        def send(self, command: str, parameters: dict[str, str]) -> None:
            self.commands.append((command, parameters))

    session = Session()
    admission = _RequestAdmission({"https://cdn.test", "https://page.test"})
    requests = [
        ("page", "GET", "https://page.test/"),
        ("cdn", "GET", "https://cdn.test/app.js"),
        ("tracker", "GET", "https://tracker.test/beacon.js"),
        ("post", "POST", "https://page.test/cdn-cgi/rum"),
    ]

    for request_id, method, url in requests:
        admission.observe_network(method, url)
        admission.enforce(
            session,
            {
                "requestId": request_id,
                "request": {"method": method, "url": url},
            },
        )

    assert session.commands == [
        ("Fetch.continueRequest", {"requestId": "page"}),
        ("Fetch.continueRequest", {"requestId": "cdn"}),
        (
            "Fetch.failRequest",
            {"requestId": "tracker", "errorReason": "BlockedByClient"},
        ),
        (
            "Fetch.failRequest",
            {"requestId": "post", "errorReason": "BlockedByClient"},
        ),
    ]
    assert admission.observed_request_count == 4
    assert admission.observed_origins == {
        "https://cdn.test",
        "https://page.test",
        "https://tracker.test",
    }
    assert admission.expandable_origins == {
        "https://cdn.test",
        "https://page.test",
        "https://tracker.test",
    }
    assert sorted(admission.exclusions.values(), key=lambda item: item["url"]) == [
        {
            "url": "https://page.test/cdn-cgi/rum",
            "reason": "unsafe method: POST",
        },
        {
            "url": "https://tracker.test/beacon.js",
            "reason": "origin not approved",
        },
    ]


def test_repeated_fetch_policy_is_applied_twice_but_network_is_counted_once() -> None:
    admission = _RequestAdmission({"https://page.test"})
    event = {
        "requestId": "fetch-1",
        "request": {"method": "GET", "url": "https://page.test/data"},
    }
    assert admission.command(event)[0] == "Fetch.continueRequest"
    assert admission.command({**event, "requestId": "fetch-2"})[0] == "Fetch.continueRequest"
    admission.observe_network("GET", "https://page.test/data")
    assert admission.observed_request_count == 1


def test_request_stage_admission_rejects_a_response_stage_event():
    admission = _RequestAdmission({"https://page.test"})

    with pytest.raises(RuntimeError, match="response stage"):
        admission.command(
            {
                "requestId": "response-stage",
                "request": {"method": "GET", "url": "https://page.test/"},
                "responseStatusCode": 200,
            }
        )


def test_discover_page_installs_request_stage_policy_before_navigation(monkeypatch):
    clock_ns = [0]
    driver_validations = []
    monkeypatch.setattr(discover_module.time, "monotonic_ns", lambda: clock_ns[0])
    monkeypatch.setattr(
        discover_module,
        "validate_default_playwright_driver_once",
        lambda: driver_validations.append(True),
    )
    events = [
        {
            "requestId": "page-chain",
            "request": {"method": "GET", "url": "https://page.test/", "headers": {}},
            "type": "Document",
            "documentURL": "https://page.test/",
        },
        {
            "requestId": "page-chain",
            "request": {
                "method": "GET",
                "url": "https://page.test/home",
                "headers": {},
            },
            "type": "Document",
            "documentURL": "https://page.test/",
            "redirectResponse": {"status": 302},
            "redirectHasExtraInfo": False,
        },
        {
            "requestId": "cdn",
            "request": {
                "method": "GET",
                "url": "https://cdn.test/app.js",
                "headers": {"Accept": "*/*"},
            },
            "type": "Script",
            "documentURL": "https://page.test/home",
        },
        {
            "requestId": "cdn-repeat",
            "request": {
                "method": "GET",
                "url": "https://cdn.test/app.js",
                "headers": {"Accept": "*/*"},
            },
            "type": "Script",
            "documentURL": "https://page.test/home",
        },
        {
            "requestId": "tracker",
            "request": {
                "method": "GET",
                "url": "https://tracker.test/beacon.js",
                "headers": {},
            },
            "type": "Script",
            "documentURL": "https://page.test/",
        },
        {
            "requestId": "post",
            "request": {
                "method": "POST",
                "url": "https://page.test/cdn-cgi/rum",
                "headers": {},
            },
            "type": "Fetch",
            "documentURL": "https://page.test/",
        },
    ]

    class Session:
        def __init__(self) -> None:
            self.handlers = {}
            self.commands = []
            self.paused = {}
            for index, event in enumerate(events):
                self.paused[f"fetch-{index}"] = [event]

        def on(self, event: str, handler) -> None:
            self.handlers[event] = handler

        def send(self, command: str, parameters=None) -> dict:
            self.commands.append((command, parameters))
            if command == "Target.getTargetInfo":
                return {
                    "targetInfo": {
                        "targetId": "root-page",
                        "type": "page",
                        "url": "https://page.test/",
                        "browserContextId": "browser-context",
                    }
                }
            if command == "Page.addScriptToEvaluateOnNewDocument":
                return {"identifier": "root-egress-init"}
            if command == "Runtime.evaluate":
                expression = parameters["expression"]
                if "__qcsd_popup_navigation_guard_v1__" in expression:
                    return {"result": {"type": "boolean", "value": True}}
                return {
                    "result": {
                        "type": "object",
                        "value": {
                            "schema_version": 1,
                            "policy": NON_REPLAYABLE_EGRESS_POLICY,
                            "protected_apis": sorted(target_egress_apis("page")),
                            "unavailable_apis": [],
                            "failed_apis": [],
                            "already_installed": True,
                        },
                    }
                }
            if command == "Fetch.continueRequest":
                network_event = self.paused[parameters["requestId"]].pop(0)
                self.handlers["Network.requestWillBeSent"](network_event)
                is_redirect_predecessor = (
                    network_event["requestId"] == "page-chain"
                    and network_event["request"]["url"] == "https://page.test/"
                )
                if not self.paused[parameters["requestId"]] and not is_redirect_predecessor:
                    network_id = network_event["requestId"]
                    self.handlers["Network.responseReceived"](
                        {
                            "requestId": network_id,
                            "hasExtraInfo": False,
                            "response": {},
                        }
                    )
                    self.handlers["Network.loadingFinished"]({"requestId": network_id})
            if command == "Fetch.failRequest":
                network_event = self.paused[parameters["requestId"]].pop(0)
                self.handlers["Network.requestWillBeSent"](network_event)
                self.handlers["Network.loadingFailed"]({"requestId": network_event["requestId"]})
            return {}

    class Page:
        source_url = "https://page.test/"
        url = "https://page.test/home"

        def __init__(self, session: Session) -> None:
            self.session = session
            self.handlers = {}

        def on(self, event: str, handler) -> None:
            self.handlers[event] = handler

        def goto(self, url: str, *, wait_until: str, timeout: int) -> None:
            assert url == self.source_url
            assert wait_until == "commit"
            assert timeout == 1_000
            assert "load" in self.handlers
            previous_fetch_id = None
            for index, event in enumerate(events):
                fetch_id = f"fetch-{index}"
                redirect_fields = (
                    {"redirectedRequestId": previous_fetch_id}
                    if event.get("redirectResponse") is not None
                    else {}
                )
                self.session.handlers["Fetch.requestPaused"](
                    {
                        **event,
                        **redirect_fields,
                        "requestId": fetch_id,
                        "networkId": event["requestId"],
                    }
                )
                previous_fetch_id = fetch_id
            self.handlers["load"]()

        def wait_for_timeout(self, milliseconds: int) -> None:
            assert 1 <= milliseconds <= 100
            clock_ns[0] += milliseconds * 1_000_000

        def close(self) -> None:
            return None

    class Context:
        def __init__(self) -> None:
            self.session = Session()
            self.page = Page(self.session)
            self.closed = False
            self.service_workers = []
            self.init_scripts = []
            self.websocket_routes = []
            self.handlers = {}

        def add_init_script(self, *, script: str) -> None:
            self.init_scripts.append(script)

        def route_web_socket(self, pattern: str, handler) -> None:
            self.websocket_routes.append((pattern, handler))

        def route(self, pattern: str, handler) -> None:
            assert pattern == "**/*"
            self.handlers["route"] = handler

        def on(self, event: str, handler) -> None:
            self.handlers[event] = handler

        def new_page(self) -> Page:
            return self.page

        def new_cdp_session(self, page: Page) -> Session:
            assert page is self.page
            return self.session

        def close(self) -> None:
            self.closed = True
            self.page.close()

    class BrowserSession:
        def __init__(self) -> None:
            self.handlers = {}
            self.commands = []
            self.detached = False

        def on(self, event: str, handler) -> None:
            self.handlers[event] = handler

        def send(self, command: str, parameters=None) -> dict:
            self.commands.append((command, parameters))
            if (
                command == "Target.setAutoAttach"
                and parameters.get("autoAttach") is True
                and any(
                    item.get("type") == "tab" and item.get("exclude") is False
                    for item in parameters.get("filter", [])
                )
            ):
                self.handlers["Target.attachedToTarget"](
                    {
                        "sessionId": "root-tab-session",
                        "targetInfo": {
                            "targetId": "root-tab",
                            "type": "tab",
                            "url": "https://page.test/",
                            "browserContextId": "browser-context",
                            "attached": True,
                        },
                        "waitingForDebugger": False,
                    }
                )
            if command == "Target.getTargets":
                return {
                    "targetInfos": [
                        {
                            "targetId": "root-page",
                            "type": "page",
                            "url": "https://page.test/",
                            "browserContextId": "browser-context",
                            "attached": True,
                        }
                    ]
                }
            return {}

        def detach(self) -> None:
            self.detached = True

    class Browser:
        version = "test-chromium"

        def __init__(self) -> None:
            self.context = Context()
            self.browser_session = BrowserSession()
            self.context_options = None
            self.launch_options = None

        def new_context(self, **options) -> Context:
            self.context_options = options
            return self.context

        def new_browser_cdp_session(self) -> BrowserSession:
            return self.browser_session

        def close(self) -> None:
            return None

    browser = Browser()
    launch_calls = []

    def launch_production(playwright, *, approved_origins, origin_ip_pins):
        launch_calls.append(
            {
                "playwright": playwright,
                "approved_origins": list(approved_origins),
                "origin_ip_pins": dict(origin_ip_pins),
            }
        )
        return browser, {"launch_profile": "production-fail-closed"}

    monkeypatch.setattr(discover_module, "launch_production_browser", launch_production)

    class Chromium:
        def launch(self, **options) -> Browser:
            browser.launch_options = options
            return browser

    class Playwright:
        chromium = Chromium()

        def __enter__(self):
            return self

        def __exit__(self, *_args) -> None:
            return None

    sync_api = ModuleType("playwright.sync_api")
    sync_api.Error = RuntimeError  # type: ignore[attr-defined]
    sync_api.sync_playwright = Playwright  # type: ignore[attr-defined]
    playwright = ModuleType("playwright")
    playwright.sync_api = sync_api  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "playwright", playwright)
    monkeypatch.setitem(sys.modules, "playwright.sync_api", sync_api)

    result = discover_page(
        "https://page.test/",
        allow_origins=["https://page.test", "https://cdn.test"],
        timeout_ms=1_000,
        origin_ip_pins={
            "https://page.test": "1.1.1.1",
            "https://cdn.test": "8.8.8.8",
        },
    )

    assert driver_validations == [True]
    assert len(launch_calls) == 1
    assert launch_calls[0]["approved_origins"] == [
        "https://cdn.test",
        "https://page.test",
    ]
    assert browser.context_options == {
        "ignore_https_errors": False,
        "service_workers": "block",
        "viewport": {"width": 1365, "height": 768},
        "device_scale_factor": 1,
    }
    assert browser.context.closed is True
    assert browser.browser_session.commands == [
        (
            "Target.setDiscoverTargets",
            {
                "discover": True,
                "filter": [
                    {"type": "page", "exclude": False},
                    {"type": "service_worker", "exclude": False},
                    {"exclude": True},
                ],
            },
        ),
        (
            "Target.setAutoAttach",
            {
                "autoAttach": True,
                "waitForDebuggerOnStart": True,
                "flatten": True,
                "filter": [
                    {"type": "shared_worker", "exclude": False},
                    {"type": "tab", "exclude": False},
                    {"exclude": True},
                ],
            },
        ),
        ("Target.getTargets", {}),
        (
            "Target.setAutoAttach",
            {
                "autoAttach": False,
                "waitForDebuggerOnStart": False,
                "flatten": True,
            },
        ),
        (
            "Target.setDiscoverTargets",
            {"discover": False},
        ),
    ]
    assert browser.browser_session.detached is True
    assert (
        "Fetch.enable",
        {"patterns": [{"urlPattern": "*", "requestStage": "Request"}]},
    ) in browser.context.session.commands
    assert (
        "Target.setAutoAttach",
        {
            "autoAttach": True,
            "waitForDebuggerOnStart": True,
            "flatten": False,
        },
    ) in browser.context.session.commands
    assert [resource["url"] for resource in result.resources] == [
        "https://page.test/",
        "https://page.test/home",
        "https://cdn.test/app.js",
        "https://cdn.test/app.js",
    ]
    assert [resource["id"] for resource in result.resources] == [0, 1, 2, 3]
    assert [resource["depends_on"] for resource in result.resources] == [[], [0], [1], [1]]
    assert result.observed_request_count == 6
    assert result.expandable_origins == [
        "https://cdn.test",
        "https://page.test",
        "https://tracker.test",
    ]
    assert result.exclusions == [
        {
            "url": "https://page.test/cdn-cgi/rum",
            "reason": "unsafe method: POST",
        },
        {
            "url": "https://tracker.test/beacon.js",
            "reason": "origin not approved",
        },
    ]
    assert result.settle_ms == 10_000
    assert result.passive_render_contract_sha256 == PASSIVE_RENDER_CONTRACT_SHA256
    assert result.render_observation == {
        "schema_version": RENDER_OBSERVATION_SCHEMA_VERSION,
        "clock": "monotonic-relative-ms",
        "navigation_started_ms": 0,
        "load_event_ms": 0,
        "last_relevant_event_ms": 0,
        "quiet_started_ms": 10_000,
        "cutoff_ms": 13_000,
        "active_request_ids": [],
        "active_request_count": 0,
            "router_shutdown_ready": True,
            "bootstrap_prearm_summary": _bootstrap_prearm_summary(),
            "egress_prearm_summary": _egress_prearm_summary(),
            "non_replayable_egress_summary": _successful_egress_guard().success_summary(),
            "browser_context_service_worker_count": 0,
            "cutoff_reason": "quiescent",
        }
    assert result.discovery_event_audit["summary"] == {
        "event_count": 17,
        "target_event_count": 0,
        "network_request_count": 6,
        "fetch_request_count": 6,
        "fetch_internal_restart_count": 0,
        "terminal_event_count": 5,
        "resource_occurrence_count": 4,
        "exclusion_occurrence_count": 2,
    }


def test_navigation_load_wait_surfaces_router_failure_after_one_poll(
    monkeypatch,
) -> None:
    clock = [0.0]
    monkeypatch.setattr(discover_module.time, "monotonic", lambda: clock[0])

    class Router:
        def __init__(self) -> None:
            self.checks = 0

        def raise_if_failed(self) -> None:
            self.checks += 1
            if self.checks == 2:
                raise CdpTargetIntegrityError("worker instrumentation failed")

    class Page:
        def __init__(self) -> None:
            self.waits = []

        def wait_for_timeout(self, milliseconds: int) -> None:
            self.waits.append(milliseconds)
            clock[0] += milliseconds / 1_000

    router = Router()
    page = Page()
    with pytest.raises(CdpTargetIntegrityError, match="worker instrumentation failed"):
        _wait_for_navigation_load(
            page,
            router,  # type: ignore[arg-type]
            [False],
            _successful_egress_guard(),
            deadline=1.0,
        )

    assert router.checks == 2
    assert len(page.waits) == 1
    assert 1 <= page.waits[0] <= 100


def test_navigation_load_wait_uses_the_existing_absolute_deadline(monkeypatch) -> None:
    clock = [0.9]
    monkeypatch.setattr(discover_module.time, "monotonic", lambda: clock[0])

    class Router:
        def __init__(self) -> None:
            self.checks = 0

        def raise_if_failed(self) -> None:
            self.checks += 1

    class Page:
        def __init__(self) -> None:
            self.waits = []

        def wait_for_timeout(self, milliseconds: int) -> None:
            self.waits.append(milliseconds)
            clock[0] += milliseconds / 1_000

    router = Router()
    page = Page()
    with pytest.raises(
        RecoverableAcquisitionError,
        match="did not reach the genuine page load event",
    ):
        _wait_for_navigation_load(
            page,
            router,  # type: ignore[arg-type]
            [False],
            _successful_egress_guard(),
            deadline=1.0,
        )

    assert page.waits == [100]
    assert router.checks == 2


class _PassiveClock:
    def __init__(self) -> None:
        self.ms = 0

    def nanoseconds(self) -> int:
        return self.ms * 1_000_000


class _PassiveRouter:
    def __init__(
        self,
        *,
        shutdown_ready: bool = True,
        bootstrap_prearm_summary: dict | None = None,
    ) -> None:
        self.active_request_identities = ()
        self.shutdown_ready = shutdown_ready
        self.bootstrap_prearm_summary = bootstrap_prearm_summary or _bootstrap_prearm_summary()
        self.egress_prearm_summary = _egress_prearm_summary()

    def raise_if_failed(self) -> None:
        return None


class _PassivePage:
    def __init__(self, clock: _PassiveClock, callbacks=()) -> None:
        self.clock = clock
        self.callbacks = list(callbacks)

    def wait_for_timeout(self, milliseconds: int) -> None:
        before = self.clock.ms
        self.clock.ms += milliseconds
        pending = []
        for at_ms, callback in self.callbacks:
            if before < at_ms <= self.clock.ms:
                self.clock.ms = at_ms
                callback()
                self.clock.ms = before + milliseconds
            else:
                pending.append((at_ms, callback))
        self.callbacks = pending


def test_passive_render_waits_for_quiet_after_minimum_and_a_late_fetch() -> None:
    clock = _PassiveClock()
    audit = _SanitizedEventProjection(clock_ns=clock.nanoseconds)
    router = _PassiveRouter()
    source = CdpTargetSource((), "page", "page")
    network_event = {
        "requestId": "late",
        "request": {"method": "GET", "url": "https://page.test/late"},
        "type": "Fetch",
    }

    def start_fetch() -> None:
        audit.record_network(source, network_event)
        audit.record_fetch(
            source,
            {
                "requestId": "late-fetch",
                "networkId": "late",
                "request": network_event["request"],
            },
            decision="continue",
            reason=None,
        )
        router.active_request_identities = ((source, "late"),)

    def finish_fetch() -> None:
        audit.record_terminal(
            source,
            {"requestId": "late"},
            outcome="finished",
            occurrence_ids=(),
        )
        router.active_request_identities = ()

    page = _PassivePage(clock, ((12_000, start_fetch), (12_500, finish_fetch)))
    observation = _wait_for_passive_render(
        page,
        router,  # type: ignore[arg-type]
        audit,
        _successful_egress_guard(),
        _NoServiceWorkerContext(),
        navigation_started_ms=0,
        load_event_ms=0,
    )

    assert observation["quiet_started_ms"] == 12_500
    assert observation["cutoff_ms"] == 15_500
    assert observation["cutoff_reason"] == "quiescent"


def test_passive_render_waits_for_terminal_shared_worker_prearm() -> None:
    clock = _PassiveClock()
    audit = _SanitizedEventProjection(clock_ns=clock.nanoseconds)
    router = _PassiveRouter(
        shutdown_ready=False,
        bootstrap_prearm_summary=_bootstrap_prearm_summary(held=1),
    )

    def release_prearm() -> None:
        router.shutdown_ready = True
        router.bootstrap_prearm_summary = _bootstrap_prearm_summary(
            held=1,
            released=1,
            released_after_setup=1,
        )

    page = _PassivePage(clock, ((14_000, release_prearm),))
    observation = _wait_for_passive_render(
        page,
        router,  # type: ignore[arg-type]
        audit,
        _successful_egress_guard(),
        _NoServiceWorkerContext(),
        navigation_started_ms=0,
        load_event_ms=0,
    )

    assert observation["cutoff_ms"] == 14_000
    assert observation["router_shutdown_ready"] is True
    assert observation["bootstrap_prearm_summary"] == _bootstrap_prearm_summary(
        held=1,
        released=1,
        released_after_setup=1,
    )


def test_passive_render_hard_cap_is_a_typed_rejection_with_active_ids() -> None:
    clock = _PassiveClock()
    audit = _SanitizedEventProjection(clock_ns=clock.nanoseconds)
    router = _PassiveRouter()
    source = CdpTargetSource((), "page", "page")
    router.active_request_identities = ((source, "never-finishes"),)
    page = _PassivePage(clock)

    with pytest.raises(PassiveRenderPolicyError) as caught:
        _wait_for_passive_render(
            page,
            router,  # type: ignore[arg-type]
            audit,
            _successful_egress_guard(),
            _NoServiceWorkerContext(),
            navigation_started_ms=0,
            load_event_ms=0,
        )

    observation = caught.value.evidence["render_observation"]
    assert observation["cutoff_ms"] == 30_000
    assert observation["active_request_count"] == 1
    assert observation["cutoff_reason"] == "hard-cap-non-quiescent"


def test_passive_render_hard_cap_rejects_unready_router_without_active_requests() -> None:
    clock = _PassiveClock()
    audit = _SanitizedEventProjection(clock_ns=clock.nanoseconds)
    router = _PassiveRouter(
        shutdown_ready=False,
        bootstrap_prearm_summary=_bootstrap_prearm_summary(held=1),
    )

    with pytest.raises(PassiveRenderPolicyError) as caught:
        _wait_for_passive_render(
            _PassivePage(clock),
            router,  # type: ignore[arg-type]
            audit,
            _successful_egress_guard(),
            _NoServiceWorkerContext(),
            navigation_started_ms=0,
            load_event_ms=0,
        )

    observation = caught.value.evidence["render_observation"]
    assert observation["cutoff_ms"] == 30_000
    assert observation["active_request_count"] == 0
    assert observation["router_shutdown_ready"] is False
    assert observation["bootstrap_prearm_summary"]["pending_total"] == 1
    assert observation["cutoff_reason"] == "hard-cap-non-quiescent"


@pytest.mark.parametrize(
    "failure_kind",
    [
        "policy",
        "playwright",
        "playwright-cleanup-failure",
        "playwright-browser-close-failure",
        "keyboard-interrupt",
        "router-start-setup-failure",
        "partial-guard-start",
        "normal-shutdown-guard-failure",
        "egress-priority",
        "router-priority",
    ],
)
def test_discover_page_aborts_pre_shutdown_failure_without_masking_primary(
    monkeypatch,
    failure_kind: str,
) -> None:
    clock_ns = [0]
    lifecycle: list[str] = []
    monkeypatch.setattr(discover_module.time, "monotonic_ns", lambda: clock_ns[0])
    monkeypatch.setattr(discover_module, "validate_default_playwright_driver_once", lambda: None)

    class PlaywrightFailure(RuntimeError):
        pass

    class SetupFailure(RuntimeError):
        pass

    class ShutdownFailure(RuntimeError):
        pass

    keyboard_primary = KeyboardInterrupt("synthetic discovery interrupt")
    router_post_close_checks = [0]

    class Router:
        active_request_identities = ()
        shutdown_ready = failure_kind == "normal-shutdown-guard-failure"
        bootstrap_prearm_summary = _bootstrap_prearm_summary(
            held=0 if failure_kind == "normal-shutdown-guard-failure" else 1
        )
        egress_prearm_summary = _egress_prearm_summary()

        def __init__(self, *_args, **_kwargs) -> None:
            self.abort_started = False

        def start(self) -> None:
            lifecycle.append("router-start")
            if failure_kind == "router-start-setup-failure":
                raise SetupFailure("synthetic router setup failure")

        def raise_if_failed(self) -> None:
            if failure_kind in {"egress-priority", "router-priority"} and browser.closed:
                router_post_close_checks[0] += 1
                raise CdpTargetIntegrityError("synthetic retained router failure")
            return None

        def begin_shutdown(self) -> None:
            if failure_kind != "normal-shutdown-guard-failure":
                raise AssertionError("unready router must not use normal shutdown")
            lifecycle.append("router-begin-shutdown")

        def begin_abort(self) -> None:
            self.abort_started = True
            lifecycle.append("router-begin-abort")

        def finish_abort(self) -> None:
            assert self.abort_started
            lifecycle.append("router-finish-abort")
            if failure_kind == "playwright-cleanup-failure":
                raise LookupError("synthetic router cleanup failure")

    class Guard:
        def __init__(self, _session, router: Router) -> None:
            self.router = router
            self.abort_started = False

        def start(self) -> None:
            lifecycle.append("guard-start")
            if failure_kind == "partial-guard-start":
                raise SetupFailure("synthetic partial guard start")

        def begin_abort(self) -> None:
            assert self.router.abort_started
            self.abort_started = True
            lifecycle.append("guard-begin-abort")

        def finish_abort(self) -> None:
            assert self.abort_started
            lifecycle.append("guard-finish-abort")

        def begin_shutdown(self) -> None:
            lifecycle.append("guard-begin-shutdown")
            if failure_kind == "normal-shutdown-guard-failure":
                raise ShutdownFailure("synthetic guard shutdown failure")

        def finish(self) -> None:
            lifecycle.append("guard-finish")

    class Page:
        url = "https://page.test/"

        def __init__(self) -> None:
            self.handlers = {}

        def on(self, event: str, handler) -> None:
            self.handlers[event] = handler

        def goto(self, *_args, **_kwargs) -> None:
            if failure_kind == "keyboard-interrupt":
                raise keyboard_primary
            if failure_kind.startswith("playwright") or failure_kind in {
                "egress-priority",
                "router-priority",
            }:
                raise PlaywrightFailure("synthetic navigation timeout")
            self.handlers["load"]()

        def wait_for_timeout(self, milliseconds: int) -> None:
            clock_ns[0] += milliseconds * 1_000_000

    class Context:
        def __init__(self) -> None:
            self.page = Page()
            self.closed = False
            self.service_workers = []

        def add_init_script(self, *, script: str) -> None:
            assert script

        def route_web_socket(self, pattern: str, _handler) -> None:
            assert pattern == "**"

        def route(self, pattern: str, _handler) -> None:
            assert pattern == "**/*"

        def on(self, event: str, _handler) -> None:
            assert event == "serviceworker"

        def new_page(self) -> Page:
            return self.page

        def new_cdp_session(self, _page: Page) -> object:
            return object()

        def close(self) -> None:
            self.closed = True
            lifecycle.append("context-close")

    egress_guards: list[NonReplayableEgressGuard] = []

    class Browser:
        version = "test-chromium"

        def __init__(self) -> None:
            self.context = Context()
            self.closed = False

        def new_context(self, **_kwargs) -> Context:
            return self.context

        def new_browser_cdp_session(self) -> object:
            return object()

        def close(self) -> None:
            self.closed = True
            lifecycle.append("browser-close")
            if failure_kind == "egress-priority":
                egress_guards[0].record(
                    source=None,
                    api="WebSocket",
                    mechanism="paused-target-runtime-shim",
                    url=None,
                )
            if failure_kind in {"playwright-browser-close-failure", "keyboard-interrupt"}:
                raise LookupError("synthetic browser close failure")

    browser = Browser()
    monkeypatch.setattr(
        discover_module,
        "launch_production_browser",
        lambda _playwright, **_kwargs: (
            browser,
            {"launch_profile": "production-fail-closed"},
        ),
    )

    class Chromium:
        def launch(self, **_kwargs) -> Browser:
            return browser

    class PlaywrightManager:
        chromium = Chromium()

        def __enter__(self):
            return self

        def __exit__(self, *_args) -> None:
            return None

    sync_api = ModuleType("playwright.sync_api")
    sync_api.Error = PlaywrightFailure  # type: ignore[attr-defined]
    sync_api.sync_playwright = PlaywrightManager  # type: ignore[attr-defined]
    playwright = ModuleType("playwright")
    playwright.sync_api = sync_api  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "playwright", playwright)
    monkeypatch.setitem(sys.modules, "playwright.sync_api", sync_api)
    monkeypatch.setattr(discover_module, "RecursiveCdpTargetRouter", Router)
    monkeypatch.setattr(discover_module, "BrowserSharedWorkerGuard", Guard)

    def new_egress_guard() -> NonReplayableEgressGuard:
        guard = NonReplayableEgressGuard()
        egress_guards.append(guard)
        return guard

    monkeypatch.setattr(discover_module, "NonReplayableEgressGuard", new_egress_guard)

    if failure_kind == "policy":
        with pytest.raises(PassiveRenderPolicyError) as caught:
            discover_page(
                "https://page.test/",
                allow_origins=["https://page.test"],
                timeout_ms=1_000,
                origin_ip_pins={"https://page.test": "1.1.1.1"},
            )
        observation = caught.value.evidence["render_observation"]
        assert observation["bootstrap_prearm_summary"]["pending_total"] == 1
        assert observation["cutoff_reason"] == "hard-cap-non-quiescent"
    elif failure_kind.startswith("playwright"):
        with pytest.raises(RecoverableAcquisitionError) as caught:
            discover_page(
                "https://page.test/",
                allow_origins=["https://page.test"],
                timeout_ms=1_000,
                origin_ip_pins={"https://page.test": "1.1.1.1"},
            )
        assert isinstance(caught.value.__cause__, PlaywrightFailure)
        notes = getattr(caught.value.__cause__, "__notes__", [])
        if failure_kind == "playwright-cleanup-failure":
            assert notes == ["rejected-render cleanup router-finish-abort failed with LookupError"]
        elif failure_kind == "playwright-browser-close-failure":
            assert notes == [
                "browser-discovery cleanup browser-close failed with LookupError"
            ]
        else:
            assert notes == []
    elif failure_kind == "keyboard-interrupt":
        with pytest.raises(KeyboardInterrupt) as caught:
            discover_page(
                "https://page.test/",
                allow_origins=["https://page.test"],
                timeout_ms=1_000,
                origin_ip_pins={"https://page.test": "1.1.1.1"},
            )
        assert caught.value is keyboard_primary
        assert getattr(caught.value, "__notes__", []) == [
            "browser-discovery cleanup browser-close failed with LookupError"
        ]
    elif failure_kind in {"router-start-setup-failure", "partial-guard-start"}:
        expected = (
            "synthetic router setup failure"
            if failure_kind == "router-start-setup-failure"
            else "synthetic partial guard start"
        )
        with pytest.raises(SetupFailure, match=expected):
            discover_page(
                "https://page.test/",
                allow_origins=["https://page.test"],
                timeout_ms=1_000,
                origin_ip_pins={"https://page.test": "1.1.1.1"},
            )
    elif failure_kind == "normal-shutdown-guard-failure":
        with pytest.raises(ShutdownFailure, match="synthetic guard shutdown failure"):
            discover_page(
                "https://page.test/",
                allow_origins=["https://page.test"],
                timeout_ms=1_000,
                origin_ip_pins={"https://page.test": "1.1.1.1"},
            )
    elif failure_kind == "egress-priority":
        with pytest.raises(NonReplayableEgressPolicyError):
            discover_page(
                "https://page.test/",
                allow_origins=["https://page.test"],
                timeout_ms=1_000,
                origin_ip_pins={"https://page.test": "1.1.1.1"},
            )
        assert router_post_close_checks == [0]
    else:
        assert failure_kind == "router-priority"
        with pytest.raises(CdpTargetIntegrityError, match="synthetic retained router failure"):
            discover_page(
                "https://page.test/",
                allow_origins=["https://page.test"],
                timeout_ms=1_000,
                origin_ip_pins={"https://page.test": "1.1.1.1"},
            )
        assert router_post_close_checks == [1]
    assert browser.context.closed is True
    assert browser.closed is True
    if failure_kind == "normal-shutdown-guard-failure":
        assert lifecycle == [
            "router-start",
            "guard-start",
            "router-begin-shutdown",
            "guard-begin-shutdown",
            "context-close",
            "browser-close",
        ]
    elif failure_kind == "router-start-setup-failure":
        assert lifecycle == [
            "router-start",
            "context-close",
            "browser-close",
        ]
    else:
        assert lifecycle == [
            "router-start",
            "guard-start",
            "router-begin-abort",
            "guard-begin-abort",
            "context-close",
            "guard-finish-abort",
            "router-finish-abort",
            "browser-close",
        ]


def test_post_cutoff_network_occurrence_cannot_enter_an_accepted_graph() -> None:
    clock = _PassiveClock()
    audit = _SanitizedEventProjection(clock_ns=clock.nanoseconds)
    source = CdpTargetSource((), "page", "page")
    request = {
        "requestId": "first",
        "request": {"method": "GET", "url": "https://page.test/"},
        "type": "Document",
    }
    event = audit.record_network(source, request)
    event["mapping"] = {"kind": "resource", "resource_id": 0}
    fetch = audit.record_fetch(
        source,
        {
            "requestId": "fetch-first",
            "networkId": "first",
            "request": request["request"],
        },
        decision="continue",
        reason=None,
    )
    fetch["network_occurrence_id"] = event["occurrence_id"]
    fetch["relationship"] = "primary"
    audit.record_terminal(
        source,
        {"requestId": "first"},
        outcome="finished",
        occurrence_ids=[event["occurrence_id"]],
    )
    audit.freeze()
    late = audit.record_network(
        source,
        {
            "requestId": "late",
            "request": {"method": "GET", "url": "https://page.test/late"},
            "type": "Script",
        },
    )
    late["mapping"] = {"kind": "resource", "resource_id": 1}
    render = {
        "schema_version": RENDER_OBSERVATION_SCHEMA_VERSION,
        "clock": "monotonic-relative-ms",
        "navigation_started_ms": 0,
        "load_event_ms": 0,
        "last_relevant_event_ms": 0,
        "quiet_started_ms": 10_000,
        "cutoff_ms": 13_000,
        "active_request_ids": [],
        "active_request_count": 0,
        "router_shutdown_ready": True,
        "bootstrap_prearm_summary": _bootstrap_prearm_summary(),
        "egress_prearm_summary": {
            **_egress_prearm_summary(),
            "by_target_type": {
                **_egress_prearm_summary()["by_target_type"],
                "page": {
                    **_egress_prearm_summary()["by_target_type"]["page"],
                    "protected_api_observations": len(target_egress_apis("page")),
                },
            },
        },
        "non_replayable_egress_summary": _successful_egress_guard().success_summary(),
        "browser_context_service_worker_count": 0,
        "cutoff_reason": "quiescent",
    }
    resources = [
        {"id": 0, "url": "https://page.test/", "type": "Document", "depends_on": []},
        {
            "id": 1,
            "url": "https://page.test/late",
            "type": "Script",
            "depends_on": [],
        },
    ]
    with pytest.raises(ValueError, match="map every retained resource"):
        audit.build(
            instrumentation_policy=discover_module.CDP_TARGET_INSTRUMENTATION_POLICY,
            render_observation=render,
            resources=resources,
            exclusions=[],
            approved_origins=["https://page.test"],
            observed_origins=["https://page.test"],
            observed_request_count=2,
        )


def test_initiator_stack_recurses_and_dependency_resolution_is_latest_scoped() -> None:
    assert _stack_frame_urls(
        {
            "callFrames": [{"url": "https://page.test/current.js"}],
            "parent": {
                "callFrames": [{"url": "https://page.test/parent.js"}],
                "parent": {"callFrames": [{"url": "https://page.test/root.js"}]},
            },
        }
    ) == [
        "https://page.test/current.js",
        "https://page.test/parent.js",
        "https://page.test/root.js",
    ]
    source = CdpTargetSource((), "page", "page")
    occurrences = [
        _DependencyOccurrence(source, "root-frame", "https://page.test/app.js", 0),
        _DependencyOccurrence(source, "root-frame", "https://page.test/app.js", 2),
        _DependencyOccurrence(source, "other-frame", "https://page.test/app.js", 3),
    ]
    assert (
        _resolve_dependency_url(
            occurrences,
            source=source,
            scope="root-frame",
            url="https://page.test/app.js",
        )
        == 2
    )


def test_cdp_header_merge_is_case_insensitive_and_extra_info_wins():
    headers: dict[str, str] = {}

    merge_request_headers(
        headers,
        {"User-Agent": "request-will-be-sent", "ACCEPT": "*/*"},
    )
    merge_request_headers(
        headers,
        {"user-agent": "extra-info", "Accept": "text/html"},
    )

    assert headers == {"user-agent": "extra-info", "accept": "text/html"}


def test_cdp_extra_info_is_fifo_across_redirect_request_id_reuse():
    first = DiscoveredRequest("https://page.test/old", "Document", {"accept": "first-base"})
    second = DiscoveredRequest("https://page.test/new", "Document", {"accept": "second-base"})
    association = _RequestExtraInfoAssociator()

    association.add_request("redirect-chain", first, redirected=False)
    # Chromium may announce the successor before delivering its predecessor's
    # ExtraInfo. A latest-index map would attach this first header to `second`.
    association.add_request(
        "redirect-chain",
        second,
        redirected=True,
        redirect_has_extra_info=True,
    )
    association.add_extra_info("redirect-chain", {"Accept": "first-wire"})
    association.add_response("redirect-chain", True)
    association.add_extra_info("redirect-chain", {"Accept": "second-wire"})
    association.add_terminal("redirect-chain", failed=False)
    association.finish()

    assert first.headers == {"accept": "first-wire"}
    assert second.headers == {"accept": "second-wire"}


def test_cdp_extra_info_same_raw_id_is_isolated_across_target_sessions():
    iframe = DiscoveredRequest("https://frame.test/data", "Fetch", {})
    worker = DiscoveredRequest("https://worker.test/data", "Fetch", {})
    iframe_source = CdpTargetSource(("iframe-session",), "iframe-target")
    worker_source = CdpTargetSource(("worker-session",), "worker-target")
    association = _RequestExtraInfoAssociator()

    iframe_key = iframe_source.request_chain_key("duplicate")
    worker_key = worker_source.request_chain_key("duplicate")
    association.add_request(iframe_key, iframe, redirected=False)
    association.add_request(worker_key, worker, redirected=False)
    association.add_response(worker_key, True)
    association.add_extra_info(worker_key, {"Accept": "worker-wire"})
    association.add_response(iframe_key, True)
    association.add_extra_info(iframe_key, {"Accept": "iframe-wire"})
    association.add_terminal(worker_key, failed=False)
    association.add_terminal(iframe_key, failed=False)
    association.finish()

    assert iframe.headers == {"accept": "iframe-wire"}
    assert worker.headers == {"accept": "worker-wire"}


def test_cdp_extra_info_skips_a_redirect_occurrence_declared_without_it():
    first = DiscoveredRequest("https://page.test/old", "Document", {})
    second = DiscoveredRequest("https://page.test/new", "Document", {})
    association = _RequestExtraInfoAssociator()

    association.add_request("redirect-chain", first, redirected=False)
    # The successor's ExtraInfo may precede requestWillBeSent. The redirect flag
    # inserts a deterministic gap for the predecessor before it is associated.
    association.add_extra_info("redirect-chain", {"Accept": "second-wire"})
    association.add_request(
        "redirect-chain",
        second,
        redirected=True,
        redirect_has_extra_info=False,
    )
    association.add_response("redirect-chain", True)
    association.add_terminal("redirect-chain", failed=False)
    association.finish()

    assert first.headers == {}
    assert second.headers == {"accept": "second-wire"}


def test_cdp_extra_info_completion_rejects_missing_and_unmatched_events():
    missing = _RequestExtraInfoAssociator()
    missing.add_request(
        "missing", DiscoveredRequest("https://page.test/", "Document", {}), redirected=False
    )
    missing.add_response("missing", True)
    missing.add_terminal("missing", failed=False)
    with pytest.raises(RuntimeError, match="declared but did not deliver"):
        missing.finish()

    unmatched = _RequestExtraInfoAssociator()
    unmatched.add_extra_info("unmatched", {"Accept": "orphan"})
    with pytest.raises(RuntimeError, match="could not be associated"):
        unmatched.finish()


def test_cdp_extra_info_completion_resolves_one_unflagged_failed_final_request():
    request = DiscoveredRequest("https://page.test/fails", "Script", {})
    association = _RequestExtraInfoAssociator()
    association.add_request("failed", request, redirected=False)
    association.add_extra_info("failed", {"Accept": "wire-before-failure"})
    association.add_terminal("failed", failed=True)

    # CDP can omit responseReceived (and its hasExtraInfo flag) on failure.
    association.finish()

    assert request.headers == {"accept": "wire-before-failure"}


def test_cdp_extra_info_rejects_success_without_response_metadata():
    association = _RequestExtraInfoAssociator()
    association.add_request(
        "successful",
        DiscoveredRequest("https://page.test/succeeds", "Script", {}),
        redirected=False,
    )
    association.add_terminal("successful", failed=False)

    with pytest.raises(RuntimeError, match="omitted response ExtraInfo metadata"):
        association.finish()
