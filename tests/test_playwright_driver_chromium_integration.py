"""Opt-in real-Chromium concurrency check for the pinned Playwright driver."""

from __future__ import annotations

import os
import runpy
import threading
import time
from collections.abc import Iterator, Mapping
from concurrent.futures import Future, ThreadPoolExecutor, wait
from pathlib import Path
from typing import Any

import pytest

from qcsd_lab.browser_egress import (
    BROWSER_EGRESS_EXPLICIT_BARE_CHROMIUM_ARGS,
    BROWSER_EGRESS_SUBPROCESS_WRAPPER_ARGUMENT,
    NonReplayableEgressGuard,
    install_context_egress_guards,
    launch_pinned_cdp_probe_browser,
)
from qcsd_lab.browser_egress_fixture import (
    FIXTURE_CERTIFICATE,
    FIXTURE_PRIVATE_KEY,
    _FixtureHttpServer,
    browser_action_expression,
    dedicated_worker_action_bridge_expression,
    dedicated_worker_action_message,
    dedicated_worker_ready_bridge_expression,
    execute_live_browser_action,
    expected_fetch_denial_observations,
    expected_fixture_requests,
    vector_by_id,
)
from qcsd_lab.cdp_targets import (
    _ERROR_DOCUMENT_RESOURCE_SIGNATURES,
    BrowserSharedWorkerGuard,
    CdpTargetSource,
    RecursiveCdpTargetRouter,
)
from qcsd_lab.playwright_driver import (
    EXPECTED_CHROMIUM_VERSION,
    OWNERSHIP_MARKER_NAME,
    chromium_child_environment,
    pinned_chromium_executable_path,
    playwright_driver_session,
    validate_default_playwright_driver_once,
)

pytestmark = pytest.mark.skipif(
    os.environ.get("QCSD_RUN_PINNED_CDP_PROBE") != "1",
    reason="set QCSD_RUN_PINNED_CDP_PROBE=1 inside the prepare image",
)

_DIRECT_CHROMIUM_ARGS = (
    "--no-sandbox",
    *BROWSER_EGRESS_EXPLICIT_BARE_CHROMIUM_ARGS,
    BROWSER_EGRESS_SUBPROCESS_WRAPPER_ARGUMENT,
    "--site-per-process",
)


def _set_http_credentials_via_protocol(
    context: Any,
    credentials: Mapping[str, str] | None,
) -> None:
    """Exercise the pinned driver mutation boundary absent from Python's API."""

    parameters = (
        {} if credentials is None else {"httpCredentials": dict(credentials)}
    )
    context._sync(
        context._impl_obj._channel.send(
            "setHTTPCredentials",
            None,
            parameters,
        )
    )


@pytest.fixture
def dedicated_worker_http_fixture() -> Iterator[tuple[str, _FixtureHttpServer]]:
    """Serve the production dedicated-worker bytes from one loopback origin."""

    vector = vector_by_id("constructor--dedicated-worker--webtransport")
    server = _FixtureHttpServer(("127.0.0.1", 0), "primary", None, vector)
    server.daemon_threads = True
    thread = threading.Thread(
        target=server.serve_forever,
        name="qcsd-dedicated-worker-integration-fixture",
        daemon=True,
    )
    thread.start()
    try:
        yield f"http://localhost:{server.server_port}", server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive()


@pytest.fixture
def named_frame_http_fixture() -> Iterator[tuple[str, _FixtureHttpServer]]:
    """Serve the exact named-frame vector from one approved loopback origin."""

    vector = vector_by_id("popup--page--window-open-existing-named-frame")
    server = _FixtureHttpServer(("127.0.0.1", 0), "primary", None, vector)
    server.daemon_threads = True
    thread = threading.Thread(
        target=server.serve_forever,
        name="qcsd-named-frame-integration-fixture",
        daemon=True,
    )
    thread.start()
    try:
        yield f"http://localhost:{server.server_port}", server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive()


def test_five_overlapping_mixed_ownership_browser_lifetimes() -> None:
    """Prove one exclusive and four native drivers can overlap without leakage."""

    from playwright.sync_api import sync_playwright

    validate_default_playwright_driver_once()
    original_marker = os.environ.get(OWNERSHIP_MARKER_NAME)
    assert original_marker in (None, "1")

    worker_count = 5
    all_browsers_started = threading.Barrier(worker_count)
    all_sessions_observed = threading.Barrier(worker_count)

    def run_browser(index: int) -> tuple[int, bool, str, bool, bool]:
        exclusive = index == 0
        disconnected = threading.Event()
        with playwright_driver_session(sync_playwright, exclusive=exclusive) as playwright:
            browser = playwright.chromium.launch(
                executable_path=pinned_chromium_executable_path(),
                headless=True,
                args=list(_DIRECT_CHROMIUM_ARGS),
                env=chromium_child_environment(),
            )
            browser.on("disconnected", lambda: disconnected.set())
            try:
                assert browser.version == EXPECTED_CHROMIUM_VERSION
                context = browser.new_context(service_workers="block")
                try:
                    page = context.new_page()
                    page.set_default_timeout(15_000)
                    page.set_content(f"<title>qcsd-{index}</title>")
                    assert page.title() == f"qcsd-{index}"
                    attached_workers = []
                    page.on("worker", lambda worker: attached_workers.append(worker))
                    assert browser.is_connected()
                    all_browsers_started.wait(timeout=90)
                    assert browser.is_connected()

                    # Without the QCSD router, the filtered exclusive driver must
                    # leave this wait-for-debugger worker paused and must not expose
                    # a Playwright Worker object.  Every inactive driver must retain
                    # Playwright's native attachment and resume the same script.
                    worker_result = page.evaluate(
                        """
                        async () => {
                          const source = new Blob(
                            ["postMessage('native')"],
                            {type: 'text/javascript'}
                          );
                          const workerUrl = URL.createObjectURL(source);
                          const worker = new Worker(workerUrl);
                          try {
                            return await Promise.race([
                              new Promise(resolve => {
                                worker.onmessage = event => resolve(event.data);
                                worker.onerror = () => resolve('worker-error');
                              }),
                              new Promise(resolve => {
                                setTimeout(() => resolve('worker-timeout'), 5000);
                              }),
                            ]);
                          } finally {
                            worker.terminate();
                            URL.revokeObjectURL(workerUrl);
                          }
                        }
                        """
                    )
                    assert worker_result == ("worker-timeout" if exclusive else "native")
                    assert len(attached_workers) == (0 if exclusive else 1)
                    playwright_owned_worker = bool(attached_workers)

                    all_sessions_observed.wait(timeout=90)
                    assert browser.is_connected()
                finally:
                    context.close()
            finally:
                browser.close()
            assert disconnected.wait(timeout=10)
            assert not browser.is_connected()
        return (
            index,
            exclusive,
            worker_result,
            playwright_owned_worker,
            disconnected.is_set(),
        )

    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        futures = [executor.submit(run_browser, index) for index in range(worker_count)]

        def abort_peer_barriers_after_failure(
            completed: Future[tuple[int, bool, str, bool, bool]],
        ) -> None:
            if not completed.cancelled() and completed.exception() is not None:
                all_browsers_started.abort()
                all_sessions_observed.abort()

        for future in futures:
            future.add_done_callback(abort_peer_barriers_after_failure)
        done, not_done = wait(futures, timeout=120)
        assert not not_done, "mixed-ownership browser workers did not terminate"
        failures = [
            (index, repr(future.exception()))
            for index, future in enumerate(futures)
            if future.exception() is not None
        ]
        assert not failures, f"mixed-ownership browser workers failed: {failures}"
        assert done == set(futures)
        results = [future.result() for future in futures]

    assert os.environ.get(OWNERSHIP_MARKER_NAME) == original_marker
    assert results == [
        (0, True, "worker-timeout", False, True),
        (1, False, "native", True, True),
        (2, False, "native", True, True),
        (3, False, "native", True, True),
        (4, False, "native", True, True),
    ]


def test_exclusive_dedicated_worker_bridge_uses_recursive_cdp_ownership(
    dedicated_worker_http_fixture: tuple[str, _FixtureHttpServer],
) -> None:
    """Run the exact worker bridge while Playwright remains excluded from its target."""

    from playwright.sync_api import sync_playwright

    validate_default_playwright_driver_once()
    origin, fixture_server = dedicated_worker_http_fixture
    root_url = f"{origin}/"
    worker_url = f"{origin}/dedicated-worker.js"
    allowed_urls = {root_url, worker_url}
    fetch_urls: list[str] = []
    denied_urls: list[str] = []
    guard_events: list[tuple[str | None, str, str, object | None]] = []
    attached_workers: list[object] = []
    disconnected = threading.Event()

    with playwright_driver_session(sync_playwright, exclusive=True) as playwright:
        browser, _command_line = launch_pinned_cdp_probe_browser(
            playwright,
            approved_origins=(origin,),
            origin_ip_pins={origin: "127.0.0.1"},
        )
        browser.on("disconnected", lambda: disconnected.set())
        context = None
        context_closed = False
        try:
            browser_session = browser.new_browser_cdp_session()
            context = browser.new_context(service_workers="block")
            egress_guard = NonReplayableEgressGuard()
            install_context_egress_guards(context, egress_guard)
            page = context.new_page()
            egress_guard.bind_root_page(page)
            page.set_default_timeout(15_000)
            page.on("worker", lambda worker: attached_workers.append(worker))
            session = context.new_cdp_session(page)

            router: RecursiveCdpTargetRouter

            def on_event(
                source: CdpTargetSource,
                method: str,
                payload: Mapping[str, object],
            ) -> None:
                if method != "Fetch.requestPaused":
                    return
                request = payload.get("request")
                url = request.get("url") if isinstance(request, Mapping) else None
                request_id = payload.get("requestId")
                if not isinstance(url, str) or not isinstance(request_id, str):
                    raise TypeError("dedicated-worker integration Fetch event is malformed")
                fetch_urls.append(url)
                if url in allowed_urls:
                    router.send(
                        source,
                        "Fetch.continueRequest",
                        {"requestId": request_id},
                        label="dedicated-worker-integration-allow",
                    )
                else:
                    denied_urls.append(url)
                    router.send(
                        source,
                        "Fetch.failRequest",
                        {"requestId": request_id, "errorReason": "BlockedByClient"},
                        label="dedicated-worker-integration-deny",
                    )

            def record_non_replayable_egress(
                source: CdpTargetSource | None,
                api: str,
                mechanism: str,
                url: object | None,
            ) -> None:
                guard_events.append(
                    (source.target_type if source is not None else None, api, mechanism, url)
                )
                egress_guard.record(source=source, api=api, mechanism=mechanism, url=url)

            router = RecursiveCdpTargetRouter(
                session,
                on_event=on_event,
                on_non_replayable_egress=record_non_replayable_egress,
            )
            router.start()
            browser_guard = BrowserSharedWorkerGuard(browser_session, router)
            browser_guard.start()

            page.goto(root_url, wait_until="load")
            assert page.evaluate(dedicated_worker_ready_bridge_expression(), worker_url) is True

            deadline = time.monotonic() + 10
            while not router.shutdown_ready:
                router.raise_if_failed()
                if time.monotonic() >= deadline:
                    raise TimeoutError("dedicated-worker integration prearm did not converge")
                page.wait_for_timeout(10)

            vector = vector_by_id("constructor--dedicated-worker--webtransport")
            message = dedicated_worker_action_message(vector)
            raw = page.evaluate(dedicated_worker_action_bridge_expression(), message)
            router.raise_if_failed()

            assert message["expression"] == browser_action_expression()
            assert raw == {
                "resolved_type": "function",
                "own_descriptor": "data",
                "action_issued": True,
                "action_succeeded": False,
                "exception_name": "TypeError",
            }
            assert egress_guard.attempt_count == 1
            assert guard_events == [("worker", "WebTransport", "paused-target-runtime-shim", None)]
            assert attached_workers == []
            assert denied_urls == []
            assert worker_url in fetch_urls
            with fixture_server.request_lock:
                fixture_requests = dict(fixture_server.request_counts)
            assert fixture_requests == {"/": 1, "/dedicated-worker.js": 1}
            worker_prearm = router.egress_prearm_summary["by_target_type"]["worker"]
            assert worker_prearm["target_count"] == 1
            assert worker_prearm["installed_count"] == 1
            assert worker_prearm["pending_count"] == 0
            assert router.egress_prearm_summary["pending_total"] == 0
            assert router.bootstrap_prearm_summary["pending_total"] == 0
            assert router.shutdown_ready is True

            router.begin_shutdown()
            browser_guard.begin_shutdown()
            context.close()
            context_closed = True
            browser_guard.finish()
            router.finish()
        finally:
            if context is not None and not context_closed:
                context.close()
            browser.close()

    assert disconnected.wait(timeout=10)


def test_named_frame_block_accepts_only_pinned_chromium_error_document_finish(
    named_frame_http_fixture: tuple[str, _FixtureHttpServer],
) -> None:
    """Bind M143's failed-navigation/error-document lifecycle to the router."""

    from playwright.sync_api import sync_playwright

    validate_default_playwright_driver_once()
    vector = vector_by_id("popup--page--window-open-existing-named-frame")
    origin, fixture_server = named_frame_http_fixture
    forbidden_url = expected_fetch_denial_observations(vector)[0]["url"]
    fetch_denials: list[dict[str, str]] = []
    forbidden_network_ids: list[str] = []
    raw_action_lifecycle: list[tuple[str, dict[str, object]]] = []
    record_action_lifecycle = [False]
    routed_action_lifecycle: list[
        tuple[CdpTargetSource, str, dict[str, object]]
    ] = []
    browser = None
    context = None
    context_closed = False

    with playwright_driver_session(sync_playwright, exclusive=True) as playwright:
        try:
            browser, _command_line = launch_pinned_cdp_probe_browser(
                playwright,
                approved_origins=(origin,),
                origin_ip_pins={origin: "127.0.0.1"},
            )
            browser_session = browser.new_browser_cdp_session()
            context = browser.new_context(service_workers="block")
            egress_guard = NonReplayableEgressGuard()
            install_context_egress_guards(context, egress_guard)
            page = context.new_page()
            egress_guard.bind_root_page(page)
            page.set_default_timeout(15_000)
            session = context.new_cdp_session(page)

            def record_raw(
                method: str,
                payload: Mapping[str, object],
            ) -> None:
                if not record_action_lifecycle[0]:
                    return
                raw_action_lifecycle.append((method, dict(payload)))
                if method != "Network.requestWillBeSent":
                    return
                request = payload.get("request")
                if isinstance(request, Mapping) and request.get("url") == forbidden_url:
                    request_id = payload.get("requestId")
                    if not isinstance(request_id, str) or not request_id:
                        raise TypeError("named-frame Network request ID is malformed")
                    forbidden_network_ids.append(request_id)

            for raw_method in (
                "Network.requestWillBeSent",
                "Fetch.requestPaused",
                "Network.loadingFailed",
                "Network.loadingFinished",
                "Network.requestServedFromCache",
                "Network.responseReceived",
            ):
                session.on(
                    raw_method,
                    lambda payload, method=raw_method: record_raw(method, payload),
                )

            router: RecursiveCdpTargetRouter

            def on_event(
                source: CdpTargetSource,
                method: str,
                payload: Mapping[str, object],
            ) -> None:
                if record_action_lifecycle[0]:
                    routed_action_lifecycle.append((source, method, dict(payload)))
                request = payload.get("request")
                url = request.get("url") if isinstance(request, Mapping) else None
                request_id = payload.get("requestId")
                if method == "Network.requestWillBeSent" and url == forbidden_url:
                    return
                if (
                    method == "Network.loadingFailed"
                    and request_id in forbidden_network_ids
                ):
                    return
                if method != "Fetch.requestPaused":
                    return
                request_method = request.get("method") if isinstance(request, Mapping) else None
                if not all(isinstance(item, str) for item in (url, request_method, request_id)):
                    raise TypeError("named-frame integration Fetch event is malformed")
                assert isinstance(url, str)
                assert isinstance(request_method, str)
                assert isinstance(request_id, str)
                if url.startswith(f"{origin}/"):
                    router.send(
                        source,
                        "Fetch.continueRequest",
                        {"requestId": request_id},
                        label="named-frame-integration-allow",
                    )
                    return
                fetch_denials.append({"url": url, "method": request_method})
                router.send(
                    source,
                    "Fetch.failRequest",
                    {"requestId": request_id, "errorReason": "BlockedByClient"},
                    label="named-frame-integration-deny",
                )

            router = RecursiveCdpTargetRouter(
                session,
                on_event=on_event,
                on_non_replayable_egress=lambda source, api, mechanism, url: egress_guard.record(
                    source=source,
                    api=api,
                    mechanism=mechanism,
                    url=url,
                ),
            )
            router.start()
            browser_guard = BrowserSharedWorkerGuard(browser_session, router)
            browser_guard.start()
            page.goto(f"{origin}/", wait_until="load")
            assert page.evaluate(
                """url => new Promise((resolve, reject) => {
                  const frame = document.createElement('iframe');
                  frame.name = 'qcsd-egress-popup-v1';
                  frame.onload = () => resolve(true);
                  frame.onerror = () => reject(new Error('named frame failed to load'));
                  frame.src = url;
                  document.body.append(frame);
                })""",
                f"{origin}/frame",
            ) is True

            deadline = time.monotonic() + 10
            while not router.shutdown_ready:
                router.raise_if_failed()
                if time.monotonic() >= deadline:
                    raise TimeoutError("named-frame integration prearm did not converge")
                page.wait_for_timeout(10)

            realm_type = runpy.run_path(
                str(Path(__file__).parents[1] / "tools/browser_egress_qualification.py"),
                run_name="qcsd_named_frame_chromium_integration",
            )["_PlaywrightRealm"]
            realm = realm_type(
                evaluator=page,
                page=page,
                guard=egress_guard,
                fetch_denials=fetch_denials,
                router=router,
                prearmed=True,
                command_line_projection={},
                child_environment={},
            )
            record_action_lifecycle[0] = True
            actor = execute_live_browser_action(vector=vector, realm=realm)

            deadline = time.monotonic() + 10
            while True:
                router.raise_if_failed()
                internal_requests = [
                    payload
                    for method, payload in raw_action_lifecycle
                    if method == "Network.requestWillBeSent"
                    and isinstance(payload.get("request"), Mapping)
                    and str(payload["request"].get("url", "")).startswith(
                        "data:image/png;base64,"
                    )
                ]
                internal_ids = {
                    payload["requestId"]
                    for payload in internal_requests
                    if isinstance(payload.get("requestId"), str)
                }
                internal_finishes = [
                    payload
                    for method, payload in raw_action_lifecycle
                    if method == "Network.loadingFinished"
                    and payload.get("requestId") in internal_ids
                ]
                document_terminals = [
                    payload
                    for method, payload in raw_action_lifecycle
                    if method in {"Network.loadingFailed", "Network.loadingFinished"}
                    and payload.get("requestId") in forbidden_network_ids
                ]
                if (
                    len(internal_requests) == 3
                    and len(internal_ids) == 3
                    and len(internal_finishes) == 3
                    and len(document_terminals) == 2
                    and not router.active_request_identities
                    and router.shutdown_ready
                ):
                    break
                if time.monotonic() >= deadline:
                    raise TimeoutError("named-frame terminal lifecycle did not converge")
                page.wait_for_timeout(10)
            router.raise_if_failed()

            assert forbidden_network_ids and len(set(forbidden_network_ids)) == 1
            document_id = forbidden_network_ids[0]
            internal_ids_in_order = [payload["requestId"] for payload in internal_requests]
            relevant_raw = [
                (method, payload)
                for method, payload in raw_action_lifecycle
                if payload.get("requestId") in {document_id, *internal_ids_in_order}
                or payload.get("networkId") == document_id
            ]
            assert [method for method, _payload in relevant_raw] == [
                "Network.requestWillBeSent",
                "Fetch.requestPaused",
                "Network.loadingFailed",
                "Network.loadingFinished",
                "Network.requestWillBeSent",
                "Network.requestServedFromCache",
                "Network.responseReceived",
                "Network.loadingFinished",
                "Network.requestWillBeSent",
                "Network.requestServedFromCache",
                "Network.responseReceived",
                "Network.loadingFinished",
                "Network.requestWillBeSent",
                "Network.requestServedFromCache",
                "Network.responseReceived",
                "Network.loadingFinished",
            ]
            assert _ERROR_DOCUMENT_RESOURCE_SIGNATURES == (
                (
                    4026,
                    "98da97a017b2bd58cb9851bda86d9634cee3a573f4e210a384926eddaf3cb692",
                    624,
                ),
                (
                    6366,
                    "ea2294b4439707e90c81be91f46f2e4399d1f0f9ef67a0abbb2e513acf0e9632",
                    624,
                ),
                (
                    230,
                    "3b99d5fc9d5cbfc903dc91de38fe13a68a643a816014921c83c9dcffcbffc642",
                    625,
                ),
            )
            internal_urls = [payload["request"]["url"] for payload in internal_requests]
            assert [
                RecursiveCdpTargetRouter._error_document_resource_signature(url)
                for url in internal_urls
            ] == [(0, 4026), (1, 6366), (2, 230)]

            raw_terminals = [
                (method, payload)
                for method, payload in relevant_raw
                if method in {"Network.loadingFailed", "Network.loadingFinished"}
                and payload.get("requestId") == document_id
            ]
            failed = raw_terminals[0][1]
            finished = raw_terminals[1][1]
            assert set(failed) == {
                "requestId",
                "timestamp",
                "type",
                "errorText",
                "canceled",
                "blockedReason",
            }
            assert failed == {
                "requestId": forbidden_network_ids[0],
                "timestamp": failed["timestamp"],
                "type": "Document",
                "errorText": "net::ERR_BLOCKED_BY_CLIENT",
                "canceled": False,
                "blockedReason": "inspector",
            }
            assert set(finished) == {"requestId", "timestamp", "encodedDataLength"}
            assert finished["requestId"] == forbidden_network_ids[0]
            assert isinstance(failed["timestamp"], (int, float))
            assert isinstance(finished["timestamp"], (int, float))
            assert finished["timestamp"] > failed["timestamp"]
            assert isinstance(finished["encodedDataLength"], (int, float))
            assert finished["encodedDataLength"] > 0
            routed_document_events = [
                (source, method, payload)
                for source, method, payload in routed_action_lifecycle
                if payload.get("requestId") == document_id
                or payload.get("networkId") == document_id
            ]
            assert [method for _source, method, _payload in routed_document_events] == [
                "Network.requestWillBeSent",
                "Fetch.requestPaused",
                "Network.loadingFailed",
            ]
            assert all(
                source == router.root_source
                for source, _method, _payload in routed_document_events
            )
            assert not [
                (method, payload)
                for _source, method, payload in routed_action_lifecycle
                if payload.get("requestId") in internal_ids
                or payload.get("networkId") in internal_ids
            ]
            assert fetch_denials == expected_fetch_denial_observations(vector)
            assert actor["measurement"]["fetch_denials"] == fetch_denials
            assert actor["measurement"]["fetch_denial_count"] == 1
            assert actor["measurement"]["action_issued"] is True
            assert actor["measurement"]["action_succeeded"] is True
            assert egress_guard.attempt_count == 0
            with fixture_server.request_lock:
                fixture_requests = {
                    f"primary:{path}": count
                    for path, count in fixture_server.request_counts.items()
                }
            assert fixture_requests == expected_fixture_requests(vector)
            assert router.shutdown_ready is True

            router.begin_shutdown()
            browser_guard.begin_shutdown()
            context.close()
            context_closed = True
            browser_guard.finish()
            router.finish()
        finally:
            if context is not None and not context_closed:
                context.close()
            if browser is not None and browser.is_connected():
                browser.close()


@pytest.mark.parametrize("surface", ["trusted-anchor-ping", "legacy-csp-report"])
@pytest.mark.parametrize("document_context", ["page", "same-origin-frame", "cross-origin-frame"])
def test_url_loader_suppression_and_csp_report_in_each_document_context(
    document_context: str, surface: str
) -> None:
    """Prove M143 suppresses audit pings and exposes only a blocked script's CSP report."""

    from playwright.sync_api import sync_playwright

    validate_default_playwright_driver_once()
    vector = vector_by_id(f"urlloader--{document_context}--{surface}")
    primary_server = _FixtureHttpServer(("127.0.0.1", 0), "primary", None, vector)
    cross_server = _FixtureHttpServer(("127.0.0.1", 0), "cross", None, vector)
    for server in (primary_server, cross_server):
        server.daemon_threads = True
    fixture_threads = [
        threading.Thread(
            target=server.serve_forever,
            name=f"qcsd-csp-integration-{role}",
            daemon=True,
        )
        for role, server in (("primary", primary_server), ("cross", cross_server))
    ]
    for thread in fixture_threads:
        thread.start()
    primary = f"http://localhost:{primary_server.server_port}"
    cross = f"http://localhost:{cross_server.server_port}"
    approved_origins = (primary, cross)
    denied_requests: list[dict[str, str]] = []
    browser = None
    context = None
    router = None
    browser_guard = None
    context_closed = False
    try:
        with playwright_driver_session(sync_playwright, exclusive=True) as playwright:
            browser, _command_line = launch_pinned_cdp_probe_browser(
                playwright,
                approved_origins=approved_origins,
                origin_ip_pins={origin: "127.0.0.1" for origin in approved_origins},
            )
            browser_session = browser.new_browser_cdp_session()
            context = browser.new_context(service_workers="block")
            egress_guard = NonReplayableEgressGuard()
            install_context_egress_guards(context, egress_guard)
            page = context.new_page()
            egress_guard.bind_root_page(page)
            session = context.new_cdp_session(page)

            def on_event(
                source: CdpTargetSource,
                method: str,
                payload: Mapping[str, object],
            ) -> None:
                if method != "Fetch.requestPaused":
                    return
                request = payload.get("request")
                url = request.get("url") if isinstance(request, Mapping) else None
                request_method = request.get("method") if isinstance(request, Mapping) else None
                request_id = payload.get("requestId")
                if not all(isinstance(item, str) for item in (url, request_method, request_id)):
                    raise TypeError("CSP integration Fetch event is malformed")
                assert isinstance(url, str)
                assert isinstance(request_method, str)
                assert isinstance(request_id, str)
                if any(url.startswith(f"{origin}/") for origin in approved_origins):
                    router.send(
                        source,
                        "Fetch.continueRequest",
                        {"requestId": request_id},
                        label="csp-integration-allow",
                    )
                    return
                denied_requests.append({"url": url, "method": request_method})
                router.send(
                    source,
                    "Fetch.failRequest",
                    {"requestId": request_id, "errorReason": "BlockedByClient"},
                    label="csp-integration-deny",
                )

            router = RecursiveCdpTargetRouter(
                session,
                on_event=on_event,
                on_non_replayable_egress=lambda source, api, mechanism, url: egress_guard.record(
                    source=source, api=api, mechanism=mechanism, url=url
                ),
            )
            router.start()
            browser_guard = BrowserSharedWorkerGuard(browser_session, router)
            browser_guard.start()
            page.goto(f"{primary}/", wait_until="load")
            evaluator = page
            if document_context != "page":
                frame_origin = primary if document_context == "same-origin-frame" else cross
                with page.expect_event("framenavigated"):
                    handle = page.evaluate_handle(
                        "url => { const frame=document.createElement('iframe'); frame.src=url; "
                        "document.body.append(frame); return frame; }",
                        f"{frame_origin}/frame",
                    )
                element = handle.as_element()
                assert element is not None
                evaluator = element.content_frame()
                assert evaluator is not None

            deadline = time.monotonic() + 10
            while not router.shutdown_ready:
                router.raise_if_failed()
                if time.monotonic() >= deadline:
                    raise TimeoutError("CSP integration prearm did not converge")
                page.wait_for_timeout(10)

            realm_type = runpy.run_path(
                str(Path(__file__).parents[1] / "tools/browser_egress_qualification.py"),
                run_name="qcsd_browser_egress_chromium_integration",
            )["_PlaywrightRealm"]
            realm = realm_type(
                evaluator=evaluator,
                page=page,
                guard=egress_guard,
                fetch_denials=denied_requests,
                router=router,
                prearmed=True,
                command_line_projection={},
                child_environment={},
            )
            actor = execute_live_browser_action(vector=vector, realm=realm)
            router.raise_if_failed()

            assert {
                key: actor["measurement"][key]
                for key in (
                    "resolved_type",
                    "own_descriptor",
                    "action_issued",
                    "action_succeeded",
                    "exception_name",
                )
            } == {
                "resolved_type": "function",
                "own_descriptor": "data",
                "action_issued": True,
                "action_succeeded": True,
                "exception_name": None,
            }
            expected_denials = expected_fetch_denial_observations(vector)
            assert denied_requests == expected_denials
            assert actor["measurement"]["fetch_denials"] == expected_denials
            assert actor["measurement"]["fetch_denial_count"] == len(expected_denials)
            assert egress_guard.attempt_count == 0

            router.begin_shutdown()
            browser_guard.begin_shutdown()
            context.close()
            context_closed = True
            browser_guard.finish()
            router.finish()
            browser.close()
            browser = None
    finally:
        if context is not None and not context_closed:
            context.close()
        if browser is not None and browser.is_connected():
            browser.close()
        for server in (primary_server, cross_server):
            server.shutdown()
            server.server_close()
        for thread in fixture_threads:
            thread.join(timeout=5)
            assert not thread.is_alive()


def test_http_credentials_are_rejected_only_by_exclusive_driver(tmp_path: Path) -> None:
    """Bind awaited v8 context rejection without poisoning the driver."""

    from playwright.sync_api import Error as PlaywrightError
    from playwright.sync_api import sync_playwright

    validate_default_playwright_driver_once()
    credentials = {"username": "qcsd-user", "password": "qcsd-password"}
    proxy = {"server": "http://127.0.0.1:9", **credentials}
    lab_root = Path(__file__).parents[1]
    client_certificate = {
        "origin": "https://localhost",
        "cert": (lab_root / FIXTURE_CERTIFICATE["path"]).read_bytes(),
        "key": (lab_root / FIXTURE_PRIVATE_KEY["path"]).read_bytes(),
    }

    with playwright_driver_session(sync_playwright, exclusive=True) as playwright:
        browser = playwright.chromium.launch(
            executable_path=pinned_chromium_executable_path(),
            headless=True,
            args=list(_DIRECT_CHROMIUM_ARGS),
            env=chromium_child_environment(),
        )
        try:
            with pytest.raises(
                PlaywrightError,
                match="QCSD exclusive CDP ownership forbids HTTP or proxy credentials",
            ):
                browser.new_context(
                    http_credentials=credentials,
                    service_workers="block",
                )
            assert browser.contexts == []
            with pytest.raises(
                PlaywrightError,
                match="QCSD exclusive CDP ownership forbids HTTP or proxy credentials",
            ):
                browser.new_context(proxy=proxy, service_workers="block")
            assert browser.contexts == []
            with pytest.raises(
                PlaywrightError,
                match="QCSD exclusive CDP ownership forbids HTTP or proxy credentials",
            ):
                browser.new_context(
                    http_credentials=credentials,
                    client_certificates=[client_certificate],
                    service_workers="block",
                )
            assert browser.contexts == []

            certificate_context = browser.new_context(
                client_certificates=[client_certificate],
                service_workers="block",
            )
            certificate_context.close()
            assert browser.contexts == []
            context = browser.new_context(service_workers="block")
            try:
                _set_http_credentials_via_protocol(context, None)
                with pytest.raises(
                    PlaywrightError,
                    match="QCSD exclusive CDP ownership forbids HTTP or proxy credentials",
                ):
                    _set_http_credentials_via_protocol(context, credentials)
                page = context.new_page()
                page.set_content("<title>exclusive-driver-survived</title>")
                assert page.title() == "exclusive-driver-survived"
            finally:
                context.close()
        finally:
            browser.close()

        browser = playwright.chromium.launch(
            executable_path=pinned_chromium_executable_path(),
            headless=True,
            args=list(_DIRECT_CHROMIUM_ARGS),
            env=chromium_child_environment(),
            proxy=proxy,
        )
        try:
            with pytest.raises(
                PlaywrightError,
                match="QCSD exclusive CDP ownership forbids HTTP or proxy credentials",
            ):
                browser.new_context(service_workers="block")
            assert browser.contexts == []
        finally:
            browser.close()

        exclusive_profile = tmp_path / "exclusive-persistent-profile"
        with pytest.raises(
            PlaywrightError,
            match="QCSD exclusive CDP ownership forbids HTTP or proxy credentials",
        ):
            playwright.chromium.launch_persistent_context(
                str(exclusive_profile),
                executable_path=pinned_chromium_executable_path(),
                headless=True,
                args=list(_DIRECT_CHROMIUM_ARGS),
                env=chromium_child_environment(),
                http_credentials=credentials,
                service_workers="block",
            )
        assert not exclusive_profile.exists()

        exclusive_proxy_profile = tmp_path / "exclusive-proxy-persistent-profile"
        with pytest.raises(
            PlaywrightError,
            match="QCSD exclusive CDP ownership forbids HTTP or proxy credentials",
        ):
            playwright.chromium.launch_persistent_context(
                str(exclusive_proxy_profile),
                executable_path=pinned_chromium_executable_path(),
                headless=True,
                args=list(_DIRECT_CHROMIUM_ARGS),
                env=chromium_child_environment(),
                proxy=proxy,
                service_workers="block",
            )
        assert not exclusive_proxy_profile.exists()

        browser = playwright.chromium.launch(
            executable_path=pinned_chromium_executable_path(),
            headless=True,
            args=list(_DIRECT_CHROMIUM_ARGS),
            env=chromium_child_environment(),
        )
        try:
            context = browser.new_context(service_workers="block")
            try:
                page = context.new_page()
                page.set_content("<title>persistent-rejection-survived</title>")
                assert page.title() == "persistent-rejection-survived"
            finally:
                context.close()
        finally:
            browser.close()

    with playwright_driver_session(sync_playwright, exclusive=False) as playwright:
        browser = playwright.chromium.launch(
            executable_path=pinned_chromium_executable_path(),
            headless=True,
            args=list(_DIRECT_CHROMIUM_ARGS),
            env=chromium_child_environment(),
        )
        try:
            context = browser.new_context(
                http_credentials=credentials,
                proxy=proxy,
                service_workers="block",
            )
            try:
                _set_http_credentials_via_protocol(context, credentials)
                _set_http_credentials_via_protocol(context, None)
                page = context.new_page()
                page.set_content("<title>native-credentials</title>")
                assert page.title() == "native-credentials"
            finally:
                context.close()
        finally:
            browser.close()

        native_profile = tmp_path / "native-persistent-profile"
        context = playwright.chromium.launch_persistent_context(
            str(native_profile),
            executable_path=pinned_chromium_executable_path(),
            headless=True,
            args=list(_DIRECT_CHROMIUM_ARGS),
            env=chromium_child_environment(),
            http_credentials=credentials,
            proxy=proxy,
            service_workers="block",
        )
        try:
            page = context.new_page()
            page.set_content("<title>native-persistent-credentials</title>")
            assert page.title() == "native-persistent-credentials"
        finally:
            context.close()
