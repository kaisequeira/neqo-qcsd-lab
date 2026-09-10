"""Opt-in real-Chromium concurrency check for the pinned Playwright driver."""

from __future__ import annotations

import os
import runpy
import threading
import time
from collections.abc import Iterator, Mapping
from concurrent.futures import Future, ThreadPoolExecutor
from pathlib import Path

import pytest

from qcsd_lab.browser_egress import (
    NonReplayableEgressGuard,
    install_context_egress_guards,
    launch_pinned_cdp_probe_browser,
)
from qcsd_lab.browser_egress_fixture import (
    _FixtureHttpServer,
    browser_action_expression,
    dedicated_worker_action_bridge_expression,
    dedicated_worker_action_message,
    dedicated_worker_ready_bridge_expression,
    execute_live_browser_action,
    expected_fetch_denial_observations,
    vector_by_id,
)
from qcsd_lab.cdp_targets import (
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
                args=["--no-sandbox", "--no-proxy-server", "--site-per-process"],
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
        results = [future.result(timeout=120) for future in futures]

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


def test_http_credentials_are_rejected_only_by_exclusive_driver() -> None:
    """Bind the v7 credentials fail-close without changing inactive Playwright."""

    from playwright.sync_api import Error as PlaywrightError
    from playwright.sync_api import sync_playwright

    validate_default_playwright_driver_once()
    credentials = {"username": "qcsd-user", "password": "qcsd-password"}

    with playwright_driver_session(sync_playwright, exclusive=True) as playwright:
        browser = playwright.chromium.launch(
            executable_path=pinned_chromium_executable_path(),
            headless=True,
            args=["--no-sandbox", "--no-proxy-server", "--site-per-process"],
            env=chromium_child_environment(),
        )
        try:
            context = browser.new_context(
                http_credentials=credentials,
                service_workers="block",
            )
            try:
                with pytest.raises(
                    PlaywrightError,
                    match="QCSD exclusive CDP ownership forbids HTTP credentials",
                ):
                    context.new_page()
            finally:
                context.close()
        finally:
            browser.close()

    with playwright_driver_session(sync_playwright, exclusive=False) as playwright:
        browser = playwright.chromium.launch(
            executable_path=pinned_chromium_executable_path(),
            headless=True,
            args=["--no-sandbox", "--no-proxy-server", "--site-per-process"],
            env=chromium_child_environment(),
        )
        try:
            context = browser.new_context(
                http_credentials=credentials,
                service_workers="block",
            )
            try:
                page = context.new_page()
                page.set_content("<title>native-credentials</title>")
                assert page.title() == "native-credentials"
            finally:
                context.close()
        finally:
            browser.close()
