"""Opt-in lower-level probe against the pinned Playwright/Chromium pair.

The local origin is deliberately plain HTTP: this probes real CDP target and
ledger wiring without weakening ``discover_page``'s production TLS checks.
End-to-end HTTPS admission remains covered by deterministic integration mocks.
"""

from __future__ import annotations

import importlib.metadata
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from qcsd_lab.cdp_targets import RecursiveCdpTargetRouter
from qcsd_lab.discover import (
    DiscoveredRequest,
    _RequestExtraInfoAssociator,
    _RequestObservationLedger,
)


pytestmark = pytest.mark.skipif(
    os.environ.get("QCSD_RUN_PINNED_CDP_PROBE") != "1",
    reason="set QCSD_RUN_PINNED_CDP_PROBE=1 inside the prepare image",
)


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - stdlib callback name
        if self.path == "/":
            body = b"""<iframe src='http://b.test:PORT/frame'></iframe><script>
            new Worker('/worker.js'); new SharedWorker('/worker.js');
            fetch('/duplicate'); fetch('/duplicate'); fetch('/redirect');
            </script>""".replace(b"PORT", str(self.server.server_port).encode())
            kind = "text/html"
        elif self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/redirected")
            self.end_headers()
            return
        elif self.path == "/frame":
            body, kind = b"<script>fetch('/frame-data')</script>", "text/html"
        elif self.path == "/worker.js":
            body, kind = b"fetch('/worker-data')", "text/javascript"
        else:
            body, kind = b"ok", "text/plain"
        self.send_response(200)
        self.send_header("Content-Type", kind)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *_args: object) -> None:
        pass


def test_pinned_chromium_recursive_topology_and_shutdown() -> None:
    assert importlib.metadata.version("playwright") == "1.52.0"
    executable = os.environ.get("PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH")
    assert executable, "enabled probe requires PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH"
    from playwright.sync_api import sync_playwright

    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    observed_events: list[tuple[str, str, str]] = []
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(
                executable_path=executable,
                headless=True,
                args=[
                    "--no-sandbox",
                    "--no-proxy-server",
                    "--site-per-process",
                    "--host-resolver-rules=MAP a.test 127.0.0.1,MAP b.test 127.0.0.1",
                ],
            )
            context = browser.new_context(service_workers="block")
            page = context.new_page()
            session = context.new_cdp_session(page)
            router: RecursiveCdpTargetRouter
            ledger = _RequestObservationLedger(
                eligible=lambda method, url: method == "GET" and url.startswith("http://")
            )
            extra_info = _RequestExtraInfoAssociator()

            def event(source, method, payload):
                request = payload.get("request", {})
                url = str(request.get("url", "")) if isinstance(request, dict) else ""
                observed_events.append((source.target_type, method, url))
                if method == "Network.requestWillBeSent":
                    redirected = payload.get("redirectResponse") is not None
                    extra_info.add_request(
                        source.request_chain_key(str(payload["requestId"])),
                        DiscoveredRequest(url, str(payload.get("type", "Other")), {}),
                        redirected=redirected,
                        redirect_has_extra_info=(
                            payload.get("redirectHasExtraInfo") if redirected else None
                        ),
                    )
                    ledger.add_network(
                        source,
                        request_id=str(payload["requestId"]),
                        method=str(request.get("method", "")),
                        url=url,
                    )
                elif method == "Network.requestWillBeSentExtraInfo":
                    extra_info.add_extra_info(
                        source.request_chain_key(str(payload["requestId"])),
                        payload.get("headers"),
                    )
                elif method == "Network.responseReceived":
                    extra_info.add_response(
                        source.request_chain_key(str(payload["requestId"])),
                        payload.get("hasExtraInfo"),
                    )
                elif method in {"Network.loadingFinished", "Network.loadingFailed"}:
                    ledger.add_terminal(source, str(payload["requestId"]))
                    extra_info.add_terminal(
                        source.request_chain_key(str(payload["requestId"])),
                        failed=method == "Network.loadingFailed",
                    )
                elif method == "Fetch.requestPaused":
                    ledger.add_interception(source, payload)
                    router.send(
                        source,
                        "Fetch.continueRequest",
                        {"requestId": payload["requestId"]},
                        label="probe-policy",
                    )

            router = RecursiveCdpTargetRouter(session, on_event=event)
            router.start()
            page.goto(f"http://a.test:{server.server_port}/", wait_until="load")
            page.wait_for_timeout(1_000)
            router.begin_shutdown()
            context.close()
            router.finish()
            ledger.finish()
            extra_info.finish()
            browser.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    # Site isolation must expose the cross-site frame; worker targets must be
    # recursively instrumented even though Fetch remains page/frame-owned.
    observed_types = {target_type for target_type, _method, _url in observed_events}
    assert {"iframe", "worker", "shared_worker"}.issubset(observed_types)
    assert any(
        target_type == "iframe"
        and method == "Network.requestWillBeSent"
        and url.endswith("/frame-data")
        for target_type, method, url in observed_events
    )
    assert sum(
        method == "Network.requestWillBeSent" and url.endswith("/duplicate")
        for _target_type, method, url in observed_events
    ) == 2
    assert any(
        method == "Network.requestWillBeSent" and url.endswith("/redirected")
        for _target_type, method, url in observed_events
    )
    worker_network_types = {
        target_type
        for target_type, method, url in observed_events
        if method == "Network.requestWillBeSent" and url.endswith("/worker-data")
    }
    assert worker_network_types == {"worker", "shared_worker"}
    # The pinned prepare-image runtime reports worker request-stage interception
    # on the owning page session even though Network events remain on the worker
    # sessions. This is the cross-session relation the discovery ledger must
    # reconcile.
    assert any(
        target_type == "page"
        and method == "Fetch.requestPaused"
        and url.endswith("/worker-data")
        for target_type, method, url in observed_events
    )
