"""Opt-in real-Chromium concurrency check for the pinned Playwright driver."""

from __future__ import annotations

import os
import threading
from concurrent.futures import Future, ThreadPoolExecutor

import pytest

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
