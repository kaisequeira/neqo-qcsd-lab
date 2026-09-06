"""Opt-in live check of the receipt-producing pinned-CDP probe implementation."""

from __future__ import annotations

import os

import pytest

from qcsd_lab.cdp_targets import (
    BrowserSharedWorkerGuard,
    CdpTargetIntegrityError,
    RecursiveCdpTargetRouter,
)
from qcsd_lab.pinned_cdp import run_pinned_cdp_probe
from qcsd_lab.playwright_driver import (
    chromium_child_environment,
    pinned_chromium_executable_path,
    playwright_driver_session,
    validate_default_playwright_driver_once,
)

pytestmark = pytest.mark.skipif(
    os.environ.get("QCSD_RUN_PINNED_CDP_PROBE") != "1",
    reason="set QCSD_RUN_PINNED_CDP_PROBE=1 inside the prepare image",
)


def test_pinned_chromium_recursive_topology_and_shutdown() -> None:
    """Exercise the exact implementation used to publish the durable receipt."""

    observation = run_pinned_cdp_probe(
        expected_uid=int(os.environ["QCSD_PINNED_CDP_EXPECTED_UID"]),
        expected_gid=int(os.environ["QCSD_PINNED_CDP_EXPECTED_GID"]),
    )
    topology = observation["topology"]
    assert {"iframe", "worker", "shared_worker"}.issubset(topology["observed_target_types"])
    assert topology["worker_network_target_types"] == ["shared_worker", "worker"]
    assert topology["duplicate_request_occurrences"] == 2
    assert topology["dedicated_worker_network_request"] is True
    assert topology["shared_worker_network_request"] is True
    assert topology["dedicated_worker_fetch_paused_on_page"] is True
    assert topology["shared_worker_fetch_paused_on_shared_worker"] is True
    assert topology["router_closed"] is True
    assert topology["browser_guard_closed"] is True
    assert topology["ledger_closed"] is True
    assert topology["extra_info_closed"] is True
    assert topology["browser_closed"] is True
    assert topology["server_thread_stopped"] is True


def test_public_cdp_rejects_window_open_sibling_page() -> None:
    """Prove a real Chromium popup cannot remain outside the accepted graph."""

    from playwright.sync_api import sync_playwright

    validate_default_playwright_driver_once()
    with playwright_driver_session(sync_playwright, exclusive=True) as playwright:
        browser = playwright.chromium.launch(
            headless=True,
            executable_path=pinned_chromium_executable_path(),
            args=["--no-sandbox"],
            env=chromium_child_environment(),
        )
        context = browser.new_context(service_workers="block")
        page = context.new_page()
        page_session = context.new_cdp_session(page)
        browser_session = browser.new_browser_cdp_session()
        router = RecursiveCdpTargetRouter(
            page_session,
            on_event=lambda *_args: None,
        )
        router.start()
        guard = BrowserSharedWorkerGuard(browser_session, router)
        guard.start()
        try:
            assert page.evaluate("() => Boolean(window.open('about:blank', '_blank'))") is True
            with pytest.raises(CdpTargetIntegrityError, match="sibling popup/page"):
                for _ in range(50):
                    page.wait_for_timeout(20)
                    router.raise_if_failed()
                pytest.fail("window.open sibling target was not rejected")
        finally:
            router.begin_abort()
            guard.begin_abort()
            context.close()
            guard.finish_abort()
            router.finish_abort()
            browser.close()
