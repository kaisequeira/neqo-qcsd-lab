"""Host-only regressions for the production browser-service control actor."""

from __future__ import annotations

import argparse
import runpy
import sys
from contextlib import contextmanager
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

from qcsd_lab import playwright_driver
from qcsd_lab.browser_egress_fixture import (
    BROWSER_SERVICE_CONTROL_DWELL_MS,
    browser_service_control_actor_result,
    expected_browser_launch_contract,
    expected_vectors,
    vector_by_id,
)


CONTROL_VECTORS = tuple(
    vector for vector in expected_vectors() if vector.family == "browser-service-control"
)


@pytest.fixture
def actor_harness(monkeypatch):
    actor = runpy.run_path(
        str(Path(__file__).resolve().parents[1] / "tools/browser_egress_qualification.py")
    )["_browser_service_control_actor"]
    calls = []
    emitted = []
    state = SimpleNamespace(
        create_response={"targetId": "raw-target"}, create_error=None, close_error=None
    )
    sync_playwright = object()
    playwright = object()
    sync_api = ModuleType("playwright.sync_api")
    sync_api.sync_playwright = sync_playwright
    monkeypatch.setitem(sys.modules, "playwright.sync_api", sync_api)

    @contextmanager
    def driver_session(factory, *, exclusive):
        assert factory is sync_playwright
        assert exclusive is True
        calls.append(("driver-enter",))
        try:
            yield playwright
        finally:
            calls.append(("driver-exit",))

    def send(method, params):
        calls.append((method, params))
        if method == "Target.createTarget":
            if state.create_error is not None:
                raise state.create_error
            return state.create_response
        if method == "Target.closeTarget":
            if state.close_error is not None:
                raise state.close_error
            return {"success": True}
        pytest.fail(f"Unexpected CDP command: {method}")

    # Only expose the allowed operations: context/page attachment or inspection
    # through any other browser API fails rather than silently succeeding.
    page = SimpleNamespace(
        goto=lambda url, **kwargs: calls.append(("goto", url, kwargs)),
        wait_for_timeout=lambda timeout: calls.append(("page-dwell", timeout)),
    )

    def new_page():
        calls.append(("new-page",))
        return page

    context = SimpleNamespace(
        new_page=new_page, close=lambda: calls.append(("context-close",))
    )

    def new_context():
        calls.append(("new-context",))
        return context

    def new_browser_cdp_session():
        calls.append(("browser-cdp-session",))
        return SimpleNamespace(send=send)

    browser = SimpleNamespace(
        new_context=new_context,
        new_browser_cdp_session=new_browser_cdp_session,
        close=lambda: calls.append(("browser-close",)),
    )

    def launch(actual_playwright, vector):
        assert actual_playwright is playwright
        calls.append(("launch", vector.vector_id))
        return browser, ["chromium", "--example"], {"driver": "bound"}, {}, ["policy"]

    dwell_ns = BROWSER_SERVICE_CONTROL_DWELL_MS * 1_000_000
    timestamps = iter((100, 200, 200 + dwell_ns, 300 + dwell_ns))
    monkeypatch.setattr(playwright_driver, "playwright_driver_session", driver_session)
    monkeypatch.setitem(actor.__globals__, "_launch_vector_browser", launch)
    monkeypatch.setitem(actor.__globals__, "_emit", emitted.append)
    monkeypatch.setitem(
        actor.__globals__,
        "time",
        SimpleNamespace(
            monotonic_ns=lambda: next(timestamps),
            sleep=lambda seconds: calls.append(("sleep", seconds)),
        ),
    )
    return SimpleNamespace(actor=actor, calls=calls, emitted=emitted, state=state)


@pytest.mark.parametrize("vector", CONTROL_VECTORS, ids=lambda vector: vector.vector_id)
def test_control_actor_preserves_profile_navigation_dwell_and_receipt(actor_harness, vector):
    harness = actor_harness
    contract = expected_browser_launch_contract(vector)
    target_url = contract["control_document_origin"] + contract["control_document_path"]

    harness.actor(argparse.Namespace(), vector)

    if contract["context_kind"] == "raw-default-profile-cdp-unattached-target":
        # No browserContextId means Chromium's default profile. A NEW window is
        # required because Playwright starts Chromium without any initial page.
        operations = [
            ("browser-cdp-session",),
            ("Target.createTarget", {"url": target_url, "newWindow": True}),
            ("sleep", BROWSER_SERVICE_CONTROL_DWELL_MS / 1_000),
            ("Target.closeTarget", {"targetId": "raw-target"}),
        ]
    else:
        assert contract["context_kind"] == "off-the-record-playwright"
        operations = [
            ("new-context",),
            ("new-page",),
            ("goto", target_url, {"wait_until": "load"}),
            ("page-dwell", BROWSER_SERVICE_CONTROL_DWELL_MS),
            ("context-close",),
        ]
    assert harness.calls == [
        ("driver-enter",),
        ("launch", vector.vector_id),
        *operations,
        ("browser-close",),
        ("driver-exit",),
    ]
    dwell_ns = BROWSER_SERVICE_CONTROL_DWELL_MS * 1_000_000
    assert harness.emitted == [
        {
            "schema_version": 1,
            "role": "actor",
            "vector_id": vector.vector_id,
            "browser_started_ns": 100,
            "browser_exited_ns": 300 + dwell_ns,
            "actor_result": browser_service_control_actor_result(
                vector, started_ns=200, finished_ns=200 + dwell_ns
            ),
            "effective_argv": ["chromium", "--example"],
            "driver_runtime": {"driver": "bound"},
            "child_environment": {},
            "policy_volume_file_inventory": ["policy"],
        }
    ]


@pytest.mark.parametrize(
    "response",
    [None, [], {}, {"targetId": None}, {"targetId": ""}, {"targetId": 42}, {"targetId": True}],
)
def test_default_profile_actor_closes_browser_after_missing_target(actor_harness, response):
    harness = actor_harness
    harness.state.create_response = response
    vector = vector_by_id("browser-service-control--default-profile--dns-prefetch-disabled")

    with pytest.raises(ValueError, match="control target was not created"):
        harness.actor(argparse.Namespace(), vector)

    assert harness.calls[-2:] == [("browser-close",), ("driver-exit",)]
    assert not any(call[0] in {"Target.closeTarget", "sleep"} for call in harness.calls)
    assert harness.emitted == []


def test_default_profile_actor_closes_browser_after_create_error(actor_harness):
    harness = actor_harness
    error = RuntimeError("Target.createTarget failed")
    harness.state.create_error = error
    vector = vector_by_id("browser-service-control--default-profile--dns-prefetch-disabled")

    with pytest.raises(RuntimeError) as raised:
        harness.actor(argparse.Namespace(), vector)

    assert raised.value is error
    assert harness.calls[-2:] == [("browser-close",), ("driver-exit",)]
    assert not any(call[0] in {"Target.closeTarget", "sleep"} for call in harness.calls)
    assert harness.emitted == []


def test_default_profile_actor_closes_browser_after_target_close_error(actor_harness):
    harness = actor_harness
    error = RuntimeError("Target.closeTarget failed")
    harness.state.close_error = error
    vector = vector_by_id("browser-service-control--default-profile--dns-prefetch-disabled")

    with pytest.raises(RuntimeError) as raised:
        harness.actor(argparse.Namespace(), vector)

    assert raised.value is error
    assert harness.calls[-3:] == [
        ("Target.closeTarget", {"targetId": "raw-target"}),
        ("browser-close",),
        ("driver-exit",),
    ]
    assert harness.emitted == []
