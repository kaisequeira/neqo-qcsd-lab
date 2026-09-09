from __future__ import annotations

import runpy
import signal
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace

import pytest

from qcsd_lab.browser_egress_fixture import (
    dedicated_worker_action_bridge_expression,
    dedicated_worker_ready_bridge_expression,
)


def _tool_namespace() -> dict[str, object]:
    return runpy.run_path(
        str(Path(__file__).parents[1] / "tools/browser_egress_qualification.py"),
        run_name="qcsd_browser_egress_actor_test",
    )


class _RecordingPage:
    def __init__(self, result: object) -> None:
        self.result = result
        self.calls: list[tuple[str, object]] = []

    def evaluate(self, expression: str, argument: object) -> object:
        self.calls.append((expression, argument))
        return self.result


def test_dedicated_worker_evaluator_uses_the_frozen_page_message() -> None:
    namespace = _tool_namespace()
    evaluator_type = namespace["_DedicatedWorkerEvaluator"]
    message = {
        "protocol": "qcsd-dedicated-worker-action-v1",
        "expression": "async value => value",
        "argument": {"value": 7},
    }
    page = _RecordingPage({"result": "measured"})
    evaluator = evaluator_type(page, SimpleNamespace(context="dedicated-worker"), lambda _: message)

    assert evaluator.evaluate(message["expression"], message["argument"]) == {"result": "measured"}
    assert len(page.calls) == 1
    bridge, supplied = page.calls[0]
    assert supplied is message
    assert bridge == dedicated_worker_action_bridge_expression()

    with pytest.raises(ValueError, match="differs from its frozen message"):
        evaluator.evaluate("async value => null", message["argument"])
    with pytest.raises(ValueError, match="differs from its frozen message"):
        evaluator.evaluate(message["expression"], {"value": 8})


class _CleanupStep:
    def __init__(self, name: str, calls: list[str], failures: set[str]) -> None:
        self.name = name
        self.calls = calls
        self.failures = failures

    def _run(self, operation: str) -> None:
        label = f"{self.name}-{operation}"
        self.calls.append(label)
        if label in self.failures:
            raise RuntimeError(label)

    def begin_abort(self) -> None:
        self._run("begin-abort")

    def begin_shutdown(self) -> None:
        self._run("begin-shutdown")

    def finish_abort(self) -> None:
        self._run("finish-abort")

    def finish(self) -> None:
        self._run("finish")

    def close(self) -> None:
        self._run("close")


def test_actor_abort_orders_the_target_graph_and_preserves_cleanup_failures() -> None:
    namespace = _tool_namespace()
    abort = namespace["_abort_actor_target_graph"]
    calls: list[str] = []
    primary = RuntimeError("primary")

    abort(
        _CleanupStep("context", calls, {"guard-finish-abort"}),
        _CleanupStep("router", calls, {"guard-finish-abort"}),
        _CleanupStep("guard", calls, {"guard-finish-abort"}),
        primary,
    )

    assert calls == [
        "router-begin-abort",
        "guard-begin-abort",
        "context-close",
        "guard-finish-abort",
    ]
    assert primary.__notes__ == [
        "browser-egress actor cleanup guard-finish-abort failed with RuntimeError"
    ]


@pytest.mark.parametrize(
    ("failure", "expected_calls"),
    [
        ("router-begin-abort", ["router-begin-abort", "context-close"]),
        (
            "guard-begin-abort",
            ["router-begin-abort", "guard-begin-abort", "context-close"],
        ),
        (
            "context-close",
            ["router-begin-abort", "guard-begin-abort", "context-close"],
        ),
        (
            "guard-finish-abort",
            [
                "router-begin-abort",
                "guard-begin-abort",
                "context-close",
                "guard-finish-abort",
            ],
        ),
        (
            "router-finish-abort",
            [
                "router-begin-abort",
                "guard-begin-abort",
                "context-close",
                "guard-finish-abort",
                "router-finish-abort",
            ],
        ),
    ],
)
def test_actor_abort_gates_every_dependent_cleanup_step(
    failure: str,
    expected_calls: list[str],
) -> None:
    namespace = _tool_namespace()
    abort = namespace["_abort_actor_target_graph"]
    calls: list[str] = []
    primary = RuntimeError("primary")

    abort(
        _CleanupStep("context", calls, {failure}),
        _CleanupStep("router", calls, {failure}),
        _CleanupStep("guard", calls, {failure}),
        primary,
    )

    assert calls == expected_calls
    note_step = "context-dispose" if failure == "context-close" else failure
    assert primary.__notes__ == [
        f"browser-egress actor cleanup {note_step} failed with RuntimeError"
    ]


@pytest.mark.parametrize(
    ("failure", "expected_calls"),
    [
        (
            "guard-begin-shutdown",
            ["guard-begin-shutdown", "context-close"],
        ),
        (
            "context-close",
            ["guard-begin-shutdown", "context-close"],
        ),
        (
            "guard-finish",
            ["guard-begin-shutdown", "context-close", "guard-finish"],
        ),
        (
            "router-finish",
            [
                "guard-begin-shutdown",
                "context-close",
                "guard-finish",
                "router-finish",
            ],
        ),
    ],
)
def test_actor_normal_shutdown_preserves_its_first_failure_and_gates_dependents(
    failure: str,
    expected_calls: list[str],
) -> None:
    namespace = _tool_namespace()
    finish_shutdown = namespace["_finish_actor_target_graph_shutdown"]
    calls: list[str] = []

    with pytest.raises(RuntimeError, match=failure) as caught:
        finish_shutdown(
            _CleanupStep("context", calls, {failure}),
            _CleanupStep("router", calls, {failure}),
            _CleanupStep("guard", calls, {failure}),
        )

    assert str(caught.value) == failure
    assert calls == expected_calls


def test_actor_normal_shutdown_attaches_later_cleanup_failure_to_first() -> None:
    namespace = _tool_namespace()
    finish_shutdown = namespace["_finish_actor_target_graph_shutdown"]
    calls: list[str] = []

    with pytest.raises(RuntimeError, match="guard-begin-shutdown") as caught:
        finish_shutdown(
            _CleanupStep("context", calls, {"context-close"}),
            _CleanupStep("router", calls, set()),
            _CleanupStep("guard", calls, {"guard-begin-shutdown"}),
        )

    assert calls == ["guard-begin-shutdown", "context-close"]
    assert caught.value.__notes__ == [
        "browser-egress actor cleanup context-dispose failed with RuntimeError"
    ]


def _install_partial_start_actor_fakes(
    monkeypatch: pytest.MonkeyPatch,
    namespace: dict[str, object],
    lifecycle: list[str],
    primary: Exception,
    *,
    browser_session_error: Exception | None = None,
    browser_close_error: Exception | None = None,
    router_close_error: Exception | None = None,
) -> None:
    from qcsd_lab import browser_egress, cdp_targets, playwright_driver

    class EgressGuard:
        def bind_root_page(self, _page: object) -> None:
            return None

        def record(self, **_kwargs: object) -> None:
            return None

    class Page:
        def set_default_timeout(self, _timeout: int) -> None:
            return None

        def set_default_navigation_timeout(self, _timeout: int) -> None:
            return None

    class Context:
        def new_page(self) -> Page:
            lifecycle.append("context-new-page")
            return Page()

        def new_cdp_session(self, _page: Page) -> object:
            lifecycle.append("context-new-cdp-session")
            return object()

        def close(self) -> None:
            lifecycle.append("context-close")

    class Browser:
        def new_browser_cdp_session(self) -> object:
            lifecycle.append("browser-new-cdp-session")
            if browser_session_error is not None:
                raise browser_session_error
            return object()

        def new_context(self, **_kwargs: object) -> Context:
            lifecycle.append("browser-new-context")
            return Context()

        def close(self) -> None:
            lifecycle.append("browser-close")
            if browser_close_error is not None:
                raise browser_close_error

    class Router:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            return None

        def start(self) -> None:
            lifecycle.append("router-start")

        def begin_abort(self) -> None:
            lifecycle.append("router-begin-abort")

        def finish_abort(self) -> None:
            lifecycle.append("router-finish-abort")

        def raise_if_failed(self) -> None:
            if router_close_error is not None:
                raise router_close_error

    class BrowserGuard:
        def __init__(self, _session: object, _router: Router) -> None:
            return None

        def start(self) -> None:
            lifecycle.append("guard-start")
            raise primary

        def begin_abort(self) -> None:
            lifecycle.append("guard-begin-abort")

        def finish_abort(self) -> None:
            lifecycle.append("guard-finish-abort")

    monkeypatch.setattr(browser_egress, "NonReplayableEgressGuard", EgressGuard)
    monkeypatch.setattr(
        browser_egress,
        "install_context_egress_guards",
        lambda _context, _guard: None,
    )
    monkeypatch.setattr(cdp_targets, "RecursiveCdpTargetRouter", Router)
    monkeypatch.setattr(cdp_targets, "BrowserSharedWorkerGuard", BrowserGuard)
    monkeypatch.setattr(
        playwright_driver,
        "playwright_driver_session",
        lambda *_args, **_kwargs: nullcontext(object()),
    )
    actor_globals = namespace["_actor"].__globals__
    monkeypatch.setitem(
        actor_globals,
        "vector_by_id",
        lambda _vector_id: SimpleNamespace(
            family="constructor",
            context="main-frame",
            surface="fetch",
        ),
    )
    monkeypatch.setitem(actor_globals, "_ready", lambda: None)
    monkeypatch.setitem(actor_globals, "_wait", lambda _event: None)
    monkeypatch.setitem(
        actor_globals,
        "_launch_vector_browser",
        lambda _playwright, _vector: (
            Browser(),
            {"command_line_projection": {}},
            {},
            {},
            [],
        ),
    )
    monkeypatch.setattr(signal, "signal", lambda *_args: None)


def test_actor_aborts_a_partially_started_guard_and_preserves_the_primary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    namespace = _tool_namespace()
    actor = namespace["_actor"]
    lifecycle: list[str] = []
    primary = RuntimeError("partial guard start")
    browser_close_error = RuntimeError("browser close")
    router_close_error = RuntimeError("router close")
    _install_partial_start_actor_fakes(
        monkeypatch,
        namespace,
        lifecycle,
        primary,
        browser_close_error=browser_close_error,
        router_close_error=router_close_error,
    )

    with pytest.raises(RuntimeError, match="partial guard start") as caught:
        actor(SimpleNamespace(vector_id="test-vector"))

    assert caught.value is primary
    assert lifecycle == [
        "browser-new-cdp-session",
        "browser-new-context",
        "context-new-page",
        "context-new-cdp-session",
        "router-start",
        "guard-start",
        "router-begin-abort",
        "guard-begin-abort",
        "context-close",
        "guard-finish-abort",
        "router-finish-abort",
        "browser-close",
    ]
    assert primary.__notes__ == [
        "browser-egress actor cleanup browser-close failed with RuntimeError",
        "browser-egress actor cleanup router-post-close failed with RuntimeError",
    ]


def test_actor_closes_the_browser_when_setup_fails_before_context_creation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    namespace = _tool_namespace()
    actor = namespace["_actor"]
    lifecycle: list[str] = []
    primary = RuntimeError("browser session setup")
    _install_partial_start_actor_fakes(
        monkeypatch,
        namespace,
        lifecycle,
        RuntimeError("unused guard failure"),
        browser_session_error=primary,
    )

    with pytest.raises(RuntimeError, match="browser session setup") as caught:
        actor(SimpleNamespace(vector_id="test-vector"))

    assert caught.value is primary
    assert lifecycle == ["browser-new-cdp-session", "browser-close"]


def test_actor_no_longer_waits_for_a_playwright_worker_object() -> None:
    source = (Path(__file__).parents[1] / "tools/browser_egress_qualification.py").read_text(
        encoding="utf-8"
    )
    actor = source.split("def _actor(", maxsplit=1)[1].split(
        "\nclass _PlaywrightRealm", maxsplit=1
    )[0]

    assert "expect_worker" not in actor
    assert "dedicated_worker_ready_bridge_expression()" in actor
    assert "_DedicatedWorkerEvaluator" in actor
    assert "_abort_actor_target_graph(context, router, browser_guard, error)" in actor


def test_dedicated_worker_bridge_expressions_bind_one_named_worker() -> None:
    ready = dedicated_worker_ready_bridge_expression()
    action = dedicated_worker_action_bridge_expression()

    assert "const worker = new Worker(url);" in ready
    assert "qcsd-dedicated-worker-action-v1" in ready
    assert "window.__qcsdDedicatedWorker = worker;" in ready
    assert "const worker = window.__qcsdDedicatedWorker;" in action
    assert "event.data.protocol === message.protocol" in action
    assert "worker.postMessage(message);" in action
