from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

import pytest

from qcsd_lab.cdp_targets import (
    CDP_TARGET_INSTRUMENTATION_POLICY,
    CdpTargetIntegrityError,
    CdpTargetSource,
    RecursiveCdpTargetRouter,
)


class _FakeNonFlatSession:
    """Minimal recursive non-flat CDP transport with synchronous responses."""

    def __init__(self, *, hold_methods: set[str] | None = None) -> None:
        self.handlers: dict[str, Any] = {}
        self.commands: list[tuple[tuple[str, ...], str, dict[str, Any]]] = []
        self.route_info: dict[tuple[str, ...], dict[str, str]] = {
            (): {"targetId": "root-page", "type": "page"}
        }
        self.hold_methods = hold_methods or set()
        self.held: list[tuple[tuple[str, ...], int, dict[str, Any]]] = []

    def on(self, event: str, handler: Any) -> None:
        self.handlers[event] = handler

    def send(
        self, method: str, params: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        parameters = dict(params or {})
        self.commands.append(((), method, parameters))
        if method == "Target.getTargetInfo":
            return {"targetInfo": dict(self.route_info[()])}
        if method == "Target.sendMessageToTarget":
            session_id = parameters["sessionId"]
            route = (session_id,)
            self._process(route, json.loads(parameters["message"]))
        return {}

    def attach(
        self,
        parent_route: tuple[str, ...],
        *,
        session_id: str,
        target_id: str,
        target_type: str,
        waiting: bool = True,
        parent_frame_id: str | None = None,
    ) -> tuple[str, ...]:
        route = (*parent_route, session_id)
        self.route_info[route] = {"targetId": target_id, "type": target_type}
        params = {
            "sessionId": session_id,
            "targetInfo": {"targetId": target_id, "type": target_type},
            "waitingForDebugger": waiting,
        }
        if parent_frame_id is not None:
            params["targetInfo"]["parentFrameId"] = parent_frame_id
        if parent_route:
            self._deliver(
                parent_route,
                {"method": "Target.attachedToTarget", "params": params},
            )
        else:
            self.handlers["Target.attachedToTarget"](params)
        return route

    def detach(self, parent_route: tuple[str, ...], *, session_id: str) -> None:
        route = (*parent_route, session_id)
        params = {
            "sessionId": session_id,
            "targetId": self.route_info[route]["targetId"],
        }
        if parent_route:
            self._deliver(
                parent_route,
                {"method": "Target.detachedFromTarget", "params": params},
            )
        else:
            self.handlers["Target.detachedFromTarget"](params)

    def emit(
        self, route: tuple[str, ...], method: str, params: Mapping[str, Any]
    ) -> None:
        if route:
            self._deliver(route, {"method": method, "params": dict(params)})
        else:
            self.handlers[method](dict(params))

    def _process(self, route: tuple[str, ...], payload: Mapping[str, Any]) -> None:
        command_id = payload["id"]
        method = payload["method"]
        params = dict(payload.get("params", {}))
        self.commands.append((route, method, params))
        if method in self.hold_methods:
            self.held.append((route, command_id, self._result(route, method)))
            return
        self._deliver(route, {"id": command_id, "result": self._result(route, method)})
        if method == "Target.sendMessageToTarget":
            child_route = (*route, params["sessionId"])
            self._process(child_route, json.loads(params["message"]))

    def _result(self, route: tuple[str, ...], method: str) -> dict[str, Any]:
        if method == "Target.getTargetInfo":
            return {"targetInfo": dict(self.route_info[route])}
        return {}

    def _deliver(self, route: tuple[str, ...], payload: Mapping[str, Any]) -> None:
        if not route:
            raise AssertionError("root events use their direct CDP event handler")
        nested: Mapping[str, Any] = payload
        for index in range(len(route) - 1, 0, -1):
            child_route = route[: index + 1]
            nested = {
                "method": "Target.receivedMessageFromTarget",
                "params": {
                    "sessionId": route[index],
                    "targetId": self.route_info[child_route]["targetId"],
                    "message": json.dumps(nested),
                },
            }
        first_route = route[:1]
        self.handlers["Target.receivedMessageFromTarget"](
            {
                "sessionId": route[0],
                "targetId": self.route_info[first_route]["targetId"],
                "message": json.dumps(nested),
            }
        )


def _router(
    session: _FakeNonFlatSession,
) -> tuple[
    RecursiveCdpTargetRouter,
    list[tuple[CdpTargetSource, str, Mapping[str, Any]]],
]:
    observed: list[tuple[CdpTargetSource, str, Mapping[str, Any]]] = []
    router = RecursiveCdpTargetRouter(
        session,
        on_event=lambda source, method, event: observed.append(
            (source, method, event)
        ),
    )
    router.start()
    return router, observed


def _complete_request(
    session: _FakeNonFlatSession,
    route: tuple[str, ...],
    request_id: str,
    url: str,
) -> None:
    session.emit(
        route,
        "Network.requestWillBeSent",
        {"requestId": request_id, "request": {"method": "GET", "url": url}},
    )
    session.emit(route, "Network.loadingFinished", {"requestId": request_id})


def test_policy_is_pinned_and_root_is_instrumented_before_navigation() -> None:
    session = _FakeNonFlatSession()
    router, _observed = _router(session)

    assert CDP_TARGET_INSTRUMENTATION_POLICY == (
        "playwright-1.52-public-cdp-recursive-non-flat-paused-debugger-targets-v3"
    )
    assert [method for route, method, _params in session.commands if route == ()] == [
        "Target.getTargetInfo",
        "Debugger.enable",
        "Network.enable",
        "Network.setCacheDisabled",
        "Network.setBypassServiceWorker",
        "Fetch.enable",
        "Target.setAutoAttach",
        "Target.getTargetInfo",
    ]
    router.begin_shutdown()
    router.finish()


def test_oopif_and_worker_are_fully_configured_before_resume() -> None:
    session = _FakeNonFlatSession()
    router, observed = _router(session)
    iframe = session.attach(
        (), session_id="iframe-session", target_id="iframe-target", target_type="iframe"
    )
    worker = session.attach(
        (), session_id="worker-session", target_id="worker-target", target_type="worker"
    )

    iframe_expected = [
        "Debugger.enable",
        "Network.enable",
        "Network.setCacheDisabled",
        "Network.setBypassServiceWorker",
        "Fetch.enable",
        "Target.setAutoAttach",
        "Target.getTargetInfo",
        "Runtime.runIfWaitingForDebugger",
    ]
    worker_expected = [method for method in iframe_expected if method != "Fetch.enable"]
    assert [
        method for seen, method, _params in session.commands if seen == iframe
    ] == iframe_expected
    assert [
        method for seen, method, _params in session.commands if seen == worker
    ] == worker_expected

    _complete_request(session, iframe, "same-request-id", "https://frame.test/a")
    _complete_request(session, worker, "same-request-id", "https://worker.test/a")
    request_sources = [
        source
        for source, method, _event in observed
        if method == "Network.requestWillBeSent"
    ]
    assert request_sources[0].request_chain_key("same-request-id") != (
        request_sources[1].request_chain_key("same-request-id")
    )

    session.detach((), session_id="iframe-session")
    session.detach((), session_id="worker-session")
    router.begin_shutdown()
    router.finish()


def test_nested_related_target_is_instrumented_through_parent_transport() -> None:
    session = _FakeNonFlatSession()
    router, observed = _router(session)
    iframe = session.attach(
        (), session_id="iframe-session", target_id="iframe-target", target_type="iframe"
    )
    nested = session.attach(
        iframe,
        session_id="nested-worker-session",
        target_id="nested-worker-target",
        target_type="worker",
    )

    _complete_request(
        session,
        nested,
        "nested-request",
        "https://frame.test/worker-data.json",
    )
    assert any(source.session_path == nested for source, _method, _event in observed)
    assert any(
        route == iframe and method == "Target.sendMessageToTarget"
        for route, method, _params in session.commands
    )

    session.detach(iframe, session_id="nested-worker-session")
    session.detach((), session_id="iframe-session")
    router.begin_shutdown()
    router.finish()


def test_reattached_target_receives_a_new_collision_safe_generation() -> None:
    session = _FakeNonFlatSession()
    router, observed = _router(session)
    first = session.attach(
        (), session_id="first-session", target_id="worker-target", target_type="worker"
    )
    _complete_request(session, first, "request", "https://worker.test/first")
    session.detach((), session_id="first-session")
    second = session.attach(
        (), session_id="second-session", target_id="worker-target", target_type="worker"
    )
    _complete_request(session, second, "request", "https://worker.test/second")
    sources = [
        source
        for source, method, _event in observed
        if method == "Network.requestWillBeSent"
    ]
    assert [source.generation for source in sources] == [0, 1]
    assert sources[0].request_chain_key("request") != sources[1].request_chain_key("request")
    session.detach((), session_id="second-session")
    router.begin_shutdown()
    router.finish()


def test_oopif_terminal_events_route_to_the_root_request_occurrence() -> None:
    session = _FakeNonFlatSession()
    router, observed = _router(session)
    iframe = session.attach(
        (),
        session_id="iframe-session",
        target_id="frame-id",
        target_type="iframe",
        parent_frame_id="root-frame",
    )
    session.emit(
        (),
        "Network.requestWillBeSent",
        {
            "requestId": "navigation",
            "loaderId": "navigation",
            "frameId": "frame-id",
            "type": "Document",
            "request": {"method": "GET", "url": "https://frame.test/"},
        },
    )
    for method, payload in (
        ("Network.responseReceived", {"requestId": "navigation", "response": {}}),
        ("Network.requestWillBeSentExtraInfo", {"requestId": "navigation", "headers": {}}),
        ("Network.loadingFinished", {"requestId": "navigation"}),
    ):
        session.emit(iframe, method, payload)

    routed = [source for source, method, _event in observed if method.startswith("Network.")]
    assert len(routed) == 4
    assert all(source.session_path == () for source in routed)
    session.detach((), session_id="iframe-session")
    router.begin_shutdown()
    router.finish()


def test_oopif_redirect_request_keeps_the_root_canonical_source() -> None:
    session = _FakeNonFlatSession()
    router, observed = _router(session)
    iframe = session.attach(
        (), session_id="iframe", target_id="frame-id", target_type="iframe"
    )
    first = {
        "requestId": "navigation",
        "loaderId": "navigation",
        "frameId": "frame-id",
        "type": "Document",
        "request": {"method": "GET", "url": "https://frame.test/first"},
    }
    session.emit((), "Network.requestWillBeSent", first)
    session.emit(
        iframe,
        "Network.requestWillBeSent",
        {
            **first,
            "redirectResponse": {"status": 302},
            "request": {"method": "GET", "url": "https://frame.test/final"},
        },
    )
    session.emit(iframe, "Network.loadingFinished", {"requestId": "navigation"})
    sources = [source for source, method, _event in observed if method.startswith("Network.")]
    assert len(sources) == 3
    assert all(source.session_path == () for source in sources)
    session.detach((), session_id="iframe")
    router.begin_shutdown()
    router.finish()


def test_oopif_migration_with_two_plausible_origins_fails_closed() -> None:
    session = _FakeNonFlatSession()
    router, _observed = _router(session)
    iframe = session.attach(
        (), session_id="iframe", target_id="frame-id", target_type="iframe"
    )
    worker = session.attach(
        (), session_id="worker", target_id="worker-id", target_type="worker"
    )
    event = {
        "requestId": "collision",
        "loaderId": "collision",
        "frameId": "frame-id",
        "type": "Document",
        "request": {"method": "GET", "url": "https://frame.test/"},
    }
    session.emit((), "Network.requestWillBeSent", event)
    session.emit(worker, "Network.requestWillBeSent", event)
    session.emit(
        iframe,
        "Network.requestWillBeSent",
        {**event, "redirectResponse": {"status": 302}},
    )
    with pytest.raises(CdpTargetIntegrityError, match="migration is ambiguous"):
        router.raise_if_failed()


def test_duplicate_session_identity_on_another_branch_fails_closed() -> None:
    session = _FakeNonFlatSession()
    router, _observed = _router(session)
    iframe = session.attach(
        (), session_id="iframe-session", target_id="iframe-target", target_type="iframe"
    )
    session.attach(
        (), session_id="duplicate-session", target_id="first-worker", target_type="worker"
    )
    session.attach(
        iframe,
        session_id="duplicate-session",
        target_id="second-worker",
        target_type="worker",
    )

    with pytest.raises(CdpTargetIntegrityError, match="identity was reused"):
        router.raise_if_failed()


@pytest.mark.parametrize("target_type", ["service_worker", "page", "other"])
def test_unsupported_related_target_types_fail_closed(target_type: str) -> None:
    session = _FakeNonFlatSession()
    router, _observed = _router(session)
    session.attach(
        (),
        session_id="unsupported-session",
        target_id="unsupported-target",
        target_type=target_type,
    )

    with pytest.raises(CdpTargetIntegrityError, match="worker|unsupported"):
        router.raise_if_failed()


def test_child_network_event_during_enable_race_fails_closed() -> None:
    session = _FakeNonFlatSession(hold_methods={"Network.enable"})
    router, _observed = _router(session)
    worker = session.attach(
        (), session_id="worker-session", target_id="worker-target", target_type="worker"
    )
    session.emit(
        worker,
        "Network.requestWillBeSent",
        {
            "requestId": "too-early",
            "request": {"method": "GET", "url": "https://worker.test/data"},
        },
    )

    with pytest.raises(CdpTargetIntegrityError, match="before instrumentation"):
        router.raise_if_failed()


def test_detach_during_setup_is_normal_for_a_short_lived_worker() -> None:
    session = _FakeNonFlatSession(hold_methods={"Network.enable"})
    router, _observed = _router(session)
    session.attach(
        (), session_id="worker-session", target_id="worker-target", target_type="worker"
    )
    session.detach((), session_id="worker-session")

    router.raise_if_failed()


def test_detach_with_active_request_or_live_descendant_fails_closed() -> None:
    session = _FakeNonFlatSession()
    router, _observed = _router(session)
    iframe = session.attach(
        (), session_id="iframe-session", target_id="iframe-target", target_type="iframe"
    )
    session.attach(
        iframe,
        session_id="nested-session",
        target_id="nested-target",
        target_type="worker",
    )
    session.emit(
        iframe,
        "Network.requestWillBeSent",
        {
            "requestId": "active",
            "request": {"method": "GET", "url": "https://frame.test/data"},
        },
    )
    session.detach((), session_id="iframe-session")

    with pytest.raises(CdpTargetIntegrityError, match="work pending"):
        router.raise_if_failed()


def test_deliberate_shutdown_drains_long_lived_child_before_detach() -> None:
    session = _FakeNonFlatSession()
    router, _observed = _router(session)
    worker = session.attach(
        (), session_id="worker-session", target_id="worker-target", target_type="worker"
    )
    session.emit(
        worker,
        "Network.requestWillBeSent",
        {
            "requestId": "long-lived",
            "request": {"method": "GET", "url": "https://worker.test/events"},
        },
    )

    router.begin_shutdown()
    session.emit(worker, "Network.loadingFailed", {"requestId": "long-lived"})
    session.detach((), session_id="worker-session")
    router.finish()


def test_target_attachment_after_shutdown_boundary_is_positively_resumed() -> None:
    session = _FakeNonFlatSession()
    router, _observed = _router(session)
    router.begin_shutdown()
    session.attach(
        (), session_id="late-session", target_id="late-target", target_type="worker"
    )

    router.finish()
    assert [
        method for route, method, _params in session.commands if route == ("late-session",)
    ] == ["Runtime.runIfWaitingForDebugger"]


def test_late_shutdown_attachment_cannot_leave_resume_unresolved() -> None:
    session = _FakeNonFlatSession(hold_methods={"Runtime.runIfWaitingForDebugger"})
    router, _observed = _router(session)
    router.begin_shutdown()
    session.attach(
        (), session_id="late-session", target_id="late-target", target_type="worker"
    )
    with pytest.raises(CdpTargetIntegrityError, match="shutdown commands remain unresolved"):
        router.finish()


@pytest.mark.parametrize(
    "method", ["Inspector.targetCrashed", "Target.targetCrashed", "Target.targetDestroyed"]
)
def test_child_crash_or_unknown_lifecycle_cannot_look_like_clean_detach(
    method: str,
) -> None:
    session = _FakeNonFlatSession()
    router, _observed = _router(session)
    worker = session.attach(
        (), session_id="worker-session", target_id="worker-target", target_type="worker"
    )
    session.emit(worker, method, {"targetId": "worker-target"})
    session.detach((), session_id="worker-session")

    with pytest.raises(CdpTargetIntegrityError, match="crashed|destroyed"):
        router.raise_if_failed()


def test_known_target_info_change_and_post_detach_destruction_are_validated() -> None:
    session = _FakeNonFlatSession()
    router, _observed = _router(session)
    session.attach(
        (), session_id="worker-session", target_id="worker-target", target_type="worker"
    )
    session.emit(
        (),
        "Target.targetInfoChanged",
        {
            "targetInfo": {
                "targetId": "worker-target",
                "type": "worker",
                "url": "https://worker.test/worker.js",
            }
        },
    )
    session.detach((), session_id="worker-session")
    session.emit((), "Target.targetDestroyed", {"targetId": "worker-target"})

    router.begin_shutdown()
    router.finish()


def test_unknown_nested_target_lifecycle_message_fails_closed() -> None:
    session = _FakeNonFlatSession()
    router, _observed = _router(session)
    worker = session.attach(
        (), session_id="worker-session", target_id="worker-target", target_type="worker"
    )
    session.emit(worker, "Target.futureLifecycleEvent", {})

    with pytest.raises(CdpTargetIntegrityError, match="unsupported nested"):
        router.raise_if_failed()


def test_child_cache_policy_violation_fails_closed() -> None:
    session = _FakeNonFlatSession()
    router, _observed = _router(session)
    worker = session.attach(
        (), session_id="worker-session", target_id="worker-target", target_type="worker"
    )
    session.emit(worker, "Network.requestServedFromCache", {"requestId": "cached"})

    with pytest.raises(CdpTargetIntegrityError, match="served a request from cache"):
        router.raise_if_failed()


def test_result_bearing_child_command_is_rejected_instead_of_discarded() -> None:
    session = _FakeNonFlatSession()
    router, _observed = _router(session)
    worker = session.attach(
        (), session_id="worker-session", target_id="worker-target", target_type="worker"
    )
    source = CdpTargetSource(worker, "worker-target")

    with pytest.raises(CdpTargetIntegrityError, match="result-bearing"):
        router.send(
            source,
            "Network.getResponseBody",
            {"requestId": "request"},
            label="response-body",
        )


def test_finish_tolerates_context_disposal_before_related_detach_callback() -> None:
    session = _FakeNonFlatSession()
    router, _observed = _router(session)
    session.attach(
        (), session_id="worker-session", target_id="worker-target", target_type="worker"
    )
    router.begin_shutdown()

    router.finish()
